#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <sys/select.h>

static const uint8_t key[] = {'C', 'E', 'R', 'I', 'S', 'E', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const uint8_t iv[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

void handle_openssl_errors(void)
{
    unsigned long err_code;
    while ((err_code = ERR_get_error()) != 0)
    {
        const char *err_str = ERR_reason_error_string(err_code);
        fprintf(stderr, "OpenSSL Error: %s\n", err_str ? err_str : "Unknown");
    }
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, const unsigned char *key,
            const unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        handle_openssl_errors();
        return -1;
    }
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    {
        handle_openssl_errors();
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        handle_openssl_errors();
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
        handle_openssl_errors();
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <serial_device_path>\n", argv[0]);
        fprintf(stderr, "Example: %s /dev/pts/10\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *serial_device_path = argv[1];
    int serial_fd = -1;
    struct termios old_tty, tty;

#define MAX_EVENT_SIZE 16384
    unsigned char read_buffer[(MAX_EVENT_SIZE + AES_BLOCK_SIZE) * 2];
    unsigned char decrypted_buffer[MAX_EVENT_SIZE + AES_BLOCK_SIZE];
    size_t buffered = 0;

    printf("Waiting for encrypted JSON supervisor data on %s...\n", serial_device_path);

    serial_fd = open(serial_device_path, O_RDONLY | O_NONBLOCK);
    if (serial_fd < 0)
    {
        perror("Error opening serial device");
        return EXIT_FAILURE;
    }

    if (tcgetattr(serial_fd, &tty) != 0)
    {
        perror("Error in tcgetattr");
        close(serial_fd);
        return EXIT_FAILURE;
    }
    old_tty = tty;
    cfmakeraw(&tty);
    tty.c_cflag |= (CREAD | CLOCAL);
    if (tcsetattr(serial_fd, TCSANOW, &tty) != 0)
    {
        perror("Error in tcsetattr");
        close(serial_fd);
        return EXIT_FAILURE;
    }
    tcflush(serial_fd, TCIFLUSH);

    while (1)
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(serial_fd, &rfds);

        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;

        int sel = select(serial_fd + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0)
        {
            if (errno == EINTR)
                continue;
            perror("select");
            break;
        }
        if (sel == 0)
            continue;

        if (buffered == sizeof(read_buffer))
        {
            memmove(read_buffer, read_buffer + (buffered / 2), buffered - (buffered / 2));
            buffered = buffered - (buffered / 2);
        }

        ssize_t n = read(serial_fd, read_buffer + buffered, sizeof(read_buffer) - buffered);
        if (n < 0)
        {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            perror("read");
            break;
        }
        if (n == 0)
            continue;

        buffered += (size_t)n;

        size_t pos = 0;
        while (buffered - pos >= sizeof(uint16_t))
        {
            uint16_t payload_len_net;
            memcpy(&payload_len_net, read_buffer + pos, sizeof(payload_len_net));
            uint16_t payload_len = ntohs(payload_len_net);

            if (payload_len == 0 || payload_len > MAX_EVENT_SIZE + AES_BLOCK_SIZE || payload_len % AES_BLOCK_SIZE != 0)
            {
                pos += 1;
                continue;
            }

            if (buffered - pos < sizeof(uint16_t) + payload_len)
                break;

            int decrypted_len = decrypt(read_buffer + pos + sizeof(uint16_t), payload_len, key, iv, decrypted_buffer);
            if (decrypted_len < 0)
            {
                pos += 1;
                continue;
            }

            decrypted_buffer[decrypted_len] = '\0';

            char *end = (char *)decrypted_buffer + decrypted_len - 1;
            while (end >= (char *)decrypted_buffer && isspace((unsigned char)*end))
            {
                *end = '\0';
                end--;
            }

            printf("%s\n", (char *)decrypted_buffer);
            fflush(stdout);

            pos += sizeof(uint16_t) + payload_len;
        }

        if (pos > 0)
        {
            memmove(read_buffer, read_buffer + pos, buffered - pos);
            buffered -= pos;
        }
    }

    printf("\nConnection closed.\n");
    tcsetattr(serial_fd, TCSANOW, &old_tty);
    close(serial_fd);
    return EXIT_SUCCESS;
}