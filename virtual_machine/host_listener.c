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

static struct termios old_tty;
static int serial_fd = -1;

void restore_terminal_settings(void);
static const uint8_t key[] = {'C', 'E', 'R', 'I', 'S', 'E', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const uint8_t iv[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

void handle_openssl_errors(void)
{
    fprintf(stderr, "OpenSSL Error:\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, const unsigned char *key,
            const unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handle_openssl_errors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handle_openssl_errors();

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handle_openssl_errors();
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handle_openssl_errors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

ssize_t read_exact(int fd, void *buf, size_t count)
{
    size_t bytes_read_total = 0;
    while (bytes_read_total < count)
    {
        ssize_t bytes_read_now = read(fd, (char *)buf + bytes_read_total, count - bytes_read_total);
        if (bytes_read_now < 0)
        {
            return -1;
        }
        if (bytes_read_now == 0)
        {
            return bytes_read_total;
        }
        bytes_read_total += bytes_read_now;
    }
    return bytes_read_total;
}

int main(int argc, char *argv[])
{
    unsigned char read_buffer[4096 + AES_BLOCK_SIZE];
    unsigned char decrypted_buffer[4096 + AES_BLOCK_SIZE];

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <serial_device_path>\n", argv[0]);
        fprintf(stderr, "Example: %s /dev/pts/4\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *serial_device_path = argv[1];

    printf("Waiting for encrypted data on %s...\n", serial_device_path);

    serial_fd = open(serial_device_path, O_RDONLY);
    if (serial_fd < 0)
    {
        perror("Error opening serial device");
        return EXIT_FAILURE;
    }

    atexit(restore_terminal_settings);

    struct termios tty;

    if (tcgetattr(serial_fd, &tty) != 0)
    {
        perror("Error in tcgetattr");
        return EXIT_FAILURE;
    }
    old_tty = tty;

    cfmakeraw(&tty);

    if (tcsetattr(serial_fd, TCSANOW, &tty) != 0)
    {
        perror("Error in tcsetattr");
        return EXIT_FAILURE;
    }

    while (1)
    {
        uint16_t payload_len_net;

        ssize_t len_bytes_read = read_exact(serial_fd, &payload_len_net, sizeof(payload_len_net));

        if (len_bytes_read == 0)
        {
            break;
        }
        if (len_bytes_read < sizeof(payload_len_net))
        {
            fprintf(stderr, "\nError: Failed to read payload size header (connection closed?).\n");
            break;
        }

        uint16_t payload_len = ntohs(payload_len_net);

        if (payload_len > sizeof(read_buffer))
        {
            fprintf(stderr, "\nError: Received payload (%u bytes) is larger than the read buffer.\n", payload_len);
            break;
        }

        ssize_t payload_bytes_read = read_exact(serial_fd, read_buffer, payload_len);
        if (payload_bytes_read < payload_len)
        {
            fprintf(stderr, "\nError: Incomplete payload. Expected %u, received %zd.\n", payload_len, payload_bytes_read);
            break;
        }

        int decrypted_len;
        decrypted_len = decrypt(read_buffer, payload_bytes_read, key, iv, decrypted_buffer);
        decrypted_buffer[decrypted_len] = '\0';
        printf("%s", (char *)decrypted_buffer);
        fflush(stdout);
    }

    printf("\nConnection closed.\n");
    close(serial_fd);
    serial_fd = -1;

    return EXIT_SUCCESS;
}

void restore_terminal_settings(void)
{
    if (serial_fd != -1)
    {
        tcsetattr(serial_fd, TCSANOW, &old_tty);
    }
}