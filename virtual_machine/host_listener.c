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
#include <sys/wait.h>
#include <ctype.h>
#include <errno.h>

static const uint8_t key[] = {'C', 'E', 'R', 'I', 'S', 'E', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const uint8_t iv[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

void handle_openssl_errors(const char *prefix)
{
    unsigned long err_code;
    const char *err_str;

    while ((err_code = ERR_get_error()) != 0)
    {
        err_str = ERR_reason_error_string(err_code);
        if (err_str == NULL)
        {
            err_str = "Unknown OpenSSL error";
        }

        if (prefix)
            fprintf(stderr, "[%s] OpenSSL Error: %s\n", prefix, err_str);
        else
            fprintf(stderr, "OpenSSL Error: %s\n", err_str);
    }
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, const unsigned char *key,
            const unsigned char *iv, unsigned char *plaintext, const char *err_prefix)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        handle_openssl_errors(err_prefix); // Prints details
        return -1;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    {
        handle_openssl_errors(err_prefix);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        handle_openssl_errors(err_prefix);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    { // This is where "bad decrypt" usually happens
        handle_openssl_errors(err_prefix);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
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
            if (errno == EINTR)
            {
                continue; // Interrupted by a signal, retry the read.
            }
            perror("read_exact"); // A real error occurred.
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

static int listen_on_serial(const char *serial_device_path, int use_prefix)
{
#define MAX_EVENT_SIZE 8192
    int serial_fd = -1;
    struct termios old_tty;

    unsigned char read_buffer[MAX_EVENT_SIZE + AES_BLOCK_SIZE];
    unsigned char decrypted_buffer[MAX_EVENT_SIZE + AES_BLOCK_SIZE];

    printf("Waiting for encrypted data on %s...\n", serial_device_path);

    serial_fd = open(serial_device_path, O_RDONLY);
    if (serial_fd < 0)
    {
        // Use fprintf with prefix for consistency
        if (use_prefix)
            fprintf(stderr, "[%s] Error opening serial device: %s\n", serial_device_path, strerror(errno));
        else
            fprintf(stderr, "Error opening serial device: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    struct termios tty;

    if (tcgetattr(serial_fd, &tty) != 0)
    {
        if (use_prefix)
            fprintf(stderr, "[%s] Error in tcgetattr: %s\n", serial_device_path, strerror(errno));
        else
            fprintf(stderr, "Error in tcgetattr: %s\n", strerror(errno));
        close(serial_fd);
        return EXIT_FAILURE;
    }
    old_tty = tty;

    cfmakeraw(&tty);
    tty.c_cflag |= (CREAD | CLOCAL);

    if (tcsetattr(serial_fd, TCSANOW, &tty) != 0)
    {
        if (use_prefix)
            fprintf(stderr, "[%s] Error in tcsetattr: %s\n", serial_device_path, strerror(errno));
        else
            fprintf(stderr, "Error in tcsetattr: %s\n", strerror(errno));
        close(serial_fd);
        return EXIT_FAILURE;
    }

    if (tcflush(serial_fd, TCIFLUSH) == -1)
    {
        if (use_prefix)
            fprintf(stderr, "[%s] Warning: tcflush failed: %s\n", serial_device_path, strerror(errno));
        else
            fprintf(stderr, "Warning: tcflush failed: %s\n", strerror(errno));
        // This is not a fatal error, so we continue
    }

    while (1)
    {
        uint16_t payload_len_net;

        ssize_t len_bytes_read = read_exact(serial_fd, &payload_len_net, sizeof(payload_len_net));

        if (len_bytes_read < 0)
        {
            if (use_prefix)
                fprintf(stderr, "[%s] Error: Read operation failed while getting payload size.\n", serial_device_path);
            else
                fprintf(stderr, "Error: Read operation failed while getting payload size.\n");
            break;
        }

        if (len_bytes_read == 0)
        {
            break;
        }
        if (len_bytes_read < sizeof(payload_len_net))
        {
            if (use_prefix)
                fprintf(stderr, "[%s] Error: Failed to read payload size header (connection closed?).\n", serial_device_path);
            else
                fprintf(stderr, "Error: Failed to read payload size header (connection closed?).\n");
            break;
        }

        uint16_t payload_len = ntohs(payload_len_net);

        // 1. Check if payload is too large for the buffer
        if (payload_len > sizeof(read_buffer))
        {
            if (use_prefix)
                fprintf(stderr, "[%s] Error: Received payload (%u bytes) is larger than the read buffer (%zu bytes).\n", serial_device_path, payload_len, sizeof(read_buffer));
            else
                fprintf(stderr, "Error: Received payload (%u bytes) is larger than the read buffer (%zu bytes).\n", payload_len, sizeof(read_buffer));
            break;
        }

        // 2. Check if payload size is valid for AES-CBC (must be a non-zero multiple of block size)
        if (payload_len == 0 || payload_len % AES_BLOCK_SIZE != 0)
        {
            if (use_prefix)
                fprintf(stderr, "[%s] Error: Received payload size (%u) is not a non-zero multiple of AES block size (%d). Framing error.\n", serial_device_path, payload_len, AES_BLOCK_SIZE);
            else
                fprintf(stderr, "Error: Received payload size (%u) is not a non-zero multiple of AES block size (%d). Framing error.\n", payload_len, AES_BLOCK_SIZE);
            break;
        }

        ssize_t payload_bytes_read = read_exact(serial_fd, read_buffer, payload_len);
        if (payload_bytes_read < 0)
        {
            if (use_prefix)
                fprintf(stderr, "[%s] Error: Read operation failed while getting payload data.\n", serial_device_path);
            else
                fprintf(stderr, "Error: Read operation failed while getting payload data.\n");
            break;
        }

        if (payload_bytes_read < payload_len)
        {
            if (use_prefix)
                fprintf(stderr, "[%s] Error: Incomplete payload. Expected %u, received %zd.\n", serial_device_path, payload_len, payload_bytes_read);
            else
                fprintf(stderr, "Error: Incomplete payload. Expected %u, received %zd.\n", payload_len, payload_bytes_read);
            break;
        }

        int decrypted_len;
        const char *prefix_for_decrypt = use_prefix ? serial_device_path : NULL;
        decrypted_len = decrypt(read_buffer, payload_bytes_read, key, iv, decrypted_buffer, prefix_for_decrypt);
        if (decrypted_len < 0)
        {
            if (use_prefix)
                fprintf(stderr, "[%s] Decryption failed. The stream may be corrupted. Stopping this listener.\n", serial_device_path);
            else
                fprintf(stderr, "Decryption failed. The stream may be corrupted. Stopping this listener.\n");
            break; // Stop processing this stream
        }
        decrypted_buffer[decrypted_len] = '\0';

        // Trim trailing whitespace (like \n, \r, etc.) from the decrypted string
        char *end = (char *)decrypted_buffer + decrypted_len - 1;
        while (end >= (char *)decrypted_buffer && isspace((unsigned char)*end))
        {
            *end = '\0';
            end--;
        }

        if (use_prefix)
        {
            printf("[%s] %s\n", serial_device_path, (char *)decrypted_buffer);
        }
        else
        {
            printf("%s\n", (char *)decrypted_buffer);
        }
        fflush(stdout);
    }

    printf("\nConnection closed.\n");
    tcsetattr(serial_fd, TCSANOW, &old_tty);
    close(serial_fd);

    return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <serial_device_path> [serial_device_path ...]\n", argv[0]);
        fprintf(stderr, "Example (single): %s /dev/pts/4\n", argv[0]);
        fprintf(stderr, "Example (multi):  %s /dev/pts/4 /dev/pts/5 /dev/pts/6\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (argc == 2)
    {
        return listen_on_serial(argv[1], 0);
    }

    int child_count = 0;
    for (int i = 1; i < argc; i++)
    {
        pid_t pid = fork();
        if (pid == 0)
        {
            return listen_on_serial(argv[i], 1);
        }
        if (pid > 0)
        {
            child_count++;
            continue;
        }

        perror("Failed to fork host listener child");
    }

    for (int i = 0; i < child_count; i++)
    {
        wait(NULL);
    }

    return EXIT_SUCCESS;
}