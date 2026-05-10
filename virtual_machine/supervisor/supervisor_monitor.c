#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <signal.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/select.h>
#include <time.h>

#define SERIAL_DEVICE_PATH "/dev/vport0p10"
#define SUPERVISOR_SCRIPT_PATH "./supervisor/supervisor.py"

static const uint8_t key[] = {'C', 'E', 'R', 'I', 'S', 'E', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const uint8_t iv[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

static pid_t supervisor_pid = -1;

void handle_openssl_errors(void)
{
    fprintf(stderr, "OpenSSL Error:\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

int encrypt(unsigned char *plaintext, int plaintext_len, const unsigned char *key,
            const unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handle_openssl_errors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handle_openssl_errors();

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handle_openssl_errors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handle_openssl_errors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

ssize_t write_exact(int fd, const void *buf, size_t count)
{
    size_t bytes_written_total = 0;
    struct timespec start_ts;
    struct timespec now_ts;
    const long timeout_ms = 5000;

    clock_gettime(CLOCK_MONOTONIC, &start_ts);

    while (bytes_written_total < count)
    {
        clock_gettime(CLOCK_MONOTONIC, &now_ts);
        long elapsed_ms = (now_ts.tv_sec - start_ts.tv_sec) * 1000L +
                          (now_ts.tv_nsec - start_ts.tv_nsec) / 1000000L;
        if (elapsed_ms >= timeout_ms)
        {
            return (ssize_t)bytes_written_total;
        }

        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200000;

        int ready = select(fd + 1, NULL, &wfds, NULL, &tv);
        if (ready < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return -1;
        }
        if (ready == 0)
        {
            continue;
        }

        ssize_t bytes_written_now = write(fd, (const char *)buf + bytes_written_total, count - bytes_written_total);
        if (bytes_written_now < 0)
        {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                continue;
            }
            return -1;
        }
        if (bytes_written_now == 0)
        {
            continue;
        }
        bytes_written_total += bytes_written_now;
    }

    return (ssize_t)bytes_written_total;
}

static FILE *execute_command_and_get_pipe(const char *file, char *const argv[], pid_t *child_pid_out)
{
    int pipefd[2];
    pid_t pid;

    if (pipe(pipefd) == -1)
    {
        perror("pipe");
        return NULL;
    }

    pid = fork();
    if (pid == -1)
    {
        perror("fork in execute_command");
        close(pipefd[0]);
        close(pipefd[1]);
        return NULL;
    }

    if (pid == 0)
    {
        if (setsid() < 0)
        {
            perror("setsid");
            exit(EXIT_FAILURE);
        }

        close(pipefd[0]);

        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);

        int dev_null_fd = open("/dev/null", O_RDONLY);
        if (dev_null_fd != -1)
        {
            dup2(dev_null_fd, STDIN_FILENO);
            close(dev_null_fd);
        }

        close(pipefd[1]);

        execvp(file, argv);

        perror("execvp");
        exit(127);
    }
    else
    {
        close(pipefd[1]);
        *child_pid_out = pid;

        FILE *stream = fdopen(pipefd[0], "r");
        if (stream == NULL)
        {
            perror("fdopen");
            close(pipefd[0]);
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
            return NULL;
        }
        return stream;
    }
}

void cleanup_handler(int signum)
{
    (void)signum;
    if (supervisor_pid > 0)
    {
        kill(supervisor_pid, SIGTERM);
        waitpid(supervisor_pid, NULL, 0);
    }
    exit(0);
}

int read_line(FILE *fp, char *buffer, int size)
{
    int pos = 0;
    int c;

    while ((c = fgetc(fp)) != EOF && c != '\n' && pos < size - 1)
    {
        buffer[pos++] = c;
    }

    if (c == '\n')
    {
        buffer[pos++] = '\n';
    }

    buffer[pos] = '\0';

    if (pos == 0)
        return -1;

    return pos;
}

int main(void)
{
    fprintf(stdout, "[supervisor_monitor] Starting...\n");
    fflush(stdout);

    if (geteuid() != 0)
    {
        fprintf(stderr, "Error: This program must run as root\n");
        exit(EXIT_FAILURE);
    }

    FILE *command_pipe;
    int serial_fd;
#define MAX_EVENT_SIZE 16384
    char buffer[MAX_EVENT_SIZE];

    signal(SIGINT, cleanup_handler);
    signal(SIGTERM, cleanup_handler);

    fprintf(stdout, "[supervisor_monitor] Opening serial device %s...\n", SERIAL_DEVICE_PATH);
    fflush(stdout);

    serial_fd = open(SERIAL_DEVICE_PATH, O_WRONLY | O_NONBLOCK);
    if (serial_fd < 0)
    {
        fprintf(stdout, "[supervisor_monitor] Failed to open serial device: %s\n", strerror(errno));
        fflush(stdout);
        perror("Error opening serial device");
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "[supervisor_monitor] Serial device opened successfully\n");
    fflush(stdout);

    char *const supervisor_argv[] = {
        "/usr/bin/python3",
        "-u",
        SUPERVISOR_SCRIPT_PATH,
        NULL};

    fprintf(stdout, "[supervisor_monitor] Executing supervisor script...\n");
    fflush(stdout);

    command_pipe = execute_command_and_get_pipe(supervisor_argv[0], supervisor_argv, &supervisor_pid);
    if (command_pipe == NULL)
    {
        fprintf(stdout, "[supervisor_monitor] Failed to execute supervisor script\n");
        fflush(stdout);
        fprintf(stderr, "Failed to execute supervisor script.\n");
        close(serial_fd);
        exit(EXIT_FAILURE);
    }

    setvbuf(command_pipe, NULL, _IOLBF, 0);

    fprintf(stdout, "[supervisor_monitor] Supervisor script started (PID %d). Waiting for events...\n", supervisor_pid);
    fflush(stdout);

    while (read_line(command_pipe, buffer, sizeof(buffer)) > 0)
    {
        int buf_len = strlen(buffer);
        fprintf(stdout, "[supervisor_monitor] Received event (%d bytes)\n", buf_len);
        fprintf(stdout, "[supervisor_monitor] Content: %s", buffer);
        fflush(stdout);

        unsigned char ciphertext[sizeof(buffer) + AES_BLOCK_SIZE] = {0};
        unsigned char message_to_send[sizeof(uint16_t) + sizeof(ciphertext)] = {0};
        int ciphertext_len;

        ciphertext_len = encrypt((unsigned char *)buffer, strlen(buffer), key, iv, ciphertext);

        uint16_t payload_len_net = htons(ciphertext_len);
        memcpy(message_to_send, &payload_len_net, sizeof(payload_len_net));
        memcpy(message_to_send + sizeof(payload_len_net), ciphertext, ciphertext_len);

        size_t total_to_write = sizeof(payload_len_net) + ciphertext_len;
        ssize_t written_bytes = write_exact(serial_fd, message_to_send, total_to_write);

        if (written_bytes < 0)
        {
            fprintf(stdout, "[supervisor_monitor] Error writing to serial device\n");
            fflush(stdout);
            perror("write");
            continue;
        }
        if ((size_t)written_bytes < total_to_write)
        {
            fprintf(stdout, "[supervisor_monitor] Incomplete write to serial device\n");
            fflush(stdout);
            continue;
        }
        fprintf(stdout, "[supervisor_monitor] Successfully sent %zd bytes to serial device\n", written_bytes);
        fflush(stdout);
    }

    fclose(command_pipe);
    close(serial_fd);

    if (supervisor_pid > 0)
    {
        waitpid(supervisor_pid, NULL, 0);
    }

    return EXIT_SUCCESS;
}