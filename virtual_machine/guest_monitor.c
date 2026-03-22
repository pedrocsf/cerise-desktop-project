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

#define MAX_MONITORS 10

typedef struct
{
    const char *bpftrace_script_path;
    const char *serial_device_path;
} MonitorConfig;

MonitorConfig configs[] = {
    {"/home/cerise/Downloads/privilege_escalation.bt", "/dev/vport0p1"},
    {"/home/cerise/Downloads/privilege_escalation.bt", "/dev/vport0p2"},
    {"/home/cerise/Downloads/privilege_escalation.bt", "/dev/vport0p3"},
    {"/home/cerise/Downloads/privilege_escalation.bt", "/dev/vport0p4"},
};

static const uint8_t key[] = {'C', 'E', 'R', 'I', 'S', 'E', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const uint8_t iv[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

static pid_t child_pids[MAX_MONITORS];
static int num_children = 0;

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
    while (bytes_written_total < count)
    {
        ssize_t bytes_written_now = write(fd, (const char *)buf + bytes_written_total, count - bytes_written_total);
        if (bytes_written_now < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            perror("write_exact");
            return -1;
        }
        bytes_written_total += bytes_written_now;
    }
    return bytes_written_total;
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

void run_monitor_instance(const MonitorConfig *config)
{
    FILE *command_pipe;
    pid_t command_pid = -1;
    int serial_fd;
#define MAX_EVENT_SIZE 8192
    char buffer[MAX_EVENT_SIZE];

    printf("[PID %d] Starting monitor for %s -> %s\n", getpid(), config->bpftrace_script_path, config->serial_device_path);

    serial_fd = open(config->serial_device_path, O_WRONLY);
    if (serial_fd < 0)
    {
        perror("Error opening serial device");
        fprintf(stderr, "[PID %d] Check if device '%s' exists and if you have permission.\n", getpid(), config->serial_device_path);
        fprintf(stderr, "Was the VM started with the correct virtio-serial chardev?\n");
        exit(EXIT_FAILURE);
    }

    char *const bpftrace_argv[] = {
        "stdbuf",
        "-oL",
        "/usr/bin/bpftrace",
        (char *)config->bpftrace_script_path,
        NULL};

    command_pipe = execute_command_and_get_pipe("stdbuf", bpftrace_argv, &command_pid);
    if (command_pipe == NULL)
    {
        fprintf(stderr, "[PID %d] Failed to execute command and create pipe.\n", getpid());
        close(serial_fd);
        exit(EXIT_FAILURE);
    }

    printf("[PID %d] Monitoring active. Encrypted output is being sent to the host.\n", getpid());

    while (fgets(buffer, sizeof(buffer), command_pipe) != NULL)
    {
        printf("[%s] Sending event: %s", config->serial_device_path, buffer);
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
            fprintf(stderr, "[%s] Error writing to serial device. Shutting down this monitor.\n", config->serial_device_path);
            break;
        }
        if ((size_t)written_bytes < total_to_write)
        {
            fprintf(stderr, "[%s] Incomplete write to serial device (wrote %zd of %zu). Shutting down.\n",
                    config->serial_device_path, written_bytes, total_to_write);
            break;
        }
    }

    printf("[PID %d] Shutting down monitor for %s...\n", getpid(), config->bpftrace_script_path);
    fclose(command_pipe);
    close(serial_fd);

    if (command_pid > 0)
    {
        waitpid(command_pid, NULL, 0);
    }

    exit(EXIT_SUCCESS);
}

void cleanup_handler(int signum)
{
    (void)signum;
    printf("\nTermination signal received. Stopping all child monitors...\n");
    for (int i = 0; i < num_children; i++)
    {
        if (child_pids[i] > 0)
        {
            printf("Stopping child PID %d...\n", child_pids[i]);
            kill(child_pids[i], SIGTERM);
        }
    }
    for (int i = 0; i < num_children; i++)
    {
        wait(NULL);
    }
    printf("All monitors stopped. Exiting.\n");
    exit(0);
}

int main(void)
{
    int num_configs = (int)(sizeof(configs) / sizeof(MonitorConfig));
    if (num_configs > MAX_MONITORS)
    {
        fprintf(stderr, "Error: Number of configured monitors exceeds MAX_MONITORS limit.\n");
        return EXIT_FAILURE;
    }

    signal(SIGINT, cleanup_handler);
    signal(SIGTERM, cleanup_handler);

    for (int i = 0; i < num_configs; i++)
    {
        pid_t pid = fork();
        if (pid == 0)
        {
            run_monitor_instance(&configs[i]);
        }
        else if (pid > 0)
        {
            child_pids[num_children++] = pid;
        }
        else
        {
            perror("Failed to fork");
        }
    }

    printf("All monitors started. Parent process (PID %d) is waiting...\n", getpid());
    for (int i = 0; i < num_children; i++)
    {
        wait(NULL);
    }

    return EXIT_SUCCESS;
}
