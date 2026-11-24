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
#include <poll.h>
#include <time.h>
#include "frame_auth.h"

#define MAX_MONITORS 10
#define MAX_EVENT_SIZE 8192
#define PIPE_CHUNK_SIZE 4096
#define SENSOR_NAME_MAX 64
#define SCRIPT_SUFFIX ".bt"
#define HEARTBEAT_INTERVAL_SECONDS 5
#define HEARTBEAT_MESSAGE_MAX 160
#define HEARTBEAT_FORMAT "{\"e\":\"hb\",\"s\":\"%s\",\"q\":%u,\"a\":%d}\n"
#define DMI_TYPE11_PATH "/sys/firmware/dmi/tables/DMI"
#define DMI_RAW_MAX_BYTES 65536
#define SMBIOS_TYPE_OEM_STRINGS 11
#define SESSION_KEY_NAME "cerisekey"
#define FRAME_OVERHEAD_MARGIN 128
#define FRAME_BUFFER_SIZE (MAX_EVENT_SIZE + FRAME_OVERHEAD_MARGIN)
#define NANOSECONDS_PER_SECOND 1000000000ULL

typedef struct
{
    const char *bpftrace_script_path;
    const char *serial_device_path;
} MonitorConfig;

MonitorConfig configs[] = {
    {"/home/cerise/Downloads/dangerous_syscalls.bt", "/dev/vport0p1"},
    {"/home/cerise/Downloads/docker_socket_acess.bt", "/dev/vport0p2"},
    {"/home/cerise/Downloads/fileless_execution.bt", "/dev/vport0p3"},
    {"/home/cerise/Downloads/kernel_module_load.bt", "/dev/vport0p4"},
    {"/home/cerise/Downloads/log_tampering.bt", "/dev/vport0p5"},
    {"/home/cerise/Downloads/network_suspicious.bt", "/dev/vport0p6"},
    {"/home/cerise/Downloads/privilege_escalation.bt", "/dev/vport0p7"},
    {"/home/cerise/Downloads/sensitive_file_acess.bt", "/dev/vport0p8"},
    {"/home/cerise/Downloads/suspicious_exec.bt", "/dev/vport0p9"},
    {"/home/cerise/Downloads/persistence_activity.bt", "/dev/vport0p11"},
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

static fa_keys session_keys;
static int authenticated_mode = 0;
static uint64_t last_frame_counter = 0;

static uint64_t next_frame_counter(void)
{
    struct timespec now;
    uint64_t counter;
    clock_gettime(CLOCK_MONOTONIC, &now);
    counter = (uint64_t)now.tv_sec * NANOSECONDS_PER_SECOND + (uint64_t)now.tv_nsec;
    if (counter <= last_frame_counter)
    {
        counter = last_frame_counter + 1;
    }
    last_frame_counter = counter;
    return counter;
}

static unsigned char dmi_table_buffer[DMI_RAW_MAX_BYTES + 1];

static ssize_t read_dmi_raw(unsigned char *buffer, size_t capacity)
{
    int dmi_fd = open(DMI_TYPE11_PATH, O_RDONLY);
    if (dmi_fd < 0)
    {
        return -1;
    }
    size_t total_bytes = 0;
    while (total_bytes < capacity)
    {
        ssize_t read_bytes = read(dmi_fd, buffer + total_bytes, capacity - total_bytes);
        if (read_bytes < 0)
        {
            close(dmi_fd);
            return -1;
        }
        if (read_bytes == 0)
        {
            break;
        }
        total_bytes += (size_t)read_bytes;
    }
    close(dmi_fd);
    return (ssize_t)total_bytes;
}

static int load_session_keys(void)
{
    char session_key_hex[FA_SESSION_KEY_HEX_LEN + 1];
    const unsigned char *structure = NULL;
    size_t structure_len = 0;
    int status;

    ssize_t raw_len = read_dmi_raw(dmi_table_buffer, sizeof(dmi_table_buffer));
    if (raw_len <= 0 || (size_t)raw_len > DMI_RAW_MAX_BYTES)
    {
        OPENSSL_cleanse(dmi_table_buffer, sizeof(dmi_table_buffer));
        return -1;
    }
    status = fa_find_smbios_structure(dmi_table_buffer, (size_t)raw_len, SMBIOS_TYPE_OEM_STRINGS, &structure, &structure_len);
    if (status == FA_OK)
    {
        status = fa_parse_dmi_type11(structure, structure_len, SESSION_KEY_NAME, session_key_hex, sizeof(session_key_hex));
    }
    if (status == FA_OK)
    {
        status = fa_derive_keys(session_key_hex, &session_keys);
    }
    OPENSSL_cleanse(session_key_hex, sizeof(session_key_hex));
    OPENSSL_cleanse(dmi_table_buffer, sizeof(dmi_table_buffer));
    return status == FA_OK ? 0 : -1;
}

static int send_authenticated_line(int serial_fd, const char *line, size_t line_len)
{
    unsigned char frame[FRAME_BUFFER_SIZE];
    size_t frame_len = 0;

    int status = fa_build_frame(&session_keys, next_frame_counter(), (const unsigned char *)line, line_len,
                                frame, sizeof(frame), &frame_len);
    if (status != FA_OK)
    {
        return -1;
    }
    ssize_t written_bytes = write_exact(serial_fd, frame, frame_len);
    if (written_bytes < 0 || (size_t)written_bytes < frame_len)
    {
        return -1;
    }
    return 0;
}

static int send_encrypted_line(int serial_fd, const char *line, size_t line_len)
{
    if (authenticated_mode)
    {
        return send_authenticated_line(serial_fd, line, line_len);
    }

    unsigned char ciphertext[MAX_EVENT_SIZE + AES_BLOCK_SIZE] = {0};
    unsigned char message_to_send[sizeof(uint16_t) + sizeof(ciphertext)] = {0};

    int ciphertext_len = encrypt((unsigned char *)line, (int)line_len, key, iv, ciphertext);

    uint16_t payload_len_net = htons(ciphertext_len);
    memcpy(message_to_send, &payload_len_net, sizeof(payload_len_net));
    memcpy(message_to_send + sizeof(payload_len_net), ciphertext, ciphertext_len);

    size_t total_to_write = sizeof(payload_len_net) + ciphertext_len;
    ssize_t written_bytes = write_exact(serial_fd, message_to_send, total_to_write);

    if (written_bytes < 0)
    {
        return -1;
    }
    if ((size_t)written_bytes < total_to_write)
    {
        return -1;
    }
    return 0;
}

static void sensor_name_from_path(const char *script_path, char *name_out, size_t name_out_size)
{
    const char *base = strrchr(script_path, '/');
    base = (base != NULL) ? base + 1 : script_path;

    size_t length = strlen(base);
    size_t suffix_length = strlen(SCRIPT_SUFFIX);
    if (length > suffix_length && strcmp(base + length - suffix_length, SCRIPT_SUFFIX) == 0)
    {
        length -= suffix_length;
    }
    if (length >= name_out_size)
    {
        length = name_out_size - 1;
    }
    memcpy(name_out, base, length);
    name_out[length] = '\0';
}

static int child_is_alive(pid_t *child_pid)
{
    if (*child_pid <= 0)
    {
        return 0;
    }
    pid_t result = waitpid(*child_pid, NULL, WNOHANG);
    if (result == 0)
    {
        return 1;
    }
    *child_pid = -1;
    return 0;
}

static int send_heartbeat(int serial_fd, const char *sensor_name, unsigned int sequence, int alive)
{
    char message[HEARTBEAT_MESSAGE_MAX];
    int length = snprintf(message, sizeof(message), HEARTBEAT_FORMAT, sensor_name, sequence, alive);
    if (length <= 0 || (size_t)length >= sizeof(message))
    {
        return -1;
    }
    return send_encrypted_line(serial_fd, message, (size_t)length);
}

static int forward_event_line(const MonitorConfig *config, int serial_fd, const char *line, size_t line_len)
{
    printf("[%s] Sending event: %s", config->serial_device_path, line);
    fflush(stdout);

    if (send_encrypted_line(serial_fd, line, line_len) < 0)
    {
        fprintf(stderr, "[%s] Error writing to serial device. Shutting down this monitor.\n", config->serial_device_path);
        return -1;
    }
    return 0;
}

static int drain_pipe_chunk(const MonitorConfig *config, int serial_fd, const char *chunk, ssize_t chunk_len,
                            char *line, size_t *line_len)
{
    for (ssize_t index = 0; index < chunk_len; index++)
    {
        line[(*line_len)++] = chunk[index];
        if (chunk[index] != '\n' && *line_len < MAX_EVENT_SIZE - 1)
        {
            continue;
        }
        line[*line_len] = '\0';
        int status = forward_event_line(config, serial_fd, line, *line_len);
        *line_len = 0;
        if (status < 0)
        {
            return -1;
        }
    }
    return 0;
}

static int next_poll_timeout_ms(time_t next_heartbeat)
{
    time_t remaining = next_heartbeat - time(NULL);
    if (remaining < 1)
    {
        return 1;
    }
    return (int)(remaining * 1000);
}

void run_monitor_instance(const MonitorConfig *config)
{
    FILE *command_pipe;
    pid_t command_pid = -1;
    int serial_fd;
    char sensor_name[SENSOR_NAME_MAX];
    char line[MAX_EVENT_SIZE];
    size_t line_len = 0;
    unsigned int heartbeat_sequence = 0;
    time_t next_heartbeat = 0;
    int serial_failed = 0;
    int stream_open = 1;

    sensor_name_from_path(config->bpftrace_script_path, sensor_name, sizeof(sensor_name));

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

    int pipe_fd = fileno(command_pipe);

    printf("[PID %d] Monitoring active. Encrypted output is being sent to the host.\n", getpid());

    while (stream_open && !serial_failed)
    {
        if (time(NULL) >= next_heartbeat)
        {
            int alive = child_is_alive(&command_pid);
            if (send_heartbeat(serial_fd, sensor_name, heartbeat_sequence++, alive) < 0)
            {
                serial_failed = 1;
                break;
            }
            next_heartbeat = time(NULL) + HEARTBEAT_INTERVAL_SECONDS;
            if (!alive)
            {
                break;
            }
        }

        struct pollfd pipe_poll = {.fd = pipe_fd, .events = POLLIN, .revents = 0};
        int ready = poll(&pipe_poll, 1, next_poll_timeout_ms(next_heartbeat));
        if (ready < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            perror("poll");
            break;
        }
        if (ready == 0)
        {
            continue;
        }

        char chunk[PIPE_CHUNK_SIZE];
        ssize_t chunk_len = read(pipe_fd, chunk, sizeof(chunk));
        if (chunk_len < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            perror("read");
            break;
        }
        if (chunk_len == 0)
        {
            stream_open = 0;
            continue;
        }
        if (drain_pipe_chunk(config, serial_fd, chunk, chunk_len, line, &line_len) < 0)
        {
            serial_failed = 1;
        }
    }

    if (!serial_failed && line_len > 0)
    {
        line[line_len] = '\0';
        forward_event_line(config, serial_fd, line, line_len);
    }

    child_is_alive(&command_pid);
    if (!serial_failed)
    {
        send_heartbeat(serial_fd, sensor_name, heartbeat_sequence, 0);
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

    authenticated_mode = load_session_keys() == 0;
    printf(authenticated_mode ? "authenticated mode\n" : "legacy mode\n");
    fflush(stdout);

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
