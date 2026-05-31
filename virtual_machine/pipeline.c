#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define SERIAL_PORTS_FILE "serial_ports.list"
#define BATCH_INTERVAL_SEC 30
#define MAX_BATCH_SIZE 131072
#define MAX_LINE_SIZE 8192
#define MAX_PORTS 16
#define OLLAMA_PORT 11434
#define OLLAMA_HOST "127.0.0.1"
#define RESPONSE_BUFFER_SIZE 262144

static volatile int running = 1;
static pid_t listener_pid = -1;

static const char *ANALYSIS_PROMPT_PREFIX =
    "### Instruction:\\n"
    "You are a malware analyst. Analyze the following data collected from a sandboxed virtual machine.\\n"
    "The data includes kernel-level syscall traces (from eBPF) and network request logs.\\n"
    "Identify suspicious behaviors, potential malware indicators, and describe what the malware appears to be doing.\\n"
    "Output ONLY the analysis result in plain text.\\n"
    "Do NOT output any timestamps, debug logs, or simulate system output.\\n"
    "\\n### Input:\\n";

static const char *ANALYSIS_PROMPT_SUFFIX =
    "\\n\\n### Response:\\n";

void signal_handler(int signum)
{
    (void)signum;
    running = 0;
    if (listener_pid > 0)
        kill(listener_pid, SIGTERM);
}

int load_ports_from_file(const char *filepath, char ports[][128], int max_ports)
{
    FILE *f = fopen(filepath, "r");
    if (!f)
        return 0;

    int count = 0;
    char line[256];
    while (fgets(line, sizeof(line), f) && count < max_ports)
    {
        char label[64], path[128];
        if (sscanf(line, "%63s %127s", label, path) == 2)
        {
            strncpy(ports[count], path, 127);
            ports[count][127] = '\0';
            count++;
        }
    }
    fclose(f);
    return count;
}

int spawn_host_listener(char ports[][128], int port_count, pid_t *pid_out)
{
    int pipefd[2];
    if (pipe(pipefd) < 0)
    {
        perror("pipe");
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0)
    {
        perror("fork");
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0)
    {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        char self_path[512];
        ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
        if (len < 0)
            _exit(127);
        self_path[len] = '\0';

        char *dir_end = strrchr(self_path, '/');
        if (dir_end)
            *(dir_end + 1) = '\0';

        char listener_path[512];
        snprintf(listener_path, sizeof(listener_path), "%shost_listener", self_path);

        char *argv[MAX_PORTS + 2];
        argv[0] = listener_path;
        for (int i = 0; i < port_count; i++)
            argv[i + 1] = ports[i];
        argv[port_count + 1] = NULL;

        execv(listener_path, argv);
        perror("execv host_listener");
        _exit(127);
    }

    close(pipefd[1]);
    *pid_out = pid;

    int flags = fcntl(pipefd[0], F_GETFL, 0);
    fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);

    return pipefd[0];
}

char *json_escape(const char *input, char *output, size_t output_size)
{
    size_t j = 0;
    for (size_t i = 0; input[i] != '\0' && j < output_size - 2; i++)
    {
        switch (input[i])
        {
        case '"':
            if (j + 2 >= output_size) goto done;
            output[j++] = '\\';
            output[j++] = '"';
            break;
        case '\\':
            if (j + 2 >= output_size) goto done;
            output[j++] = '\\';
            output[j++] = '\\';
            break;
        case '\n':
            if (j + 2 >= output_size) goto done;
            output[j++] = '\\';
            output[j++] = 'n';
            break;
        case '\r':
            if (j + 2 >= output_size) goto done;
            output[j++] = '\\';
            output[j++] = 'r';
            break;
        case '\t':
            if (j + 2 >= output_size) goto done;
            output[j++] = '\\';
            output[j++] = 't';
            break;
        default:
            if ((unsigned char)input[i] < 0x20)
            {
                if (j + 6 >= output_size) goto done;
                j += snprintf(output + j, output_size - j, "\\u%04x", (unsigned char)input[i]);
            }
            else
            {
                output[j++] = input[i];
            }
            break;
        }
    }
done:
    output[j] = '\0';
    return output;
}

int connect_to_ollama(void)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(OLLAMA_PORT);
    inet_pton(AF_INET, OLLAMA_HOST, &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(sock);
        return -1;
    }

    return sock;
}

ssize_t send_all(int sock, const char *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len)
    {
        ssize_t n = write(sock, buf + sent, len - sent);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        sent += n;
    }
    return (ssize_t)sent;
}

char *find_json_field(const char *json, const char *field)
{
    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", field);
    char *pos = strstr(json, search);
    if (!pos)
        return NULL;
    pos += strlen(search);
    while (*pos == ' ' || *pos == ':')
        pos++;
    return pos;
}

char *extract_json_string(const char *start, char *out, size_t out_size)
{
    if (*start != '"')
        return NULL;
    start++;
    size_t j = 0;
    for (size_t i = 0; start[i] != '\0' && j < out_size - 1; i++)
    {
        if (start[i] == '\\' && start[i + 1] != '\0')
        {
            i++;
            switch (start[i])
            {
            case '"': out[j++] = '"'; break;
            case '\\': out[j++] = '\\'; break;
            case 'n': out[j++] = '\n'; break;
            case 'r': out[j++] = '\r'; break;
            case 't': out[j++] = '\t'; break;
            default: out[j++] = start[i]; break;
            }
        }
        else if (start[i] == '"')
        {
            break;
        }
        else
        {
            out[j++] = start[i];
        }
    }
    out[j] = '\0';
    return out;
}

void send_batch_to_llama(const char *batch_data)
{
    if (!batch_data || strlen(batch_data) == 0)
        return;

    size_t escaped_size = strlen(batch_data) * 2 + 1;
    char *escaped_data = malloc(escaped_size);
    if (!escaped_data)
        return;
    json_escape(batch_data, escaped_data, escaped_size);

    size_t prompt_size = strlen(ANALYSIS_PROMPT_PREFIX) + strlen(escaped_data) + strlen(ANALYSIS_PROMPT_SUFFIX) + 1;
    char *full_prompt = malloc(prompt_size);
    if (!full_prompt)
    {
        free(escaped_data);
        return;
    }
    snprintf(full_prompt, prompt_size, "%s%s%s", ANALYSIS_PROMPT_PREFIX, escaped_data, ANALYSIS_PROMPT_SUFFIX);

    size_t body_size = strlen(full_prompt) + 256;
    char *body = malloc(body_size);
    if (!body)
    {
        free(full_prompt);
        free(escaped_data);
        return;
    }
    snprintf(body, body_size,
             "{\"model\":\"llama2\",\"prompt\":\"%s\",\"stream\":true,\"options\":{\"temperature\":0.0}}",
             full_prompt);

    size_t body_len = strlen(body);

    size_t request_size = body_len + 256;
    char *request = malloc(request_size);
    if (!request)
    {
        free(body);
        free(full_prompt);
        free(escaped_data);
        return;
    }
    snprintf(request, request_size,
             "POST /api/generate HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %zu\r\n"
             "\r\n",
             OLLAMA_HOST, OLLAMA_PORT, body_len);

    int sock = connect_to_ollama();
    if (sock < 0)
    {
        fprintf(stderr, "[pipeline] Error: Could not connect to Ollama at %s:%d\n", OLLAMA_HOST, OLLAMA_PORT);
        free(request);
        free(body);
        free(full_prompt);
        free(escaped_data);
        return;
    }

    if (send_all(sock, request, strlen(request)) < 0 || send_all(sock, body, body_len) < 0)
    {
        fprintf(stderr, "[pipeline] Error: Failed to send request to Ollama\n");
        close(sock);
        free(request);
        free(body);
        free(full_prompt);
        free(escaped_data);
        return;
    }

    free(request);
    free(body);
    free(full_prompt);
    free(escaped_data);

    printf("\n\033[1;36m═══════════════════════ ANALYSIS ═══════════════════════\033[0m\n");
    fflush(stdout);

    char *recv_buf = malloc(RESPONSE_BUFFER_SIZE);
    if (!recv_buf)
    {
        close(sock);
        return;
    }

    size_t recv_total = 0;
    int headers_done = 0;
    char *body_start = NULL;
    char token_buf[4096];

    while (running)
    {
        ssize_t n = read(sock, recv_buf + recv_total, RESPONSE_BUFFER_SIZE - recv_total - 1);
        if (n <= 0)
            break;
        recv_total += n;
        recv_buf[recv_total] = '\0';

        if (!headers_done)
        {
            body_start = strstr(recv_buf, "\r\n\r\n");
            if (!body_start)
                continue;
            body_start += 4;
            headers_done = 1;
        }
        else
        {
            body_start = recv_buf;
        }

        char *line_start = body_start;
        char *newline;
        while ((newline = strchr(line_start, '\n')) != NULL)
        {
            *newline = '\0';

            char *resp_field = find_json_field(line_start, "response");
            if (resp_field)
            {
                if (extract_json_string(resp_field, token_buf, sizeof(token_buf)))
                {
                    printf("%s", token_buf);
                    fflush(stdout);
                }
            }

            char *done_field = find_json_field(line_start, "done");
            if (done_field && strncmp(done_field, "true", 4) == 0)
            {
                goto stream_done;
            }

            line_start = newline + 1;
        }

        size_t remaining = recv_total - (line_start - recv_buf);
        if (remaining > 0 && line_start != recv_buf)
        {
            memmove(recv_buf, line_start, remaining);
        }
        recv_total = remaining;
    }

stream_done:
    printf("\n\033[1;36m════════════════════════════════════════════════════════\033[0m\n\n");
    fflush(stdout);

    free(recv_buf);
    close(sock);
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    char self_path[512];
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (len < 0)
    {
        perror("readlink");
        return EXIT_FAILURE;
    }
    self_path[len] = '\0';

    char *dir_end = strrchr(self_path, '/');
    if (!dir_end)
    {
        fprintf(stderr, "Error: could not determine binary directory\n");
        return EXIT_FAILURE;
    }
    *(dir_end + 1) = '\0';

    char ports_file_path[512];
    snprintf(ports_file_path, sizeof(ports_file_path), "%s%s", self_path, SERIAL_PORTS_FILE);

    char ports[MAX_PORTS][128];
    int port_count = load_ports_from_file(ports_file_path, ports, MAX_PORTS);

    if (port_count == 0)
    {
        fprintf(stderr, "[pipeline] Error: No serial ports found in %s\n", ports_file_path);
        fprintf(stderr, "[pipeline] Start the VM via vm_controller first.\n");
        return EXIT_FAILURE;
    }

    printf("[pipeline] Auto-detected %d serial port(s):\n", port_count);
    for (int i = 0; i < port_count; i++)
        printf("[pipeline]   %s\n", ports[i]);

    char listener_path[512];
    snprintf(listener_path, sizeof(listener_path), "%shost_listener", self_path);

    if (access(listener_path, X_OK) != 0)
    {
        fprintf(stderr, "[pipeline] Error: %s not found or not executable\n", listener_path);
        return EXIT_FAILURE;
    }

    printf("[pipeline] Spawning host_listener on all %d ports...\n", port_count);
    fflush(stdout);

    int listener_fd = spawn_host_listener(ports, port_count, &listener_pid);
    if (listener_fd < 0)
    {
        fprintf(stderr, "[pipeline] Error: failed to spawn host_listener\n");
        return EXIT_FAILURE;
    }

    printf("[pipeline] Listener running (PID %d). Collecting data (batch every %ds)...\n",
           listener_pid, BATCH_INTERVAL_SEC);
    fflush(stdout);

    char *batch_buffer = malloc(MAX_BATCH_SIZE);
    if (!batch_buffer)
    {
        perror("malloc");
        close(listener_fd);
        return EXIT_FAILURE;
    }
    batch_buffer[0] = '\0';
    size_t batch_used = 0;

    char line_partial[MAX_LINE_SIZE];
    size_t line_pos = 0;

    time_t last_batch_time = time(NULL);
    int batch_count = 0;

    while (running)
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(listener_fd, &rfds);

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int sel = select(listener_fd + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0)
        {
            if (errno == EINTR)
                continue;
            perror("select");
            break;
        }

        if (sel > 0 && FD_ISSET(listener_fd, &rfds))
        {
            char tmp[4096];
            ssize_t n = read(listener_fd, tmp, sizeof(tmp));
            if (n > 0)
            {
                for (ssize_t i = 0; i < n; i++)
                {
                    if (tmp[i] == '\n' || line_pos >= MAX_LINE_SIZE - 1)
                    {
                        line_partial[line_pos] = '\0';
                        if (line_pos > 0 && batch_used + line_pos + 16 < MAX_BATCH_SIZE)
                        {
                            printf("[pipeline] %s\n", line_partial);
                            fflush(stdout);
                            batch_used += snprintf(batch_buffer + batch_used,
                                                   MAX_BATCH_SIZE - batch_used,
                                                   "%s\n", line_partial);
                        }
                        line_pos = 0;
                    }
                    else
                    {
                        line_partial[line_pos++] = tmp[i];
                    }
                }
            }
            else if (n == 0)
            {
                printf("[pipeline] Listener closed connection.\n");
                break;
            }
        }

        time_t now = time(NULL);
        if (now - last_batch_time >= BATCH_INTERVAL_SEC && batch_used > 0)
        {
            batch_count++;
            printf("[pipeline] Sending batch #%d (%zu bytes) to Llama...\n", batch_count, batch_used);
            fflush(stdout);

            send_batch_to_llama(batch_buffer);

            batch_buffer[0] = '\0';
            batch_used = 0;
            last_batch_time = now;
        }
    }

    if (batch_used > 0)
    {
        batch_count++;
        printf("[pipeline] Sending final batch #%d (%zu bytes) to Llama...\n", batch_count, batch_used);
        fflush(stdout);
        send_batch_to_llama(batch_buffer);
    }

    free(batch_buffer);
    close(listener_fd);

    if (listener_pid > 0)
    {
        kill(listener_pid, SIGTERM);
        waitpid(listener_pid, NULL, 0);
    }

    printf("[pipeline] Shutdown complete.\n");

    return EXIT_SUCCESS;
}
