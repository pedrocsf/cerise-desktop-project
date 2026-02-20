/**
 * Compilação:
 *   gcc -o vm_monitor vm_monitor.c
 *
 * Uso:
 *   sudo ./vm_monitor
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <dirent.h>

#define SCRIPT_DIR "."
#define LOG_DIR "../../logs" 
#define MAX_PATH 512
#define MAX_SCRIPT_NAME 128
#define MAX_SCRIPTS 20
#define QEMU_PID_FILE "qemu.pid"

/**
 * Comando para iniciar a VM. Altere aqui conforme necessário.
 * -daemonize: Roda em background.
 * -pidfile: Salva o PID para gerenciamento.
 * -display none: Desativa a saída gráfica.
 */
#define QEMU_COMMAND "qemu-system-x86_64 -m 2048 -smp 2 -drive file=malware_vm.qcow2 -display none -pidfile " QEMU_PID_FILE " -daemonize"

typedef struct
{
    pid_t pid;
    char script_name[MAX_SCRIPT_NAME];
    char log_file[MAX_PATH];
    int active;
} BackgroundProcess;

typedef struct
{
    char name[MAX_SCRIPT_NAME];
} DiscoveredScript;

BackgroundProcess bg_processes[MAX_SCRIPTS];
int process_count = 0;
pid_t qemu_pid = 0;

void clear_screen();
void pause_screen();
void show_header(const char *title);
void create_log_directory();
char *get_timestamp();

void execute_script_background(const char *script_path, const char *script_name);
void start_all_scripts();
void show_status();
void stop_all_scripts();
void start_qemu_vm();
void stop_qemu_vm();
void start_specific_script();
void cleanup_and_exit(int signum);

int main()
{
    int choice;
    create_log_directory();

    signal(SIGINT, cleanup_and_exit);
    signal(SIGTERM, cleanup_and_exit);
    atexit(stop_all_scripts);

    while (1)
    {
        show_header("VM MONITOR ORCHESTRATOR");
        printf("  VM Management\n");
        printf("  1. Start QEMU VM\n");
        printf("  2. Stop QEMU VM\n");
        printf("  ───────────────────────────────────────────────────────────\n");
        printf("  Monitoring Scripts\n");
        printf("  3. Start ALL monitoring scripts\n");
        printf("  4. Start a SPECIFIC monitoring script\n");
        printf("  5. Stop ALL monitoring scripts\n");
        printf("  ───────────────────────────────────────────────────────────\n");
        printf("  Status & Exit\n");
        printf("  6. Show status of VM and scripts\n");
        printf("  0. Exit (stops VM and scripts)\n");
        printf("  ───────────────────────────────────────────────────────────\n");
        printf("\nChoose an option: ");

        if (scanf("%d", &choice) != 1)
        {
            while (getchar() != '\n')
                ; 
            printf("\nInvalid input!\n");
            pause_screen();
            continue;
        }
        while (getchar() != '\n')
            ;

        switch (choice)
        {
        case 1:
            start_qemu_vm();
            break;
        case 2:
            stop_qemu_vm();
            printf("\nQEMU VM stop command issued.\n");
            pause_screen();
            break;
        case 3:
            start_all_scripts();
            break;
        case 4:
            start_specific_script();
            break;
        case 5:
            stop_all_scripts();
            printf("\nAll scripts terminated.\n");
            pause_screen();
            break;
        case 6:
            show_status();
            break;
        case 0:
            printf("\nExiting and stopping all scripts...\n");
            cleanup_and_exit(0);
            break;
        default:
            printf("\nInvalid option!\n");
            pause_screen();
            break;
        }
    }

    return 0;
}

void start_all_scripts()
{
    show_header("STARTING SCRIPTS");
    DIR *dir = opendir(SCRIPT_DIR);
    if (dir == NULL)
    {
        perror("Error opening script directory");
        pause_screen();
        return;
    }

    struct dirent *entry;
    int started_count = 0;
    while ((entry = readdir(dir)) != NULL)
    {
        if (strstr(entry->d_name, ".bt") != NULL)
        {
            char script_path[MAX_PATH];
            snprintf(script_path, MAX_PATH, "%s/%s", SCRIPT_DIR, entry->d_name);
            execute_script_background(script_path, entry->d_name);
            started_count++;
        }
    }
    closedir(dir);

    if (started_count == 0)
    {
        printf("No '.bt' scripts found in this directory.\n");
    }
    else
    {
        printf("\n%d script(s) started in the background.\n", started_count);
    }
    pause_screen();
}

void execute_script_background(const char *script_path, const char *script_name)
{
    if (process_count >= MAX_SCRIPTS)
    {
        printf("Process limit reached, cannot start '%s'\n", script_name);
        return;
    }

    char log_file[MAX_PATH];
    char *timestamp = get_timestamp();
    snprintf(log_file, MAX_PATH, "%s/%s_%s.log", LOG_DIR, script_name, timestamp);
    free(timestamp);

    pid_t pid = fork();

    if (pid == 0) 
    {
        setsid(); 

        int dev_null = open("/dev/null", O_RDWR);
        if (dev_null > 0)
        {
            dup2(dev_null, STDIN_FILENO);
            close(dev_null);
        }

        char command[MAX_PATH * 2];
        snprintf(command, sizeof(command), "exec sudo bpftrace -f json %s > %s 2>&1", script_path, log_file);
        execl("/bin/sh", "sh", "-c", command, NULL);
        perror("execl failed");
        exit(1);
    }
    else if (pid > 0) 
    {
        bg_processes[process_count].pid = pid;
        strncpy(bg_processes[process_count].script_name, script_name, MAX_SCRIPT_NAME - 1);
        strncpy(bg_processes[process_count].log_file, log_file, MAX_PATH - 1);
        bg_processes[process_count].active = 1;
        process_count++;

        printf(" -> Started '%s' (PID: %d, Log: %s)\n", script_name, pid, log_file);
    }
    else
    {
        perror("fork failed");
    }
}

void show_status()
{
    show_header("RUNNING VM & SCRIPTS STATUS");
    int active_count = 0;

    if (qemu_pid > 0)
    {
        if (kill(qemu_pid, 0) == 0)
        { 
            printf("  [ACTIVE] QEMU VM (PID: %d)\n", qemu_pid);
        }
        else
        {
            printf("  [STOPPED] QEMU VM (last PID: %d) is no longer running.\n", qemu_pid);
            qemu_pid = 0; 
        }
    }
    else
    {
        printf("  [STOPPED] QEMU VM is not running.\n");
    }
    printf("  ───────────────────────────────────────────────────────────\n");

    for (int i = 0; i < process_count; i++)
    {
        if (bg_processes[i].active)
        {
            int status;
            pid_t result = waitpid(bg_processes[i].pid, &status, WNOHANG);
            if (result == bg_processes[i].pid)
            { 
                bg_processes[i].active = 0;
            }
            else if (result == 0)
            { 
                printf("  [ACTIVE] PID %-6d | Script: %s\n", bg_processes[i].pid, bg_processes[i].script_name);
                printf("           Log: %s\n", bg_processes[i].log_file);
                active_count++;
            }
        }
    }

    if (active_count == 0)
    {
        printf("  No active monitoring scripts found.\n");
    }
    pause_screen();
}

void stop_all_scripts()
{
    for (int i = 0; i < process_count; i++)
    {
        if (bg_processes[i].active)
        {
            printf("Stopping PID %d (%s)...\n", bg_processes[i].pid, bg_processes[i].script_name);
            char cmd[64];
            snprintf(cmd, sizeof(cmd), "sudo kill %d", bg_processes[i].pid);
            system(cmd);
            waitpid(bg_processes[i].pid, NULL, 0); 
            bg_processes[i].active = 0;
        }
    }
    process_count = 0;
}

void start_qemu_vm()
{
    show_header("STARTING QEMU VM");

    if (qemu_pid > 0 && kill(qemu_pid, 0) == 0)
    {
        printf("QEMU VM is already running (PID: %d).\n", qemu_pid);
        pause_screen();
        return;
    }

    printf("Starting QEMU VM with command:\n%s\n\n", QEMU_COMMAND);
    int ret = system(QEMU_COMMAND);

    if (ret != 0)
    {
        printf("Failed to start QEMU VM. Check if the image file exists and QEMU is installed.\n");
        pause_screen();
        return;
    }

    sleep(2);

    FILE *f = fopen(QEMU_PID_FILE, "r");
    if (f)
    {
        if (fscanf(f, "%d", &qemu_pid) == 1)
        {
            printf("QEMU VM started successfully with PID: %d\n", qemu_pid);
        }
        else
        {
            qemu_pid = 0;
            printf("Could not read PID from pidfile.\n");
        }
        fclose(f);
        remove(QEMU_PID_FILE); 
    }
    else
    {
        printf("Warning: Could not open QEMU pidfile '%s'. PID is unknown.\n", QEMU_PID_FILE);
        qemu_pid = 0;
    }
    pause_screen();
}

void stop_qemu_vm()
{
    if (qemu_pid > 0)
    {
        printf("Stopping QEMU VM (PID: %d)...\n", qemu_pid);
        if (kill(qemu_pid, SIGTERM) == 0)
        {
            waitpid(qemu_pid, NULL, 0);
            printf("QEMU VM stopped.\n");
        }
        else
        {
            if (kill(qemu_pid, 0) != 0)
            {
                printf("QEMU VM was already stopped.\n");
            }
            else
            {
                perror("Failed to send SIGTERM to QEMU VM");
            }
        }
        qemu_pid = 0;
    }
}

void start_specific_script()
{
    show_header("START A SPECIFIC SCRIPT");

    DiscoveredScript scripts[MAX_SCRIPTS];
    int script_count = 0;

    DIR *dir = opendir(SCRIPT_DIR);
    if (dir == NULL)
    {
        perror("Error opening script directory");
        pause_screen();
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && script_count < MAX_SCRIPTS)
    {
        if (strstr(entry->d_name, ".bt") != NULL)
        {
            strncpy(scripts[script_count].name, entry->d_name, MAX_SCRIPT_NAME - 1);
            script_count++;
        }
    }
    closedir(dir);

    if (script_count == 0)
    {
        printf("No '.bt' scripts found in this directory.\n");
        pause_screen();
        return;
    }

    printf("Available scripts:\n");
    for (int i = 0; i < script_count; i++)
    {
        printf("  %2d. %s\n", i + 1, scripts[i].name);
    }
    printf("\n  0. Cancel\n");
    printf("───────────────────────────────────────────────────────────\n");
    printf("Choose a script to start (0-%d): ", script_count);

    int choice;
    if (scanf("%d", &choice) != 1)
    {
        while (getchar() != '\n')
            ;
        printf("\nInvalid input!\n");
        pause_screen();
        return;
    }
    while (getchar() != '\n')
        ;

    if (choice > 0 && choice <= script_count)
    {
        char script_path[MAX_PATH];
        snprintf(script_path, MAX_PATH, "%s/%s", SCRIPT_DIR, scripts[choice - 1].name);
        printf("\nStarting '%s'...\n", scripts[choice - 1].name);
        execute_script_background(script_path, scripts[choice - 1].name);
        pause_screen();
    }
    else if (choice != 0)
    {
        printf("\nInvalid selection.\n");
        pause_screen();
    }
}

void cleanup_and_exit(int signum)
{
    stop_qemu_vm();
    stop_all_scripts();
    exit(0);
}

void clear_screen()
{
    system("clear");
}

void pause_screen()
{
    printf("\nPress ENTER to continue...");
    getchar();
}

void show_header(const char *title)
{
    clear_screen();
}

void create_log_directory()
{
    struct stat st = {0};
    if (stat(LOG_DIR, &st) == -1)
    {
        if (mkdir(LOG_DIR, 0755) != 0)
        {
            perror("Failed to create log directory");
            exit(1);
        }
    }
}

char *get_timestamp()
{
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char *timestamp = malloc(20);
    if (timestamp)
    {
        strftime(timestamp, 20, "%Y%m%d_%H%M%S", t);
    }
    return timestamp;
}