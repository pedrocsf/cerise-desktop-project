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

#define MAX_PATH 512
#define MAX_SCRIPT_NAME 128
#define MAX_SCRIPTS 50
#define LOG_DIR "logs"

typedef struct
{
    char name[MAX_SCRIPT_NAME];
    char path[MAX_PATH];
    char description[256];
} Script;

typedef struct
{
    pid_t pid;
    char script_name[MAX_SCRIPT_NAME];
    char log_file[MAX_PATH];
    int active;
} BackgroundProcess;

BackgroundProcess bg_processes[MAX_SCRIPTS];

const char *categories[] = {
    "01_lifecycle",
    "02_syscalls",
    "03_filesystem",
    "04_network",
    "05_scheduling",
    "06_memory",
    "07_security",
    "08_hardware"};

const char *category_names[] = {
    "Processes & Execution (Lifecycle)",
    "Syscalls (User Behavior)",
    "Filesystem & I/O",
    "Networking",
    "Scheduling, CPU & Performance",
    "Memory & Mapping",
    "Privileges, Credentials & Security",
    "Devices, Sensors & Hardware"};

const int num_categories = 8;

void clear_screen();
void pause_screen();
void show_header();
void show_main_menu();
void show_category_menu(int category_idx);
void show_help(int category_idx);
void list_scripts(int category_idx, Script scripts[], int *count);
void execute_script_foreground(const char *script_path);
void execute_script_background(const char *script_path, const char *script_name);
void show_background_processes();
void kill_background_process();
void view_log();
void create_log_directory();
char *get_timestamp();

int main()
{
    int choice;

    create_log_directory();

    while (1)
    {
        show_main_menu();
        printf("\nChoose an option (0-12): ");

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

        if (choice == 0)
        {
            printf("\nExiting Cerise Menu...\n");
            for (int i = 0; i < MAX_SCRIPTS; i++)
            {
                if (bg_processes[i].active)
                {
                    char cmd[64];
                    snprintf(cmd, sizeof(cmd), "sudo kill %d", bg_processes[i].pid);
                    system(cmd);
                    waitpid(bg_processes[i].pid, NULL, 0);
                }
            }
            break;
        }
        else if (choice >= 1 && choice <= 8)
        {
            show_category_menu(choice - 1);
        }
        else if (choice == 9)
        {
            show_background_processes();
        }
        else if (choice == 10)
        {
            view_log();
        }
        else
        {
            printf("\nInvalid option!\n");
            pause_screen();
        }
    }

    return 0;
}

void clear_screen()
{
    if (system("clear") != 0)
    {
        printf("\n\n\n");
    }
}

void pause_screen()
{
    printf("\nPress ENTER to continue...");
    getchar();
}

void show_header()
{
    clear_screen();
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║           CERISE DESKTOP PROJECT                           ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");
}

void show_main_menu()
{
    show_header();

    for (int i = 0; i < num_categories; i++)
    {
        printf("  %2d. %s\n", i + 1, category_names[i]);
    }

    printf("\n  ───────────────────────────────────────────────────────────\n");
    printf("   9.  View background processes\n");
    printf("  10.  View logs\n");
    printf("   0.  Exit\n");
    printf("  ───────────────────────────────────────────────────────────\n");
}

void show_category_menu(int category_idx)
{
    Script scripts[MAX_SCRIPTS];
    int script_count = 0;
    int choice;

    list_scripts(category_idx, scripts, &script_count);

    while (1)
    {
        show_header();
        printf("Category: %s\n\n", category_names[category_idx]);

        if (script_count == 0)
        {
            printf("No scripts found in this category.\n");
        }
        else
        {
            for (int i = 0; i < script_count; i++)
            {
                printf("  %2d. %s\n", i + 1, scripts[i].name);
            }
        }

        printf("\n  ───────────────────────────────────────────────────────────\n");
        printf("  98. View help for this category\n");
        printf("  99. Back to main menu\n");
        printf("   0. Exit\n");
        printf("  ───────────────────────────────────────────────────────────\n");
        printf("\nChoose a script (0-%d, 98-99): ", script_count);

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

        if (choice == 0)
        {
            exit(0);
        }
        else if (choice == 99)
        {
            return;
        }
        else if (choice == 98)
        {
            show_help(category_idx);
        }
        else if (choice >= 1 && choice <= script_count)
        {
            int exec_choice;
            printf("\nExecute '%s':\n", scripts[choice - 1].name);
            printf("  1. Direct execution (foreground)\n");
            printf("  2. Background execution (generates log)\n");
            printf("  0. Cancel\n");
            printf("\nChoose: ");

            if (scanf("%d", &exec_choice) != 1)
            {
                while (getchar() != '\n')
                    ;
                printf("\nInvalid input!\n");
                pause_screen();
                continue;
            }
            while (getchar() != '\n')
                ;

            if (exec_choice == 1)
            {
                execute_script_foreground(scripts[choice - 1].path);
            }
            else if (exec_choice == 2)
            {
                execute_script_background(scripts[choice - 1].path, scripts[choice - 1].name);
            }
        }
        else
        {
            printf("\nInvalid option!\n");
            pause_screen();
        }
    }
}

void show_help(int category_idx)
{
    char readme_path[MAX_PATH];
    snprintf(readme_path, MAX_PATH, "modules/%s/README.md", categories[category_idx]);

    clear_screen();
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  HELP: %s\n", category_names[category_idx]);
    printf("╚════════════════════════════════════════════════════════════╝\n\n");

    FILE *fp = fopen(readme_path, "r");
    if (fp == NULL)
    {
        printf("Help file not found: %s\n", readme_path);
    }
    else
    {
        char line[512];
        while (fgets(line, sizeof(line), fp))
        {
            printf("%s", line);
        }
        fclose(fp);
    }

    pause_screen();
}

void list_scripts(int category_idx, Script scripts[], int *count)
{
    char dir_path[MAX_PATH];
    snprintf(dir_path, MAX_PATH, "modules/%s", categories[category_idx]);

    DIR *dir = opendir(dir_path);
    if (dir == NULL)
    {
        *count = 0;
        return;
    }

    struct dirent *entry;
    *count = 0;

    while ((entry = readdir(dir)) != NULL && *count < MAX_SCRIPTS)
    {
        if (strstr(entry->d_name, ".bt") != NULL)
        {
            strncpy(scripts[*count].name, entry->d_name, MAX_SCRIPT_NAME - 1);
            snprintf(scripts[*count].path, MAX_PATH, "%s/%s", dir_path, entry->d_name);
            (*count)++;
        }
    }

    closedir(dir);
}

void execute_script_foreground(const char *script_path)
{
    printf("\nExecuting in foreground...\n");
    printf("Press Ctrl+C to interrupt\n\n");
    sleep(2);

    char command[MAX_PATH + 64];
    snprintf(command, sizeof(command), "sudo bpftrace %s", script_path);

    if (system(command) != 0)
    {
        printf("\nExecution finished with a non-zero exit code\n");
    }

    printf("\nExecution finished.\n");
    pause_screen();
}

void execute_script_background(const char *script_path, const char *script_name)
{
    int slot = -1;
    for (int i = 0; i < MAX_SCRIPTS; i++)
    {
        if (!bg_processes[i].active)
        {
            slot = i;
            break;
        }
    }

    if (slot == -1)
    {
        printf("\nBackground process limit reached!\n");
        pause_screen();
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

        char command[MAX_PATH * 3];
        snprintf(command, sizeof(command), "exec sudo bpftrace -f json %s > %s 2>&1", script_path, log_file);
        execl("/bin/sh", "sh", "-c", command, NULL);
        exit(1);
    }
    else if (pid > 0)
    {
        bg_processes[slot].pid = pid;
        strncpy(bg_processes[slot].script_name, script_name, MAX_SCRIPT_NAME - 1);
        strncpy(bg_processes[slot].log_file, log_file, MAX_PATH - 1);
        bg_processes[slot].active = 1;

        printf("\nScript started in background!\n");
        printf("   PID: %d\n", pid);
        printf("   Log: %s\n", log_file);
        pause_screen();
    }
    else
    {
        printf("\nError creating process!\n");
        pause_screen();
    }
}

void show_background_processes()
{
    show_header();
    printf("BACKGROUND PROCESSES\n\n");

    int active_count = 0;
    char response;

    for (int i = 0; i < MAX_SCRIPTS; i++)
    {
        if (bg_processes[i].active)
        {
            int status;
            pid_t result = waitpid(bg_processes[i].pid, &status, WNOHANG);
            if (result != 0)
            {
                bg_processes[i].active = 0;
            }
        }
    }

    for (int i = 0; i < MAX_SCRIPTS; i++)
    {
        if (bg_processes[i].active)
        {
            printf("  %2d. [PID %d] %s\n", i + 1, bg_processes[i].pid, bg_processes[i].script_name);
            printf("      Log: %s\n", bg_processes[i].log_file);
            active_count++;
        }
    }

    if (active_count == 0)
    {
        printf("  No active background processes.\n");
    }
    else
    {
        printf("\n  ───────────────────────────────────────────────────────────\n");
        printf("  Do you want to kill a process? (y/N): ");

        if (scanf(" %c", &response) == 1)
        {
            while (getchar() != '\n')
                ;

            if (response == 'Y' || response == 'y')
            {
                kill_background_process();
                return;
            }
        }
    }

    pause_screen();
}

void kill_background_process()
{
    int choice;
    printf("\n  Enter the process number to kill (0 to cancel): ");

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

    if (choice == 0)
        return;

    if (choice >= 1 && choice <= MAX_SCRIPTS && bg_processes[choice - 1].active)
    {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "sudo kill %d", bg_processes[choice - 1].pid);
        system(cmd);
        waitpid(bg_processes[choice - 1].pid, NULL, 0);
        bg_processes[choice - 1].active = 0;
        printf("\nProcess %d terminated.\n", bg_processes[choice - 1].pid);
    }
    else
    {
        printf("\nInvalid process!\n");
    }

    pause_screen();
}

void view_log()
{
    show_header();
    printf("VIEW LOGS\n\n");

    DIR *dir = opendir(LOG_DIR);
    if (dir == NULL)
    {
        printf("Log directory not found.\n");
        pause_screen();
        return;
    }

    char log_files[MAX_SCRIPTS][MAX_PATH];
    int log_count = 0;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && log_count < MAX_SCRIPTS)
    {
        if (strstr(entry->d_name, ".log") != NULL)
        {
            snprintf(log_files[log_count], MAX_PATH, "%s/%s", LOG_DIR, entry->d_name);
            printf("  %2d. %s\n", log_count + 1, entry->d_name);
            log_count++;
        }
    }
    closedir(dir);

    if (log_count == 0)
    {
        printf("  No logs found.\n");
        pause_screen();
        return;
    }

    printf("\n  0. Back\n");
    printf("\n  Choose a log to view: ");

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

    if (choice >= 1 && choice <= log_count)
    {
        int action;
        printf("\nOptions for '%s':\n", log_files[choice - 1]);
        printf("  1. View log (less)\n");
        printf("  2. Analyze with Llama\n");
        printf("  0. Cancel\n");
        printf("\nChoose: ");

        if (scanf("%d", &action) != 1)
        {
            while (getchar() != '\n')
                ;
            return;
        }
        while (getchar() != '\n')
            ;

        if (action == 1)
        {
            char command[MAX_PATH + 10];
            snprintf(command, sizeof(command), "less %s", log_files[choice - 1]);
            system(command);
        }
        else if (action == 2)
        {
            if (access("llama.py", F_OK) != -1)
            {
                char command[MAX_PATH + 64];
                snprintf(command, sizeof(command), "python3 llama.py %s", log_files[choice - 1]);
                system(command);
            }
            else
            {
                printf("\n[ERROR] Script 'llama.py' not found in the current directory.\n");
            }
            pause_screen();
        }
    }
}

void create_log_directory()
{
    struct stat st = {0};
    if (stat(LOG_DIR, &st) == -1)
    {
        mkdir(LOG_DIR, 0755);
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
