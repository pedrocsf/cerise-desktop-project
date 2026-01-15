/*
 * Cerise Desktop Project - Interactive Menu
 *
 * Menu interativo para gerenciar scripts bpftrace
 * Permite execução direta, background, visualização de logs e ajuda
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

#define MAX_PATH 512
#define MAX_SCRIPT_NAME 128
#define MAX_SCRIPTS 50
#define LOG_DIR "logs"

// Estrutura para representar um script
typedef struct
{
    char name[MAX_SCRIPT_NAME];
    char path[MAX_PATH];
    char description[256];
} Script;

// Estrutura para processos em background
typedef struct
{
    pid_t pid;
    char script_name[MAX_SCRIPT_NAME];
    char log_file[MAX_PATH];
    int active;
} BackgroundProcess;

BackgroundProcess bg_processes[MAX_SCRIPTS];

// Categorias do projeto
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
    "Processos & Execução (Lifecycle)",
    "Syscalls (Comportamento de Usuário)",
    "Sistema de Arquivos & I/O",
    "Rede (Networking)",
    "Escalonamento, CPU & Performance",
    "Memória & Mapeamento",
    "Privilégios, Credenciais & Segurança",
    "Dispositivos, Sensores & Hardware"};

const int num_categories = 8;

// Protótipos de funções
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
        printf("\nEscolha uma opção (0-12): ");

        if (scanf("%d", &choice) != 1)
        {
            while (getchar() != '\n')
                ; // Limpar buffer
            printf("\nEntrada inválida!\n");
            pause_screen();
            continue;
        }
        while (getchar() != '\n')
            ; // Limpar buffer

        if (choice == 0)
        {
            printf("\nEncerrando Cerise Menu...\n");
            // Matar processos em background
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
            printf("\nOpcao invalida!\n");
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
    printf("\nPressione ENTER para continuar...");
    getchar();
}

void show_header()
{
    clear_screen();
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║           CERISE DESKTOP PROJECT                           ║\n");
    printf("║              BPFtrace Monitoring & Security                ║\n");
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
    printf("   9.  Ver processos em background\n");
    printf("  10.  Visualizar logs\n");
    printf("   0.  Sair\n");
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
        printf("Categoria: %s\n\n", category_names[category_idx]);

        if (script_count == 0)
        {
            printf("Nenhum script encontrado nesta categoria.\n");
        }
        else
        {
            for (int i = 0; i < script_count; i++)
            {
                printf("  %2d. %s\n", i + 1, scripts[i].name);
            }
        }

        printf("\n  ───────────────────────────────────────────────────────────\n");
        printf("  98. Ver ajuda desta categoria\n");
        printf("  99. Voltar ao menu principal\n");
        printf("   0. Sair\n");
        printf("  ───────────────────────────────────────────────────────────\n");
        printf("\nEscolha um script (0-%d, 98-99): ", script_count);

        if (scanf("%d", &choice) != 1)
        {
            while (getchar() != '\n')
                ;
            printf("\nEntrada invalida!\n");
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
            printf("\nExecutar '%s':\n", scripts[choice - 1].name);
            printf("  1. Execução direta (foreground)\n");
            printf("  2. Execução em background (gera log)\n");
            printf("  0. Cancelar\n");
            printf("\nEscolha: ");

            if (scanf("%d", &exec_choice) != 1)
            {
                while (getchar() != '\n')
                    ;
                printf("\nEntrada invalida!\n");
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
            printf("\nOpcao invalida!\n");
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
    printf("║  AJUDA: %s\n", category_names[category_idx]);
    printf("╚════════════════════════════════════════════════════════════╝\n\n");

    FILE *fp = fopen(readme_path, "r");
    if (fp == NULL)
    {
        printf("Arquivo de ajuda nao encontrado: %s\n", readme_path);
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
    printf("\nExecutando em foreground...\n");
    printf("Pressione Ctrl+C para interromper\n\n");
    sleep(2);

    char command[MAX_PATH + 20];
    snprintf(command, sizeof(command), "sudo bpftrace %s", script_path);

    if (system(command) != 0)
    {
        printf("\nExecucao finalizada com codigo de saida diferente de 0\n");
    }

    printf("\nExecucao finalizada.\n");
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
        printf("\nLimite de processos em background atingido!\n");
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
        // Processo filho
        setsid(); // Cria nova sessão para isolar do terminal do menu

        // Redireciona stdin para /dev/null para evitar conflito de TTY
        int dev_null = open("/dev/null", O_RDWR);
        if (dev_null > 0) {
            dup2(dev_null, STDIN_FILENO);
            close(dev_null);
        }

        char command[MAX_PATH * 2];
        snprintf(command, sizeof(command), "exec sudo bpftrace %s > %s 2>&1", script_path, log_file);
        execl("/bin/sh", "sh", "-c", command, NULL);
        exit(1);
    }
    else if (pid > 0)
    {
        // Processo pai
        bg_processes[slot].pid = pid;
        strncpy(bg_processes[slot].script_name, script_name, MAX_SCRIPT_NAME - 1);
        strncpy(bg_processes[slot].log_file, log_file, MAX_PATH - 1);
        bg_processes[slot].active = 1;

        printf("\nScript iniciado em background!\n");
        printf("   PID: %d\n", pid);
        printf("   Log: %s\n", log_file);
        pause_screen();
    }
    else
    {
        printf("\nErro ao criar processo!\n");
        pause_screen();
    }
}

void show_background_processes()
{
    show_header();
    printf("PROCESSOS EM BACKGROUND\n\n");

    int active_count = 0;
    char response;

    // Verificar quais processos ainda estão ativos
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

    // Listar processos ativos
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
        printf("  Nenhum processo em background ativo.\n");
    }
    else
    {
        printf("\n  ───────────────────────────────────────────────────────────\n");
        printf("  Deseja matar algum processo? (S/n): ");

        if (scanf(" %c", &response) == 1)
        {
            while (getchar() != '\n')
                ;

            if (response == 'S' || response == 's')
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
    printf("\n  Digite o número do processo para matar (0 para cancelar): ");

    if (scanf("%d", &choice) != 1)
    {
        while (getchar() != '\n')
            ;
        printf("\nX Entrada inválida!\n");
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
        printf("\nProcesso %d terminado.\n", bg_processes[choice - 1].pid);
    }
    else
    {
        printf("\nProcesso invalido!\n");
    }

    pause_screen();
}

void view_log()
{
    show_header();
    printf("VISUALIZAR LOGS\n\n");

    DIR *dir = opendir(LOG_DIR);
    if (dir == NULL)
    {
        printf("Diretorio de logs nao encontrado.\n");
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
        printf("  Nenhum log encontrado.\n");
        pause_screen();
        return;
    }

    printf("\n  0. Voltar\n");
    printf("\n  Escolha um log para visualizar: ");

    int choice;
    if (scanf("%d", &choice) != 1)
    {
        while (getchar() != '\n')
            ;
        printf("\nEntrada invalida!\n");
        pause_screen();
        return;
    }
    while (getchar() != '\n')
        ;

    if (choice >= 1 && choice <= log_count)
    {
        char command[MAX_PATH + 10];
        snprintf(command, sizeof(command), "less %s", log_files[choice - 1]);
        if (system(command) != 0)
        {
            printf("\nErro ao abrir log\n");
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
