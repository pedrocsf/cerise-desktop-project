#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>

#define QEMU_PID_FILE "qemu_vm.pid"
#define SERIAL_PORTS_FILE "serial_ports.list"

#define QEMU_COMMAND "qemu-system-x86_64 "                                                    \
                     "-m 8192 "                                                               \
                     "-smp 6 "                                                                \
                     "-machine q35,accel=kvm "                                                \
                     "-cpu host "                                                             \
                     "-drive file=/home/pacto/malware_vm.qcow2,format=qcow2,cache=writeback " \
                     "-netdev user,id=net0,hostfwd=tcp::2222-:22 "                            \
                     "-device e1000,netdev=net0 "                                             \
                     "-device virtio-serial-pci,max_ports=16 "                                \
                     "-chardev pty,id=ch1 "                                                   \
                     "-device virtserialport,chardev=ch1,name=com.cerise.ch1 "                \
                     "-chardev pty,id=ch2 "                                                   \
                     "-device virtserialport,chardev=ch2,name=com.cerise.ch2 "                \
                     "-chardev pty,id=ch3 "                                                   \
                     "-device virtserialport,chardev=ch3,name=com.cerise.ch3 "                \
                     "-chardev pty,id=ch4 "                                                   \
                     "-device virtserialport,chardev=ch4,name=com.cerise.ch4 "                \
                     "-chardev pty,id=ch5 "                                                   \
                     "-device virtserialport,chardev=ch5,name=com.cerise.ch5 "                \
                     "-chardev pty,id=ch6 "                                                   \
                     "-device virtserialport,chardev=ch6,name=com.cerise.ch6 "                \
                     "-chardev pty,id=ch7 "                                                   \
                     "-device virtserialport,chardev=ch7,name=com.cerise.ch7 "                \
                     "-chardev pty,id=ch8 "                                                   \
                     "-device virtserialport,chardev=ch8,name=com.cerise.ch8 "                \
                     "-chardev pty,id=ch9 "                                                   \
                     "-device virtserialport,chardev=ch9,name=com.cerise.ch9 "                \
                     "-chardev pty,id=ch10 "                                                  \
                     "-device virtserialport,chardev=ch10,name=com.cerise.ch10 "              \
                     "-chardev pty,id=ch11 "                                                  \
                     "-device virtserialport,chardev=ch11,name=com.cerise.ch11 "              \
                     "-daemonize "                                                            \
                     "-pidfile " QEMU_PID_FILE " "                                            \
                     "-enable-kvm"

pid_t qemu_pid = 0;

/* Global storage for captured chardev pty ports */
#define MAX_PORTS 16
int g_port_count = 0;
char g_ports[MAX_PORTS][128];   /* device path, e.g. /dev/pts/3 */
char g_labels[MAX_PORTS][64];   /* label, e.g. ch1 */

void clear_screen();
void pause_screen();
void show_header(const char *title);

void start_qemu_vm();
void stop_qemu_vm();
void check_qemu_status();
void show_serial_ports();
void cleanup_and_exit(int signum);
void load_pid_from_file();
void save_ports_to_file(void);

int main()
{
    int choice;

    signal(SIGINT, cleanup_and_exit);
    signal(SIGTERM, cleanup_and_exit);

    load_pid_from_file();

    while (1)
    {
        show_header("QEMU VM Controller");
        printf("  1. Start VM\n");
        printf("  2. Stop VM\n");
        printf("  3. Check VM Status\n");
        printf("  4. View Serial Ports\n");
        printf("  0. Exit\n");
        printf("  ────────────────────────────────\n");
        printf("\nChoose an option: ");

        if (scanf("%d", &choice) != 1)
        {
            while (getchar() != '\n')
                ;
            printf("\nInvalid input! Please enter a number.\n");
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
            break;
        case 3:
            check_qemu_status();
            break;
        case 4:
            show_serial_ports();
            break;
        case 0:
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

void start_qemu_vm()
{
    show_header("Start QEMU VM");

    if (qemu_pid > 0 && kill(qemu_pid, 0) == 0)
    {
        printf("QEMU VM is already running (PID: %d).\n", qemu_pid);
        pause_screen();
        return;
    }

    printf("Starting QEMU VM...\n\n");

    /* Redirect stderr to stdout so we can capture chardev pty assignments */
    char cmd_with_redirect[8192];
    snprintf(cmd_with_redirect, sizeof(cmd_with_redirect), "%s 2>&1", QEMU_COMMAND);

    FILE *fp = popen(cmd_with_redirect, "r");
    if (!fp)
    {
        printf("\n[ERROR] Failed to start QEMU VM.\n");
        printf("Check if QEMU is installed and the disk image 'malware_vm.qcow2' exists.\n");
        pause_screen();
        return;
    }

    /* Parse output lines looking for pty redirections */
    char line[512];
    g_port_count = 0;

    while (fgets(line, sizeof(line), fp))
    {
        /* QEMU prints: "char device redirected to /dev/pts/X (label chN)" */
        char dev[128], lbl[64];
        if (sscanf(line, "char device redirected to %127s (label %63[^)])", dev, lbl) == 2)
        {
            if (g_port_count < MAX_PORTS)
            {
                strncpy(g_ports[g_port_count], dev, sizeof(g_ports[g_port_count]) - 1);
                g_ports[g_port_count][sizeof(g_ports[g_port_count]) - 1] = '\0';
                strncpy(g_labels[g_port_count], lbl, sizeof(g_labels[g_port_count]) - 1);
                g_labels[g_port_count][sizeof(g_labels[g_port_count]) - 1] = '\0';
                g_port_count++;
            }
        }
    }

    int ret = pclose(fp);

    if (ret != 0)
    {
        printf("\n[ERROR] Failed to start QEMU VM (exit code %d).\n", ret);
        printf("Check if QEMU is installed and the disk image 'malware_vm.qcow2' exists.\n");
        pause_screen();
        return;
    }

    sleep(2);
    load_pid_from_file();

    if (qemu_pid > 0)
    {
        printf("  QEMU VM started successfully with PID: %d\n\n", qemu_pid);
    }
    else
    {
        printf("\n[ERROR] VM may have started, but could not read its PID.\n");
    }

    if (g_port_count > 0)
    {
        printf("  ── Allocated Serial Ports ──────────────────\n\n");
        printf("  %-20s  %s\n", "LABEL", "DEVICE");
        printf("  %-20s  %s\n", "────────────────────", "──────────────────");
        for (int i = 0; i < g_port_count; i++)
        {
            printf("  %-20s  %s\n", g_labels[i], g_ports[i]);
        }
        printf("\n");
        save_ports_to_file();
    }
    else
    {
        printf("  [WARN] No chardev pty ports detected in QEMU output.\n\n");
    }

    pause_screen();
}

void stop_qemu_vm()
{
    show_header("Stop QEMU VM");
    if (qemu_pid <= 0 || kill(qemu_pid, 0) != 0)
    {
        printf("QEMU VM is not running.\n");
        qemu_pid = 0;
        pause_screen();
        return;
    }

    printf("Stopping QEMU VM (PID: %d)...\n", qemu_pid);
    if (kill(qemu_pid, SIGTERM) == 0)
    {
        waitpid(qemu_pid, NULL, 0);
        printf("QEMU VM stopped.\n");
    }
    else
    {
        perror("Failed to send stop signal to QEMU VM");
    }
    qemu_pid = 0;
    g_port_count = 0;
    remove(QEMU_PID_FILE);
    remove(SERIAL_PORTS_FILE);
    pause_screen();
}

void check_qemu_status()
{
    show_header("VM Status");
    if (qemu_pid > 0 && kill(qemu_pid, 0) == 0)
    {
        printf("  [ACTIVE] QEMU VM is running (PID: %d)\n", qemu_pid);
    }
    else
    {
        printf("  [STOPPED] QEMU VM is not running.\n");
        if (qemu_pid > 0)
        {
            qemu_pid = 0;
            remove(QEMU_PID_FILE);
        }
    }
    pause_screen();
}

void show_serial_ports()
{
    show_header("Serial Ports");

    if (qemu_pid <= 0 || kill(qemu_pid, 0) != 0)
    {
        printf("  VM is not running. Start the VM first.\n");
        pause_screen();
        return;
    }

    if (g_port_count == 0)
    {
        printf("  No serial ports were captured.\n");
        printf("  Ports are captured when the VM is started from this controller.\n");
        pause_screen();
        return;
    }

    printf("  VM PID: %d\n\n", qemu_pid);
    printf("  ── Allocated Serial Ports ──────────────────\n\n");
    printf("  %-20s  %s\n", "LABEL", "DEVICE");
    printf("  %-20s  %s\n", "────────────────────", "──────────────────");
    for (int i = 0; i < g_port_count; i++)
    {
        printf("  %-20s  %s\n", g_labels[i], g_ports[i]);
    }
    printf("\n  Total: %d port(s)\n", g_port_count);
    pause_screen();
}

void load_pid_from_file()
{
    FILE *f = fopen(QEMU_PID_FILE, "r");
    if (f)
    {
        if (fscanf(f, "%d", &qemu_pid) != 1)
        {
            qemu_pid = 0;
        }
        fclose(f);
        if (qemu_pid > 0 && kill(qemu_pid, 0) != 0)
        {
            qemu_pid = 0;
            remove(QEMU_PID_FILE);
        }
    }
}

void cleanup_and_exit(int signum)
{
    printf("\n\nExit requested. Stopping VM if it is running...\n");
    if (qemu_pid > 0 && kill(qemu_pid, 0) == 0)
    {
        stop_qemu_vm();
    }
    printf("Exiting.\n");
    exit(0);
}

void save_ports_to_file(void)
{
    if (g_port_count == 0)
        return;
    FILE *f = fopen(SERIAL_PORTS_FILE, "w");
    if (!f)
        return;
    for (int i = 0; i < g_port_count; i++)
        fprintf(f, "%s %s\n", g_labels[i], g_ports[i]);
    fclose(f);
}

void clear_screen()
{
    system("clear");
}

void pause_screen()
{
    printf("\nPress ENTER to continue...");
    int c;
    while ((c = getchar()) != '\n' && c != EOF)
        ;
    if (c == EOF)
    {
        cleanup_and_exit(0);
    }
}

void show_header(const char *title)
{
    clear_screen();
    printf("--- %s ---\n\n", title);
}