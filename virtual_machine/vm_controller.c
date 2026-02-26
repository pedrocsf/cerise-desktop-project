#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>

#define QEMU_PID_FILE "qemu_vm.pid"

#define QEMU_COMMAND "qemu-system-x86_64 "                                                     \
                     "-m 8192 "                                                                \
                     "-smp 6 "                                                                 \
                     "-machine q35,accel=kvm "                                                 \
                     "-cpu host "                                                              \
                     "-drive file=/home/pacto/malware_vm.qcow2,format=qcow2,cache=writeback "  \
                     "-netdev user,id=net0,hostfwd=tcp::2222-:22 "                             \
                     "-device e1000,netdev=net0 "                                              \
                     "-device virtio-serial-pci "                                              \
                     "-chardev pty,id=privesc_channel "                                        \
                     "-device virtserialport,chardev=privesc_channel,name=com.cerise.privesc " \
                     "-pidfile " QEMU_PID_FILE " "                                             \
                     "-enable-kvm"

pid_t qemu_pid = 0;

void clear_screen();
void pause_screen();
void show_header(const char *title);

void start_qemu_vm();
void stop_qemu_vm();
void check_qemu_status();
void cleanup_and_exit(int signum);
void load_pid_from_file();

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

    printf("Starting QEMU VM...\n");
    int ret = system(QEMU_COMMAND);

    if (ret != 0)
    {
        printf("\n[ERROR] Failed to start QEMU VM.\n");
        printf("Check if QEMU is installed and the disk image 'malware_vm.qcow2' exists.\n");
        pause_screen();
        return;
    }

    sleep(2);
    load_pid_from_file();

    if (qemu_pid > 0)
    {
        printf("\nQEMU VM started successfully with PID: %d\n", qemu_pid);
    }
    else
    {
        printf("\n[ERROR] VM may have started, but could not read its PID.\n");
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
    remove(QEMU_PID_FILE);
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