#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>

#define QEMU_PID_FILE "qemu_vm.pid"
#define QEMU_QMP_SOCKET "qemu_qmp.sock"
#define SERIAL_PORTS_FILE "serial_ports.list"
#define SESSION_KEY_FILE ".session_key"
#define SESSION_KEY_BYTES 16
#define SESSION_KEY_HEX_LENGTH (SESSION_KEY_BYTES * 2)
#define SESSION_KEY_FILE_MODE 0600
#define SMBIOS_BASE "-smbios type=11"
#define SMBIOS_KEY_VALUE ",value=cerisekey="
#define SMBIOS_LOCKDOWN_VALUE ",value=cerisemodlock=1"
#define SMBIOS_ARGS_SIZE (sizeof(SMBIOS_BASE) + sizeof(SMBIOS_KEY_VALUE) + SESSION_KEY_HEX_LENGTH + sizeof(SMBIOS_LOCKDOWN_VALUE) + 2)
#define VM_SHARED_DIR "/home/pedro/Github/cerise-desktop-project/virtual_machine/vm_shared"

#define VIRTFS_ARGS "-virtfs local,path=" VM_SHARED_DIR ",mount_tag=cerise_share,security_model=mapped-xattr,id=cerise_share "

#define QEMU_COMMAND_FMT "qemu-system-x86_64 "                                                \
                     "-m %d "                                                                 \
                     "-smp %d "                                                               \
                     "-machine q35,accel=kvm "                                                \
                     "-cpu host "                                                             \
                     "-drive file=/home/pedro/Downloads/cerise.qcow2,format=qcow2,cache=writeback " \
                     "%s"                                                                     \
                     "%s"                                                                     \
                     "%s"                                                                     \
                     "-netdev user,id=net0%s,hostfwd=tcp::2222-:22 "                         \
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
                     "-vnc 127.0.0.1:0 "                                                      \
                     "-vga none "                                                             \
                     "-device virtio-vga,xres=1280,yres=720 "                                 \
                     "-qmp unix:" QEMU_QMP_SOCKET ",server=on,wait=off "                       \
                     "-daemonize "                                                            \
                     "-pidfile " QEMU_PID_FILE " "                                            \
                     "-enable-kvm"

pid_t qemu_pid = 0;
int g_interactive = 1;

/* Global storage for captured chardev pty ports */
#define MAX_PORTS 16
int g_port_count = 0;
char g_ports[MAX_PORTS][128];   /* device path, e.g. /dev/pts/3 */
char g_labels[MAX_PORTS][64];   /* label, e.g. ch1 */

void clear_screen();
void pause_screen();
void show_header(const char *title);

int start_qemu_vm();
int stop_qemu_vm();
int check_qemu_status();
void show_serial_ports();
void cleanup_and_exit(int signum);
void load_pid_from_file();
int prepare_session_key(char *smbios_args, size_t size);
int build_smbios_args(char *smbios_args, size_t size, const char *key_hex, int lockdown);
int env_flag_enabled(const char *name);
void save_ports_to_file(void);

int main(int argc, char *argv[])
{
    int choice;

    signal(SIGINT, cleanup_and_exit);
    signal(SIGTERM, cleanup_and_exit);

    load_pid_from_file();

    if (argc > 1)
    {
        g_interactive = 0;
        int ok;
        if (strcmp(argv[1], "start") == 0)
            ok = start_qemu_vm();
        else if (strcmp(argv[1], "stop") == 0)
            ok = stop_qemu_vm();
        else if (strcmp(argv[1], "status") == 0)
            ok = check_qemu_status();
        else
        {
            fprintf(stderr, "Usage: %s [start|stop|status]\n", argv[0]);
            return 1;
        }
        return ok ? 0 : 1;
    }

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

int start_qemu_vm()
{
    show_header("Start QEMU VM");

    if (qemu_pid > 0 && kill(qemu_pid, 0) == 0)
    {
        printf("QEMU VM is already running (PID: %d).\n", qemu_pid);
        pause_screen();
        return 1;
    }

    printf("Starting QEMU VM...\n\n");

    mkdir(VM_SHARED_DIR, 0755);

    int ram_mb = 8192, cpus = 6;
    const char *ram_env = getenv("CERISE_RAM_MB");
    const char *cpus_env = getenv("CERISE_CPUS");
    if (ram_env)
    {
        int v = atoi(ram_env);
        if (v >= 512 && v <= 32768)
            ram_mb = v;
    }
    if (cpus_env)
    {
        int v = atoi(cpus_env);
        if (v >= 1 && v <= 16)
            cpus = v;
    }

    const char *net_isolated_env = getenv("CERISE_NET_ISOLATED");
    const char *net_restrict = ",restrict=on";
    if (net_isolated_env && strcmp(net_isolated_env, "0") == 0)
        net_restrict = "";

    const char *detonation_env = getenv("CERISE_DETONATION");
    int detonation = detonation_env && strcmp(detonation_env, "1") == 0;
    const char *snapshot_args = detonation ? "-snapshot " : "";
    const char *virtfs_args = detonation ? "" : VIRTFS_ARGS;

    char smbios_args[SMBIOS_ARGS_SIZE];
    if (!prepare_session_key(smbios_args, sizeof(smbios_args)))
    {
        printf("\n[ERROR] Failed to prepare the session key.\n");
        pause_screen();
        return 0;
    }

    char qemu_cmd[8192];
    snprintf(qemu_cmd, sizeof(qemu_cmd), QEMU_COMMAND_FMT, ram_mb, cpus, snapshot_args, virtfs_args, smbios_args, net_restrict);

    /* Redirect stderr to stdout so we can capture chardev pty assignments */
    char cmd_with_redirect[8224];
    snprintf(cmd_with_redirect, sizeof(cmd_with_redirect), "%s 2>&1", qemu_cmd);

    FILE *fp = popen(cmd_with_redirect, "r");
    if (!fp)
    {
        printf("\n[ERROR] Failed to start QEMU VM.\n");
        printf("Check if QEMU is installed and the disk image 'malware_vm.qcow2' exists.\n");
        pause_screen();
        return 0;
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
        return 0;
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
        pause_screen();
        return 0;
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
        pause_screen();
        return 0;
    }

    pause_screen();
    return 1;
}

int stop_qemu_vm()
{
    show_header("Stop QEMU VM");
    if (qemu_pid <= 0 || kill(qemu_pid, 0) != 0)
    {
        printf("QEMU VM is not running.\n");
        qemu_pid = 0;
        remove(QEMU_PID_FILE);
        remove(SERIAL_PORTS_FILE);
        remove(QEMU_QMP_SOCKET);
    remove(SESSION_KEY_FILE);
        pause_screen();
        return 1;
    }

    printf("Stopping QEMU VM (PID: %d)...\n", qemu_pid);
    int stopped = kill(qemu_pid, SIGTERM) == 0;
    if (stopped)
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
    remove(QEMU_QMP_SOCKET);
    remove(SESSION_KEY_FILE);
    pause_screen();
    return stopped;
}

int check_qemu_status()
{
    show_header("VM Status");
    int active = qemu_pid > 0 && kill(qemu_pid, 0) == 0;
    if (active)
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
    return active;
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

int read_random_bytes(unsigned char *buffer, size_t length)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return 0;
    size_t total = 0;
    while (total < length)
    {
        ssize_t n = read(fd, buffer + total, length - total);
        if (n <= 0)
        {
            close(fd);
            return 0;
        }
        total += (size_t)n;
    }
    close(fd);
    return 1;
}

int write_session_key_file(const char *hex)
{
    int fd = open(SESSION_KEY_FILE, O_WRONLY | O_CREAT | O_TRUNC, SESSION_KEY_FILE_MODE);
    if (fd < 0)
        return 0;
    size_t length = strlen(hex);
    size_t total = 0;
    while (total < length)
    {
        ssize_t n = write(fd, hex + total, length - total);
        if (n <= 0)
        {
            close(fd);
            return 0;
        }
        total += (size_t)n;
    }
    return close(fd) == 0;
}

int env_flag_enabled(const char *name)
{
    const char *value = getenv(name);
    return value && strcmp(value, "1") == 0;
}

int build_smbios_args(char *smbios_args, size_t size, const char *key_hex, int lockdown)
{
    smbios_args[0] = '\0';
    if (!key_hex && !lockdown)
        return 1;

    int written = snprintf(smbios_args, size, SMBIOS_BASE "%s%s%s ",
                           key_hex ? SMBIOS_KEY_VALUE : "", key_hex ? key_hex : "",
                           lockdown ? SMBIOS_LOCKDOWN_VALUE : "");
    if (written < 0 || (size_t)written >= size)
    {
        smbios_args[0] = '\0';
        return 0;
    }
    return 1;
}

int prepare_session_key(char *smbios_args, size_t size)
{
    smbios_args[0] = '\0';
    int lockdown = env_flag_enabled("CERISE_MODULE_LOCKDOWN");

    if (!env_flag_enabled("CERISE_AUTH"))
    {
        remove(SESSION_KEY_FILE);
        return build_smbios_args(smbios_args, size, NULL, lockdown);
    }

    unsigned char raw[SESSION_KEY_BYTES];
    if (!read_random_bytes(raw, sizeof(raw)))
        return 0;

    char hex[SESSION_KEY_HEX_LENGTH + 1];
    for (int i = 0; i < SESSION_KEY_BYTES; i++)
        snprintf(hex + i * 2, 3, "%02x", raw[i]);

    if (!write_session_key_file(hex))
    {
        remove(SESSION_KEY_FILE);
        return 0;
    }

    if (!build_smbios_args(smbios_args, size, hex, lockdown))
    {
        remove(SESSION_KEY_FILE);
        return 0;
    }
    return 1;
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
    (void)signum;
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
    if (!g_interactive)
        return;
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
    if (!g_interactive)
        return;
    clear_screen();
    printf("--- %s ---\n\n", title);
}