# Monitoramento de Virtualização (QEMU)

Esta pasta contém scripts `bpftrace` e um orquestrador em C para monitorar o comportamento do processo de uma VM QEMU (`qemu-system-x86_64`) a partir do sistema hospedeiro.

O objetivo é detectar atividades anômalas que possam indicar um escape da VM ou comportamento malicioso interagindo com o host.

## Scripts

Os scripts `.bt` nesta pasta são versões modificadas dos scripts de segurança gerais, filtrados para observar apenas o processo `qemu-system-x86_64`.

## Orquestrador `vm_monitor`

O arquivo `vm_monitor.c` é um programa para gerenciar a execução de todos os scripts de monitoramento e também para **iniciar e parar a própria VM QEMU**.

### Funcionalidades

- Iniciar/Parar a máquina virtual QEMU.
- Iniciar/Parar todos os scripts de monitoramento (`.bt`) de uma vez.
- Iniciar um script de monitoramento específico.
- Verificar o status dos scripts e da VM.
- Salvar a saída dos scripts em arquivos de log formatados em JSON.

### Customização da VM

O comando para iniciar a VM QEMU está definido no topo do arquivo `vm_monitor.c` e pode ser customizado:

```c
#define QEMU_COMMAND "qemu-system-x86_64 -m 2048 -smp 2 -drive file=malware_vm.qcow2 -display none -pidfile qemu.pid -daemonize"
```

### Compilação

```bash
gcc -o vm_monitor vm_monitor.c
```

### Execução

O orquestrador precisa de permissões de superusuário para executar o `bpftrace`.

```bash
sudo ./vm_monitor
```
