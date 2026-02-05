# Cerise Desktop Project

Coleção abrangente de scripts **bpftrace** para monitoramento, observabilidade e segurança do sistema Linux.

Arquitetura baseada em camadas de comportamento do sistema operacional.

---

## Arquitetura de Módulos

### 1 [Processos & Execução (Lifecycle)](modules/01_lifecycle/)

Base de quase todo monitoramento com bpftrace.

- **process_exec.bt** - execução de novos processos
- **process_exit.bt** - término de processos

_Monitora: fork, clone, execve, exit, relação pai→filho, UID/GID, linha de comando_

---

### 2 [Syscalls (Comportamento de Usuário)](modules/02_syscalls/)

Onde o "comportamento real" aparece.

- **syscall_openat.bt** - abertura de arquivos
- **syscall_read_write.bt** - leituras e escritas
- **sys_enter_connect.bt** - tentativas de conexão

_Monitora: chamadas de sistema, frequência, padrões, argumentos sensíveis_

---

### 3 [Sistema de Arquivos & I/O](modules/03_filesystem/)

Tudo que toca disco.

- **io_latency.bt** - latência de I/O do disco
- **io_size.bt** - tamanho das operações de I/O
- **block_io_latency.bt** - latência de I/O por processo

_Monitora: criação, leitura, escrita, deleção, renomeações, permissões_

---

### 4 [Rede (Networking)](modules/04_network/)

Observabilidade de tráfego no nível de processo.

- **tcp_established.bt** - conexões TCP bem sucedidas
- **tcp_v4_connect.bt** - tentativas de conexão
- **tcp_destroy.bt** - conexões encerradas
- **tcp_send_reset.bt** / **tcp_receive_reset.bt** - resets TCP
- **tcp_retransmit.bt** / **tcp_retransmit_skb.bt** - retransmissões
- **tcp_bad_csum.bt** - erros de checksum
- **tcp_cong_state_set.bt** - controle de congestionamento
- **udp_traffic.bt** - tráfego UDP

_Monitora: sockets, TCP/UDP, DNS, bytes enviados/recebidos, Processo↔IP↔Porta_

---

### 5 [Escalonamento, CPU & Performance](modules/05_scheduling/)

Quando e por quanto tempo algo roda.

- **cpu_usage.bt** - uso de CPU por processo
- **runq_latency.bt** - latência da fila de execução

_Monitora: tempo de CPU, context switches, latência, bloqueios, starvation_

---

### 6 [Memória & Mapeamento](modules/06_memory/)

Fundamental para detectar técnicas avançadas.

- **kmalloc_latency.bt** - latência de alocações do kernel
- **kmalloc_stats.bt** - estatísticas de alocações

_Monitora: alocações, regiões executáveis, proteções suspeitas, page faults_

---

### 7 [Privilégios, Credenciais & Segurança](modules/07_security/)

Tudo que muda identidade ou comportamento suspeito.

- **sensitive_file_access.bt** - acesso a arquivos sensíveis
- **suspicious_exec.bt** - execuções suspeitas
- **dangerous_syscalls.bt** - syscalls perigosas (ptrace, mount, setns, bpf)
- **privilege_escalation.bt** - escalação de privilégios
- **network_suspicious.bt** - atividade de rede suspeita
- **kernel_module_load.bt** - carregamento de módulos do kernel (rootkits)
- **fileless_execution.bt** - execução "sem arquivo" via memfd_create
- **docker_socket_access.bt** - acesso ao socket do Docker (container escape)
- **log_tampering.bt** - tentativa de alteração de logs

_Monitora: UID/GID, capabilities, sudo/su, setuid, arquivos sensíveis_

---

### 8 [Dispositivos, Sensores & Hardware](modules/08_hardware/)

Interação direta com o hardware.

- **drm_vblank.bt** - eventos de vblank da GPU
- **thermal_trip.bt** - eventos de temperatura

_Monitora: sensores, /dev/_, temperatura, GPU/CPU freq, ioctl\*

---
