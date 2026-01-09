# cerise-desktop-project

Coleção de scripts bpftrace para monitoramento e observabilidade do sistema Linux.

##  Módulos

###  Network

**tcp_established**: conexão TCP bem sucedida  
**tcp_v4_connect**: tentativas de conexões TCP  
**tcp_destroy**: conexão TCP encerrada  
**tcp_send_reset** e **tcp_receive_reset**: resets de TCP (fim anormal de conexão)  
**tcp_retransmit_skb**: retransmissão de pacotes TCP (novo envio de pacote)  
**tcp_retransmit**: rastreamento de retransmissões TCP  
**tcp_bad_csum**: erros de checksum (pacote TCP chega corrompido)  
**tcp_cong_state_set**: mudança de estado de controle de congestionamento TCP  
**udp_traffic**: monitoramento de tráfego UDP (envio e recebimento)

###  Memory 

**io_latency**: latência de I/O do disco (histograma de tempo de resposta)  
**io_size**: tamanho das operações de I/O no disco  
**kmalloc_latency**: latência de alocações de memória do kernel (kmalloc)  
**kmalloc_stats**: estatísticas de alocações kmalloc do kernel

###  Process 

**block_io_latency**: latência de I/O de bloco por processo  
**cpu_usage**: uso de CPU por processo (amostragem)  
**drm_vblank**: eventos de vblank da GPU (sincronização vertical)  
**process_exec**: rastreamento de execução de novos processos (execve)  
**process_exit**: rastreamento de saída/término de processos  
**runq_latency**: latência da fila de execução do scheduler  
**sys_enter_connect**: tentativa de usar o syscall connect()  
**syscall_openat**: rastreamento de abertura de arquivos (openat)  
**syscall_read_write**: rastreamento de leituras e escritas (read/write)  
**thermal_trip**: eventos de temperatura térmica do sistema

###  Security 

**sensitive_file_access**: monitora acesso a arquivos sensíveis (/etc/passwd, /etc/shadow, chaves SSH)  
**suspicious_exec**: detecta execuções suspeitas (binários em /tmp, exec sem TTY)  
**dangerous_syscalls**: monitora syscalls perigosas (ptrace, mount, setns, bpf)  
**privilege_escalation**: detecta tentativas de escalação de privilégios (setuid, setgid, capabilities)  
**network_suspicious**: detecta atividade de rede suspeita (portas conhecidas, reverse shells)

##

Todos os scripts podem ser executados com:

```bash
sudo bpftrace modules/<categoria>/<script>.bt
```

Exemplo:

```bash
sudo bpftrace modules/network/tcp_established.bt
```
