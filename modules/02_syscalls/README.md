# 2 Syscalls (Comportamento de Usuário)

Onde o "comportamento real" aparece.

## Scripts

**syscall_openat.bt**: rastreamento de abertura de arquivos (openat)  
**syscall_read_write.bt**: rastreamento de leituras e escritas (read/write)  
**sys_enter_connect.bt**: tentativa de usar o syscall connect()

## O que monitora

- Chamadas de sistema individuais
- Frequência e padrões
- Argumentos sensíveis

## Exemplos comuns

- **Arquivos**: openat, read, write, unlink
- **Privilégios**: setuid, setgid
- **Memória**: mmap, mprotect
- **Debug**: ptrace
- **Tempo**: nanosleep

## Probes

- `tracepoint:syscalls:sys_enter_*`
- `tracepoint:syscalls:sys_exit_*`
