# 1 Processos & Execução (Lifecycle)

Base de quase todo monitoramento com bpftrace.

## Scripts

**process_exec.bt**: rastreamento de execução de novos processos (execve)  
**process_exit.bt**: rastreamento de saída/término de processos

## O que monitora

- Criação de processos (fork, clone)
- Execução de binários (execve)
- Encerramento (exit)
- Relação pai → filho
- UID/GID no momento da execução
- Linha de comando completa

