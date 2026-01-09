# 7 Privilégios, Credenciais & Segurança

Tudo que muda identidade ou comportamento suspeito.

## Scripts

**sensitive_file_access.bt**: monitora acesso a arquivos sensíveis (/etc/passwd, /etc/shadow, chaves SSH)  
**suspicious_exec.bt**: detecta execuções suspeitas (binários em /tmp, exec sem TTY)  
**dangerous_syscalls.bt**: monitora syscalls perigosas (ptrace, mount, setns, bpf)  
**privilege_escalation.bt**: detecta tentativas de escalação de privilégios (setuid, setgid, capabilities)  
**network_suspicious.bt**: detecta atividade de rede suspeita (portas conhecidas, reverse shells)

## O que monitora

- Troca de UID/GID
- Capacidades (capset)
- Uso de sudo/su
- Setuid binários
- Acessos a arquivos sensíveis
- Syscalls perigosas
