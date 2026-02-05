# 7 Privilégios, Credenciais & Segurança

Tudo que muda identidade ou representa comportamento suspeito.

## Scripts

**sensitive_file_access.bt**: rastreia o acesso a arquivos sensíveis (ex: /etc/shadow).  
**suspicious_exec.bt**: detecta a execução de processos a partir de locais incomuns (ex: /tmp).  
**dangerous_syscalls.bt**: monitora o uso de syscalls perigosas (ptrace, mount, setns, bpf).  
**privilege_escalation.bt**: detecta tentativas de escalação de privilégios (setuid, setgid).  
**network_suspicious.bt**: monitora atividades de rede suspeitas, como conexões em portas não padrão.  
**kernel_module_load.bt**: rastreia o carregamento de módulos do kernel (potenciais rootkits).  
**fileless_execution.bt**: detecta o uso de `memfd_create` para execução de código em memória.  
**docker_socket_access.bt**: monitora o acesso ao socket do Docker, prevenindo container escapes.  
**log_tampering.bt**: detecta tentativas de escrita ou modificação em arquivos de log do sistema.

## O que monitora

- Mudanças de UID/GID
- Uso de `capabilities`
- Execução de `sudo`/`su`
- Binários com bit `setuid`
- Acesso a arquivos de credenciais e configuração
- Técnicas de evasão e persistência
