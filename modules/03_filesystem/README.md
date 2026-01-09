# 3 Sistema de Arquivos & I/O

Tudo que toca disco.

## Scripts

**io_latency.bt**: latência de I/O do disco (histograma de tempo de resposta)  
**io_size.bt**: tamanho das operações de I/O no disco  
**block_io_latency.bt**: latência de I/O de bloco por processo

## O que monitora

- Criação, leitura, escrita, deleção
- Renomeações
- Mudança de permissões
- Acesso a paths específicos

## Eventos

- openat, rename, unlink
- chmod, chown
- Escrita em arquivos sensíveis

## Probes úteis

- `vfs_open`
- `vfs_write`
- `vfs_unlink`
- `tracepoint:syscalls:sys_enter_openat`
