# 6 Memória & Mapeamento

Fundamental para detectar técnicas avançadas.

## Scripts

**kmalloc_latency.bt**: latência de alocações de memória do kernel (kmalloc)  
**kmalloc_stats.bt**: estatísticas de alocações kmalloc do kernel

## O que monitora

- Alocações de memória
- Regiões executáveis
- Proteções suspeitas
- Page faults

## Syscalls

- mmap
- mprotect
- brk
- munmap

## Indicadores interessantes

- PROT_EXEC | PROT_WRITE
- Execução sem binário no disco
