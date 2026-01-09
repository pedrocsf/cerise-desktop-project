# 5 Escalonamento, CPU & Performance

Quando e por quanto tempo algo roda.

## Scripts

**cpu_usage.bt**: uso de CPU por processo (amostragem)  
**runq_latency.bt**: latência da fila de execução do scheduler

## O que monitora

- Tempo de CPU por processo
- Context switches
- Latência de execução
- Bloqueios

## Eventos

- `sched:sched_switch`
- `sched:sched_wakeup`
- `sched:sched_stat_runtime`

## Muito usado para

- Performance
- Detecção de loops
- Análise de starvation
