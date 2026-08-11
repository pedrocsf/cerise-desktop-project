# Rubricas de avaliação — batches sintéticos do MalTrace

Este arquivo é a **fonte da verdade** da avaliação por rubrica. Ele é lido e interpretado
por `eval_llm.py`, que envia cada critério a um juiz LLM (Claude Sonnet 5) junto com o log
de entrada do batch e a resposta do agente avaliado.

Cada critério é verificado de forma **binária** (ATENDIDO / NÃO ATENDIDO), independente dos
demais. A nota é derivada dos critérios, não atribuída diretamente pelo juiz:

```
escala = 10 / (peso total dos critérios positivos do batch)
nota   = (peso dos positivos atendidos × escala) − (peso dos negativos disparados × escala)
nota   = clamp(0, 10, nota)
```

Positivos e negativos passam pela **mesma** escala. Isso faz o peso significar a mesma
coisa nos dois sinais e entre batches: um critério negativo de peso 2.0 custa exatamente o
que vale um positivo de peso 2.0. Como consequência, **você não precisa fechar a soma dos
pesos positivos em 10** ao editar a rubrica — pode adicionar ou remover critérios à
vontade, que a normalização se ajusta sozinha.

## Formato (não altere a estrutura, só o conteúdo)

```
## Batch 000N — <título>

### Critérios positivos
- [peso] `identificador` — Descrição verificável do que a resposta precisa conter.

### Critérios negativos
- [peso] `identificador` — Descrição do erro. Só dispara se a resposta AFIRMAR isso.
```

O parser espera exatamente: hífen, peso entre colchetes, identificador entre crases,
travessão `—`, descrição. A descrição pode ocupar várias linhas desde que as
continuações sejam indentadas.

## Regras dadas ao juiz

1. Julgar **semanticamente**, não por palavra-chave. Paráfrase correta atende o critério;
   citar o termo exato sem entender não atende.
2. Critérios negativos só disparam quando a resposta **afirma** aquilo. Mencionar para
   **negar** ("não há evidência de exfiltração") ou para descrever risco futuro
   condicional **não** dispara a penalidade.
3. Na dúvida entre atendido e não atendido, marcar como **não atendido** e explicar.
4. Um critério de cadeia causal só é atendido se a resposta **conectar** os eventos
   explicitamente, não se apenas listar os dois eventos em parágrafos separados.

---

## Batch 0001 — Reverse shell + anti-debug

### Critérios positivos

- [1.5] `masquerading-path` — Identificou que o binário executa de `/tmp/.systemd-helper/agent` e reconheceu que o caminho imita um componente legítimo do systemd (masquerading / evasão).
- [1.5] `c2-endpoint` — Identificou a conexão de saída para `203.0.113.77` na porta `4444` e a caracterizou como C2 / reverse shell.
- [1.5] `payload-decodificado` — Decodificou ou interpretou corretamente o payload como um comando de spawn de shell interativo (`pty.spawn` / upgrade de PTY), reconhecendo que veio do servidor para a vítima.
- [1.5] `confirmacao-root` — Reconheceu a resposta `uid=0(root)` como confirmação de que o atacante obteve shell root interativo.
- [1.0] `ptrace-antidebug` — Interpretou o `ptrace request=0` como PTRACE_TRACEME / técnica anti-debug ou auto-rastreamento.
- [1.0] `ptrace-injecao` — Interpretou o `ptrace request=16` (PTRACE_ATTACH em outro PID) como tentativa de injeção em processo, credential dumping ou movimento lateral.
- [2.0] `cadeia-causal` — Amarrou execução suspeita → callback C2 → shell interativo → anti-debug/injeção como **um único ataque coordenado**, e não como achados independentes.
- [1.0] `ruido-benigno` — Tratou o DNS para `security.ubuntu.com` e o tráfego ICMP como benignos / atividade de fundo, sem atribuir-lhes intenção maliciosa.

### Critérios negativos

- [2.0] `alega-base64` — Afirmou que o payload de rede está codificado em base64 (o payload é hexadecimal ASCII).
- [1.5] `alucina-banner` — Tratou a linha de inicialização do listener (`Waiting for encrypted data on /dev/pts/...`) como evidência de backdoor, implante pré-existente ou sessão interativa.
- [1.5] `alegacao-sem-evidencia` — Afirmou como fato um indicador técnico ausente do log de entrada. **Só dispara se o erro não estiver já coberto por outro critério negativo deste batch** — cada engano é penalizado uma única vez.

---

## Batch 0002 — Escalação de privilégio + roubo de credenciais

### Critérios positivos

- [1.5] `escalacao-sudo` — Identificou que o UID 1001 escalou para root via `sudo`, citando `setresuid` (ruid/euid/suid = 0) ou `capset`.
- [1.0] `escalacao-su` — Identificou o **segundo** vetor de escalação, via `su` com `setuid` de 1001 para 0.
- [1.0] `shadow` — Apontou a leitura de `/etc/shadow` como coleta de hashes de senha.
- [1.0] `chave-ssh` — Apontou a leitura de `/root/.ssh/id_rsa` como roubo de chave privada.
- [0.5] `bash-history` — Apontou a leitura de `/root/.bash_history`.
- [0.5] `sudoers` — Apontou a leitura de `/etc/sudoers`.
- [2.0] `correlacao-pos-escalacao` — Correlacionou explicitamente a escalação com a leitura subsequente dos arquivos como **roubo de credenciais pós-escalação**, tratando as duas fases como uma sequência única.
- [1.5] `sem-exfiltracao` — Reconheceu corretamente que **não há tráfego de exfiltração** neste batch, ou ao menos não afirmou que houve.
- [1.0] `ruido-benigno` — Tratou o DNS para `security.ubuntu.com` e o ping ICMP como atividade de fundo, sem transformá-los em evidência de ataque.

### Critérios negativos

- [2.0] `alega-exfiltracao` — **Afirmou** que houve exfiltração de dados. Não dispara se o modelo apenas nega a exfiltração, ou se descreve exfiltração como risco futuro claramente condicional.
- [1.0] `alega-scanning` — Afirmou que houve varredura ou reconhecimento de rede com base no DNS/ICMP benignos.
- [1.5] `alegacao-sem-evidencia` — Afirmou como fato um indicador técnico ausente do log de entrada. **Só dispara se o erro não estiver já coberto por outro critério negativo deste batch** — cada engano é penalizado uma única vez.

---

## Batch 0003 — Fuga de container + rootkit

### Critérios positivos

- [1.5] `namespace-escape` — Identificou `unshare` e/ou `setns` como manipulação de namespace com objetivo de escapar do container.
- [1.5] `docker-socket` — Identificou o acesso a `/var/run/docker.sock` e explicou por que isso concede controle em nível de host.
- [1.5] `download-payload` — Identificou o download de `evil_mod.ko` via `wget` a partir de `drop.bad-c2-domain.test`, nomeando o artefato exato.
- [1.0] `chroot-pivo` — Interpretou `chroot /host_root` como pivô para o filesystem do host (e **não** como escalação de privilégio).
- [1.5] `insmod-rootkit` — Identificou o `insmod` / `finit_module` como carregamento de módulo de kernel, caracterizando instalação de rootkit ou persistência em ring-0.
- [2.0] `timeline-completa` — Montou a timeline fuga-de-container → download do payload → carregamento do módulo como uma cadeia única, usando o HTTP capturado para ligar o artefato baixado ao `insmod` seguinte.
- [1.0] `ruido-benigno` — Tratou o tráfego ICMP inicial como checagem de conectividade / ruído, sem torná-lo achado central.

### Critérios negativos

- [1.5] `flag-namespace-errada` — Nomeou incorretamente a constante de `unshare(flags=0x20000000)`, por exemplo como `CLONE_NEWUSER` ou `CLONE_NEWNS` (o valor corresponde a `CLONE_NEWPID`). Só dispara se o modelo **nomear** a constante errada; não dispara se ele não arriscar o nome.
- [1.0] `chroot-como-privesc` — Tratou `chroot` como técnica de escalação de privilégio.
- [1.5] `omitiu-mecanismo-fuga` — Descreveu apenas a metade final da cadeia (download → chroot → insmod) sem mencionar o mecanismo de fuga do container (`unshare`/`setns`/docker.sock).

---

## Batch 0004 — Execução fileless + anti-forense + DNS DGA

### Critérios positivos

- [2.0] `fileless` — Identificou o evento como `memfd_create` / execução fileless, isto é, execução a partir de memória sem arquivo em disco.
- [1.0] `tampering-authlog` — Identificou a adulteração de `/var/log/auth.log`.
- [0.5] `tampering-syslog` — Identificou a adulteração de `/var/log/syslog`.
- [1.5] `dga` — Reconheceu os subdomínios pseudo-aleatórios sob `bad-c2-domain.test` como padrão DGA / geração algorítmica de domínio.
- [1.0] `ttl-baixo` — Notou o TTL muito baixo (5s) e/ou a rotação de IPs como infraestrutura evasiva (fast-flux).
- [0.5] `processo-oculto` — Notou que as consultas DNS não têm processo associado (`process: null`), sugerindo ocultação.
- [1.5] `anti-forense` — Ligou explicitamente o tampering de log à execução fileless como estratégia anti-forense coordenada, e não como dois achados soltos.
- [1.0] `dns-nao-sinalizado` — Identificou o padrão DGA **por conta própria**, a partir do tráfego bruto, e não apenas repetindo eventos que já vinham pré-rotulados pelos scripts eBPF.
- [0.5] `ruido-benigno` — Tratou o DNS para `security.ubuntu.com` e o ICMP como tráfego benigno de fundo.

### Critérios negativos

- [1.5] `fm-como-fork` — Interpretou o evento `"e":"fm"` como "fork/memory", criação de processo filho ou manipulação genérica de arquivo, em vez de execução fileless.
- [1.5] `alucina-implante` — Afirmou existir sessão de backdoor interativa ou implante pré-existente sem evidência no log.
- [1.5] `alegacao-sem-evidencia` — Afirmou como fato um indicador técnico ausente do log de entrada. **Só dispara se o erro não estiver já coberto por outro critério negativo deste batch** — cada engano é penalizado uma única vez.

---

## Batch 0005 — Cryptominer disfarçado

### Critérios positivos

- [1.5] `kworker-masquerading` — Identificou que o processo `kworker/0:2` se disfarça de kernel worker thread e explicou por que isso é anômalo (kthreads não têm executável em disco).
- [1.0] `path-suspeito` — Apontou o caminho de execução `/tmp/.cache/kworker/0:2`.
- [1.5] `bpf-evasao` — Interpretou o `bpf cmd=5` como `BPF_PROG_LOAD` e o caracterizou como técnica de evasão / ocultação em nível de kernel.
- [1.5] `stratum-pool` — Identificou a conexão `stratum` para `pool.darkpool-mining.test:14444` como comunicação com pool de mineração.
- [1.5] `xmrig-wallet` — Identificou o miner especificamente (XMRig) e/ou o endereço de carteira Monero a partir do payload ou do cmdline.
- [0.5] `root` — Notou que o processo roda como root (UID 0).
- [2.0] `analise-real` — Cruzou caminho de execução suspeito + syscall `bpf` + payload/cmdline bruto para concluir que é cryptominer, em vez de apenas repetir as flags que já vinham pré-marcadas pelos scripts eBPF.
- [0.5] `porta-nao-sinalizada` — Notou que a conexão na porta 14444 **não** foi sinalizada por nenhum script de rede, tendo sido identificada a partir do tráfego bruto.

### Critérios negativos

- [1.0] `icmp-superinterpretado` — Tratou o ping ICMP benigno como canal encoberto, beacon ou evidência de C2.
- [1.5] `alegacao-sem-evidencia` — Afirmou como fato um indicador técnico ausente do log de entrada. **Só dispara se o erro não estiver já coberto por outro critério negativo deste batch** — cada engano é penalizado uma única vez.

---
