# Auditoria por rubrica — resultados

Juiz: `claude-sonnet-5` · rubricas: `rubric.md` · temperatura 0.

Notas calculadas pelo script a partir dos vereditos por critério; o juiz não atribui nota diretamente.

## COM RAG

Fonte: `rag_test_results.md`

| Batch | Cenário | RedSage (RedSage-8B-DPO, via llama-server local) | Gemini 2.5 Flash (via API, free tier) | Claude Sonnet 4.6 (via API) | GPT-5.5 (via API) |
|---|---|---|---|---|---|
| 1 | Reverse shell + anti-debug | 0.00 | 6.82 | 8.64 | 6.82 |
| 2 | Escalação de privilégio + roubo de credenciais | 6.50 | 5.50 | 6.00 | 10.00 |
| 3 | Fuga de container + rootkit | 0.00 | 6.50 | 9.00 | 7.50 |
| 4 | Execução fileless + anti-forense + DNS DGA | 0.00 | 1.58 | 4.74 | 5.26 |
| 5 | Cryptominer disfarçado | 2.50 | 4.50 | 9.50 | 6.50 |
| **Média** | | **1.80** | **4.98** | **7.57** | **7.22** |

### Comportamento por agente

**RedSage (RedSage-8B-DPO, via llama-server local)**

- **Ruído benigno tratado sistematicamente mal**: em todos os 5 batches o critério `ruido-benigno` aparece como não atendido (Batches 0001-0005), mostrando que o agente nunca diferencia tráfego/eventos legítimos do malicioso, um padrão consistente de omissão.

- **Falha recorrente em construir cadeia causal explícita**: `cadeia-causal` (Batch 0001), `correlacao-pos-escalacao` (Batch 0002), `timeline-completa` (Batch 0003) e a ausência de conexão entre eventos eBPF/rede (Batch 0005) indicam que o agente identifica eventos isolados mas não articula a sequência causal do ataque.

- **Omissão sistemática do mecanismo técnico central do ataque**: o agente ignora a fase-chave da intrusão em múltiplos casos — não decodifica o payload (`payload-decodificado`, Batch 0001), ignora a fuga de container via `namespace-escape`/`docker-socket` (Batch 0003, erro `omitiu-mecanismo-fuga`), e não reconhece `fileless`/`dga` (Batch 0004), sugerindo análise superficial que cobre apenas a camada mais visível do log.

- **Tendência a erros factuais por especulação sem evidência**: erros como `alega-base64` (Batch 0001), `chroot-como-privesc` (Batch 0003), `fm-como-fork` e `alegacao-sem-evidencia` (Batch 0004) mostram um padrão de o agente preencher lacunas de entendimento com afirmações técnicas incorretas em vez de reconhecer incerteza.

- **Respostas rasas mesmo quando o VERDICT geral está correto**: em Batches 0001, 0002 e 0005 o agente acerta o veredito ou vetor principal, mas a observação do juiz descreve a análise como "genérica", "rasa" ou sem explorar detalhes (root, BPF_PROG_LOAD, XMRig/wallet em 0005; bash-history em 0002), indicando um padrão de superficialidade mesmo quando a direção geral está certa.

**Gemini 2.5 Flash (via API, free tier)**

- **Omissão sistemática do tratamento de ruído benigno**: o critério "ruido-benigno" não foi atendido em nenhum dos 5 batches (0001, 0002, 0003, 0004, 0005), indicando um padrão consistente de não diferenciar tráfego incidental (DNS/ICMP) do malicioso, mesmo quando identifica corretamente a cadeia principal do ataque.

- **Tendência a especular sem base evidencial**: no Batch 0002, o agente afirmou exfiltração via ICMP sem evidência clara, sugerindo que, ao tentar preencher lacunas analíticas, o agente pode inferir mecanismos não sustentados pelos dados observados.

- **Omissão recorrente de detalhamento de mecanismos técnicos específicos**: em múltiplos batches o agente identifica o evento macro mas falha em explicar o "como" — masquerading-path e ptrace-antidebug (Batch 0001), docker-socket e chroot-pivo (Batch 0003), kworker-masquerading e bpf-evasao (Batch 0005) — revelando um padrão de análise superficial quanto a técnicas de evasão/disfarce, mesmo com a causa raiz corretamente apontada.

- **Colapso de desempenho em cenários multi-camada de anti-forense**: no Batch 0004, sete de sete critérios falharam (fileless, dga, ttl-baixo, processo-oculto, anti-forense, dns-nao-sinalizado, ruido-benigno), com nota 1.58 destoante das demais (4.50–6.82), sugerindo que o agente tem dificuldade acentuada quando múltiplos mecanismos de evasão coexistem e exigem correlação simultânea, não apenas identificação isolada de C2/tampering.

- **Boa aderência formal, mas raso em profundidade causal**: não houve erros de formato disparados em nenhum batch, e o agente consistentemente acerta a identificação do vetor principal (C2, escalação, fuga de container, cryptominer), porém repete a falha de não conectar esses achados aos mecanismos técnicos subjacentes que os viabilizam (ex: shadow/chave-ssh no Batch 0002, analise-real/porta-nao-sinalizada no Batch 0005).

**Claude Sonnet 4.6 (via API)**

- **Tratamento de ruído benigno é ponto fraco recorrente**: o agente falhou no critério `ruido-benigno` tanto no Batch 0002 quanto no Batch 0003, e no Batch 0002 isso se agravou a ponto de disparar `alegacao-sem-evidencia`, ao interpretar um ping ICMP como confirmação de viabilidade de exfiltração/C2 — indicando um padrão sistemático de sobrevalorizar tráfego ICMP trivial como evidência de ataque.

- **Tendência a hiperinterpretar sinais ambíguos como prova de comprometimento**: no Batch 0001 o agente "alucinou" um banner eBPF como implante pré-existente (`alucina-banner`), e no Batch 0002 repetiu esse padrão de extrapolação ao tratar ruído como confirmação de capacidade de exfiltração — sugerindo viés de excesso de confiança na atribuição causal quando a evidência é fraca.

- **Erros pontuais de interpretação técnica em mecanismos específicos**: no Batch 0004 o agente confundiu o evento `fm` com fork/manipulação de arquivo em vez de execução fileless (`fm-como-fork`), e no Batch 0005 não sinalizou que a porta 14444 não tinha sido apontada por scripts de rede (`porta-nao-sinalizada`) — ambos indicam lacunas específicas na leitura fina de indicadores técnicos, mesmo quando a narrativa geral está correta.

- **Boa construção de cadeia causal, mas com omissões de síntese estratégica**: nos Batches 0001, 0003 e 0005 (notas 8.64, 9.00 e 9.50) o agente amarra bem os eventos técnicos em uma narrativa coerente de ataque; porém no Batch 0004 essa força não se sustenta, pois não conectou explicitamente tampering de log e execução fileless como uma estratégia anti-forense coordenada (`anti-forense`), revelando que a síntese de "intenção do atacante" nem sempre acompanha a correção dos fatos técnicos individuais.

- **Nenhuma violação de formato relatada**: em nenhum dos 5 batches houve críticas relacionadas à estrutura ou apresentação da resposta, sugerindo que os problemas do agente são consistentemente de julgamento analítico (superinterpretação e lacunas de mecanismo), não de aderência ao formato solicitado.

**GPT-5.5 (via API)**

- **Boa capacidade de correlação causal, mas superficialidade em mecanismos técnicos específicos**: em Batch 0001 (ptrace-antidebug, ptrace-injecao), Batch 0003 (docker-socket, chroot-pivo) e Batch 0005 (kworker-masquerading, bpf-evasao) o agente monta a cadeia geral do ataque corretamente, porém repetidamente falha em detalhar o "como" técnico de cada mecanismo, tratando-os de forma genérica.

- **Omissão recorrente de técnicas de "masquerading"/disfarce**: o padrão aparece em contextos distintos — masquerading-path (Batch 0001) e kworker-masquerading (Batch 0005) — sugerindo uma lacuna sistemática do agente em reconhecer e explicar técnicas de disfarce de processos/paths, não um erro isolado de um único cenário.

- **Sem erros factuais disparados em nenhum dos 5 batches**: isso indica que as omissões (critérios não atendidos) não vêm de invenção ou alucinação de fatos, mas de cobertura incompleta — reforçado pela observação do Batch 0002, onde o agente evitou inventar exfiltração/scanning ao tratar corretamente ruído benigno.

- **Degradação de desempenho quando há múltiplos mecanismos concorrentes no mesmo cenário**: no Batch 0004 (nota 5.26, a mais baixa), quatro critérios distintos falharam simultaneamente (fileless, processo-oculto, anti-forense, ruido-benigno), e o juiz aponta que o agente não conectou anti-forense com fileless — um padrão de "escolher" um subconjunto do incidente (DGA/DNS) e negligenciar os demais fios da mesma cadeia.

- **Inconsistência de profundidade entre critérios "high-level" e "low-level"**: em todos os batches com nota abaixo de 10 (0001, 0003, 0004, 0005), o padrão é o mesmo — a narrativa macro (o que aconteceu) é bem capturada, mas os detalhes técnicos granulares (o porquê/como de cada IOC) são sistematicamente deixados de fora, apontando para um viés do agente em favor de síntese sobre profundidade forense.

<details>
<summary>Vereditos por critério</summary>

#### RedSage (RedSage-8B-DPO, via llama-server local)

**Batch 0001** — nota 0.00

- [ ] `masquerading-path` (1.5) — A resposta não menciona o caminho '/tmp/.systemd-helper/agent' nem qualquer imitação de componente systemd.
- [x] `c2-endpoint` (1.5) — Identificou a conexão para 203.0.113.77:4444 e a caracterizou como 'potential remote command execution', equivalente a C2/reverse shell.
- [ ] `payload-decodificado` (1.5) — Não decodificou o payload; apenas afirmou (erroneamente) que era base64 sem interpretar o comando pty.spawn.
- [ ] `confirmacao-root` (1.5) — Não há menção à resposta 'uid=0(root)' como confirmação de shell root.
- [ ] `ptrace-antidebug` (1.0) — Menciona ptrace apenas como 'unusual for a non-system process', sem interpretar request=0 como PTRACE_TRACEME/anti-debug.
- [ ] `ptrace-injecao` (1.0) — Não diferencia o segundo ptrace (request=16, PID 1500) como tentativa de injeção/attach em outro processo.
- [ ] `cadeia-causal` (2.0) — Os eventos são listados sequencialmente e apenas dito que 'align' e 'confirming malicious activity', sem amarrar explicitamente execução→C2→shell→anti-debug/injeção como ataque único.
- [ ] `ruido-benigno` (1.0) — Não há qualquer menção ao tráfego DNS ou ICMP como benignos ou de fundo.
- **ERRO** `alega-base64` (−2.0) — A resposta afirma 'The payload in the network packets contains base64-encoded strings', quando na verdade é hexadecimal ASCII.

**Batch 0002** — nota 6.50

- [x] `escalacao-sudo` (1.5) — A resposta cita explicitamente 'sudo commands executed by a non-root user (UID 1001)... setresuid, capset' como escalação de privilégio.
- [x] `escalacao-su` (1.0) — Menciona 'The su command further escalates privileges to root (UID 0)' identificando o segundo vetor.
- [x] `shadow` (1.0) — Cita a leitura de /etc/shadow no contexto de 'potential credential harvesting'.
- [x] `chave-ssh` (1.0) — Cita a leitura de /root/.ssh/id_rsa junto ao contexto de credential harvesting.
- [ ] `bash-history` (0.5) — A resposta não menciona em nenhum momento /root/.bash_history.
- [x] `sudoers` (0.5) — Cita explicitamente a leitura de /etc/sudoers na lista de arquivos sensíveis acessados.
- [ ] `correlacao-pos-escalacao` (2.0) — Usa apenas 'Additionally' para listar a leitura de arquivos após a escalação, sem estabelecer explicitamente uma sequência causal de roubo de credenciais pós-escalação.
- [x] `sem-exfiltracao` (1.5) — A resposta não afirma em nenhum momento que houve exfiltração de dados.
- [ ] `ruido-benigno` (1.0) — A resposta ignora completamente os pacotes DNS e ICMP, não os tratando explicitamente como ruído benigno.

**Batch 0003** — nota 0.00

- [ ] `namespace-escape` (1.5) — A resposta não menciona unshare ou setns em nenhum momento, começando a narrativa a partir do wget.
- [ ] `docker-socket` (1.5) — Não há qualquer menção ao acesso a /var/run/docker.sock nem sua implicação de controle sobre o host.
- [x] `download-payload` (1.5) — A resposta identifica 'wget downloading a file... evil_mod.ko' a partir de 'drop.bad-c2-domain.test', nomeando o artefato exato.
- [ ] `chroot-pivo` (1.0) — O chroot foi tratado como parte da 'escalation de privilégios' junto com insmod, e não como pivô para o filesystem do host.
- [ ] `insmod-rootkit` (1.5) — A resposta apenas diz que insmod 'load the module' e que evil_mod.ko 'could be a malicious kernel module', sem caracterizar explicitamente rootkit ou persistência em ring-0.
- [ ] `timeline-completa` (2.0) — A cadeia narrada começa no wget e vai até insmod, mas omite completamente a etapa de fuga do container (unshare/setns), então a timeline não está completa desde o início do ataque.
- [ ] `ruido-benigno` (1.0) — O tráfego ICMP não é mencionado em nenhum momento da análise.
- **ERRO** `chroot-como-privesc` (−1.0) — O texto afirma que 'the use of chroot and insmod indicates attempts to escalate privileges', tratando chroot incorretamente como técnica de escalação de privilégio.
- **ERRO** `omitiu-mecanismo-fuga` (−1.5) — A análise cobre apenas download→chroot→insmod, sem qualquer referência ao mecanismo real de fuga do container (unshare/setns/docker.sock).

**Batch 0004** — nota 0.00

- [ ] `fileless` (2.0) — A resposta não menciona memfd_create ou execução fileless; trata o evento 'fm' apenas como parte de atividade suspeita genérica do bash.
- [x] `tampering-authlog` (1.0) — A resposta cita explicitamente que 'bash' está modificando '/var/log/auth.log'.
- [x] `tampering-syslog` (0.5) — A resposta cita explicitamente que 'bash' está modificando '/var/log/syslog'.
- [ ] `dga` (1.5) — A resposta apenas lista os domínios como 'suspicious domains', sem reconhecer o padrão de geração algorítmica (DGA).
- [ ] `ttl-baixo` (1.0) — Não há menção ao TTL de 5s nem à rotação de IPs como infraestrutura fast-flux.
- [ ] `processo-oculto` (0.5) — A resposta atribui incorretamente as consultas DNS ao processo 'bash', ignorando que o campo process é null nesses pacotes.
- [ ] `anti-forense` (1.5) — O tampering de log é mencionado como achado separado ('Additionally'), sem conectá-lo explicitamente à execução fileless como estratégia anti-forense coordenada.
- [ ] `dns-nao-sinalizado` (1.0) — A resposta não demonstra reconhecimento próprio do padrão DGA a partir do tráfego bruto; apenas rotula os domínios como suspeitos sem análise.
- [ ] `ruido-benigno` (0.5) — A resposta não menciona o tráfego DNS para security.ubuntu.com nem os pacotes ICMP como ruído benigno.
- **ERRO** `fm-como-fork` (−1.5) — A resposta atribui o evento 'fm' (ligado ao processo bash com PID 8200) como parte de atividade genérica de C2/tampering, sem reconhecê-lo como execução fileless, tratando-o implicitamente como ação de arquivo/processo do bash.
- **ERRO** `alegacao-sem-evidencia` (−1.5) — A resposta afirma que as categorias 'docker_socket_access' se aplicam ao caso, mas não há nenhuma evidência de acesso a socket Docker no log.

**Batch 0005** — nota 2.50

- [ ] `kworker-masquerading` (1.5) — A resposta não explica por que o nome 'kworker' é uma máscara anômala nem menciona que kthreads não têm executável em disco.
- [x] `path-suspeito` (1.0) — Cita explicitamente o caminho '/tmp/.cache/kworker/0:2' como execução suspeita.
- [ ] `bpf-evasao` (1.5) — Não menciona o evento eBPF 'cmd=5' nem o interpreta como BPF_PROG_LOAD ou técnica de evasão.
- [x] `stratum-pool` (1.5) — Identifica a conexão à porta 14444 e ao domínio 'pool.darkpool-mining.test' como atividade de mineração/pool.
- [ ] `xmrig-wallet` (1.5) — Não menciona XMRig nem o endereço de carteira Monero presente no cmdline/payload.
- [ ] `root` (0.5) — Não menciona que o processo roda como root/UID 0.
- [ ] `analise-real` (2.0) — A análise é superficial, apenas repete que o processo teve caminho suspeito e porta não-padrão, sem cruzar syscall bpf, payload ou cmdline detalhadamente.
- [ ] `porta-nao-sinalizada` (0.5) — Não observa que a porta 14444 não foi sinalizada por nenhum script automatizado, apenas menciona 'non-standard port'.

#### Gemini 2.5 Flash (via API, free tier)

**Batch 0001** — nota 6.82

- [ ] `masquerading-path` (1.5) — A resposta chama o caminho de 'highly suspicious path' mas não reconhece que ele imita um componente legítimo do systemd (masquerading).
- [x] `c2-endpoint` (1.5) — Identificou a conexão outbound para 203.0.113.77:4444 e a associou a reverse shells/C2.
- [x] `payload-decodificado` (1.5) — Decodificou o payload hex como 'python3 -c "import pty;pty.spawn(\'/bin/sh\')"', reconhecendo o comando de shell interativo vindo do servidor.
- [x] `confirmacao-root` (1.5) — Reconheceu 'uid=0(root) gid=0(root)' como confirmação de execução root-level via reverse shell.
- [ ] `ptrace-antidebug` (1.0) — Tratou ptrace request=0 apenas como 'process manipulation or injection', sem interpretá-lo especificamente como PTRACE_TRACEME/anti-debug.
- [x] `ptrace-injecao` (1.0) — Interpretou ptrace request=16 sobre outro PID (1500) como indicativo de manipulação/injeção de processo.
- [x] `cadeia-causal` (2.0) — A conclusão amarra explicitamente binário suspeito + syscalls perigosas + C2 + reverse shell + acesso root como um único ataque coordenado.
- [ ] `ruido-benigno` (1.0) — A resposta não menciona nem qualifica o tráfego DNS ou ICMP como benigno; simplesmente os ignora.

**Batch 0002** — nota 5.50

- [x] `escalacao-sudo` (1.5) — Cita UID 1001 escalando via sudo, setresuid ruid/euid/suid=0 e capset.
- [x] `escalacao-su` (1.0) — Identifica segundo vetor via su, setuid 1001->0.
- [ ] `shadow` (1.0) — Lista /etc/shadow apenas como arquivo sensível, sem mencionar hashes de senha.
- [ ] `chave-ssh` (1.0) — Cita id_rsa apenas na lista, sem indicar roubo de chave privada especificamente.
- [x] `bash-history` (0.5) — Aponta leitura de /root/.bash_history entre os arquivos acessados.
- [x] `sudoers` (0.5) — Aponta leitura de /etc/sudoers entre os arquivos acessados.
- [x] `correlacao-pos-escalacao` (2.0) — Liga explicitamente escalação e leitura subsequente como sequência única de comprometimento.
- [ ] `sem-exfiltracao` (1.5) — Sugere que ICMP indica 'potential ... data exfiltration', não reconhece ausência clara de exfiltração.
- [ ] `ruido-benigno` (1.0) — Trata ICMP benigno como sugestivo de C2/exfiltração, não como ruído de fundo; ignora DNS.

**Batch 0003** — nota 6.50

- [x] `namespace-escape` (1.5) — Cita 'unshare' e 'setns' como parte de tentativa de fuga de container por escape.sh.
- [ ] `docker-socket` (1.5) — Menciona acesso a docker.sock mas não explica por que isso concede controle no host.
- [x] `download-payload` (1.5) — Identifica wget baixando evil_mod.ko de drop.bad-c2-domain.test, nome exato citado.
- [ ] `chroot-pivo` (1.0) — Apenas lista chroot /host_root, sem interpretar explicitamente como pivô ao filesystem do host.
- [x] `insmod-rootkit` (1.5) — Descreve insmod carregando módulo de kernel para 'deep system compromise', sugerindo rootkit/persistência.
- [x] `timeline-completa` (2.0) — Liga explicitamente fuga → download → chroot → insmod como sequência causal única.
- [ ] `ruido-benigno` (1.0) — Não menciona o tráfego ICMP nem o trata como ruído benigno.

**Batch 0004** — nota 1.58

- [ ] `fileless` (2.0) — Não menciona o evento 'fm' nem execução fileless/memfd_create.
- [x] `tampering-authlog` (1.0) — Menciona bash (PID 8205) adulterando /var/log/auth.log.
- [x] `tampering-syslog` (0.5) — Menciona bash (PID 8207) adulterando /var/log/syslog.
- [ ] `dga` (1.5) — Não reconhece padrão de subdomínios pseudo-aleatórios como DGA, só cita nome do domínio.
- [ ] `ttl-baixo` (1.0) — Não menciona TTL baixo ou rotação de IPs (fast-flux).
- [ ] `processo-oculto` (0.5) — Não comenta sobre process: null nas consultas DNS suspeitas.
- [ ] `anti-forense` (1.5) — Não liga tampering de log à execução fileless, pois fileless nem foi identificado.
- [ ] `dns-nao-sinalizado` (1.0) — Não demonstra reconhecimento próprio do padrão DGA a partir do tráfego bruto.
- [ ] `ruido-benigno` (0.5) — Não menciona security.ubuntu.com nem ICMP como tráfego benigno.

**Batch 0005** — nota 4.50

- [ ] `kworker-masquerading` (1.5) — Menciona 'masquerading' mas não explica por que kthreads não têm executável em disco.
- [x] `path-suspeito` (1.0) — Cita explicitamente '/tmp/.cache/kworker/0:2' como caminho suspeito.
- [ ] `bpf-evasao` (1.5) — Não menciona 'bpf cmd=5' nem BPF_PROG_LOAD como técnica de evasão.
- [x] `stratum-pool` (1.5) — Identifica 'stratum+tcp://pool.darkpool-mining.test:14444' como pool de mineração.
- [x] `xmrig-wallet` (1.5) — Menciona 'cryptocurrency wallet address' extraído do cmdline, confirmando cryptominer.
- [x] `root` (0.5) — Aponta explicitamente 'root privileges (UID: 0)'.
- [ ] `analise-real` (2.0) — Cruza path suspeito e cmdline, mas ignora syscall bpf cmd=5 na correlação.
- [ ] `porta-nao-sinalizada` (0.5) — Não menciona que a porta 14444 não foi sinalizada por nenhum script de rede.

#### Claude Sonnet 4.6 (via API)

**Batch 0001** — nota 8.64

- [x] `masquerading-path` (1.5) — Reconhece binário em /tmp/.systemd-helper/agent como masquerading de componente systemd.
- [x] `c2-endpoint` (1.5) — Identifica handshake TCP para 203.0.113.77:4444 como C2/reverse-shell.
- [x] `payload-decodificado` (1.5) — Decodifica payload pacote 10 como comando python3 pty.spawn, vindo do servidor.
- [x] `confirmacao-root` (1.5) — Decodifica uid=0(root) como confirmação de identidade root enviada ao C2.
- [x] `ptrace-antidebug` (1.0) — Nomeia request=0 como PTRACE_TRACEME, reconhecendo a técnica de auto-rastreamento.
- [x] `ptrace-injecao` (1.0) — Interpreta ptrace request=16 em PID 1500 como possível injeção/anti-forense.
- [x] `cadeia-causal` (2.0) — Liga execução → ptrace → C2 beacon e reforça na severidade como 'single chain' de pós-exploração.
- [x] `ruido-benigno` (1.0) — Trata DNS de systemd-resolved e ICMP como tráfego benigno não implicado.
- **ERRO** `alucina-banner` (−1.5) — Sugere que a linha 'Waiting for encrypted data' indica implante pré-existente.

**Batch 0002** — nota 6.00

- [x] `escalacao-sudo` (1.5) — Citou sudo UID 1001, setresuid(0,0,0) e capset como escalação para root.
- [x] `escalacao-su` (1.0) — Identificou 'su' PID 6330, setuid 1001→0 como segundo vetor de escalação.
- [x] `shadow` (1.0) — Descreveu leitura de /etc/shadow como 'password hashes'.
- [x] `chave-ssh` (1.0) — Apontou /root/.ssh/id_rsa como 'root SSH private key' roubada.
- [x] `bash-history` (0.5) — Mencionou leitura de /root/.bash_history como 'command history/intel'.
- [x] `sudoers` (0.5) — Citou leitura de /etc/sudoers como 'authorization rules'.
- [x] `correlacao-pos-escalacao` (2.0) — Descreveu sequência como 'classic post-exploitation credential harvesting' após escalação.
- [ ] `sem-exfiltracao` (1.5) — Tratou o ping ICMP como 'confirming exfiltration or C2 channel viability', não negando claramente exfiltração.
- [ ] `ruido-benigno` (1.0) — Transformou o ping ICMP em parte da cadeia causal de ataque, não como ruído benigno.
- **ERRO** `alegacao-sem-evidencia` (−1.5) — Afirma que o ping 'confirms... C2 channel viability', indicador técnico não suportado pelo log.

**Batch 0003** — nota 9.00

- [x] `namespace-escape` (1.5) — Identificou unshare/setns como manipulação de namespace para quebrar isolamento do container.
- [x] `docker-socket` (1.5) — Explicou acesso ao docker.sock como técnica clássica de escape com controle Docker em nível de host.
- [x] `download-payload` (1.5) — Nomeou evil_mod.ko baixado via wget de drop.bad-c2-domain.test.
- [x] `chroot-pivo` (1.0) — Tratou chroot /host_root como confirmação de escape para filesystem do host, não privesc.
- [x] `insmod-rootkit` (1.5) — Identificou insmod como carregamento de módulo de kernel, caracterizando instalação de rootkit.
- [x] `timeline-completa` (2.0) — Conectou explicitamente escape→docker.sock→download→chroot→insmod como cadeia única usando HTTP.
- [ ] `ruido-benigno` (1.0) — Tráfego ICMP não foi mencionado nem tratado como ruído benigno na análise.

**Batch 0004** — nota 4.74

- [ ] `fileless` (2.0) — Não identificou 'fm' como memfd_create/execução fileless; tratou como file manipulation incerta.
- [x] `tampering-authlog` (1.0) — Citou explicitamente tampering de /var/log/auth.log por bash PID 8205 UID 0.
- [x] `tampering-syslog` (0.5) — Citou explicitamente tampering de /var/log/syslog por bash PID 8207 UID 0.
- [x] `dga` (1.5) — Reconheceu subdomínios como 'algorithmically-generated' e 'classic DGA-style beaconing'.
- [x] `ttl-baixo` (1.0) — Notou TTL de 5 segundos como parte do padrão de beaconing C2.
- [x] `processo-oculto` (0.5) — Destacou process: null nas queries DNS como ocultação de processo.
- [ ] `anti-forense` (1.5) — Ligou log_tamp ao DNS C2 (item 5), mas não conectou explicitamente ao fileless como estratégia anti-forense coordenada.
- [x] `dns-nao-sinalizado` (1.0) — Analisou DGA a partir dos pacotes DNS brutos, sem etiqueta pré-rotulada nos logs eBPF.
- [x] `ruido-benigno` (0.5) — Não classificou security.ubuntu.com/ICMP como ameaça; focou apenas no tráfego suspeito.
- **ERRO** `fm-como-fork` (−1.5) — Interpretou 'e:fm' como 'fork/memory' ou 'file manipulation', não como execução fileless.

**Batch 0005** — nota 9.50

- [x] `kworker-masquerading` (1.5) — Explicou que kthreads legítimos não têm executável em /tmp/.cache, caracterizando masquerading.
- [x] `path-suspeito` (1.0) — Citou explicitamente o caminho /tmp/.cache/kworker/0:2 como anômalo.
- [x] `bpf-evasao` (1.5) — Interpretou cmd=5 como BPF_PROG_LOAD, ligando a possível rootkit/evasão em nível de kernel.
- [x] `stratum-pool` (1.5) — Identificou stratum+tcp://pool.darkpool-mining.test:14444 como pool de mineração.
- [x] `xmrig-wallet` (1.5) — Identificou XMRig e o endereço de carteira Monero no cmdline/payload.
- [x] `root` (0.5) — Notou explicitamente que o processo roda como root (UID 0).
- [x] `analise-real` (2.0) — Cruzou path suspeito, syscall bpf e payload/cmdline para concluir cryptominer, além das flags pré-marcadas.
- [ ] `porta-nao-sinalizada` (0.5) — Não mencionou que a porta 14444 não foi sinalizada por nenhum script de rede.

#### GPT-5.5 (via API)

**Batch 0001** — nota 6.82

- [ ] `masquerading-path` (1.5) — Chama o path 'suspicious writable path', mas não reconhece que imita componente systemd legítimo.
- [x] `c2-endpoint` (1.5) — Identifica 203.0.113.77:4444 como 'common reverse-shell/C2 port'.
- [x] `payload-decodificado` (1.5) — Decodifica payload como pty.spawn('/bin/sh'), reconhecendo vinda do servidor.
- [x] `confirmacao-root` (1.5) — Reconhece uid=0(root) como 'confirming an interactive root shell'.
- [ ] `ptrace-antidebug` (1.0) — Trata ptrace genericamente como 'tampering/inspection', não menciona PTRACE_TRACEME/anti-debug.
- [ ] `ptrace-injecao` (1.0) — Não diferencia request=16 como injeção/movimento lateral em outro PID especificamente.
- [x] `cadeia-causal` (2.0) — Conecta explicitamente path suspeito → conexão → payload → shell → ptrace como ataque correlacionado.
- [x] `ruido-benigno` (1.0) — Afirma 'Benign DNS...and ICMP traffic are not material'.

**Batch 0002** — nota 10.00

- [x] `escalacao-sudo` (1.5) — Citou setresuid ruid=0,euid=0,suid=0 e capset após sudo com UNEXPECTED_USER.
- [x] `escalacao-su` (1.0) — Identificou su PID 6330 com setuid uid 1001->0 como escalação confirmada.
- [x] `shadow` (1.0) — Incluiu /etc/shadow entre arquivos lidos, associando a coleta de credenciais.
- [x] `chave-ssh` (1.0) — Citou leitura de /root/.ssh/id_rsa como parte do roubo de credenciais.
- [x] `bash-history` (0.5) — Mencionou /root/.bash_history na lista de arquivos sensíveis lidos.
- [x] `sudoers` (0.5) — Mencionou /etc/sudoers entre os arquivos acessados após escalação.
- [x] `correlacao-pos-escalacao` (2.0) — Disse 'harvesting after escalation' e 'occur in sequence', conectando as duas fases.
- [x] `sem-exfiltracao` (1.5) — Não afirmou exfiltração; tratou tráfego de rede como benigno/não relacionado.
- [x] `ruido-benigno` (1.0) — Classificou DNS como benigno e ICMP como não ligado à cadeia maliciosa.

**Batch 0003** — nota 7.50

- [x] `namespace-escape` (1.5) — Cita 'namespace manipulation via unshare and setns' como parte da fuga do container.
- [ ] `docker-socket` (1.5) — Apenas lista acesso ao docker.sock na cadeia, sem explicar por que concede controle de host.
- [x] `download-payload` (1.5) — Identifica wget baixando evil_mod.ko de drop.bad-c2-domain.test, nomeando o artefato.
- [ ] `chroot-pivo` (1.0) — Menciona 'chroot path=/host_root' na lista, mas não interpreta explicitamente como pivô ao filesystem host.
- [x] `insmod-rootkit` (1.5) — Liga insmod PID 7115 a 'kernel-level compromise', caracterizando carga de módulo malicioso.
- [x] `timeline-completa` (2.0) — Descreve cadeia única: unshare/setns → docker.sock → chroot → download → insmod.
- [x] `ruido-benigno` (1.0) — Trata ICMP inicial como 'incidental', não como achado central.

**Batch 0004** — nota 5.26

- [ ] `fileless` (2.0) — Não menciona memfd_create, execução fileless ou o evento 'fm' de forma alguma.
- [x] `tampering-authlog` (1.0) — Cita explicitamente adulteração de /var/log/auth.log por bash root PID 8205.
- [x] `tampering-syslog` (0.5) — Cita explicitamente adulteração de /var/log/syslog por bash root PID 8207.
- [x] `dga` (1.5) — Chama os subdomínios de 'DGA/C2-like domains' explicitamente.
- [x] `ttl-baixo` (1.0) — Menciona 'very low TTL 5' como indicativo de C2/beaconing.
- [ ] `processo-oculto` (0.5) — Não comenta que process:null nas consultas suspeitas sugere ocultação.
- [ ] `anti-forense` (1.5) — Liga tampering ao DNS suspeito, mas não menciona execução fileless como parte da estratégia.
- [x] `dns-nao-sinalizado` (1.0) — Reconhece padrão DGA a partir do tráfego bruto, sem rótulo prévio do eBPF.
- [ ] `ruido-benigno` (0.5) — Não menciona security.ubuntu.com nem ICMP como tráfego benigno.

**Batch 0005** — nota 6.50

- [ ] `kworker-masquerading` (1.5) — Menciona 'masquerading' mas não explica por que kthreads reais não têm executável em disco.
- [x] `path-suspeito` (1.0) — Cita explicitamente '/tmp/.cache/kworker/0:2' como caminho suspeito.
- [ ] `bpf-evasao` (1.5) — Menciona 'bpf cmd=5' como suspeito de stealth, mas não identifica BPF_PROG_LOAD.
- [x] `stratum-pool` (1.5) — Identifica 'stratum+tcp://pool.darkpool-mining.test:14444' como comunicação de mineração.
- [x] `xmrig-wallet` (1.5) — Cita 'agent":"xmrig/6.20.0' do payload identificando o miner XMRig.
- [x] `root` (0.5) — Afirma que o processo roda como 'UID/root'.
- [x] `analise-real` (2.0) — Cruza caminho suspeito, cmdline, payload e bpf cmd=5 para concluir cryptominer, além das flags pré-marcadas.
- [ ] `porta-nao-sinalizada` (0.5) — Não comenta que a porta 14444 não foi sinalizada por nenhum script de rede.

</details>

## SEM RAG

Fonte: `no_rag_test_results.md`

| Batch | Cenário | Claude Sonnet 4.6 (effort high) | Gemini 3.1 Pro (effort default) | ChatGPT 5.5 | RedSage (local) |
|---|---|---|---|---|---|
| 1 | Reverse shell + anti-debug | 10.00 | 9.09 | 8.64 | 2.73 |
| 2 | Escalação de privilégio + roubo de credenciais | 9.00 | 9.00 | 8.50 | 4.50 |
| 3 | Fuga de container + rootkit | 7.50 | 8.50 | 10.00 | 0.00 |
| 4 | Execução fileless + anti-forense + DNS DGA | 3.16 | 3.68 | 5.26 | 0.00 |
| 5 | Cryptominer disfarçado | 9.50 | 4.50 | 6.50 | 3.00 |
| **Média** | | **7.83** | **6.96** | **7.78** | **2.05** |

### Comportamento por agente

**Claude Sonnet 4.6 (effort high)**

- **Falha sistemática em separar ruído benigno de sinais de ataque**: o critério `ruido-benigno` não foi atendido tanto no Batch 0002 (tráfego DNS/ICMP benigno interpretado como possível C2) quanto no Batch 0003 (tráfego ICMP benigno ignorado), indicando um padrão recorrente de dificuldade em filtrar falsos positivos de rede.

- **Tendência a especular sem evidência quando a análise se torna mais complexa**: no Batch 0004, o agente aciona os erros `fm-como-fork` e `alucina-implante`, sugerindo que em cenários com múltiplos vetores simultâneos (fileless + anti-forense + DGA) o agente perde precisão técnica e passa a inferir mecanismos não comprovados pelos dados.

- **Omissão recorrente de mecanismos técnicos específicos, mesmo com boa narrativa geral**: no Batch 0003 erra a flag de namespace (`flag-namespace-errada`), no Batch 0004 não conecta os achados como campanha anti-forense coordenada (`anti-forense`) e no Batch 0005 não sinaliza explicitamente a porta 14444 (`porta-nao-sinalizada`) — um padrão de acertar a cadeia de ataque em alto nível mas falhar em detalhes técnicos precisos.

- **Desempenho inconsistente entre batches simples e complexos**: enquanto os Batches 0001, 0002 e 0005 mantêm notas altas (10.00, 9.00, 9.50) com boa estruturação e conexão de IOCs, o Batch 0004 apresenta queda abrupta (3.16) com dois critérios não atendidos e dois erros disparados simultaneamente, sugerindo que a robustez do agente diminui significativamente em cenários com técnicas anti-forenses e fileless combinadas.

**Gemini 3.1 Pro (effort default)**

- **Omissão sistemática de mecanismos técnicos específicos**: o agente repetidamente identifica corretamente a cadeia de ataque geral, mas falha em detalhar o mecanismo técnico exato do vetor de comprometimento — visto em 'escalacao-su' (Batch 0002), 'docker-socket' (Batch 0003), 'bpf-evasao' (Batch 0005) e 'fileless'/'processo-oculto' (Batch 0004), sugerindo lacuna recorrente em profundidade técnica além do óbvio.

- **Ignora consistentemente tráfego/eventos benignos ou "negativos"**: em pelo menos dois batches (0001 e 0004) o critério 'ruido-benigno' não foi atendido, indicando um padrão de foco apenas em indicadores maliciosos, sem contextualizar o que É normal no ambiente — comportamento que compromete a análise diferencial.

- **Tendência a especular sem evidência direta**: no Batch 0004 o agente disparou o erro 'alucina-implante', afirmando existência de backdoor sem prova concreta, o que é preocupante justamente no batch de menor nota (3.68), sugerindo que a pressão por completude leva a inferências não sustentadas quando a evidência é fragmentada (fileless, DGA).

- **Boa performance em correlação causal e IOCs clássicos, mas fragilidade em técnicas de evasão modernas**: os batches com maior nota (0001, 0002, 0003 — todos ≥8.5) envolvem ataques com rastros mais "tradicionais" (shells, credenciais, containers), enquanto os batches com menor nota (0004 e 0005, <4.5) envolvem técnicas de evasão (fileless, DGA, eBPF, masquerading), indicando um padrão de degradação de desempenho frente a mecanismos anti-forense/anti-detecção.

- **Nenhuma violação de formato aparente**: em nenhum dos 5 batches há menção a erros de estrutura/formato da resposta, sugerindo que a aderência ao formato pedido não é um problema recorrente — os erros se concentram em conteúdo/cobertura técnica, não em apresentação.

**ChatGPT 5.5**

- **Falha recorrente em detalhar técnicas de disfarce/masquerading**: o agente identifica a presença do IOC mas não explica o mecanismo de imitação de nome/processo, repetindo-se em contextos distintos — batch 0001 (`masquerading-path`, nome systemd) e batch 0005 (`kworker-masquerading`), indicando um padrão de superficialidade específico para esse tipo de evasão.

- **Omissão sistemática de mecanismos técnicos "profundos" mesmo com IOCs corretos**: em cenários de maior sofisticação técnica o agente acerta os indicadores de superfície mas não nomeia o mecanismo subjacente — batch 0004 (`fileless`, `processo-oculto`) e batch 0005 (`bpf-evasao`), sugerindo lacuna consistente em explicar *como* a técnica funciona, não apenas *que* ela ocorreu.

- **Tendência a não afirmar explicitamente ausência/benignidade quando deveria**: o agente hesita em declarar negativos ou neutros mesmo tendo evidência suficiente — não afirma ausência de exfiltração no batch 0002 (`sem-exfiltracao`) e trata ICMP como possivelmente malicioso em vez de ruído benigno no batch 0004 (`ruido-benigno`), revelando viés a classificar como suspeito por padrão em vez de concluir neutralidade.

- **Boa correlação causal primária, mas degradação em cenários multi-camada**: a nota cai de 10.00 (batch 0003, cadeia única e coerente) para 5.26 (batch 0004, quatro mecanismos concorrentes: fileless + anti-forense + DGA + processo oculto), sugerindo que o agente perde precisão quando precisa amarrar múltiplos vetores simultâneos em vez de uma cadeia linear.

- **Zero erros factuais disparados em todos os 5 batches**: apesar das omissões, não há nenhum erro registrado nos 5 batches, indicando que o agente é conservador — prefere não afirmar algo com detalhe técnico incompleto do que arriscar uma afirmação incorreta.

**RedSage (local)**

- **Confunde ruído benigno (DNS/ICMP) com atividade maliciosa de forma sistemática**: o critério `ruido-benigno` falha em todos os 5 batches, e essa tendência se concretiza em erros explícitos como `alega-exfiltracao`/`alega-scanning` (Batch 0002) e `alegacao-sem-evidencia` (Batch 0004), indicando um padrão recorrente de especulação sem evidência real de tráfego suspeito.

- **Omite sistematicamente o mecanismo técnico central do ataque, mesmo capturando sintomas periféricos**: isso se repete em `masquerading-path` (Batch 0001), `namespace-escape`/`docker-socket`/`omitiu-mecanismo-fuga` (Batch 0003), `fileless`/`dga` (Batch 0004) e `kworker-masquerading`/`bpf-evasao` (Batch 0005) — o agente relata efeitos superficiais (payload, pool de mineração, path) mas não explica como o ataque de fato ocorre.

- **Erra na classificação de conceitos técnicos de segurança**, como no Batch 0003 (`chroot-como-privesc`), sugerindo confusão conceitual entre isolamento/pivô e escalação de privilégio — um erro de raciocínio técnico, não apenas de omissão.

- **Falha em construir cadeia causal e timeline coesa entre os eventos**, evidenciado por `cadeia-causal` (Batch 0001), `timeline-completa` (Batch 0003) e a observação de falta de conexão causal em `analise-real` (Batch 0005) — o agente tende a listar achados isolados em vez de narrar a progressão do ataque.

- **Desempenho inconsistente e polarizado**: enquanto em Batches 0001/0005 não há erros explícitos disparados (apenas omissões), em Batches 0003/0004 a nota cai a 0.00 com múltiplos erros simultâneos, sugerindo que a qualidade da resposta varia fortemente conforme a complexidade do cenário (fileless/anti-forense e fuga de container são os pontos mais fracos).

<details>
<summary>Vereditos por critério</summary>

#### Claude Sonnet 4.6 (effort high)

**Batch 0001** — nota 10.00

- [x] `masquerading-path` (1.5) — Identificou path /tmp/.systemd-helper/agent e chamou de 'masquerading technique'.
- [x] `c2-endpoint` (1.5) — Caracterizou conexão a 203.0.113.77:4444 como C2/reverse shell via Metasploit.
- [x] `payload-decodificado` (1.5) — Decodificou payload como pty.spawn, indicando comando do C2 para vítima.
- [x] `confirmacao-root` (1.5) — Reconheceu uid=0(root) como confirmação de shell root interativo.
- [x] `ptrace-antidebug` (1.0) — Interpretou request=0 como 'self-tracing, possible anti-debug check'.
- [x] `ptrace-injecao` (1.0) — Interpretou request=16 em PID 1500 como possível injeção de processo/credential dumping.
- [x] `cadeia-causal` (2.0) — Tabela de kill chain e veredito conectam execução, C2, shell e ptrace como ataque único.
- [x] `ruido-benigno` (1.0) — Tratou DNS/ICMP como 'appears benign and likely pre-existing system activity'.

**Batch 0002** — nota 9.00

- [x] `escalacao-sudo` (1.5) — Citou setresuid(ruid=0,euid=0,suid=0) e capset como escalação via sudo (UID 1001).
- [x] `escalacao-su` (1.0) — Identificou segundo vetor via `su` com setuid 1001→0, PID 6330.
- [x] `shadow` (1.0) — Apontou /etc/shadow como 'hashed user passwords'.
- [x] `chave-ssh` (1.0) — Apontou id_rsa como 'root's private SSH key'.
- [x] `bash-history` (0.5) — Mencionou leitura de /root/.bash_history.
- [x] `sudoers` (0.5) — Mencionou leitura de /etc/sudoers.
- [x] `correlacao-pos-escalacao` (2.0) — Conectou 'Running as root' após escalação com leitura subsequente dos arquivos sensíveis.
- [x] `sem-exfiltracao` (1.5) — Afirmou explicitamente 'No outbound exfiltration is captured in this batch'.
- [ ] `ruido-benigno` (1.0) — Transformou DNS/ICMP em possível reconnaissance/C2 probe em vez de tratá-los como puro ruído.

**Batch 0003** — nota 7.50

- [x] `namespace-escape` (1.5) — Descreveu unshare/setns como 'classic container namespace escape technique'.
- [x] `docker-socket` (1.5) — Explicou que acesso ao docker.sock concede 'full host-level container management privileges'.
- [x] `download-payload` (1.5) — Nomeou exatamente evil_mod.ko via wget de drop.bad-c2-domain.test.
- [x] `chroot-pivo` (1.0) — Descreveu chroot /host_root como pivô de filesystem, não privesc.
- [x] `insmod-rootkit` (1.5) — Identificou insmod como carregamento de rootkit com persistência ring-0.
- [x] `timeline-completa` (2.0) — Narrativa numerada liga escape→download HTTP→insmod explicitamente como cadeia única.
- [ ] `ruido-benigno` (1.0) — Tráfego ICMP inicial não foi mencionado nem tratado explicitamente como ruído benigno.
- **ERRO** `flag-namespace-errada` (−1.5) — Nomeou incorretamente flags=0x20000000 como CLONE_NEWUSER (correto seria CLONE_NEWPID).

**Batch 0004** — nota 3.16

- [ ] `fileless` (2.0) — Evento 'fm' interpretado como fork/memory spawning processos, não como execução fileless via memfd_create.
- [x] `tampering-authlog` (1.0) — Identifica explicitamente modificação de /var/log/auth.log por bash root.
- [x] `tampering-syslog` (0.5) — Identifica explicitamente modificação de /var/log/syslog por bash root.
- [x] `dga` (1.5) — Reconhece subdomínios aleatórios como DGA/DNS tunneling para C2.
- [x] `ttl-baixo` (1.0) — Menciona TTL de 5 segundos como indicativo de infraestrutura rotativa/fast-flux.
- [x] `processo-oculto` (0.5) — Nota 'process: null' sugerindo processo oculto ou terminado antes da captura.
- [ ] `anti-forense` (1.5) — Lista tampering e DGA como achados numerados separados, sem conectá-los como estratégia coordenada.
- [x] `dns-nao-sinalizado` (1.0) — Analisa padrão dos subdomínios e infere DGA a partir do tráfego bruto, não apenas rótulo pré-existente.
- [x] `ruido-benigno` (0.5) — Classifica DNS para security.ubuntu.com e ICMP como tráfego benigno de fundo.
- **ERRO** `fm-como-fork` (−1.5) — Interpreta 'fm' como 'fork/memory' com bash gerando processos filhos, não como fileless.
- **ERRO** `alucina-implante` (−1.5) — Afirma 'implante pode estar injetado em processo legítimo' sem evidência direta no log.

**Batch 0005** — nota 9.50

- [x] `kworker-masquerading` (1.5) — Explicou que kthreads reais não têm executável em disco, diferente do processo disfarçado.
- [x] `path-suspeito` (1.0) — Citou '/tmp/.cache/kworker/0:2' como caminho de execução suspeito.
- [x] `bpf-evasao` (1.5) — Interpretou cmd=5 como BPF_PROG_LOAD e associou a ocultação/evasão em nível de kernel.
- [x] `stratum-pool` (1.5) — Identificou 'stratum+tcp://pool.darkpool-mining.test:14444' como pool de mineração.
- [x] `xmrig-wallet` (1.5) — Identificou XMRig e o endereço de carteira Monero no cmdline/payload.
- [x] `root` (0.5) — Afirmou 'Running as root' e 'UID 0' explicitamente.
- [x] `analise-real` (2.0) — Cruzou path suspeito, syscall bpf e payload/cmdline para concluir cryptominer com evasão.
- [ ] `porta-nao-sinalizada` (0.5) — Não mencionou que a porta 14444 não foi sinalizada por nenhum script de rede.

#### Gemini 3.1 Pro (effort default)

**Batch 0001** — nota 9.09

- [x] `masquerading-path` (1.5) — Identificou caminho /tmp/.systemd-helper/agent e disfarce como systemd legítimo.
- [x] `c2-endpoint` (1.5) — Identificou conexão para 203.0.113.77:4444 como reverse shell/C2.
- [x] `payload-decodificado` (1.5) — Decodificou hex como python3 pty.spawn, reconhecendo origem no servidor (inbound).
- [x] `confirmacao-root` (1.5) — Reconheceu uid=0(root) como confirmação de acesso root interativo.
- [x] `ptrace-antidebug` (1.0) — Interpretou ptrace request=0 como PTRACE_TRACEME, técnica anti-debug.
- [x] `ptrace-injecao` (1.0) — Interpretou ptrace request=16 (PTRACE_ATTACH) como injeção/credential dumping em PID 1500.
- [x] `cadeia-causal` (2.0) — Conclusão amarra masquerading→C2→shell interativo→injeção como compromisso único coordenado.
- [ ] `ruido-benigno` (1.0) — Resposta não menciona DNS nem ICMP em nenhum momento, apenas omite.

**Batch 0002** — nota 9.00

- [x] `escalacao-sudo` (1.5) — Cita sudo e 'modifying system capabilities' (capset), cobrindo vetor sudo.
- [ ] `escalacao-su` (1.0) — Menciona 'su commands' genericamente, mas não cita setuid 1001→0.
- [x] `shadow` (1.0) — Aponta /etc/shadow como hashes de senha do sistema.
- [x] `chave-ssh` (1.0) — Identifica id_rsa como chave privada SSH roubada.
- [x] `bash-history` (0.5) — Cita /root/.bash_history como histórico com segredos.
- [x] `sudoers` (0.5) — Menciona /etc/sudoers como configuração de privilégios lida.
- [x] `correlacao-pos-escalacao` (2.0) — Diz 'Immediately following privilege escalation' conectando as duas fases.
- [x] `sem-exfiltracao` (1.5) — Afirma que não há exfiltração ativa, apenas checagem de conectividade.
- [x] `ruido-benigno` (1.0) — Trata DNS e ICMP como 'routine network connectivity checking'.

**Batch 0003** — nota 8.50

- [x] `namespace-escape` (1.5) — Menciona unshare/setns como manipulação de namespace para escape do container.
- [ ] `docker-socket` (1.5) — Cita acesso a docker.sock mas não explica por que isso concede controle em nível de host.
- [x] `download-payload` (1.5) — Identifica wget baixando evil_mod.ko de drop.bad-c2-domain.test.
- [x] `chroot-pivo` (1.0) — Descreve chroot /host_root como pivô para o filesystem do host, não como privesc.
- [x] `insmod-rootkit` (1.5) — Associa insmod ao carregamento de módulo de kernel e rootkit LKM persistente.
- [x] `timeline-completa` (2.0) — Conecta explicitamente fuga → download do payload → carregamento no kernel via insmod.
- [x] `ruido-benigno` (1.0) — Trata ICMP inicial como verificação de conectividade, não como achado central.

**Batch 0004** — nota 3.68

- [ ] `fileless` (2.0) — Resposta não menciona o evento 'fm' nem execução fileless/memfd_create em nenhum momento.
- [x] `tampering-authlog` (1.0) — Cita explicitamente adulteração de /var/log/auth.log por processo bash com UID 0.
- [x] `tampering-syslog` (0.5) — Cita explicitamente adulteração de /var/log/syslog pelo mesmo processo.
- [x] `dga` (1.5) — Reconhece subdomínios de alta entropia como uso de Domain Generation Algorithm (DGA).
- [x] `ttl-baixo` (1.0) — Identifica TTL de 5s e rotação de IPs como técnica fast-flux evasiva.
- [ ] `processo-oculto` (0.5) — Não menciona que as consultas DNS maliciosas têm process:null (ocultação de processo).
- [ ] `anti-forense` (1.5) — Não conecta tampering de logs à execução fileless, pois esta última nem é mencionada.
- [x] `dns-nao-sinalizado` (1.0) — Identificou padrão DGA a partir do tráfego bruto do sniffer, não de rótulo eBPF pré-existente.
- [ ] `ruido-benigno` (0.5) — Não menciona security.ubuntu.com nem tráfego ICMP como benignos; simplesmente os omite.
- **ERRO** `alucina-implante` (−1.5) — Afirma 'malware operates as a privileged backdoor or rootkit' sem evidência de sessão interativa no log.

**Batch 0005** — nota 4.50

- [ ] `kworker-masquerading` (1.5) — Identifica o disfarce como 'kworker/0:2', mas não explica que kthreads reais não têm executável em disco.
- [x] `path-suspeito` (1.0) — Aponta explicitamente '/tmp/.cache/kworker/0:2' como local suspeito de payload.
- [ ] `bpf-evasao` (1.5) — Não menciona o evento eBPF 'cmd=5' nem BPF_PROG_LOAD como técnica de evasão.
- [x] `stratum-pool` (1.5) — Identifica 'stratum+tcp://pool.darkpool-mining.test:14444' como comunicação com pool de mineração.
- [x] `xmrig-wallet` (1.5) — Identifica XMRig 6.20.0 e o endereço de carteira no cmdline/payload.
- [x] `root` (0.5) — Menciona 'executing with root privileges (UID 0)'.
- [ ] `analise-real` (2.0) — Cruza path suspeito, cmdline e payload, mas ignora completamente o evento bpf cmd=5.
- [ ] `porta-nao-sinalizada` (0.5) — Não comenta que a porta 14444 não foi sinalizada por nenhum script, apenas descreve o tráfego.

#### ChatGPT 5.5

**Batch 0001** — nota 8.64

- [ ] `masquerading-path` (1.5) — Cita o caminho e diz 'masquerading' genericamente, mas não explicita que imita um componente systemd.
- [x] `c2-endpoint` (1.5) — Identifica conexão a 203.0.113.77:4444 como 'common C2/backdoor port'.
- [x] `payload-decodificado` (1.5) — Reconhece comando de spawn de shell via Python PTY vindo do C2 para a vítima.
- [x] `confirmacao-root` (1.5) — Cita 'uid=0(root)' como confirmação de execução remota com privilégios root.
- [x] `ptrace-antidebug` (1.0) — Menciona 'ptrace on itself... consistent with anti-analysis', cobrindo request=0.
- [x] `ptrace-injecao` (1.0) — Refere ptrace em 'another process' como 'process manipulation, or code injection', cobrindo request=16.
- [x] `cadeia-causal` (2.0) — Conecta execução suspeita → C2 → shell root → ptrace como um único ataque coordenado no resumo final.
- [x] `ruido-benigno` (1.0) — Classifica DNS/ICMP inicial como 'benign... appears unrelated'.

**Batch 0002** — nota 8.50

- [x] `escalacao-sudo` (1.5) — Menciona escalação via sudo com UID changes to root e capability modification.
- [x] `escalacao-su` (1.0) — Menciona escalação via su explicitamente ('sudo and su').
- [x] `shadow` (1.0) — Aponta /etc/shadow como password hashes.
- [x] `chave-ssh` (1.0) — Aponta /root/.ssh/id_rsa como SSH private key.
- [x] `bash-history` (0.5) — Aponta /root/.bash_history como command history.
- [x] `sudoers` (0.5) — Aponta /etc/sudoers como privilege configuration.
- [x] `correlacao-pos-escalacao` (2.0) — Descreve 'local privilege escalation followed by credential harvesting' como sequência única.
- [ ] `sem-exfiltracao` (1.5) — Não menciona explicitamente ausência de exfiltração, apenas foca em coleta.
- [x] `ruido-benigno` (1.0) — Trata DNS como legítimo/não relacionado e ICMP como simple connectivity check.

**Batch 0003** — nota 10.00

- [x] `namespace-escape` (1.5) — Cita unshare/setns como manipulação de namespace para escapar do container.
- [x] `docker-socket` (1.5) — Identifica acesso ao docker.sock e liga a abuso do daemon para controle no host.
- [x] `download-payload` (1.5) — Nomeia evil_mod.ko baixado via wget como payload de segundo estágio.
- [x] `chroot-pivo` (1.0) — Descreve chroot /host_root como pivô para filesystem do host, não como privesc.
- [x] `insmod-rootkit` (1.5) — Identifica insmod como carregamento de módulo de kernel, provável rootkit/implante.
- [x] `timeline-completa` (2.0) — Resumo conecta escape→docker.sock→download→pivot→insmod como cadeia única.
- [x] `ruido-benigno` (1.0) — Trata tráfego ICMP inicial como checagem de conectividade, não achado central.

**Batch 0004** — nota 5.26

- [ ] `fileless` (2.0) — Não menciona memfd_create ou execução fileless; trata 'fm' apenas como 'root shell performing suspicious actions'.
- [x] `tampering-authlog` (1.0) — Menciona explicitamente adulteração de /var/log/auth.log.
- [x] `tampering-syslog` (0.5) — Menciona explicitamente adulteração de /var/log/syslog.
- [x] `dga` (1.5) — Reconhece subdomínios randomizados sob bad-c2-domain.test como padrão DGA.
- [x] `ttl-baixo` (1.0) — Nota TTLs muito curtos usados para rotacionar endpoints C2, indicando fast-flux.
- [ ] `processo-oculto` (0.5) — Não menciona ausência de processo associado (process: null) nas consultas DNS suspeitas.
- [ ] `anti-forense` (1.5) — Não conecta explicitamente execução fileless (não identificada) ao tampering de logs como estratégia coordenada.
- [x] `dns-nao-sinalizado` (1.0) — Identificou padrão DGA a partir da estrutura dos nomes de domínio no tráfego bruto, não pré-rotulado pelo eBPF.
- [ ] `ruido-benigno` (0.5) — Trata DNS Ubuntu como benigno, mas especula que ICMP pode ser beaconing/C2, não benigno.

**Batch 0005** — nota 6.50

- [ ] `kworker-masquerading` (1.5) — Menciona 'impersonating' mas não explica que kthreads reais não têm executável em disco.
- [x] `path-suspeito` (1.0) — Apontou explicitamente `/tmp/.cache/kworker/0:2` como local anômalo.
- [ ] `bpf-evasao` (1.5) — Fala genericamente de 'eBPF-related activity' e evasão, sem interpretar cmd=5 como BPF_PROG_LOAD.
- [x] `stratum-pool` (1.5) — Identificou conexão stratum+tcp na porta 14444 como comunicação com pool de mineração.
- [x] `xmrig-wallet` (1.5) — Citou endereço de carteira e associou a 'XMRig-style Monero mining'.
- [x] `root` (0.5) — Afirmou 'The process runs as root'.
- [x] `analise-real` (2.0) — Cruzou path suspeito, atividade eBPF e payload/cmdline para concluir cryptominer disfarçado.
- [ ] `porta-nao-sinalizada` (0.5) — Não mencionou que a porta 14444 não foi sinalizada por nenhum script de rede.

#### RedSage (local)

**Batch 0001** — nota 2.73

- [ ] `masquerading-path` (1.5) — Não menciona o caminho /tmp/.systemd-helper/agent nem masquerading de systemd.
- [x] `c2-endpoint` (1.5) — Identifica conexão para 203.0.113.77:4444 como provável C2.
- [x] `payload-decodificado` (1.5) — Interpreta o payload como comando python pty.spawn para shell.
- [ ] `confirmacao-root` (1.5) — Não menciona a resposta uid=0(root) como confirmação de shell root.
- [ ] `ptrace-antidebug` (1.0) — Menciona ptrace genericamente, sem identificar request=0 como anti-debug/TRACEME.
- [ ] `ptrace-injecao` (1.0) — Não menciona request=16 nem PID alvo diferente como injeção/movimento lateral.
- [ ] `cadeia-causal` (2.0) — Lista achados soltos (DNS, ptrace, shell) sem amarrar como ataque único coordenado.
- [ ] `ruido-benigno` (1.0) — Trata DNS de security.ubuntu.com como parte da atividade do malware, não como benigno.

**Batch 0002** — nota 4.50

- [x] `escalacao-sudo` (1.5) — Cita setresuid/euid/suid=0 via sudo para escalar a UID 1001 a root.
- [x] `escalacao-su` (1.0) — Menciona 'use of su to switch to root user' como indicador, capturando o segundo vetor.
- [x] `shadow` (1.0) — Lista /etc/shadow entre arquivos acessados, ligando a roubo de credenciais.
- [x] `chave-ssh` (1.0) — Cita /root/.ssh/id_rsa como parte do roubo de credenciais.
- [x] `bash-history` (0.5) — Menciona /root/.bash_history na lista de arquivos acessados.
- [x] `sudoers` (0.5) — Cita /etc/sudoers entre os arquivos lidos.
- [x] `correlacao-pos-escalacao` (2.0) — Diz 'This user then accessed sensitive files' ligando escalação a leitura subsequente.
- [ ] `sem-exfiltracao` (1.5) — Afirma que houve 'data exfiltration', não reconhece ausência de exfiltração.
- [ ] `ruido-benigno` (1.0) — Trata DNS e ICMP como evidência de exfiltração e reconhecimento, não como ruído.
- **ERRO** `alega-exfiltracao` (−2.0) — Frase 'indicating data exfiltration' afirma exfiltração sem evidência real.
- **ERRO** `alega-scanning` (−1.0) — Chama ICMP/DNS benignos de 'network reconnaissance', alegando varredura.

**Batch 0003** — nota 0.00

- [ ] `namespace-escape` (1.5) — Não menciona unshare/setns nem qualquer manipulação de namespace.
- [ ] `docker-socket` (1.5) — Não menciona acesso a /var/run/docker.sock.
- [x] `download-payload` (1.5) — Nomeia 'evil_mod.ko' baixado via wget, embora omita o domínio de origem.
- [ ] `chroot-pivo` (1.0) — Trata chroot como escalação de privilégio, não como pivô para o filesystem do host.
- [ ] `insmod-rootkit` (1.5) — Menciona insmod mas não caracteriza como rootkit ou persistência ring-0.
- [ ] `timeline-completa` (2.0) — Cadeia incompleta: falta unshare/setns/docker.sock; não liga HTTP ao insmod explicitamente.
- [ ] `ruido-benigno` (1.0) — Trata ICMP como 'scanning/testing' potencial, tornando-o achado, não ruído benigno.
- **ERRO** `chroot-como-privesc` (−1.0) — Afirma que chroot 'attempts to escalate privileges'.
- **ERRO** `omitiu-mecanismo-fuga` (−1.5) — Descreve apenas download→chroot→insmod, sem citar unshare/setns/docker.sock.

**Batch 0004** — nota 0.00

- [ ] `fileless` (2.0) — Não menciona memfd_create nem execução fileless; evento 'fm' ignorado.
- [ ] `tampering-authlog` (1.0) — Não menciona adulteração de /var/log/auth.log.
- [ ] `tampering-syslog` (0.5) — Não menciona adulteração de /var/log/syslog.
- [ ] `dga` (1.5) — Menciona domínio C2 mas não identifica padrão DGA/subdomínios pseudo-aleatórios.
- [ ] `ttl-baixo` (1.0) — Não comenta TTL baixo ou rotação de IPs/fast-flux.
- [ ] `processo-oculto` (0.5) — Não observa process: null nas consultas DNS suspeitas.
- [ ] `anti-forense` (1.5) — Não há menção a tampering nem a fileless, logo não há conexão anti-forense.
- [ ] `dns-nao-sinalizado` (1.0) — Não há análise autônoma de padrão DGA; apenas cita domínio suspeito genericamente.
- [ ] `ruido-benigno` (0.5) — Trata o ICMP como reconhecimento/probing, não como tráfego benigno; DNS legítimo nem mencionado.
- **ERRO** `alegacao-sem-evidencia` (−1.5) — Afirma que ICMP indica 'reconnaissance/probing' e 'network scanning', não sustentado pelo log (apenas ping simples).

**Batch 0005** — nota 3.00

- [ ] `kworker-masquerading` (1.5) — Não explicou que kworker é disfarce de kernel thread nem por que é anômalo ter executável em disco.
- [x] `path-suspeito` (1.0) — Citou explicitamente '/tmp/.cache/kworker/0:2' como caminho suspeito.
- [ ] `bpf-evasao` (1.5) — Mencionou apenas 'eBPF alerts' sem interpretar cmd=5 como BPF_PROG_LOAD ou técnica de evasão.
- [x] `stratum-pool` (1.5) — Identificou conexão a 'pool.darkpool-mining.test:14444' como pool de mineração.
- [ ] `xmrig-wallet` (1.5) — Não identificou XMRig nem endereço de carteira Monero especificamente.
- [x] `root` (0.5) — Mencionou 'root-owned worker process'.
- [ ] `analise-real` (2.0) — Não cruzou path suspeito + bpf cmd=5 + payload/cmdline; análise superficial e genérica.
- [ ] `porta-nao-sinalizada` (0.5) — Não mencionou que a porta 14444 não foi sinalizada por scripts de rede.

</details>
