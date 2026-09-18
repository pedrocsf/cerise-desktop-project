# CONTEXTO.md — Cerise Desktop Project

Documento de orientação para quem (humano ou IA) entra neste repositório pela primeira vez. Descreve o que o sistema faz, como as peças se conectam, e onde cada responsabilidade vive no código.

---

## 1. Visão geral em uma frase

**Maltrace** é um sandbox de análise dinâmica de malware: uma VM QEMU descartável executa a amostra suspeita enquanto dois canais de telemetria independentes — **eBPF/bpftrace no nível de kernel (dentro da VM)** e **captura de rede no nível de userspace (fora da VM, no host)** — alimentam, em tempo quase real, um LLM com **RAG** que classifica cada janela de eventos como `SAFE` / `SUSPICIOUS` / `THREAT`, com severidade (1-5) e justificativa.

O arquivo que orquestra tudo é `virtual_machine/pipeline_web.py`.

---

## 2. Topologia física: VM guest vs. host

```
┌─────────────────────────── VM QEMU (guest infectado) ───────────────────────────┐
│                                                                                    │
│  guest_monitor.c  → dispara 9 processos bpftrace, um por padrão de ataque:       │
│    dangerous_syscalls.bt, docker_socket_access.bt, fileless_execution.bt,        │
│    kernel_module_load.bt, log_tampering.bt, network_suspicious.bt,               │
│    privilege_escalation.bt, sensitive_file_access.bt, suspicious_exec.bt         │
│                                                                                    │
│  Cada bpftrace escreve texto (stdout) → guest_monitor criptografa (AES-128-CBC,  │
│  chave/IV fixos "CERISE...") → envia por um /dev/vportN dedicado                 │
│  (virtio-serial, um canal por script = isolamento por categoria de detecção)     │
│                                                                                    │
│  supervisor_monitor.c → roda supervisor.py (scapy + psutil) capturando pacotes   │
│  de rede da própria VM em nível de userspace, correlacionando socket→processo    │
│  → também criptografa e envia por seu(s) próprio(s) /dev/vportN                  │
│                                                                                    │
└──────────────────────────────────┬────────────────────────────────────────────-─┘
                                    │ virtio-serial (múltiplas portas, uma por script)
┌───────────────────────────────────▼──────────────────────────────────────────────┐
│                              HOST (máquina do analista)                          │
│                                                                                    │
│  vm_controller.c    → sobe/derruba a VM QEMU, descobre os /dev/pts/N que o QEMU  │
│                        expõe para cada virtserialport, grava em                  │
│                        serial_ports.list (nome:porta) — ex.: ch1..ch9 = eBPF,    │
│                        ch10+ = rede (ver `num >= 10` em pipeline_web.py)         │
│                                                                                    │
│  host_listener.c    → 1 processo, 1 fork por porta eBPF (ch1-9): lê do serial,   │
│                        decripta AES, imprime linha em stdout com prefixo [porta] │
│  supervisor_listener.c → mesmo papel, mas para a(s) porta(s) de rede            │
│                                                                                    │
│  pipeline_web.py    → spawna host_listener + supervisor_listener como           │
│                        subprocessos, lê stdout de cada um em threads dedicadas, │
│                        agrega em batches, consulta o RAG, envia ao LLM,         │
│                        serve dashboard web + SSE                                │
│                                                                                    │
└────────────────────────────────────────────────────────────────────────────────-┘
```

**Por que serial criptografado?** É o único canal de saída da VM guest — não há rede de gerência nem shared folder — então tudo (eBPF e rede) sai por `virtio-serial` com AES-128-CBC simétrico simples (chave hardcoded, não é para segurança forte, é para não trafegar texto puro por um dispositivo de VM).

---

## 3. Os dois canais de telemetria

### 3.1 eBPF (comportamento do sistema, kernel-level, dentro da VM)

- 9 scripts `bpftrace` (`.bt`, referenciados em `guest_monitor.c`, carregados de `/home/cerise/Downloads/*.bt` dentro do guest), um por categoria de ataque.
- Cada script mapeia 1:1 a um documento de conhecimento em `RAG_docs/` (mesmo nome): `dangerous_syscalls`, `docker_socket_access`, `fileless_execution`, `kernel_module_load`, `log_tampering`, `network_suspicious`, `privilege_escalation`, `sensitive_file_access`, `suspicious_exec`.
- Cada categoria roda isolada em seu próprio `/dev/vportN` → facilita saber de qual heurística um evento veio antes mesmo de chegar ao LLM.
- No host, `pipeline_web.py` classifica essas portas como `host_ports` quando o número do canal (`ch1`..`ch9`) é `< 10`.

### 3.2 Rede (comportamento de rede, userspace, dentro da VM mas fora do kernel)

- `supervisor.py` roda dentro da VM usando `scapy.sniff` para capturar pacotes (IP/TCP/UDP/ICMP/DNS/ARP) e `psutil` para correlacionar cada conexão com processo/PID/usuário/cmdline (`ConnectionCache`).
- Portas com número `>= 10` (`ch10`, `ch11`, ...) são tratadas como `supervisor_ports` em `pipeline_web.py`.
- **Detecção por conteúdo, não só por porta**: mesmo que a classificação de porta falhe, `pipeline_web.py` reconhece um evento de rede pela fingerprint textual (`_is_network_event`: presença de `"packet_number"` ou `"ethernet"` no JSON) e o rotula `network` de qualquer forma — dupla garantia.

Ambos os canais convergem no mesmo formato de saída: linhas de texto (structured/JSON-ish) lidas por `reader_thread()` em `pipeline_web.py`, cada uma taggeada como `[ebpf:portaX]` ou `[network:portaY]` e empilhada em `state.current_batch`.

---

## 4. Do evento bruto ao veredito: o pipeline em `pipeline_web.py`

1. **Ingestão** (`reader_thread`): cada linha decriptada dos processos `host_listener`/`supervisor_listener` vira um evento com `id`, `timestamp`, `port`, `source` (`ebpf`/`network`), `data`. Contadores globais (`ebpf_count`, `network_count`, `events_per_port`) e broadcast via SSE para o dashboard em tempo real.
2. **Batching** (`batch_timer_thread`): a cada `BATCH_INTERVAL` (30s), tudo que se acumulou em `current_batch` vira um `batch` (até 100 últimos eventos são usados na análise) e entra na `analysis_queue`.
3. **Análise** (`analysis_worker_thread` → `run_analysis`), sequencial (1 batch por vez):
   - **RAG retrieval** (`RagRetriever.retrieve_context`, em `log_watcher.py`):
     a. **HyDE** — o próprio LLM configurado reescreve o batch bruto em uma lista curta de ações de segurança em linguagem simples (`HYDE_PROMPT`), reduzindo ruído antes de embeddar.
     b. **Busca híbrida** — embedding denso (`cerise-embed-v1`, fine-tune de `nomic-embed-text-v1.5`, ver `finetune_embeddings.py`) via ChromaDB + busca esparsa BM25, fundidos por **Reciprocal Rank Fusion**.
     c. **Reranking** — `cross-encoder/ms-marco-MiniLM-L-6-v2` reordena os candidatos fundidos.
     d. **Filtragem por categoria** — mantém só o melhor chunk por categoria (até `MAX_CATEGORIES=3`), descarta abaixo de `MIN_RERANK_SCORE`, marca confiança `HIGH`/`MEDIUM`/`LOW`.
   - **Prompt final** (`PROMPT_TEMPLATE`): injeta o(s) bloco(s) RAG retornado(s) como contexto + os eventos brutos do batch, instrui o LLM a:
     - correlacionar eventos `[ebpf]` com `[network]` do mesmo processo como uma cadeia causal única;
     - tratar cada categoria RAG como **hipótese**, não fato — cruzar com o log bruto antes de confiar;
     - devolver `VERDICT` (`SAFE`/`SUSPICIOUS`/`THREAT`), `SEVERITY` (1-5, ancorada no `Base Criticality Level` do doc RAG mais relevante) e `ANALYSIS` com evidência concreta (pid, path, ip:porta etc.).
   - **LLM provider plugável** (`send_to_llm`): Ollama local, OpenAI-compatible (OpenAI e Gemini), ou Claude — configurável em runtime via `/api/llm/config`, com streaming token-a-token via SSE.
4. **Saída**: cada batch acumula `rag` (categoria/confiança/scores) e `response` (texto do LLM) e é servido via `/api/batch/<id>`, `/api/batches`, exportável em zip (`/api/export/batches.zip`), e transmitido ao vivo por SSE (`/api/stream`) para o dashboard (`dashboard.html`).
5. **Chat interativo** (`/api/chat`): canal separado para o analista perguntar algo livremente ao mesmo LLM configurado, fora do fluxo de batches.

---

## 5. A base de conhecimento RAG (`RAG_docs/`)

9 "fact sheets" em Markdown, **um por categoria de eBPF** (mesmos nomes dos scripts `.bt`), cada um com 5 seções fixas que `indexer.py` usa como pontos de chunking:

```
Script Objective
Anomaly Patterns
Normal Patterns (Common False Positives)
Base Criticality Level
Suggested Correlation
```

- `indexer.py`: lê cada `.md`, fatia por esses 5 headers (regex sobre `SECTION_HEADERS`), embeda cada chunk com `cerise-embed-v1` (prefixo `search_document: `) e faz upsert no ChromaDB (`vector_db/`, coleção `security_docs`).
- O encoder foi **fine-tunado especificamente** para este formato curto (frase de técnica → fact sheet), não para digerir logs brutos de milhares de linhas — por isso o RAG não indexa telemetria bruta, só documentos de conhecimento destilados.
- Adicionar uma nova categoria = escrever um novo `.md` com esses 5 headers exatos e rodar `indexer.py`.

---

## 6. Scripts auxiliares e avaliação

- `log_watcher_injector.py` — teste manual/interativo do `RagRetriever` sem precisar da VM rodando.
- `indexer.py` / `finetune_embeddings.py` — build da base vetorial e fine-tune do encoder.
- `eval_retrieval_threshold.py`, `eval_llm.py`, `eval_regex.py`, `run_rag_batches.py`, `rubric.md` — avaliação do pipeline (retrieval e veredito do LLM) contra `synthetic_batches/`, com resultados salvos em `*_results*.md`/`.json`.
- `read_db.py` — inspeção crua do ChromaDB.
- `dashboard.html` — front-end único servido por `pipeline_web.py` (status, batches, stream SSE, chat, config de LLM, painel VM Screen com noVNC, terminal do host via ttyd — ver seções 10-12).

---

## 7. Convenção de portas (`serial_ports.list`)

Formato `<label> <device_path>` (ex.: `ch1 /dev/pts/4`). `pipeline_web.py::main()` classifica pelo número extraído do label:

- `num < 10` → **host_ports** (eBPF) → spawna `host_listener` com todas de uma vez (um fork interno por porta).
- `num >= 10` → **supervisor_ports** (rede) → spawna um `supervisor_listener` **por porta individualmente**.

Esse arquivo é gerado por `vm_controller.c` ao subir a VM; `pipeline_web.py` falha rápido (`sys.exit`) se não o encontrar — ou seja, a VM precisa estar de pé (via `vm_controller`) antes do pipeline.

---

## 8. Onde isso está indo (contexto para o próximo passo)

O projeto está em fase de **ampliar a cobertura da base RAG** além das 9 categorias originais (que foram um conjunto de teste), usando datasets públicos de comportamento de intrusão/malware para gerar novos fact sheets no mesmo formato de 5 headers. Ver `PLANO_ADAPTACAO_LIDDS.md` para o plano em andamento (adaptação do LID-DS) e `PLANO_ATOMIC_RED.md` para uma linha paralela baseada em Atomic Red Team.

---

## 9. VM guest — reconstruída como `cerise.qcow2` (Ubuntu 18.04 Desktop, sem telemetria ainda)

O `malware_vm.qcow2` original (`/home/pacto/malware_vm.qcow2`) foi perdido. O usuário reinstalou um Ubuntu 18.04 Desktop genérico do zero e salvou como **`~/Downloads/cerise.qcow2`** (usuário `cerise` / senha `cerise123`, GNOME, Firefox instalado). `vm_controller.c` já aponta para esse arquivo (`-drive file=/home/pedro/Downloads/cerise.qcow2,...` — path específico desta máquina, ajustar se rodar em outra). Existe um backup em `cerise.qcow2.bak` (feito antes da primeira escrita no disco).

**O que essa VM tem hoje:**
- Um script de demonstração fake em `/home/cerise/malware` (bash): ao rodar, aloca memória aleatória (300–900MB via `/dev/urandom`+`base64`, guardada numa variável bash) e sobe de 2 a 5 processos filhos em busy-loop (`while :; do :; done`), todos herdando o nome `malware` no `comm`/`top` (confirmado: um script bash executado direto herda seu próprio nome no `/proc/pid/comm`, não o do interpretador) — sem executar malware real, só simula alto consumo de CPU/memória sob esse nome. Termina os filhos via `trap ... EXIT INT TERM` ao fechar o `top` que ele mesmo abre no final.
- `/home/cerise/show_malware_demo.sh`: abre um `gnome-terminal` rodando o script acima.
- `/home/cerise/Desktop/demo.desktop`: ícone "Sistema" que roda o script anterior (double-click abre o terminal com o `top` mostrando os processos `malware`).
- **Protetor de tela e bloqueio automático desativados** (`gsettings set org.gnome.desktop.session idle-delay 0`, `org.gnome.desktop.screensaver lock-enabled false` e `idle-activation-enabled false`) — o default do Ubuntu 18.04 travava a tela em poucos segundos de inatividade, o que parecia (e não era) um bug de teclado/mouse no noVNC.

**O que essa VM AINDA NÃO tem** (fica valendo o checklist original, resumido):
- Os 9 scripts `.bt` de `modules/07_security/*.bt` não foram copiados pra dentro do guest. **Atenção ao mesmo mismatch de nome já documentado**: `guest_monitor.c` espera `docker_socket_acess.bt` e `sensitive_file_acess.bt` (sem o "c" de "access", erro de digitação no C), enquanto os arquivos do repo usam a grafia correta — renomear ao copiar, ou corrigir o C.
- `supervisor.py` não está instalado (precisa `python3-scapy`, `python3-psutil`).
- `guest_monitor.c`/`supervisor_monitor.c` não foram compilados dentro do guest (compilar lá, não copiar binário do host — glibc mais nova no host quebra no guest).
- `bpftrace` não está instalado (checar PPA `iovisor/bpftrace` ou compilar da fonte).
- Nada inicia sozinho no boot ainda (sem unit systemd para `guest_monitor`/`supervisor_monitor`).
- SSH não está habilitado/configurado no guest (testado: `hostfwd tcp::2222-:22` conecta via TCP mas não há sshd respondendo — sem banner SSH).

**QEMU (host), estado atual de `vm_controller.c`:**
- Resolução do vídeo trocada de `-vga virtio` (default 1280x800) para `-vga none -device virtio-vga,xres=1024,yres=768` — **4:3 fixo**, pra bater exatamente com o painel "VM Screen" do dashboard (que usa `aspect-ratio:4/3` em CSS). Sem isso, o framebuffer ficava com proporção diferente do painel.
- Modo CLI não-interativo (`vm_controller start|stop|status`) com **códigos de retorno reais**: as três funções (`start_qemu_vm`, `stop_qemu_vm`, `check_qemu_status`) agora são `int` e retornam sucesso/falha de verdade (antes retornavam sempre 0 mesmo em falha, causando falso-positivo de "VM rodando" no dashboard quando o QEMU falhava por imagem de disco ausente).

---

## 10. VM Screen — noVNC embutido no dashboard

O painel "VM Screen" (aba do `dashboard.html`) embute o framebuffer real da VM via **noVNC** (vendorizado em `virtual_machine/novnc/`, não versionado no git — `.gitignore`; precisa `git clone https://github.com/novnc/noVNC.git virtual_machine/novnc` em cada máquina nova) + **`websockify`** (ponte WebSocket↔TCP para a porta VNC do QEMU, `127.0.0.1:5900`). `pipeline_web.py` spawna o `websockify` sozinho (`spawn_websockify()`) na porta `6080`, e serve os arquivos estáticos do noVNC via rota própria (`/novnc/*`, `serve_novnc_file()`) — **importante**: o `rfb.js` é importado same-origin (`/novnc/core/rfb.js`), não direto da porta do `websockify`, porque `import()` de módulo ES é sujeito a CORS e o `websockify` não manda esse header.

**Bug real encontrado e corrigido**: o container `#vnc-screen` usava `min-height`, mas o noVNC cria uma div interna com `height:100%` — `min-height` não conta como altura definida pra herança percentual em CSS, então a div interna colapsava pra 0 e o canvas nunca tinha tamanho (tela preta permanente, mesmo com WebSocket "connected"). Hoje o container usa `aspect-ratio:4/3` (altura sempre definida, deriva da largura), casando com a resolução 4:3 do QEMU (seção 9).

**Botões Start/Stop VM** no mesmo painel chamam `/api/vm/start` e `/api/vm/stop` (endpoints em `pipeline_web.py`, threads próprias `vm_start_worker`/`vm_stop_worker` que chamam o `vm_controller` real e depois `start_listeners()`/`stop_listeners()`). Estado real (`vm_running`, `vm_busy`, `vm_last_error`) é mostrado no próprio painel, incluindo uma caixa de erro quando o `vm_controller` falha (ex.: disco ausente).

**Gráficos de CPU/Memória da VM** (`VM CPU Usage`/`VM Memory Usage`, abaixo do painel): thread `vm_metrics_thread()` em `pipeline_web.py` lê `/proc/<pid do QEMU>/stat` e `/proc/<pid>/status` a cada 2s (via o PID salvo em `qemu_vm.pid` pelo `vm_controller`), calcula `%CPU` (pode passar de 100%, a VM tem 6 vCPUs) e RSS em MB, guarda os últimos ~3min (`state.vm_metrics`, `collections.deque`). Endpoint `GET /api/vm/metrics`. **Só aparecem no modo real** — ocultos e sem polling no modo demo (ver seção 12).

**Segurança (não resolvido, decisão pendente com o usuário):** `websockify` sobe sem bind explícito de host, ou seja, escuta em `0.0.0.0:6080` — como o dashboard inteiro já roda com `WEB_HOST=0.0.0.0`, qualquer um na rede local que ache a porta consegue controlar mouse/teclado da VM sem autenticação. Não foi restringido ainda porque não se sabe se o acesso de outro dispositivo na LAN é intencional (ex.: apresentação).

---

## 11. Terminal do host no dashboard (ttyd)

O card "Project Files" (navegador de arquivos do projeto, `/api/files`+`/api/file`) foi **removido** do `dashboard.html` e substituído por um terminal interativo de verdade do **host** (a máquina rodando `pipeline_web.py`, não a VM) — pedido explícito do usuário. Implementado com `ttyd` (`sudo apt install ttyd`), spawnado por `pipeline_web.py` (`spawn_ttyd()`) como o usuário do processo (não root), bash, escrita habilitada (`-W`), **bind explícito em `127.0.0.1:7682`** (diferente do `websockify`/VNC — aqui foi feito bind seguro de propósito, dado que expõe um shell completo do host). Embutido via `<iframe src="http://127.0.0.1:7682/">` — como usa `127.0.0.1` fixo (não `location.hostname`), só funciona para quem acessa o dashboard a partir da própria máquina; alguém acessando de outro dispositivo na LAN não alcança esse terminal.

Os endpoints `/api/files` e `/api/file` continuam existindo no backend (não foram removidos), só não são mais usados pelo frontend.

**Efeito colateral do `apt install ttyd` a saber:** o pacote do Ubuntu ativa e sobe sozinho um **serviço systemd `ttyd.service` rodando como root**, na porta `7681` (bind em `lo`, exige login real via PAM — não é um shell root aberto sem senha, mas é um serviço persistente não pedido, sobrevive a reboot). Independente da nossa instância (porta 7682, usuário normal). Pra desativar: `sudo systemctl disable --now ttyd`.

---

## 12. Modo demo (`MALTRACE_DEMO=1`)

Pensado para exibição em congresso sem depender de malware real rodando. Ativa com `MALTRACE_DEMO=1 python3 pipeline_web.py`. Isolado por uma env var — não altera o comportamento do modo real.

- **Pula** inicialização pesada do RAG (`rag_ready.set()` direto) e chama `seed_demo_batches()`.
- **Semeia 7 batches falsos prontos** (`status: complete`, com `VERDICT`/`SEVERITY`/`ANALYSIS` já escritos) contando uma cadeia de ataque coerente de cryptojacking Linux estilo **TeamTNT**: acesso a arquivo sensível (suspeito) → escalação de privilégio via `setresuid` sem sudo → execução fileless via `memfd` → beacon C2 (`185.220.101.47:4444`) → sondagem do socket do Docker → adulteração de logs. Eventos brutos escritos no formato exato dos `printf` reais dos scripts `.bt` de `modules/07_security/`, não inventados.
- **Dashboard/gráficos** (Events Over Time, Events by Source, portas na sidebar) populados a partir desses mesmos batches — inclusive `eventTimeline` do frontend é semeado a partir de `/api/batches` na primeira carga (isso beneficia o modo real também: antes ficava vazio até chegar o primeiro evento SSE).
- **Chat** vem pré-preenchido (`renderDemoChat()` em `dashboard.html`) com uma conversa fixa analista↔sistema sobre esse mesmo incidente (mesmos PIDs, IP, nomes de arquivo dos batches) — não chama o LLM de verdade nessa parte, é só HTML injetado uma vez (`demoChatRendered`).
- **VM Screen continua REAL** em modo demo (diferença importante de versões anteriores desta feature): conecta no noVNC de verdade, Start/Stop VM funcionam de verdade — só os números/batches/chat são mockados. A ideia é o apresentador rodar o `show_malware_demo.sh` (seção 9) ao vivo na VM enquanto o resto da tela mostra dados prontos.
- **CPU/Memory Usage ficam ocultos** no modo demo (`#vm-metrics-grid` começa com `display:none` no HTML e só é revelado no modo real; `pollVmMetrics()` nem chega a fazer fetch se `isDemoMode`).
- Existe também um terminal falso estático (`renderDemoTerminal()`, um `<pre>` com saída de `top` fixa mostrando um processo `upd8r` consumindo CPU/memória) — **não é mais usado**, guardado no código sem chamada ativa, caso sirva de referência/fallback futuro.
