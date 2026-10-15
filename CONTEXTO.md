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
   - **External Search** (opcional, `search_enrichment.py`): se o modo for Automatic, ou se o analista clicou "External Search" no batch (modo Manual), IPs públicos e domínios do batch são consultados no AbuseIPDB/VirusTotal e o resultado entra num bloco próprio do prompt. Detalhes na seção 17.
   - **Prompt final** (`PROMPT_TEMPLATE`): injeta o(s) bloco(s) RAG retornado(s) como contexto, a árvore de processos, o bloco do External Search e os eventos brutos do batch, e instrui o LLM a:
     - correlacionar eventos `[ebpf]` com `[network]` do mesmo processo como uma cadeia causal única;
     - tratar cada categoria RAG como **hipótese**, não fato — cruzar com o log bruto antes de confiar;
     - devolver `VERDICT` (`SAFE`/`SUSPICIOUS`/`THREAT`), `SEVERITY` (1-5, ancorada no `Base Criticality Level` do doc RAG mais relevante) e `ANALYSIS` com evidência concreta (pid, path, ip:porta etc.).
   - **Checagem de consistência factual** (`check_factual_consistency`, em `pipeline_web.py`): depois da resposta, extrai as afirmações concretas do LLM (IPs, caminhos, hashes, PIDs, UIDs, portas) e confere se aparecem no log bruto, ou nos resultados do External Search quando houve consulta. O que não aparece recebe o aviso "⚠ Não confirmado no log bruto: ...". A regex de caminho ignora frações e datas (`14/89`, `2026/09/23`) e não inclui o ponto final da frase no caminho. Antes disso, "14/89 engines" do VirusTotal virava um falso "PATH /89".
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
- `search_enrichment.py` — External Search: extração de IP/domínio, provedores AbuseIPDB/VirusTotal, avaliação fixa, cache e lista benigna (seção 17).
- `attack_mapping.py` + `mitre_attack/enterprise_techniques.json` + `scripts/build_attack_index.py` — mapeamento MITRE ATT&CK com validação de IDs, **pausado** (seção 18).
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

O dataset usado nessa adaptação é especificamente o **LID-DS 2019** (Leipzig Intrusion Detection Data Set), syscall traces Linux com thread info e buffers de dados, gerado a partir de ataques reais baseados em CVEs/CWEs. Repositório: https://github.com/LID-DS/LID-DS (link de download do pacote 2019 no próprio README, ~13GB). Ver `NOVOS_DATASETS.md` para outros datasets levantados como candidatos a expandir ainda mais a cobertura.

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
- Resolução do vídeo trocada de `-vga virtio` (default 1280x800) para `-vga none -device virtio-vga,xres=1280,yres=720` — **16:9 fixo** (era 4:3/1024x768 numa versão anterior; trocado porque o 4:3 ficava pequeno demais na tela), pra bater exatamente com o painel "VM Screen" do dashboard (`aspect-ratio:16/9` em CSS). Sem essa correspondência, o framebuffer fica com proporção diferente do painel.
- Modo CLI não-interativo (`vm_controller start|stop|status`) com **códigos de retorno reais**: as três funções (`start_qemu_vm`, `stop_qemu_vm`, `check_qemu_status`) agora são `int` e retornam sucesso/falha de verdade (antes retornavam sempre 0 mesmo em falha, causando falso-positivo de "VM rodando" no dashboard quando o QEMU falhava por imagem de disco ausente).
- **RAM e vCPUs configuráveis em runtime**: `QEMU_COMMAND` virou `QEMU_COMMAND_FMT` (com `%d` para `-m` e `-smp`), montado dinamicamente em `start_qemu_vm()` lendo as variáveis de ambiente `CERISE_RAM_MB` (padrão 8192, faixa válida 512–32768) e `CERISE_CPUS` (padrão 6, faixa válida 1–16) via `getenv()`. `pipeline_web.py` (`run_vm_controller`) sempre passa essas duas env vars, lendo de `state.vm_config` — configurável pelo painel "Quick VM Settings" do dashboard (seção 15). Só entra em vigor no próximo `start`, não afeta uma VM já rodando.
- **Pasta compartilhada host↔guest** via `-virtfs local,path=<repo>/virtual_machine/vm_shared,mount_tag=cerise_share,security_model=mapped-xattr,id=cerise_share` (sempre presente na linha de comando) — usada pela feature de envio de arquivo (seção 14). `start_qemu_vm()` garante a pasta com `mkdir(VM_SHARED_DIR, 0755)` antes de montar o comando.

---

## 10. VM Screen — noVNC embutido no dashboard

O painel "VM Screen" (aba do `dashboard.html`) embute o framebuffer real da VM via **noVNC** (vendorizado em `virtual_machine/novnc/`, não versionado no git — `.gitignore`; precisa `git clone https://github.com/novnc/noVNC.git virtual_machine/novnc` em cada máquina nova) + **`websockify`** (ponte WebSocket↔TCP para a porta VNC do QEMU, `127.0.0.1:5900`). `pipeline_web.py` spawna o `websockify` sozinho (`spawn_websockify()`) na porta `6080`, e serve os arquivos estáticos do noVNC via rota própria (`/novnc/*`, `serve_novnc_file()`) — **importante**: o `rfb.js` é importado same-origin (`/novnc/core/rfb.js`), não direto da porta do `websockify`, porque `import()` de módulo ES é sujeito a CORS e o `websockify` não manda esse header.

**Bug real encontrado e corrigido (#1)**: o container `#vnc-screen` usava `min-height`, mas o noVNC cria uma div interna com `height:100%` — `min-height` não conta como altura definida pra herança percentual em CSS, então a div interna colapsava pra 0 e o canvas nunca tinha tamanho (tela preta permanente, mesmo com WebSocket "connected"). Hoje o container usa `aspect-ratio:16/9` (altura sempre definida, deriva da largura), casando com a resolução 16:9 do QEMU (seção 9).

**Bug real encontrado e corrigido (#2)**: `vncRfb.resizeSession = true` fazia o noVNC pedir pro guest (GNOME) redimensionar a própria resolução virtual pra bater com o tamanho em pixels do container toda vez que ele mudava — o resultado era a área de trabalho do guest ficando maior/menor que a parte realmente visível, então ao abrir uma janela dentro da VM ela podia abrir fora do pedaço visível da tela (sintoma reportado como "mando abrir algo, ele abre, mas só vejo um pedaço da área de trabalho"). Como a resolução real da VM já é fixa via `virtio-vga` (seção 9), a correção foi setar `resizeSession = false` e deixar só o `scaleViewport = true` cuidar de escalar a imagem inteira pra caber no container, sem nunca pedir resize ao guest.

**Botão de tela cheia**: ao lado do "Stop VM", chama `toggleVmFullscreen()` (`dashboard.html`), que aplica a Fullscreen API do navegador (`requestFullscreen`/`exitFullscreen`) só no container `#vnc-screen`. CSS `#vnc-screen:fullscreen` remove o `max-width`/`aspect-ratio` fixos e expande para `100vw`/`100vh`.

**Botões Start/Stop VM** no mesmo painel chamam `/api/vm/start` e `/api/vm/stop` (endpoints em `pipeline_web.py`, threads próprias `vm_start_worker`/`vm_stop_worker` que chamam o `vm_controller` real e depois `start_listeners()`/`stop_listeners()`). Estado real (`vm_running`, `vm_busy`, `vm_last_error`) é mostrado no próprio painel, incluindo uma caixa de erro quando o `vm_controller` falha (ex.: disco ausente). **Funcionam também em modo demo** (ver seção 12 — o bloqueio que existia foi removido a pedido do usuário).

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

**Comandos pra subir o modo demo localmente** (usa o `venv` do repo, que tem `sentence_transformers`/`chromadb`/etc. instalados — sem ele o `import` de `log_watcher.py` falha com `ModuleNotFoundError`, mesmo em modo demo, porque o import acontece antes do `if DEMO_MODE` em `pipeline_web.py`):

```bash
cd /home/pedro/Github/cerise-desktop-project/virtual_machine
MALTRACE_DEMO=1 ../venv/bin/python3 pipeline_web.py
```

Dashboard sobe em `http://localhost:8080`. Pra rodar em background sem travar o terminal: `MALTRACE_DEMO=1 nohup ../venv/bin/python3 pipeline_web.py > /tmp/pipeline_web_demo.log 2>&1 & disown`.

**Pra derrubar o demo** (inclui os filhos `websockify`, na porta 6080, e `ttyd`, na 7682, que ficam órfãos se só o pai morrer):

```bash
pkill -f "[p]ipeline_web.py"; pkill -f "[w]ebsockify"; pkill -f "[t]tyd.*7682"
```

Os colchetes (`[p]ipeline_web`) são necessários quando o comando roda dentro de um shell cuja linha de comando contém o próprio padrão, como acontece nos shells do Claude Code. Sem eles, o `pkill -f` também casa com esse shell e o mata junto (exit code 144, e às vezes o servidor recém-iniciado morre em silêncio). **Não** usar `pkill -f ttyd` sem filtro: existe um `ttyd.service` do sistema na porta 7681 (seção 11).

**LLM no demo:** o padrão do `state.llm_config` é Ollama com o modelo `llama2`, que não está instalado nesta máquina. Com ele, toda análise nova dá `Ollama error: HTTP Error 404`. Os modelos locais disponíveis são `llama3.1:latest` e `llama3.1:8b-instruct-q4_K_M`: escolha um no painel ⚙ Configure antes de reanalisar batches. A configuração de LLM e a do External Search ficam só em memória e se perdem a cada reinício do servidor.

- **Pula** inicialização pesada do RAG (`rag_ready.set()` direto) e chama `seed_demo_batches()`.
- **Semeia 7 batches falsos prontos** (`status: complete`, com `VERDICT`/`SEVERITY`/`ANALYSIS` já escritos) contando uma cadeia de ataque coerente de cryptojacking Linux estilo **TeamTNT**: acesso a arquivo sensível (suspeito) → escalação de privilégio via `setresuid` sem sudo → execução fileless via `memfd` → beacon C2 (`185.220.101.47:4444`) → sondagem do socket do Docker → adulteração de logs. Eventos brutos escritos no formato exato dos `printf` reais dos scripts `.bt` de `modules/07_security/`, não inventados.
- **Dashboard/gráficos** (Events Over Time, Events by Source, portas na sidebar) populados a partir desses mesmos batches — inclusive `eventTimeline` do frontend é semeado a partir de `/api/batches` na primeira carga (isso beneficia o modo real também: antes ficava vazio até chegar o primeiro evento SSE).
- **Chat** vem pré-preenchido (`renderDemoChat()` em `dashboard.html`) com uma conversa fixa analista↔sistema sobre esse mesmo incidente (mesmos PIDs, IP, nomes de arquivo dos batches) — não chama o LLM de verdade nessa parte, é só HTML injetado uma vez (`demoChatRendered`).
- **VM Screen continua REAL** em modo demo (diferença importante de versões anteriores desta feature): conecta no noVNC de verdade, Start/Stop VM funcionam de verdade — só os números/batches/chat são mockados. A ideia é o apresentador rodar o `show_malware_demo.sh` (seção 9) ao vivo na VM enquanto o resto da tela mostra dados prontos.
- **CPU/Memory Usage ficam ocultos** no modo demo (`#vm-metrics-grid` começa com `display:none` no HTML e só é revelado no modo real; `pollVmMetrics()` nem chega a fazer fetch se `isDemoMode`).
- Existe também um terminal falso estático (`renderDemoTerminal()`, um `<pre>` com saída de `top` fixa mostrando um processo `upd8r` consumindo CPU/memória) — **não é mais usado**, guardado no código sem chamada ativa, caso sirva de referência/fallback futuro.
- **Branding do LLM forjado no modo demo**: o label do chat (`#chat-agent-label`) e o indicador do topo direito (`#ollama-status`) mostram fixo **"Opus 5"** e **"Claude"**, respectivamente, em vez do provider/model reais (`updateStatus()`/`updateAgentLabel()` em `dashboard.html`, checando `isDemoMode`) — só cosmético para apresentação, não muda o LLM de fato configurado/usado.
- **Start/Stop VM não são mais bloqueados em modo demo**: os endpoints `/api/vm/start`/`/api/vm/stop` tinham um retorno 403 fixo (`"VM control disabled in demo mode"`) quando `DEMO_MODE` estava ativo; removido a pedido do usuário, já que a VM Screen já era real em modo demo mesmo assim.
- Explicação detalhada do comportamento/narrativa simulada nos 7 batches (por que cada `VERDICT`/`SEVERITY` foi escolhido, o que cada um representa na cadeia de ataque) está em **`DEMO_BATCHES.md`** (raiz do repo).

---

## 13. Redesign visual do dashboard

`dashboard.html` passou por um redesign completo de aparência a pedido do usuário ("está com cara de IA genérica" → estilo "site/landing page", não "esquema de blocos"). Pontos que mudam a leitura do código:

- **Fundo em gradiente real**: `body` usa 4 `radial-gradient` (tons de vermelho/carmesim/vinho, opacidade baixa ~0.5 e raio de alcance curto pra não dominar a tela) sobre uma base `linear-gradient` quase preta, `background-attachment:fixed`. Ajustado por feedback iterativo (gradiente inicial ficou "muito vermelho" → aumentada a presença do preto).
- **Sem chrome de "card"**: `.card`, `.batch-detail-header`, `.response-box`, `.events-box` perderam fundo/borda/sombra sólidos — conteúdo flutua direto sobre o gradiente. Títulos de seção (`.card h3`, ex. "EVENTS OVER TIME") viraram rótulos pequenos, maiúsculos, com um divisor fino embaixo, no lugar de título de caixa. `.event-line` não usa mais listras zebra (`:nth-child(even)`) — todas as linhas têm o mesmo fundo escuro.
- **Topbar/sidebar/chat-panel** viraram vidro bem transparente (`rgba(5,3,3,~0.18–0.25)` + `backdrop-filter:blur(20px)`), deixando o gradiente vazar por trás.
- **Abas movidas para a topbar**: "Dashboard"/"Batch Detail"/"VM Screen" (`.tabs`) saíram de dentro do `.content` e foram para dentro do `.topbar`, entre o título "MalTrace" (esquerda) e as stats (direita) — `.topbar` virou `display:grid` com `grid-template-columns: 1fr auto 1fr` pra centralizar de verdade a célula do meio. Aba ativa: texto branco (`var(--text)`) e `font-weight:700`, sublinhado vermelho (`border-bottom-color:var(--accent)`) — antes era o texto inteiro em vermelho.
- **Fontes Apple SF** (`SF Pro Text`/`SF Pro Display`/`SF Mono`, instaladas localmente em `~/.local/share/fonts/`) via `--font-sans`/`--font-display`/`--font-mono`. Dois bugs de fonte real corrigidos:
  - `<button>`, `<input>`, `<select>`, `<textarea>` não herdam `font-family` do body por padrão (comportamento do UA stylesheet do navegador) — a maioria desses elementos ficava com a fonte padrão do sistema em vez de SF. Corrigido com uma regra global `button, input, select, textarea { font-family: inherit }`.
  - `.chat-msg.bot` (bolha de resposta do chat) tinha `font-family: var(--font-mono)` e `font-size: 12px` hardcoded, diferente da bolha do usuário (`.chat-msg.user`, sem override, herdava `--font-sans`) — removido para as duas bolhas usarem a mesma fonte/tamanho.
- **Ícone novo**: `maltrace-icon.svg` (aranha minimalista — elipses + 8 linhas retas, tudo em `var(--accent)`, sem gradiente/textura), usado como favicon e como ícone do título, substituindo o `maltrace-icon.png` anterior. O servidor precisou de uma rota nova pra `.svg` (`serve_static_png()` generalizado, `Content-Type: image/svg+xml`).
- **Ponto de severidade nos batches**: cada card na lista lateral de batches (`renderBatchList()`) mostra um `<span class="sev-dot">` colorido (verde = severidade 1, amarelo = 2–3, vermelho = 4–5), extraído via regex (`/SEVERITY:\s*([1-5])/i`) do texto de `response` do próprio batch — funciona igual em modo real e demo, já que os dois usam o mesmo formato `VERDICT/SEVERITY/ANALYSIS`. **Dois bugs reais corrigidos** pra isso funcionar: (1) o evento SSE `analysis_done` não incluía o campo `response`, só `status`/`duration`/`tokens`, então um batch recém-analisado nunca tinha severidade até dar refresh; (2) o endpoint `/api/batches` (usado na carga inicial da página) também não devolvia `response` — corrigidos incluindo o campo nos dois lugares.
- **VM Screen em 16:9** (era 4:3) — ver seção 9/10 para o motivo e o bug de `resizeSession` corrigido junto.

---

## 14. Envio de arquivo do host para dentro da VM

Card "Send File to VM" (aba VM Screen, abaixo da tela), pra levar um arquivo do host pra dentro do guest sem precisar de SSH ou QEMU guest-agent — **nenhum dos dois está disponível** nessa VM (SSH testado e sem sshd respondendo, ver seção 9/checklist). Fluxo:

1. **UI** (`dashboard.html`): campo de texto pro caminho absoluto no host + ícone de pasta que abre o seletor nativo do SO (`<input type="file">` oculto). Navegadores não expõem o caminho absoluto de um arquivo escolhido por esse seletor (restrição de segurança) — por isso, quando o usuário digita o caminho, o backend lê o arquivo direto do disco; quando escolhe pelo seletor, o navegador faz upload do **conteúdo** do arquivo (`fetch` com o `File` como body, `Content-Type: application/octet-stream`, nome no header `X-Filename`). Botão "Send" (`#vm-file-send-btn`) começa `disabled`/opacidade baixa e só ativa quando há caminho digitado ou arquivo escolhido (`updateVmSendBtnState()`).
2. **Backend** (`POST /api/vm/send-file`, `pipeline_web.py`): aceita `application/json` (`{"path": "..."}`, lê do disco do host) ou o corpo bruto (bytes do upload + header `X-Filename`). Em ambos os casos, grava o arquivo em `virtual_machine/vm_shared/` (nome sempre passado por `os.path.basename` pra evitar path traversal).
3. **Transporte pro guest**: `vm_shared/` é compartilhada com a VM via **9p** (`-virtfs`, ver seção 9) sob a tag `cerise_share`. Dentro do guest, isso precisa aparecer montado em algum lugar — ver auto-mount abaixo.
4. **Auto-mount automático (one-time, offline)**: como não há guest-agent nem SSH pra rodar o `mount` de dentro da VM sozinho, a solução foi editar o `/etc/fstab` do guest **direto pelo disco `.qcow2`, pelo host**, usando `virt-customize` (pacote `libguestfs-tools`, já instalado). `ensure_guest_automount()` (`pipeline_web.py`) roda isso uma única vez, sempre **antes** de `run_vm_controller("start")` em `vm_start_worker()` (a VM precisa estar parada — `virt-customize` precisa de acesso exclusivo ao disco), adiciona `mkdir -p /mnt/shared` + a linha `cerise_share /mnt/shared 9p trans=virtio,version=9p2000.L,rw,_netdev,nofail 0 0` no fstab, e marca um arquivo local (`virtual_machine/.guest_automount_configured`, não versionado) pra não repetir. Depois disso, toda vez que a VM liga, `/mnt/shared` já sobe montado sozinho — o usuário só precisa clicar "Send", nada pra digitar dentro do guest.
5. **Fallback manual**: se `virt-customize` não estiver instalado ou a configuração falhar por qualquer motivo, a resposta do envio (`auto_mounted: false`) ainda mostra o comando manual de montagem (`sudo mount -t 9p -o trans=virtio,version=9p2000.L cerise_share /mnt/shared`) como instrução na tela.

**Superfície exposta**: o `-virtfs` compartilha **só** a pasta `vm_shared/` do projeto, nunca a home do usuário nem o sistema todo — confirmado inspecionando a linha de comando real do QEMU.

---

## 15. Configurações rápidas da VM (RAM / vCPUs / disco)

Card "Quick VM Settings" (aba VM Screen, abaixo do envio de arquivo). QEMU não permite hot-resize de RAM/vCPU sem complexidade extra (QMP + balloon driver, monitor não configurado em `vm_controller.c`), então o desenho aceito foi "aplica no próximo Start VM":

- **RAM/vCPUs**: dois `<select>` (`#vm-cfg-ram`, `#vm-cfg-cpus`) + botão "Apply on Next Start" → `POST /api/vm/config` (`{"ram_mb", "cpus"}`, validado 512–32768 / 1–16) → grava em `state.vm_config` (em memória, não persiste entre reinícios do `pipeline_web.py`). `run_vm_controller()` sempre lê esse dict e repassa como env vars `CERISE_RAM_MB`/`CERISE_CPUS` pro `vm_controller` (seção 9). `GET /api/vm/config` devolve o config atual + `vm_running` + tamanho do disco, usado pra popular os `<select>` ao carregar a página.
- **Disco**: mostra o tamanho virtual atual (`get_disk_size_gb()`, via `qemu-img info --output=json` lendo `virtual-size`, não o tamanho alocado em disco — qcow2 é esparso) e permite crescer (`POST /api/vm/disk-grow`, `{"add_gb": N}`, 1–500, roda `qemu-img resize <qcow2> +NG`). **Só permitido com a VM parada** (bloqueado com 409 se `state.vm_running`, já que o qcow2 não pode ser resizado com o QEMU tendo o arquivo aberto). Crescer o `.qcow2` só aumenta o disco virtual visto pelo guest — a resposta já avisa que a partição/filesystem *dentro* da VM ainda precisa ser expandida manualmente (`growpart`/`resize2fs` ou equivalente), isso não foi automatizado.

---

## 16. Padrão de mensagens de commit

Observado nos últimos 30 commits do repositório (`git log --pretty=format:'%s'`) — sempre seguir este formato ao sugerir/criar commits:

- **Prefixo obrigatório com dois-pontos**, minúsculo, um dos três: `feat:`, `fix:`, `chore:` (contagem nos últimos 30: 19 `feat`, 6 `chore`, 4 `fix`). Não usar `docs:`, `refactor:`, `test:` etc. — não fazem parte do vocabulário do usuário.
  - `feat:` — nova funcionalidade/capacidade adicionada (ex.: "feat: adding a demo Version", "feat: implements the multiple possibility of LLMs agents").
  - `fix:` — correção de bug (ex.: "fix: fixing Hyde bug", "fix: fixing hearbleed attack detection").
  - `chore:` — manutenção/limpeza/ajuste sem ser feature nem bug (ex.: "chore: cleaning some code", "chore: adjusting some constants").
- **Uma linha só**, sem corpo/descrição estendida, sem período final.
- **Inglês**, minúsculo depois do prefixo (exceto siglas/nomes próprios: `RAG`, `LLM`, `VM`, `Hyde`, `LID DS`, `LLMs`).
- **Verbo no gerúndio é o mais comum** ("fixing", "adding", "adjusting", "improving", "recovering", "cleaning"), mas também aparece infinitivo simples em 3ª pessoa/imperativo curto ("implements", "improves", "integrates", "recalibrate", "switch") — o usuário não é rígido entre os dois, mas gerúndio é a maioria.
- **Sem scope entre parênteses** (nada como `feat(dashboard): ...`) e sem issue/PR number.
- Mensagem descreve **o que foi feito**, direto, sem justificativa (o "porquê" fica pra este documento ou pro corpo do PR, não pro commit).
- Exemplo de commit real que combina múltiplos arquivos não relacionados sob um único tema guarda-chuva: "feat: redesign dashboard UI and add VM screen tools" — ou seja, não é obrigatório 1 commit por arquivo/mudança; agrupar sob a mudança dominante é aceito.

---

## 17. External Search (reputação de IP e domínio)

Resolve uma limitação do LLM: ele não sabe se um IP ou domínio visto no batch já foi denunciado como malicioso no mundo real. Código em `search_enrichment.py` (raiz), integrado em `run_analysis()` de `pipeline_web.py`, configurado no painel ⚙ Configure → seção **"External Search"** do dashboard.

**Modos** (`state.search_config["mode"]`):
- **Disabled** (padrão): nada é consultado, o fluxo é o original.
- **Automatic**: a cada batch, consulta até 3 indicadores (`MAX_AUTO_SEARCH_TERMS`), ignorando infraestrutura benigna conhecida (`_BENIGN_IP_NETWORKS`: DNS públicos do Google, Cloudflare, Quad9 e OpenDNS, e as faixas da Canonical `91.189.88.0/21` e `185.125.188.0/22`; `_BENIGN_DOMAIN_SUFFIXES`: Ubuntu/Canonical, Debian, PyPI, GitHub, Docker, npm, Google, Cloudflare, Microsoft, Mozilla...). A seleção é determinística, sem LLM.
- **Manual**: cada batch concluído ganha o botão **"🔍 External Search"**. O clique coloca o batch de volta na fila (`POST /api/batch/<id>/search`, evento SSE `batch_requeued`), e ele é reanalisado do zero com a consulta. A nova análise **sobrescreve** a anterior. Consulta até 5 indicadores (`MAX_MANUAL_SEARCH_TERMS`), sem aplicar a lista benigna. A fila de análise carrega tuplas `(batch, force_manual_search)` pra serializar isso com os batches ao vivo.

**Indicadores e roteamento:**
- São extraídos só **IPs públicos** (privado, loopback, link-local, reservado e multicast são descartados via `ipaddress`) e **domínios** (com filtro de extensões de arquivo como `.bt` e `.py`, pra nome de arquivo não virar domínio).
- **IP** → AbuseIPDB (`/api/v2/check`, denúncias de abuso nos últimos 180 dias, ISP, tipo de uso) **e** VirusTotal (`/api/v3/ip_addresses/`, detecção por engines, AS owner). As duas respostas aparecem.
- **Domínio** → VirusTotal (`/api/v3/domains/`).
- **Hash foi removido**: nenhum script `.bt` captura hash de binário executado, e sequências de 64 caracteres hex (ex.: IDs de container do Docker) seriam consultadas por engano como SHA256. Se a captura de hash for implementada, o jeito certo é aceitar só hash rotulado no evento (`sha256=...`).
- Provedor sem chave = aquele tipo de indicador aparece como "No provider configured". Sem nenhuma chave, a nota é "No reputation provider configured.".

**Avaliação fixa na frente dos números**: cada resultado começa com uma avaliação calculada no código, e o prompt manda o LLM usá-la, não os números crus. A avaliação é **clean**, **negligible (likely false positive)**, **suspicious**, **malicious** ou **unknown**. Limiares: VirusTotal 0 / 1–2 / 3–9 / ≥10 engines, e 404 = unknown; AbuseIPDB <25% / 25–74% / ≥75% de confiança. São calibração nossa, não números oficiais, e ficam nas constantes `VT_*_MIN` e `ABUSEIPDB_*_MIN`. **Motivo**: sem a avaliação, o Llama 3.1 8B leu "1/89 engines flagged this IP as malicious" no mirror do Ubuntu (`91.189.91.39`, Canonical) e deu THREAT/4 num batch benigno. Com ela, o batch voltou a SAFE/1 e o C2 real (`185.220.101.47`) continuou THREAT/5 (2 execuções cada).

**Cache**: 6h por `(provedor, indicador)` (`CACHE_TTL_SECONDS`), em memória, com lock. Um C2 com beacon aparece em todo batch de 30s, e sem cache as cotas gratuitas (VirusTotal ~4 req/min e 500/dia; AbuseIPDB 1000/dia) acabariam em minutos. Erros (timeout, 429) não entram no cache.

**Histórico de decisões:**
1. A primeira versão usava a **Tavily** (busca web) pra todo indicador. Descartada porque busca web ordena por assunto, não pela string exata: para `91.189.91.39` ela devolvia artigos genéricos e até um IP diferente (`109.173.91.189`). IP e domínio são chaves exatas e precisam de base de reputação.
2. A Tavily ficou um tempo como reserva pra domínio e depois como "contexto de família de malware" (a partir do rótulo de família que o VirusTotal dá a hashes). Foi **removida por completo** porque o VirusTotal só dá família pra arquivo e o pipeline não captura hash, então ela nunca dispararia. Se voltar, o melhor encaixe identificado é o **chat** do dashboard (perguntas de assunto do analista).
3. O modo Automatic usava o LLM pra decidir o que consultar (`SEARCH_DECISION_PROMPT`). Isso foi trocado pela lista benigna determinística: consulta de reputação é barata e exata, e a etapa de LLM custava uma chamada extra por batch.

**Chaves**: ficam em `secrets/` (no `.gitignore`), nos arquivos `abude-ipdb.txt` e `virus_total.txt` (o `tavily.txt` ficou lá sem uso). No dashboard são informadas no painel e nunca voltam em claro (`***`). **Nunca pedir ao usuário pra colar chaves no chat**: ou ele digita no painel, ou o código lê dos arquivos sem imprimir o conteúdo.

**Testado com chaves reais** (demo + Llama 3.1 8B): IP de C2 → `malicious` nos dois provedores; mirror Ubuntu → `clean` / `negligible`; `xmrpool.eu` → `suspicious`. O LLM cita a avaliação na análise. **Não testado**: o modo Automatic de ponta a ponta (o demo não gera batches novos) e o comportamento real do HTTP 429.

---

## 18. MITRE ATT&CK (implementado e **pausado**)

Mapeamento de cada veredito para técnicas do ATT&CK Enterprise, com validação dos IDs. Documentação completa, com testes e a decisão em aberto, em **`MITRE.md`** (raiz). Resumo:

- **Base offline**: `scripts/build_attack_index.py` gera `mitre_attack/enterprise_techniques.json` (~190KB, **v19.2**, 858 técnicas, 15 táticas) a partir do STIX oficial. A v19 dividiu "Defense Evasion" em **Stealth** e **Defense Impairment** e revogou técnicas comuns (ex.: `T1562.001` → `T1685`, `T1070.002` → `T1685.006`), então os LLMs citam IDs desatualizados.
- **Validação** (`attack_mapping.py`, `map_attack`): lê a linha `ATTACK:` da resposta; descarta ID inexistente, obsoleto ou sem plataforma Linux/Containers; troca revogado pelo substituto oficial.
- **Resultado com o Llama 3.1 8B**: a validação funciona (pegou muitos IDs só de Windows, inexistentes e obsoletos), mas os IDs aceitos quase nunca correspondiam ao evento (ex.: T1087 Account Discovery pra log apagado). Um exemplo concreto no prompt ("e.g. T1053.003") fez o modelo copiar o ID em 5 de 7 batches. **Validar o ID não garante que a técnica é a certa.**
- **Opcional pela interface**: `state.attack_config["enabled"]` (padrão `false`), exposto em `GET/POST /api/attack/config` e em ⚙ Configure → "MITRE ATT&CK Mapping" (Off/On). Ligado, `build_prompt_template(True)` (em `log_watcher.py`) acrescenta a instrução `ATTACK` e a linha `ATTACK:` ao formato, e `run_analysis` passa a preencher `batch["attack"]` via `map_attack`. Desligado, o prompt é idêntico ao `PROMPT_TEMPLATE` original e `batch["attack"]` fica `None`, sem bloco no dashboard. Vale só para análises novas. O estado é capturado no início de cada análise, então trocar o toggle no meio não altera uma análise em curso. A plataforma aceita agora inclui `ESXi` (a v19.2 tem técnicas só de ESXi, como T1059.012 Hypervisor CLI). **No modo demo**, cada batch (7 principais + 2 externos) tem duas respostas preparadas, uma sem a linha `ATTACK` (opção Off) e outra com ela (On, com IDs validados, inclusive um revogado trocado em T1070.002 → T1685.006). Ligar ou desligar a opção alterna as respostas no servidor (`apply_demo_attack_variant`, variantes em `DEMO_VARIANTS`) e o dashboard se atualiza sozinho.
- **Estado anterior (pausado)**: a instrução e a linha `ATTACK` foram retiradas do `PROMPT_TEMPLATE`; `ATTACK_SECTION_VISIBLE = false` em `dashboard.html`; os seeds do demo não têm linha `ATTACK`. `pipeline_web.py` continua chamando `map_attack`, mas sem a linha na resposta o resultado é vazio. **Nada disso foi commitado ainda.**
- **Decisão pendente com o usuário**: **escolha restrita**. Cada categoria do RAG ganharia uma lista curta de técnicas Linux candidatas; o prompt ofereceria só as candidatas das categorias recuperadas, e a validação rejeitaria qualquer ID fora delas. Prós, contras e alternativas estão no `MITRE.md`, seção 6.

