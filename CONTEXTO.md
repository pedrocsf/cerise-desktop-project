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
- `dashboard.html` — front-end único servido por `pipeline_web.py` (status, batches, stream SSE, chat, config de LLM, navegador de arquivos do projeto).

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

## 9. VM guest — imagem perdida, reconstrução pendente (manual)

O `malware_vm.qcow2` referenciado em `vm_controller.c` (`/home/pacto/malware_vm.qcow2`) foi perdido. Era um Ubuntu 18.04 genérico, sem nada além dos scripts de telemetria instalados. Reconstrução ficou marcada para ser feita manualmente pelo usuário; checklist do que é preciso:

**ISO oficial** (ainda disponível em `releases.ubuntu.com/18.04/` na época deste registro):
- `ubuntu-18.04.6-desktop-amd64.iso` — instalador gráfico (Ubiquity). Mais fiel ao pedido ("instalação genérica"), mas o Ubiquity não tem um caminho de automação/preseed tão limpo quanto o instalador do Server — considerar se a instalação vai ser manual (via VNC/tela do QEMU) ou automatizada.
- `ubuntu-18.04.6-live-server-amd64.iso` — instalador via autoinstall/cloud-init, 100% automatizável e mais rápido, mas headless por padrão; precisa instalar um ambiente gráfico leve depois (ex.: `xfce4`) para dar suporte ao controle por mouse/teclado via noVNC que já foi implementado no dashboard.

**Usuário do guest:** `cerise` / senha `cerise123`. Precisa de `sudo` (ou rodar como root via systemd), porque `guest_monitor.c` chama `/usr/bin/bpftrace` diretamente, sem `sudo` — ele mesmo precisa estar rodando como root.

**Scripts de telemetria — já existem no repo, só faltam ser copiados para dentro do guest:**
- Os 9 `.bt` estão em `modules/07_security/*.bt` (idênticos em conteúdo ao que `guest_monitor.c` espera). **Atenção a um mismatch de nome**: `guest_monitor.c` referencia `/home/cerise/Downloads/docker_socket_acess.bt` e `/home/cerise/Downloads/sensitive_file_acess.bt` (sem o "c" de "access" — erro de digitação no C original), enquanto os arquivos no repo se chamam `docker_socket_access.bt` e `sensitive_file_access.bt` (grafia correta). Ao copiar para o guest, ou renomear os arquivos para bater com o C, ou corrigir o C — do jeito que está hoje, esses dois canais falhariam silenciosamente por arquivo não encontrado.
- `supervisor.py` (`virtual_machine/supervisor/supervisor.py`) também roda dentro do guest — precisa de `python3-scapy` e `python3-psutil`.
- `guest_monitor.c` e `supervisor_monitor.c` devem ser **compilados dentro do guest** (não copiar o binário já compilado no host: glibc do Ubuntu 18.04 é mais antiga que a do host atual, binário pode não rodar — erro típico "version GLIBC_x.xx not found").
- `bpftrace` não vinha nos repositórios padrão do 18.04 no lançamento; verificar disponibilidade via PPA (`iovisor/bpftrace`) ou compilar da fonte na época da reconstrução.
- As portas virtio-serial aparecem sozinhas como `/dev/vport0pN` assim que a VM sobe (driver `virtio_console` já vem no kernel padrão do Ubuntu) — não precisa de setup adicional no guest para isso.
- `guest_monitor` e `supervisor_monitor` precisam iniciar sozinhos no boot, como root (unit systemd ou `/etc/rc.local`), senão a telemetria só começa a fluir depois de um login manual.

**QEMU (host):** `vm_controller.c` já está atualizado com `-vnc 127.0.0.1:0 -vga virtio` (para o painel "VM Screen" com noVNC) e com modo CLI não-interativo (`vm_controller start|stop|status`, usado pelos botões do dashboard) — nenhuma mudança adicional necessária aqui além de trocar a imagem de disco quando a nova estiver pronta.
