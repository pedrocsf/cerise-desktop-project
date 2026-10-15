# MITRE.md: Mapeamento MITRE ATT&CK no MalTrace

Registra a integração do MITRE ATT&CK: o que foi implementado, o que os testes mostraram e a decisão que ficou em aberto.

**Status: implementado, testado e OPCIONAL (desligado por padrão).** O usuário liga ou desliga pelo painel ⚙ Configure → "MITRE ATT&CK Mapping"; ligado, o prompt volta a pedir a linha `ATTACK` e o dashboard mostra o bloco, com aviso de que o ID é validado quanto a existência e plataforma, não quanto à relevância para o log. Abaixo, o histórico da pausa original.

**Status anterior: implementado, testado e PAUSADO.** O código e a base oficial ficam no repositório, mas o prompt não pede mais técnicas ao LLM e a seção fica oculta no dashboard. Motivo: com o Llama 3.1 8B a maioria das técnicas aceitas estava errada (seção 5). A continuação depende da decisão da seção 6.

---

## 1. O que é o ATT&CK (resumo)

O ATT&CK é um catálogo público mantido pela MITRE que descreve como atacantes agem depois de entrar num sistema. Tem dois níveis:

- **Táticas:** o *objetivo* do atacante (Persistência, Escalada de privilégio, Comando e controle, Impacto…).
- **Técnicas e sub-técnicas:** o *jeito* de atingir o objetivo. Cada uma tem um código fixo, por exemplo `T1053` Scheduled Task/Job → `T1053.003` Cron.

Para o MalTrace, o ganho seria descrever cada veredito na linguagem padrão da área (útil para os artigos e para comparar com outras ferramentas), medir quais técnicas os `.bt` conseguem ou não enxergar, e ligar eventos de um mesmo ataque por fase.

---

## 2. O que foi implementado

### 2.1 Base oficial offline

- `scripts/build_attack_index.py` baixa o STIX oficial do ATT&CK Enterprise (`mitre-attack/attack-stix-data`, ~54MB) e gera um índice compacto.
- O índice fica em `mitre_attack/enterprise_techniques.json` (~190KB): versão, as 15 táticas, e para cada uma das 858 técnicas o nome, as táticas, as plataformas, o link oficial e, quando for o caso, `revoked_by` (substituto) ou `deprecated`.
- Não usa API nem chave. Para atualizar a versão, basta rodar `python3 scripts/build_attack_index.py` (ou passar o caminho de um STIX já baixado como argumento).

**Versão usada: Enterprise v19.2.** Ela mudou em relação ao ATT&CK que os LLMs conhecem do treino: agora são **15 táticas**, e "Defense Evasion" foi dividida em **Stealth** e **Defense Impairment**. Várias técnicas conhecidas foram revogadas e substituídas. Exemplos reais: `T1562.001` Disable or Modify Tools → `T1685`, e `T1070.002` Clear Linux or Mac System Logs → `T1685.006`. Isso por si só já justifica validar os IDs: o modelo cita IDs de versões antigas.

### 2.2 Validação dos IDs (`attack_mapping.py`)

- `extract_attack_ids(text)`: lê só a linha `ATTACK:` da resposta (aceita `ATT&CK:`, negrito em markdown, minúsculas) e extrai os IDs no formato `T####` ou `T####.###`, sem repetição.
- `validate_attack_ids(ids)` aplica, na ordem:
  1. **Existe?** Se não existir na v19.2, é descartado ("unknown ID").
  2. **Revogado?** É trocado pelo substituto oficial, seguindo a cadeia até 5 saltos. O dashboard mostra "LLM cited revoked X". Se não houver substituto, é descartado.
  3. **Obsoleto (deprecated)?** É descartado.
  4. **Se aplica a Linux?** A plataforma precisa incluir `Linux` ou `Containers`. Técnica só de Windows é descartada ("not applicable to Linux").
  5. Repetições depois da troca de revogados são removidas.
- `map_attack(analysis_text)` retorna `{version, techniques: [{id, name, tactics, url, replaces}], rejected: [{id, reason}]}`. Se o índice não existir, retorna `None` sem quebrar a análise.

### 2.3 Prompt (hoje desligado, ver seção 7)

A versão testada acrescentava ao `PROMPT_TEMPLATE` uma instrução e uma linha no formato de saída:

```
ATTACK must list the MITRE ATT&CK Enterprise technique IDs (format T#### for a technique or T####.### for a sub-technique) for behavior the raw input logs directly show on this Linux host, separated by commas. Prefer the most specific sub-technique when the log supports it. Do not list a technique that only the retrieved context or the External Search Results suggest without a matching event in the raw log. Write NONE when VERDICT is SAFE or when no technique is directly evidenced.

Format that you need to follow:
VERDICT: <SAFE/SUSPICIOUS/THREAT>
SEVERITY: <1-5>
ATTACK: <comma-separated technique IDs, or NONE>
ANALYSIS: <Short explanation>
```

### 2.4 Servidor e dashboard

- `pipeline_web.py`: no fim de cada análise, `batch["attack"] = map_attack(text)`. O resultado vai junto no evento SSE `analysis_done`, e os batches do demo também passam por `map_attack`.
- `dashboard.html`: `renderAttackBlock(b)` desenha um bloco "MITRE ATT&CK (Enterprise v19.2, IDs validated)" abaixo da resposta. Cada técnica aparece com link oficial, nome e táticas, seguida da lista "Discarded" com o motivo de cada descarte. O bloco é controlado pela constante `ATTACK_SECTION_VISIBLE`.

---

## 3. Teste da validação isolada

Entrada: `T1053.003, t1496, T1562.001, T1070.002, T9999, T1547.001, T1053.003, T1685`

| ID citado | Resultado |
|---|---|
| T1053.003 | aceito: Cron (Execution, Persistence, Privilege Escalation) |
| T1496 | aceito: Resource Hijacking (Impact) |
| T1562.001 | trocado por **T1685** Disable or Modify Tools (Defense Impairment) |
| T1070.002 | trocado por **T1685.006** Clear Linux or Mac System Logs |
| T9999 | descartado: não existe na v19.2 |
| T1547.001 | descartado: só Windows (Registry Run Keys) |
| T1053.003 repetido, T1685 repetido | removidos |

---

## 4. Batches do demo (respostas escritas à mão)

Na fase de teste, os 7 batches do demo ganharam uma linha `ATTACK` coerente com a narrativa (T1003.008, T1068, T1620, T1571 + T1071, T1611, T1070.002 + T1070.003). Tudo passou na validação, e a `T1070.002` foi trocada por `T1685.006`. Essas linhas foram retiradas na pausa (seção 7).

---

## 5. Teste de ponta a ponta com Llama 3.1 8B (demo, 7 batches)

### 5.1 Primeira rodada: modelo copiando o exemplo

A instrução original trazia um exemplo concreto ("e.g. T1053.003"). O Llama devolveu **T1053.003 (Cron) em 5 de 7 batches**, inclusive em batches sem cron. O modelo pequeno copiou o exemplo. A correção foi descrever só o formato (`T####` / `T####.###`), sem ID concreto.

### 5.2 Segunda rodada (sem o exemplo, 2 execuções com resultado idêntico)

| Batch | O que acontece | Aceito pela validação | Descartado | Técnica correta |
|---|---|---|---|---|
| 1 | apt → Canonical (benigno) | nenhuma (NONE) | nenhuma | nenhuma ✔ |
| 2 | vim lê `/etc/shadow` | T1087 Account Discovery | T1059.001 (Windows) | T1003.008 |
| 3 | setresuid para root | T1212 | T1055.003 (Windows) | T1068 |
| 4 | execução via memfd | nenhuma | T1059.001 (Windows), T1064 (obsoleta) | T1620 |
| 5 | beacon C2 na porta 4444 | T1210 Exploitation of Remote Services | T1190.001 (não existe) | T1571 / T1071 |
| 6 | curl no socket do Docker | T1055 Process Injection | T1210.001 (não existe) | T1611 |
| 7 | log e histórico apagados | T1087 | T1059.001 (Windows) | T1070.003 / T1685.006 |

### 5.3 Leitura

- **A validação funciona.** Ela pegou IDs inexistentes, só de Windows, obsoletos e revogados, que são muitos com um modelo de 8B.
- **Mas validar o ID não garante que a técnica corresponde ao evento.** Todos os IDs aceitos existem e se aplicam a Linux, mas quase nenhum corresponde ao que o log mostra. Só o batch benigno acertou (NONE). O Llama 3.1 8B não conhece o ATT&CK bem o bastante para escolher de memória entre ~850 técnicas.
- Observação não isolada: o batch 2 saiu THREAT, enquanto o seed do demo é SUSPICIOUS. Não havia linha de base desse batch com o prompt anterior, então não dá para dizer se a linha `ATTACK` influenciou o veredito.

---

## 6. Decisão em aberto: escolha restrita

**Proposta:** trocar a pergunta aberta ("quais das ~850 técnicas o log mostra?") por múltipla escolha ("destas poucas candidatas, quais o log confirma?").

**Como funcionaria:**
1. Cada categoria do RAG (log_tampering, privilege_escalation, fileless_execution, docker_socket_access, network_suspicious, sensitive_file_access…) ganha uma lista curta de técnicas Linux adequadas. A lista é montada à mão e validada contra o índice da v19.2.
2. Para cada batch, o prompt oferece só as candidatas das categorias recuperadas (juntando as de todas as categorias que o RAG trouxe, normalmente 1 a 3), com ID e nome.
3. O LLM escolhe as que o log confirma, ou NONE.
4. A validação passa a rejeitar qualquer ID fora das candidatas oferecidas, além das checagens da seção 2.2.

Exemplo ilustrativo (IDs a confirmar contra o índice antes de implementar):

| Categoria do RAG | Candidatas |
|---|---|
| log_tampering | T1070.003 Clear Command History, T1685.006 Clear Linux System Logs, T1070.004 File Deletion |
| privilege_escalation | T1068 Exploitation for Privilege Escalation, T1548.001 Setuid/Setgid, T1548.003 Sudo |
| docker_socket_access | T1611 Escape to Host, T1610 Deploy Container |
| network_suspicious | T1571 Non-Standard Port, T1071 Application Layer Protocol, T1095 Non-Application Layer Protocol |

No batch 7 (log apagado), o prompt ofereceria T1070.003, T1685.006 e T1070.004. O modelo só precisaria reconhecer, na lista, o que o log mostra. Uma resposta como T1087 (a de hoje) seria rejeitada por estar fora das candidatas.

**Ganhos:**
- O modelo não precisa saber o ATT&CK de cor.
- Acaba o caso "ID válido, mas sem relação com o evento".
- O mapeamento vira um artefato revisável e defensável num artigo ("estas técnicas por categoria, por estes motivos").

**Custos e riscos:**
- **Cobertura:** técnicas fora das candidatas nunca aparecem.
- **Dependência do RAG:** se a categoria recuperada estiver errada, as candidatas também estarão, e o modelo precisa responder NONE em vez de forçar uma escolha.
- **Manutenção:** a lista por categoria precisa ser revisada quando a versão do ATT&CK mudar (a v19 já revogou técnicas comuns).

**Alternativas consideradas:**
- **Mapeamento 100% determinístico** (categoria/flags dos `.bt` → técnica, sem LLM): mais previsível, porém mais grosseiro. Não distingue, dentro da mesma categoria, qual técnica o log de fato mostra.
- **Manter o modo livre com um modelo maior** (Claude/GPT pelo painel): provavelmente acerta mais, mas não foi testado. A escolha restrita também funcionaria com esses modelos.

Esse é o mesmo princípio da avaliação fixa do External Search (`CONTEXTO.md`, seção 17): o conhecimento que um modelo pequeno não tem fica no código, e o modelo faz só a parte que consegue fazer bem.

---

## 7. Estado atual (pausado) e como reativar

**O que está ativo:**
- `attack_mapping.py`, `mitre_attack/enterprise_techniques.json` e `scripts/build_attack_index.py` continuam no repositório.
- `pipeline_web.py` continua chamando `map_attack` no fim da análise e nos seeds do demo. Sem linha `ATTACK` na resposta, o resultado é uma lista vazia, sem efeito.

**O que foi desligado:**
- A instrução `ATTACK must list...` e a linha `ATTACK:` foram removidas do formato no `PROMPT_TEMPLATE` (`log_watcher.py`). A análise volta ao formato VERDICT/SEVERITY/ANALYSIS de antes.
- As linhas `ATTACK:` dos 7 batches do demo foram retiradas.
- `ATTACK_SECTION_VISIBLE = false` em `dashboard.html` oculta o bloco.

**Para reativar (modo livre, como testado):**
1. Recolocar no `PROMPT_TEMPLATE` o trecho da seção 2.3.
2. Trocar `ATTACK_SECTION_VISIBLE` para `true`.
3. Opcional: recolocar as linhas `ATTACK` nos seeds do demo (seção 4).

Se a decisão for a escolha restrita (seção 6), o passo 1 muda: a instrução passa a listar as candidatas por batch, e a validação ganha a checagem "está entre as candidatas".

**Commit:** a integração do ATT&CK ainda **não foi commitada**. O commit da integração AbuseIPDB/VirusTotal foi montado sem ela. `attack_mapping.py`, `mitre_attack/`, `scripts/build_attack_index.py`, este arquivo e os trechos do ATT&CK em `pipeline_web.py` e `dashboard.html` ficaram fora do stage.
