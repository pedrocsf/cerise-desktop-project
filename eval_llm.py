
import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RUBRIC_FILE = os.path.join(BASE_DIR, "rubric.md")
BATCH_DIR = os.path.join(BASE_DIR, "synthetic_batches")
CACHE_DIR = os.path.join(BASE_DIR, ".eval_cache")
REPORT_FILE = os.path.join(BASE_DIR, "eval_rubrica_resultados.md")

JUDGE_MODEL = "claude-sonnet-5"
JUDGE_KEY_FILE = os.path.join(BASE_DIR, "secrets", "claude.txt")
JUDGE_MAX_TOKENS = 8192


BATCH_RUBRIC = {
    1: {  # reverse shell + anti-debug
        "terms": [
            (r"systemd-helper|/tmp/\.systemd", 1.5),
            (r"203\.0\.113\.77", 1.5),
            (r"\b4444\b", 1.5),
            (r"ptrace.{0,40}(request=0|traceme|self)", 1.0),
            (r"ptrace.{0,40}(request=16|attach|1500)", 1.0),
            (r"pty\.spawn|/bin/sh|pty upgrade|interactive shell", 1.5),
            (r"uid=0\(root\)|id.{0,10}root|root identity|confirm(ed|ing)? root", 1.5),
            (r"reverse shell|c2\b|command and control", 1.0),
        ],
        "false_claims": [
            (r"base64", 2.0),
        ],
    },
    2: {  # privilege escalation + credential theft
        "terms": [
            (r"uid[:= ]*1001", 1.0),
            (r"\bsudo\b", 1.0),
            (r"setresuid|ruid=0", 1.0),
            (r"\bsu\b.{0,20}(pid|uid|setuid)|/bin/su", 1.0),
            (r"setuid.{0,15}(1001|0)", 1.0),
            (r"/etc/shadow", 1.0),
            (r"id_rsa", 1.0),
            (r"bash_history", 1.0),
            (r"sudoers", 1.0),
            (r"capset|capabilit", 0.5),
        ],
        "false_claims": [
            (r"exfiltrat", 1.5),
        ],
    },
    3: {  # container escape + rootkit
        "terms": [
            (r"\bunshare\b", 1.0),
            (r"\bsetns\b", 1.0),
            (r"docker\.sock|docker socket", 1.5),
            (r"\bwget\b", 0.5),
            (r"evil_mod\.ko", 1.5),
            (r"bad-c2-domain\.test", 1.0),
            (r"\bchroot\b", 1.0),
            (r"/host_root", 0.5),
            (r"\binsmod\b", 1.0),
            (r"kernel module|rootkit", 1.0),
        ],
        "false_claims": [
            (r"clone_newuser", 1.5),
            (r"clone_newns", 1.5),
        ],
    },
    4: {  # fileless execution + log tampering + DGA
        "terms": [
            (r"memfd_create|fileless", 1.5),
            (r"log[\s_]?tamp", 1.0),
            (r"auth\.log", 1.0),
            (r"syslog", 1.0),
            (r"dga|domain generation|algorithmically.generated", 1.0),
            (r"bad-c2-domain\.test", 1.0),
            (r"ttl.{0,10}5\b|low ttl|short ttl", 0.5),
            (r"process.{0,10}(null|hidden|none|no.{0,10}process)", 0.5),
        ],
        "false_claims": [
            (r"fork.{0,10}(/|or\s)?memory|fork/memory", 1.5),
            (r"interactive backdoor session|pre-existing implant", 1.5),
        ],
    },
    5: {  # disguised cryptominer
        "terms": [
            (r"kworker", 1.0),
            (r"/tmp/\.cache", 1.0),
            (r"bpf.{0,15}(cmd=5|prog_load)", 1.0),
            (r"stratum", 1.0),
            (r"darkpool-mining\.test|mining pool", 1.0),
            (r"\b14444\b", 1.0),
            (r"47xq2k9mf8z|wallet", 1.0),
            (r"xmrig", 1.5),
            (r"root|uid[:= ]*0", 0.5),
        ],
        "false_claims": [],
    },
}


def score_response(batch_id, text):
    rubric = BATCH_RUBRIC[batch_id]
    text_low = text.lower()

    total_weight = sum(w for _, w in rubric["terms"])
    matched_weight = sum(w for pattern, w in rubric["terms"] if re.search(pattern, text_low))
    recall = matched_weight / total_weight if total_weight else 0.0

    penalty = sum(p for pattern, p in rubric["false_claims"] if re.search(pattern, text_low))

    raw = 10 * recall - penalty
    return max(0.0, min(10.0, raw))


def _extract_fenced(secao):
    """Conteúdo entre a PRIMEIRA e a ÚLTIMA cerca ``` da seção.

    As respostas às vezes contêm blocos de código aninhados (payload decodificado, URL).
    Um casamento não-guloso (```\n(.*?)\n```) pararia na primeira cerca interna e
    truncaria a resposta — foi o que aconteceu com as respostas do Claude sem RAG nos
    batches 1 e 3, cortadas a ~38% do texto real.
    """
    linhas = secao.split("\n")
    abre = fecha = None
    for k, linha in enumerate(linhas):
        if linha.rstrip() == "```":
            if abre is None:
                abre = k
            fecha = k
    if abre is None or fecha is None or fecha <= abre:
        return None
    return "\n".join(linhas[abre + 1:fecha])


def parse_results_md(path):
    """Returns {agent_name: {batch_id: response_text}}."""
    content = open(path, encoding="utf-8").read()
    agents = {}

    agent_blocks = re.split(r"\n# (?!#)(.+)\n", content)[1:]
    for i in range(0, len(agent_blocks), 2):
        agent_name = agent_blocks[i].strip()
        agent_text = "\n" + agent_blocks[i + 1]

        batches = {}
        secoes = re.split(r"\n## Batch (\d{4})[^\n]*\n", agent_text)
        for j in range(1, len(secoes) - 1, 2):
            texto = _extract_fenced(secoes[j + 1])
            if texto is not None:
                batches[int(secoes[j])] = texto
        agents[agent_name] = batches

    return agents


_CRITERION_RE = re.compile(r"^- \[([\d.]+)\]\s*`([^`]+)`\s*—\s*(.+)$")


def parse_rubricas(path=RUBRIC_FILE):
    """Lê rubricas_avaliacao.md -> {batch_id: {'titulo', 'positivos': [...], 'negativos': [...]}}.

    Cada critério é {'peso': float, 'id': str, 'desc': str}. Linhas de continuação
    indentadas são anexadas à descrição do critério anterior.
    """
    rubricas = {}
    batch_id = None
    bucket = None
    last = None

    for raw in open(path, encoding="utf-8"):
        line = raw.rstrip("\n")

        m = re.match(r"^## Batch (\d{4})\s*—\s*(.+)$", line)
        if m:
            batch_id = int(m.group(1))
            rubricas[batch_id] = {"titulo": m.group(2).strip(), "positivos": [], "negativos": []}
            bucket = last = None
            continue

        if batch_id is None:
            continue

        if re.match(r"^### Crit[ée]rios positivos", line):
            bucket, last = "positivos", None
            continue
        if re.match(r"^### Crit[ée]rios negativos", line):
            bucket, last = "negativos", None
            continue
        if line.startswith("## ") or line.startswith("# "):
            # saiu do bloco do batch (ex.: seção de documentação no fim do arquivo)
            batch_id = bucket = last = None
            continue

        if bucket is None:
            continue

        m = _CRITERION_RE.match(line)
        if m:
            last = {"peso": float(m.group(1)), "id": m.group(2), "desc": m.group(3).strip()}
            rubricas[batch_id][bucket].append(last)
        elif last is not None and line.startswith("  ") and line.strip():
            last["desc"] += " " + line.strip()

    if not rubricas:
        raise SystemExit(f"[ERRO] Nenhuma rubrica encontrada em {path}.")
    return rubricas


def load_batch_input(batch_id):
    """Mesmo recorte de eventos que a pipeline usa (pipeline_web.run_analysis)."""
    path = os.path.join(BATCH_DIR, f"batch_{batch_id:04d}.json")
    with open(path, encoding="utf-8") as f:
        batch = json.load(f)
    return "\n".join(batch["events"][-100:])



REGRAS_JUIZ = """Regras de julgamento:
1. Julgue SEMANTICAMENTE, não por palavra-chave. Uma paráfrase correta ATENDE o critério;
   citar o termo exato sem demonstrar entendimento NÃO atende.
2. Critérios negativos só disparam quando a resposta AFIRMA aquilo. Mencionar para NEGAR
   ("não há evidência de exfiltração") ou descrever como risco futuro claramente
   condicional NÃO dispara a penalidade.
3. Na dúvida entre atendido e não atendido, marque como NÃO atendido e explique.
4. Critérios de cadeia causal só são atendidos se a resposta CONECTAR os eventos
   explicitamente, não se apenas listá-los em parágrafos separados.
5. Você não atribui nota. Só devolve o veredito de cada critério."""


def build_judge_prompt(batch_id, rubrica, batch_input, response_text):
    pos = "\n".join(f"- {c['id']}: {c['desc']}" for c in rubrica["positivos"])
    neg = "\n".join(f"- {c['id']}: {c['desc']}" for c in rubrica["negativos"])
    ids = [c["id"] for c in rubrica["positivos"] + rubrica["negativos"]]

    return f"""Você é um auditor de avaliações de análise de segurança. Sua tarefa é verificar,
critério a critério, se a RESPOSTA de um agente atende a uma rubrica, usando o LOG DE
ENTRADA original como fonte da verdade.

{REGRAS_JUIZ}

## Cenário
Batch {batch_id:04d} — {rubrica['titulo']}

## LOG DE ENTRADA (fonte da verdade)
```
{batch_input}
```

## RESPOSTA DO AGENTE (objeto da avaliação)
```
{response_text}
```

## CRITÉRIOS POSITIVOS (a resposta deveria conter)
{pos}

## CRITÉRIOS NEGATIVOS (a resposta não deveria afirmar)
{neg}

## Formato de saída
Devolva APENAS um objeto JSON válido, sem cercas de código e sem texto ao redor:

{{
  "criterios": {{
    "<id_do_criterio>": {{"atendido": true|false, "justificativa": "<no máximo 25 palavras, citando a evidência>"}}
  }},
  "observacao": "<1-2 frases sobre o comportamento do agente neste batch>"
}}

Para critérios NEGATIVOS, "atendido": true significa que o ERRO ESTÁ PRESENTE na resposta.
Inclua exatamente estas chaves em "criterios": {json.dumps(ids, ensure_ascii=False)}"""


def call_claude(prompt, api_key, max_tokens=JUDGE_MAX_TOKENS, tries=4):
    payload = {
        "model": JUDGE_MODEL,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
    }
    last = None
    for attempt in range(tries):
        try:
            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
            )
            with urllib.request.urlopen(req, timeout=300) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            texto = "".join(b.get("text", "") for b in data.get("content", [])).strip()
            return texto, data.get("stop_reason")
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")[:300]
            last = f"HTTP {e.code}: {body}"
            if e.code not in (429, 500, 502, 503, 529):
                raise RuntimeError(last)
        except Exception as e:  # timeout, conexão
            last = str(e)
        if attempt < tries - 1:
            time.sleep(5 * (attempt + 1))
    raise RuntimeError(f"juiz indisponível após {tries} tentativas: {last}")


def extract_json(text):
    """O juiz é instruído a devolver JSON puro; tolera cercas ou texto ao redor."""
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start, depth = None, 0
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    start = None
    raise ValueError(f"resposta do juiz não é JSON: {text[:200]}")


def cache_get(key, use_cache=True):
    if not use_cache:
        return None
    path = os.path.join(CACHE_DIR, key + ".json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return None


def cache_put(key, value):
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(os.path.join(CACHE_DIR, key + ".json"), "w", encoding="utf-8") as f:
        json.dump(value, f, ensure_ascii=False, indent=2)


def score_from_verdicts(rubrica, criterios):
    """A nota é calculada aqui, nunca pelo juiz.

    Positivos e negativos são normalizados pelo MESMO fator (10 / peso total positivo),
    de modo que o peso de um critério signifique a mesma coisa nos dois sinais e entre
    batches: um negativo de peso 2.0 custa exatamente o que vale um positivo de peso 2.0.
    Sem isso, como os totais positivos diferem por batch (11.0, 10.0, 9.5), a mesma
    penalidade nominal morderia frações diferentes da nota em cada cenário.
    """
    total_pos = sum(c["peso"] for c in rubrica["positivos"]) or 1.0
    escala = 10.0 / total_pos

    met = sum(
        c["peso"] for c in rubrica["positivos"]
        if criterios.get(c["id"], {}).get("atendido") is True
    )
    peso_penal = sum(
        c["peso"] for c in rubrica["negativos"]
        if criterios.get(c["id"], {}).get("atendido") is True
    )

    penalty_pts = peso_penal * escala
    raw = met * escala - penalty_pts
    return max(0.0, min(10.0, raw)), met, total_pos, penalty_pts


def judge_response(batch_id, rubrica, batch_input, response_text, agent, api_key, use_cache):
    fingerprint = hashlib.sha256(
        json.dumps(
            [JUDGE_MODEL, batch_id, response_text,
             [(c["id"], c["desc"], c["peso"]) for c in rubrica["positivos"] + rubrica["negativos"]]],
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()[:20]
    key = f"judge_{batch_id:04d}_{fingerprint}"

    cached = cache_get(key, use_cache)
    if cached:
        return cached, True

    prompt = build_judge_prompt(batch_id, rubrica, batch_input, response_text)
    # O juiz devolve uma justificativa por critério; batches com muitos critérios podem
    # estourar o limite de saída e truncar o JSON. Sobe o limite e re-tenta nesse caso.
    result = None
    limite = JUDGE_MAX_TOKENS
    for tentativa in range(3):
        texto, stop_reason = call_claude(prompt, api_key, max_tokens=limite)
        if stop_reason == "max_tokens":
            print(f"      [aviso] saída truncada em {limite} tokens ({agent} b{batch_id}); "
                  f"re-tentando com {limite * 2}")
            limite *= 2
            continue
        try:
            result = extract_json(texto)
            break
        except ValueError as e:
            if tentativa == 2:
                raise
            print(f"      [aviso] JSON inválido ({agent} b{batch_id}): {str(e)[:120]}; re-tentando")
            limite *= 2

    faltando = [
        c["id"] for c in rubrica["positivos"] + rubrica["negativos"]
        if c["id"] not in result.get("criterios", {})
    ]
    if faltando:
        print(f"      [aviso] juiz omitiu critérios em {agent} b{batch_id}: {faltando}")

    cache_put(key, result)
    return result, False


def summarize_agent(agent, rubricas, per_batch, api_key, use_cache):
    """Comentário de comportamento do agente, fundamentado nos vereditos dos 5 batches."""
    linhas = []
    for b in sorted(per_batch):
        r = per_batch[b]
        crit = r["result"].get("criterios", {})
        faltou = [c["id"] for c in rubricas[b]["positivos"] if not crit.get(c["id"], {}).get("atendido")]
        errou = [c["id"] for c in rubricas[b]["negativos"] if crit.get(c["id"], {}).get("atendido")]
        linhas.append(
            f"Batch {b:04d} ({rubricas[b]['titulo']}) — nota {r['score']:.2f}\n"
            f"  critérios não atendidos: {faltou or 'nenhum'}\n"
            f"  erros disparados: {errou or 'nenhum'}\n"
            f"  observação do juiz: {r['result'].get('observacao', '')}"
        )
    corpo = "\n\n".join(linhas)

    fingerprint = hashlib.sha256((JUDGE_MODEL + agent + corpo).encode("utf-8")).hexdigest()[:20]
    key = f"summary_{fingerprint}"
    cached = cache_get(key, use_cache)
    if cached:
        return cached["texto"], True

    prompt = f"""Você auditou as respostas do agente "{agent}" em 5 batches de análise de
segurança, critério a critério. Abaixo está o resultado consolidado.

{corpo}

Escreva um comentário em português sobre o COMPORTAMENTO deste agente, em 3 a 5 bullets.
Foque em padrões que se repetem entre batches, não em fatos isolados de um único batch.
Cada bullet deve citar a evidência (o id do critério ou o batch) que o sustenta.
Cubra, quando houver sinal para isso: erros factuais recorrentes, tendência a especular sem
evidência, omissões sistemáticas de mecanismo, e aderência ao formato pedido.
Não invente nada que não esteja no resumo acima. Devolva apenas os bullets."""

    texto, _ = call_claude(prompt, api_key, max_tokens=2048)
    cache_put(key, {"texto": texto})
    return texto, False


# ---------------------------------------------------------------------------
# Execução
# ---------------------------------------------------------------------------

def evaluate_file_regex(path, label):
    agents = parse_results_md(path)
    agent_names = list(agents.keys())
    batch_ids = sorted({b for batches in agents.values() for b in batches})

    scores = {agent: {} for agent in agent_names}
    for agent in agent_names:
        for batch_id in batch_ids:
            text = agents[agent].get(batch_id, "")
            scores[agent][batch_id] = score_response(batch_id, text) if text else 0.0

    print_table(scores, agent_names, batch_ids, f"{label} ({os.path.basename(path)})")
    return scores


def evaluate_file_rubric(path, label, rubricas, api_key, use_cache):
    agents = parse_results_md(path)
    agent_names = list(agents.keys())
    batch_ids = sorted({b for batches in agents.values() for b in batches})
    inputs = {b: load_batch_input(b) for b in batch_ids}

    scores = {a: {} for a in agent_names}
    detalhes = {a: {} for a in agent_names}
    comentarios = {}

    print(f"\n### {label} ({os.path.basename(path)}) — juiz: {JUDGE_MODEL}")
    for agent in agent_names:
        print(f"  {agent}")
        for batch_id in batch_ids:
            text = agents[agent].get(batch_id, "")
            if not text:
                scores[agent][batch_id] = 0.0
                continue
            result, hit = judge_response(
                batch_id, rubricas[batch_id], inputs[batch_id], text, agent, api_key, use_cache
            )
            score, met, total, pen = score_from_verdicts(rubricas[batch_id], result.get("criterios", {}))
            scores[agent][batch_id] = score
            detalhes[agent][batch_id] = {"result": result, "score": score,
                                         "met": met, "total": total, "pen": pen}
            print(f"    batch {batch_id:04d}: {score:5.2f}  "
                  f"({met:.1f}/{total:.1f} positivos, -{pen:.1f}){'  [cache]' if hit else ''}")

        if detalhes[agent]:
            comentarios[agent], hit = summarize_agent(
                agent, rubricas, detalhes[agent], api_key, use_cache
            )
            print(f"    comentário gerado{'  [cache]' if hit else ''}")

    print_table(scores, agent_names, batch_ids, f"{label} — rubrica")
    return scores, detalhes, comentarios


def print_table(scores, agent_names, batch_ids, label):
    col_w = max(len(a) for a in agent_names) + 2
    header = f"{'Batch':<8}" + "".join(f"{a:<{col_w}}" for a in agent_names)
    print(f"\n=== {label} ===\n")
    print(header)
    print("-" * len(header))
    for batch_id in batch_ids:
        print(f"{batch_id:<8}" + "".join(f"{scores[a][batch_id]:<{col_w}.2f}" for a in agent_names))
    print("-" * len(header))
    print(f"{'Média':<8}" + "".join(
        f"{sum(scores[a].values()) / len(scores[a]):<{col_w}.2f}" for a in agent_names))


def write_report(blocos, rubricas):
    out = ["# Auditoria por rubrica — resultados", "",
           f"Juiz: `{JUDGE_MODEL}` · rubricas: `rubricas_avaliacao.md` · temperatura 0.", "",
           "Notas calculadas pelo script a partir dos vereditos por critério; o juiz não "
           "atribui nota diretamente.", ""]

    for label, path, scores, detalhes, comentarios in blocos:
        agent_names = list(scores.keys())
        batch_ids = sorted({b for s in scores.values() for b in s})
        out += [f"## {label}", "", f"Fonte: `{os.path.basename(path)}`", "",
                "| Batch | Cenário | " + " | ".join(agent_names) + " |",
                "|---|---|" + "---|" * len(agent_names)]
        for b in batch_ids:
            out.append(f"| {b} | {rubricas[b]['titulo']} | " +
                       " | ".join(f"{scores[a][b]:.2f}" for a in agent_names) + " |")
        out.append("| **Média** | | " + " | ".join(
            f"**{sum(scores[a].values())/len(scores[a]):.2f}**" for a in agent_names) + " |")
        out.append("")

        out += ["### Comportamento por agente", ""]
        for agent in agent_names:
            out += [f"**{agent}**", "", comentarios.get(agent, "_sem comentário_"), ""]

        out += ["<details>", "<summary>Vereditos por critério</summary>", ""]
        for agent in agent_names:
            out.append(f"#### {agent}")
            for b in sorted(detalhes.get(agent, {})):
                d = detalhes[agent][b]
                out.append(f"\n**Batch {b:04d}** — nota {d['score']:.2f}\n")
                crit = d["result"].get("criterios", {})
                for c in rubricas[b]["positivos"]:
                    v = crit.get(c["id"], {})
                    mark = "x" if v.get("atendido") else " "
                    out.append(f"- [{mark}] `{c['id']}` ({c['peso']}) — {v.get('justificativa','—')}")
                for c in rubricas[b]["negativos"]:
                    v = crit.get(c["id"], {})
                    if v.get("atendido"):
                        out.append(f"- **ERRO** `{c['id']}` (−{c['peso']}) — {v.get('justificativa','—')}")
            out.append("")
        out += ["</details>", ""]

    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    print(f"\nRelatório salvo em {REPORT_FILE}")


def main():
    ap = argparse.ArgumentParser(description="Avaliação dos batches sintéticos.")
    ap.add_argument("--mode", choices=["rubric", "regex"], default="rubric")
    ap.add_argument("--file", action="append",
                    help="arquivo de resultados a avaliar (pode repetir). "
                         "Padrão: rag_test_results.md e no_rag_test_results.md")
    ap.add_argument("--no-cache", action="store_true", help="re-julga tudo, ignorando o cache")
    args = ap.parse_args()

    alvos = args.file or ["rag_test_results.md", "no_rag_test_results.md"]
    rotulos = {"rag_test_results.md": "COM RAG", "no_rag_test_results.md": "SEM RAG"}

    if args.mode == "regex":
        for nome in alvos:
            evaluate_file_regex(os.path.join(BASE_DIR, nome), rotulos.get(nome, nome))
        return

    if not os.path.exists(JUDGE_KEY_FILE):
        raise SystemExit(f"[ERRO] chave do juiz não encontrada em {JUDGE_KEY_FILE}")
    api_key = open(JUDGE_KEY_FILE, encoding="utf-8").read().strip()

    rubricas = parse_rubricas()
    print(f"Rubricas carregadas de {os.path.basename(RUBRIC_FILE)}: " + ", ".join(
        f"batch {b} ({len(r['positivos'])}+/{len(r['negativos'])}-)"
        for b, r in sorted(rubricas.items())))

    blocos = []
    for nome in alvos:
        path = os.path.join(BASE_DIR, nome)
        scores, detalhes, comentarios = evaluate_file_rubric(
            path, rotulos.get(nome, nome), rubricas, api_key, not args.no_cache
        )
        blocos.append((rotulos.get(nome, nome), path, scores, detalhes, comentarios))

    write_report(blocos, rubricas)


if __name__ == "__main__":
    main()
