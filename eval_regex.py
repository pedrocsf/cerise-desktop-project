# Scores agent analyses of the synthetic batches PURELY computationally (no LLM
# judge involved): for each batch, a fixed set of ground-truth IOCs/techniques
# (known because the synthetic batches were hand-built) is weighted and matched
# against the response text via regex; a fixed set of known false claims (real
# hallucinations observed across the test rounds) is matched and penalized.
#
#   score = clamp(0, 10, 10 * recall - penalty)
#   recall = (sum of weights of matched ground-truth terms) / (sum of all weights)
#
# Run: python eval_llm.py
# Reads rag_test_results.md and no_rag_test_results.md and prints one scored
# table per file, in the same shape as the manually-graded tables.

import re
import os
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# (regex, weight) pairs of ground-truth signals that SHOULD appear in a correct
# analysis of that batch, and (regex, penalty) pairs of known false claims that
# were actually observed (across RedSage/Gemini/Claude/GPT, RAG and non-RAG
# rounds) and should NOT appear. All matching is case-insensitive substring/regex
# against the raw response text.
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
    O casamento não-guloso original (```\n(.*?)\n```) parava na primeira cerca interna e
    truncava a resposta — foi o que aconteceu com as respostas do Claude sem RAG nos
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


def evaluate_file(path, label):
    agents = parse_results_md(path)
    agent_names = list(agents.keys())
    batch_ids = sorted({b for batches in agents.values() for b in batches})

    scores = {agent: {} for agent in agent_names}
    for agent in agent_names:
        for batch_id in batch_ids:
            text = agents[agent].get(batch_id, "")
            scores[agent][batch_id] = score_response(batch_id, text) if text else 0.0

    col_w = max(len(a) for a in agent_names) + 2
    header = f"{'Batch':<8}" + "".join(f"{a:<{col_w}}" for a in agent_names)
    print(f"\n=== {label} ({os.path.basename(path)}) ===\n")
    print(header)
    print("-" * len(header))
    for batch_id in batch_ids:
        row = f"{batch_id:<8}" + "".join(f"{scores[a][batch_id]:<{col_w}.2f}" for a in agent_names)
        print(row)
    print("-" * len(header))
    avg_row = f"{'Média':<8}" + "".join(
        f"{sum(scores[a].values()) / len(scores[a]):<{col_w}.2f}" for a in agent_names
    )
    print(avg_row)
    return scores


if __name__ == "__main__":
    evaluate_file(os.path.join(BASE_DIR, "rag_test_results.md"), "COM RAG")
    evaluate_file(os.path.join(BASE_DIR, "no_rag_test_results.md"), "SEM RAG")
