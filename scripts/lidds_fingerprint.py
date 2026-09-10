#!/usr/bin/env python3
"""Fingerprint de ATAQUE de gravacoes LID-DS-2019, para achar variantes tecnicas
distintas dentro de um mesmo cenario sem ler log bruto gravacao por gravacao.

Diferente de um resumo geral, este script extrai SOMENTE features ligadas ao ataque
e ignora o trafego de fundo (usuario normal simulado, assets, libs, temporarios),
que varia aleatoriamente entre gravacoes e nao e sinal.

Features capturadas:
  - tecnicas SQLi presentes (union / boolean-blind / time-blind / error / stacked / outfile)
  - metodo HTTP das requisicoes que carregam payload de ataque (GET vs POST)
  - endpoints alvo que receberam payload
  - alvos de path traversal (caminho resolvido, ex. /etc/passwd) e direcao (leitura/escrita)
  - comandos executados via shell por processo pai inesperado (webshell / RCE)
  - flags perigosas (ex. Ghostscript -dWRITESYSTEMDICT)
  - usuarios tentados em bruteforce de autenticacao + volume
  - respostas anomalamente grandes (bucket de KB) - vazamento de memoria
  - autenticacao bem-sucedida apos rajada de falhas (bypass)

Uso:
  python3 lidds_fingerprint.py <scenario_dir> [--limit N] [--normal] [--verbose-rep]
"""
import argparse
import csv
import hashlib
import json
import os
import re
from collections import Counter, defaultdict

TIME_RE = re.compile(r"^\d+\s+(\d+):(\d+):(\d+\.\d+)\s")

SQL_TECHNIQUES = {
    "union": re.compile(r"UNION(%20|\s|\+)+(ALL(%20|\s|\+)+)?SELECT", re.I),
    "boolean_blind": re.compile(r"CASE(%20|\s|\+)+WHEN", re.I),
    "time_blind_sleep": re.compile(r"SLEEP(%28|\()", re.I),
    "time_blind_benchmark": re.compile(r"BENCHMARK(%28|\()", re.I),
    "error_based": re.compile(r"(EXTRACTVALUE|UPDATEXML|FLOOR(%28|\()RAND|GTID_SUBSET)", re.I),
    "info_schema": re.compile(r"INFORMATION_SCHEMA", re.I),
    "stacked": re.compile(r"%3B(%20)?(SELECT|INSERT|UPDATE|DROP)", re.I),
    "into_outfile": re.compile(r"INTO(%20|\s|\+)+(OUT|DUMP)FILE", re.I),
    "comment_trick": re.compile(r"(--%20|--\s|%23)"),
    "or_tautology": re.compile(r"(OR(%20|\s|\+)+\d+(%3D|=)\d+|AND(%20|\s|\+)+\d+(%3D|=)\d+)", re.I),
}

# requisicao HTTP que carrega payload suspeito
HTTP_LINE_RE = re.compile(r'(GET|POST|PUT|HEAD)\s+(/[^\s?"]*)(\?[^\s"]*)?')
PAYLOAD_HINT_RE = re.compile(
    r"(UNION|SELECT|CASE%20WHEN|BENCHMARK|SLEEP\(|SLEEP%28|INFORMATION_SCHEMA|%27|'|\.\./|%2e%2e)", re.I
)

TRAVERSAL_OPEN_RE = re.compile(r"open .*name=([^\s]*\.\.[^\s]*?)(?:\(([^)]*)\))?\s+flags=(\d+)\(([^)]*)\)")
RESOLVED_RE = re.compile(r"name=[^\s(]*\(([^)]+)\)")
SHELL_CMD_RE = re.compile(r"exe=(?:sh|bash|dash) args=-c\.([^.\s]+)")
SHELL_PARENT_RE = re.compile(r"ptid=\d+\(([^)]+)\)")
DANGEROUS_FLAG_RE = re.compile(r"(-dWRITESYSTEMDICT|-dDELAYBIND|-dNOSAFER|--no-sandbox)")
AUTH_USER_RE = re.compile(r"data=[\d.]+ - ([A-Za-z0-9_]+) \[")
AUTH_FAIL_RE = re.compile(r"Access denied for user '([^']+)'")
BIG_WRITE_RE = re.compile(r"< writev res=(\d+)")
EXECVE_RE = re.compile(r"< execve res=0 exe=([^\s]+)")


def parse_time(line):
    m = TIME_RE.match(line)
    if not m:
        return None
    h, mi, s = m.groups()
    return int(h) * 3600 + int(mi) * 60 + float(s)


def load_runs(scenario_dir):
    with open(os.path.join(scenario_dir, "runs.csv"), newline="") as f:
        reader = csv.reader(f)
        header = [h.strip() for h in next(reader)]
        return [dict(zip(header, [c.strip() for c in row])) for row in reader]


def attack_fingerprint(scenario_dir, meta, before=5.0, after=25.0):
    name = meta["scenario_name"]
    path = os.path.join(scenario_dir, f"{name}.txt")
    if not os.path.exists(path):
        return None

    is_attack = meta["is_executing_exploit"].lower() == "true"
    exploit_start = float(meta["exploit_start_time"])

    sql_techniques = set()
    payload_endpoints = set()       # "METHOD /path"
    traversal_targets = set()       # "/etc/passwd:read" | ":write"
    shell_cmds = set()              # comando executado via sh -c
    shell_parents = set()           # processo pai que spawnou shell
    dangerous_flags = set()
    auth_users_ok = Counter()       # usuario autenticado com sucesso (campo %u do log)
    auth_users_fail = Counter()     # usuario com Access denied
    big_writes = Counter()          # bucket de KB para respostas > 8KB
    execs = set()                   # binarios executados
    post_payload = False
    get_payload = False

    first_time = None
    with open(path, errors="replace") as f:
        for line in f:
            t = parse_time(line)
            if t is None:
                continue
            if first_time is None:
                first_time = t
            rel = t - first_time
            if is_attack and exploit_start >= 0:
                if not ((exploit_start - before) <= rel <= (exploit_start + after)):
                    continue
            else:
                if not (15.0 <= rel <= 35.0):
                    continue

            # --- SQLi ---
            for tech, rx in SQL_TECHNIQUES.items():
                if rx.search(line):
                    sql_techniques.add(tech)

            # --- requisicoes com payload ---
            if PAYLOAD_HINT_RE.search(line):
                for meth, p, qs in HTTP_LINE_RE.findall(line):
                    if qs and PAYLOAD_HINT_RE.search(qs):
                        payload_endpoints.add(f"{meth} {p[:60]}")
                        if meth == "POST":
                            post_payload = True
                        else:
                            get_payload = True
                    elif meth == "POST" and PAYLOAD_HINT_RE.search(line):
                        payload_endpoints.add(f"{meth} {p[:60]}")
                        post_payload = True

            # --- path traversal (nome com .. + caminho resolvido + flags) ---
            if ".." in line and "open" in line:
                mres = RESOLVED_RE.search(line)
                resolved = mres.group(1) if mres else "?"
                if ".." in line.split("name=")[-1][:200] if "name=" in line else False:
                    mode = "write" if ("O_WRONLY" in line or "O_RDWR" in line or "O_CREAT" in line) else "read"
                    traversal_targets.add(f"{resolved[:60]}:{mode}")

            # --- execucao de shell / RCE ---
            m = SHELL_CMD_RE.search(line)
            if m:
                shell_cmds.add(m.group(1)[:30])
                pm = SHELL_PARENT_RE.search(line)
                if pm:
                    shell_parents.add(pm.group(1))
            m = EXECVE_RE.search(line)
            if m:
                execs.add(os.path.basename(m.group(1))[:30])

            for fl in DANGEROUS_FLAG_RE.findall(line):
                dangerous_flags.add(fl)

            # --- autenticacao ---
            m = AUTH_USER_RE.search(line)
            if m:
                auth_users_ok[m.group(1)] += 1
            m = AUTH_FAIL_RE.search(line)
            if m:
                auth_users_fail[m.group(1)] += 1

            # --- respostas grandes (vazamento de memoria) ---
            m = BIG_WRITE_RE.search(line)
            if m and int(m.group(1)) > 8000:
                big_writes[int(m.group(1)) // 1000] += 1

    fp = {
        "sql_techniques": sorted(sql_techniques),
        "payload_endpoints": sorted(payload_endpoints)[:10],
        "payload_via": sorted(filter(None, ["GET" if get_payload else "", "POST" if post_payload else ""])),
        "traversal_targets": sorted(traversal_targets)[:10],
        "shell_cmds": sorted(shell_cmds)[:10],
        "shell_parents": sorted(shell_parents),
        "dangerous_flags": sorted(dangerous_flags),
        "auth_users_tried": sorted(set(auth_users_ok) | set(auth_users_fail))[:12],
        "auth_fail_count_bucket": (sum(auth_users_fail.values()) // 10) * 10,
        "big_write_kb": sorted(big_writes),
        "execs": sorted(execs)[:12],
    }
    fp_hash = hashlib.md5(json.dumps(fp, sort_keys=True).encode()).hexdigest()[:10]
    return fp_hash, fp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario_dir")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--normal", action="store_true")
    args = ap.parse_args()

    runs = load_runs(args.scenario_dir)
    want_attack = not args.normal
    sel = [r for r in runs if (r["is_executing_exploit"].lower() == "true") == want_attack]
    if args.limit:
        sel = sel[: args.limit]

    groups = defaultdict(list)
    for meta in sel:
        res = attack_fingerprint(args.scenario_dir, meta)
        if res is None:
            continue
        fp_hash, fp = res
        groups[fp_hash].append((meta["scenario_name"], fp))

    print(f"# {len(sel)} gravacoes | {len(groups)} fingerprints de ataque distintos")
    for fp_hash, members in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        rep_name, fp = members[0]
        print(f"\n=== {fp_hash} | {len(members)} gravacoes | rep: {rep_name}")
        if len(members) > 1:
            print(f"    membros: {', '.join(n for n, _ in members[:6])}{' ...' if len(members) > 6 else ''}")
        for k, v in fp.items():
            if v:
                print(f"    {k}: {v}")


if __name__ == "__main__":
    main()
