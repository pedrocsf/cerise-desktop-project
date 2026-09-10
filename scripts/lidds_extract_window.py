#!/usr/bin/env python3
"""Extrai a janela de eventos relevante ao redor do exploit (ou de um trecho estável,
para gravações normais) de uma gravação .txt do LID-DS-2019.

Uso:
  python3 lidds_extract_window.py <scenario_dir> <recording_name> [--before 5] [--after 10]

<scenario_dir> = diretório já extraído de um cenário (ex.: .../CVE-2012-2122/)
                 deve conter runs.csv e <recording_name>.txt
"""
import csv
import re
import sys
import argparse

INFORMATIVE_EVENTS = {
    "execve", "execveat", "open", "openat", "unlink", "unlinkat", "chmod", "fchmod",
    "chown", "fchown", "setuid", "setgid", "setresuid", "setresgid", "clone", "fork",
    "mount", "ptrace", "bpf", "setns", "memfd_create", "rename", "renameat",
}
SOCKET_EVENTS = {"accept", "connect", "read", "write", "writev", "readv", "recvfrom", "sendto", "recv", "send"}

TIME_RE = re.compile(r"^\d+\s+(\d+):(\d+):(\d+\.\d+)\s")


def parse_time(line):
    m = TIME_RE.match(line)
    if not m:
        return None
    h, mi, s = m.groups()
    return int(h) * 3600 + int(mi) * 60 + float(s)


def load_run_meta(scenario_dir, recording_name):
    csv_path = f"{scenario_dir.rstrip('/')}/runs.csv"
    with open(csv_path, newline="") as f:
        reader = csv.reader(f)
        header = [h.strip() for h in next(reader)]
        for row in reader:
            row = [c.strip() for c in row]
            d = dict(zip(header, row))
            if d.get("scenario_name") == recording_name:
                return d
    raise SystemExit(f"Gravação '{recording_name}' não encontrada em {csv_path}")


def extract(scenario_dir, recording_name, before=5.0, after=10.0):
    meta = load_run_meta(scenario_dir, recording_name)
    is_attack = meta["is_executing_exploit"].lower() == "true"
    exploit_start = float(meta["exploit_start_time"])

    txt_path = f"{scenario_dir.rstrip('/')}/{recording_name}.txt"
    lines = open(txt_path, errors="replace").readlines()

    first_time = None
    window_lines = []
    filtered_lines = []

    for line in lines:
        t = parse_time(line)
        if t is None:
            continue
        if first_time is None:
            first_time = t
        rel = t - first_time

        if is_attack and exploit_start >= 0:
            in_window = (exploit_start - before) <= rel <= (exploit_start + after)
        else:
            # normal recording: window after warmup, arbitrary stable slice
            in_window = 15.0 <= rel <= 30.0

        if not in_window:
            continue
        window_lines.append(line)

        parts = line.split(None, 8)
        if len(parts) < 8:
            continue
        event_type = parts[7]
        if event_type in INFORMATIVE_EVENTS or event_type in SOCKET_EVENTS:
            filtered_lines.append(line)

    return {
        "meta": meta,
        "is_attack": is_attack,
        "exploit_start_rel": exploit_start if is_attack else None,
        "window_line_count": len(window_lines),
        "filtered_line_count": len(filtered_lines),
        "filtered_lines": filtered_lines,
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario_dir")
    ap.add_argument("recording_name")
    ap.add_argument("--before", type=float, default=5.0)
    ap.add_argument("--after", type=float, default=10.0)
    args = ap.parse_args()

    result = extract(args.scenario_dir, args.recording_name, args.before, args.after)
    print(f"# meta: {result['meta']}")
    print(f"# window_lines={result['window_line_count']} filtered_lines={result['filtered_line_count']}")
    for line in result["filtered_lines"]:
        sys.stdout.write(line)
