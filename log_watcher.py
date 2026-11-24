
import os
import re
import time
import chromadb
from sentence_transformers import SentenceTransformer, CrossEncoder
from rank_bm25 import BM25Okapi
from llama import send_for_analysis

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_DIR = os.path.join(_BASE_DIR, "vector_db")
COLLECTION_NAME = "security_docs"
CASES_COLLECTION_NAME = "security_cases"
CASE_CANDIDATES = 3
MODEL_NAME = os.path.join(_BASE_DIR, "models", "cerise-embed-v1")
RERANK_MODEL_NAME = "cross-encoder/ms-marco-MiniLM-L-6-v2"

QUERY_PREFIX = "search_query: "

DENSE_CANDIDATES = 8
SPARSE_CANDIDATES = 8
FUSION_CANDIDATES = 8
RRF_K = 60

MIN_RERANK_SCORE = -4.49
MAX_CATEGORIES = 3

HYDE_ENABLED = True
HYDE_LOG_PREFIX = "[hyde]"
HYDE_ERROR_MARKER = "[ERROR]"
HYDE_LOG_RESPONSE_MAX_CHARS = 200

HYDE_PROMPT = """### Instruction:
The input below is an aggregated summary of all events of a batch, not raw log lines. Each group line gives the sensor and kind, the process name, the number of events (count), distinct pids, a time interval and sample targets. Groups marked [baseline] are routine activity already seen on the clean system. Counts and the number of distinct processes matter: a very large count for one process is itself a security-relevant action.
List, one per line, the distinct security-relevant actions present (max 5). Each line: a short, plain-English sentence describing what the action does, including the process name and the count when relevant. Ignore benign/routine noise. Do not judge whether any action is malicious. If there is truly only one relevant action, output one line. Output ONLY the list, nothing else.

### Input:
{log_content}

### Response:
"""

INCIDENT_BLOCK_HEADER = "### Active incident context (earlier batches of this same run):"
INCIDENT_TIME_FORMAT = "%H:%M:%S"
INCIDENT_INSTRUCTION = (
    "An incident was already flagged in earlier batches of this same run (listed above). Classify the current batch "
    "by the evidence in its own Batch Summary. Activity that continues the incident, processes of the incident that "
    "are still present, and side effects or residual damage (services going down, mass errors) count as at least "
    "SUSPICIOUS, and ANALYSIS must say explicitly that the incident is still active. Do not invent new evidence: "
    "if the current batch shows nothing related, do not raise the verdict because of this context."
)

ATTACK_INSTRUCTION = (
    "ATTACK must list the MITRE ATT&CK Enterprise technique IDs (format T#### for a technique or T####.### "
    "for a sub-technique) for behavior the Batch Summary directly shows on this Linux host, separated by commas. "
    "Prefer the most specific sub-technique when the log supports it. Do not list a technique that only the "
    "retrieved context or the External Search Results suggest without a matching event in the Batch Summary. "
    "Write NONE when VERDICT is SAFE or when no technique is directly evidenced.\n\n"
)

class _PromptTemplate(str):
    def format(self, *args, **kwargs):
        kwargs.setdefault("incident_context", "")
        return str.format(self, *args, **kwargs)


_PROMPT_TEXT = """### Instruction:
Act as a cybersecurity analyst. Review the Batch Summary below for malicious activity based on the provided context.

The Batch Summary is an aggregated view of ALL events of the batch, not a sample of the latest ones. Groups are listed by sensor and kind, process name, uid and flags, with the event count, the number of distinct pids, the time interval and sample targets. Events tagged [ebpf] are kernel-level syscall traces; events tagged [network:...] are captured network packets, aggregated per flow. When an ebpf group is followed shortly after by related network activity from the same process, treat them as one causal chain, not independent findings. If the section contains raw log lines instead of a summary, read them directly.

How to read the Batch Summary:
- Counts and the number of distinct processes are evidence, not decoration. An unknown process (not a standard system or user program) performing thousands of file operations (chmod, rename, writes) within seconds is a strong indicator of malicious activity, for example mass file modification or encryption, even when each single event looks benign. Weigh it heavily in both the VERDICT and the SEVERITY.
- Groups marked [baseline] or [partly baseline] are activity already seen on the clean system. They must not raise the verdict by themselves; only an abnormal volume or new targets inside them can count.
- Noise from the monitoring stack and the SSH control channel was already removed and is only counted. Do not report it as a finding.
- A process whose comm appears in parentheses, such as `(imedated)`, with PPID 1, doing a burst of `mount`/`unshare`/`capset` within about 1 second is the normal sandbox setup of a systemd unit (systemd-timedated, systemd-resolved and similar) and must not, by itself, raise the verdict. The summary may mark these groups with `[systemd unit sandbox setup]`. The same burst coming from a process whose PPID is not 1, or that afterwards executes other binaries, remains suspicious.
- A WARNING about lost events means the sensors dropped events, so every count is a lower bound and the real activity was at least that large.

When a Process Tree section is present below, treat it as the primary source of causality between processes: it groups the most recent [ebpf] events of the batch by parent/child ancestry (PID/PPID), so a child appearing under a parent means that parent's process spawned it. Use the Batch Summary to confirm timing, volume and the events the tree does not cover (network activity, older events, and any probe that does not yet report PPID). If the Process Tree section says no ancestry data was available, fall back to inferring causality from timing and process names in the Batch Summary.

Each category block under Context is a retrieval hypothesis, not a verified fact. Cross-check it against the Batch Summary before trusting it:
- HIGH confidence: treat its Anomaly Patterns as a strong prior, but still confirm they match the actual input.
- MEDIUM confidence: treat it only as a hint; weigh the Batch Summary evidence more heavily than the label.
- LOW confidence, UNKNOWN category, or a Context block saying no relevant context was found: ignore that category label entirely and analyze the affected input using your own security knowledge.
If two or more retrieved categories are both plausible, read their Suggested Correlation sections to judge whether the input matches the pattern of them occurring together.

Mark VERDICT as THREAT when you find clear malicious activity (e.g. unauthorized access, suspicious execution, log tampering), SUSPICIOUS when the input matches a Normal Pattern (common false positive) about as plausibly as it matches an Anomaly Pattern, or when correlation with another category would be needed to be sure, or SAFE otherwise.

SEVERITY must start from the Base Criticality Level of whichever retrieved category you judge most relevant (if any), then adjust up or down based on how strongly the Batch Summary corroborates its Anomaly Patterns and whether multiple categories correlate together. State that adjustment reasoning in ANALYSIS.

ANALYSIS must (a) state whether you agree with each retrieved category above, and (b) cite at least one concrete piece of evidence from the input (process name, pid, path, ip:port, event count, or similar) supporting the verdict.

External Search Results, when present below, are open-source intelligence about a specific indicator (IP or domain) found in this batch, not verified fact. Treat them the same way as a retrieved category: weigh them against the Batch Summary, and if a source contradicts the batch evidence, trust the batch evidence. If you rely on one, cite it in ANALYSIS by its indicator or domain, not the full URL. Reputation results (AbuseIPDB, VirusTotal) start with a fixed assessment: clean, negligible, suspicious, malicious, or unknown. Rely on that assessment, not on the raw counts after it. A clean, negligible, or unknown assessment is not evidence of a threat, since a single antivirus engine flagging an indicator is common noise; judge that indicator from the Batch Summary alone. Only a suspicious or malicious assessment may reinforce a THREAT verdict, and only when the Batch Summary shows behavior consistent with it.

Format that you need to follow:
VERDICT: <SAFE/SUSPICIOUS/THREAT>
SEVERITY: <1-5>
ANALYSIS: <Short explanation>

### Context (top matching categories, most to least relevant):
{rag_context}

### Process Tree:
{process_tree}

### External Search Results:
{search_context}
{incident_context}
### Batch Summary (all events of the batch, aggregated):
{log_content}

### Response:
"""


PROMPT_TEMPLATE = _PromptTemplate(_PROMPT_TEXT)


def build_prompt_template(attack_enabled=False):
    if not attack_enabled:
        return PROMPT_TEMPLATE
    marker = "Format that you need to follow:\n"
    severity_line = "SEVERITY: <1-5>\n"
    return _PromptTemplate(
        _PROMPT_TEXT
        .replace(marker, ATTACK_INSTRUCTION + marker, 1)
        .replace(severity_line, severity_line + "ATTACK: <comma-separated technique IDs, or NONE>\n", 1)
    )


def _format_incident_record(record):
    stamp = time.strftime(INCIDENT_TIME_FORMAT, time.localtime(record["time"]))
    return (f"- Batch {record['batch_id']} [{record['verdict']}, severity {record['severity']}, "
            f"{stamp}]: {record['summary']}")


def format_incident_block(records):
    if not records:
        return ""
    lines = [_format_incident_record(record) for record in records]
    return "\n".join(["", INCIDENT_BLOCK_HEADER, *lines, INCIDENT_INSTRUCTION, ""])



def _tokenize(text):
    return re.findall(r"[a-zA-Z0-9_./-]+", text.lower())


class RagRetriever:
    def __init__(self, hyde_llm=send_for_analysis):
        self.hyde_llm = hyde_llm
        self.collection = None
        self.cases_collection = None
        self.encoder = None
        self.reranker = None
        self.bm25 = None
        self.corpus_ids = []
        self.corpus_docs = []
        self.corpus_meta = []
        try:
            print("Initializing RAG retriever...")
            print(f"Loading embedding model '{MODEL_NAME}'. This may take a while on the first run...")
            self.encoder = SentenceTransformer(MODEL_NAME, trust_remote_code=True)
            print(f"Loading reranker '{RERANK_MODEL_NAME}'...")
            self.reranker = CrossEncoder(RERANK_MODEL_NAME)
            print("Models loaded.")

            print(f"Connecting to vector database at '{DB_DIR}'...")
            client = chromadb.PersistentClient(path=DB_DIR)
            self.collection = client.get_collection(name=COLLECTION_NAME)
            self.cases_collection = client.get_or_create_collection(
                name=CASES_COLLECTION_NAME, metadata={"hnsw:space": "cosine"}
            )

            if self.collection.count() > 0:
                data = self.collection.get(include=["documents", "metadatas"])
                self.corpus_ids = data["ids"]
                self.corpus_docs = data["documents"]
                self.corpus_meta = data["metadatas"]
                self.bm25 = BM25Okapi([_tokenize(d) for d in self.corpus_docs])

            print("RAG retriever is ready.")
        except Exception as e:
            print(f"Error initializing RAG retriever: {e}\nAnalysis will proceed without RAG context.")

    def _hyde_rewrite(self, digest_text):
        if not HYDE_ENABLED:
            return digest_text, False
        try:
            rewritten = self.hyde_llm(HYDE_PROMPT.format(log_content=digest_text))
        except Exception as error:
            self._log_hyde_degraded(f"{type(error).__name__}: {error}")
            return digest_text, True
        if not rewritten or not rewritten.strip():
            self._log_hyde_degraded("empty response from the LLM")
            return digest_text, True
        if rewritten.strip().startswith(HYDE_ERROR_MARKER):
            self._log_hyde_degraded(f"error response: {rewritten.strip()[:HYDE_LOG_RESPONSE_MAX_CHARS]}")
            return digest_text, True
        return rewritten.strip(), False

    @staticmethod
    def _log_hyde_degraded(reason):
        print(f"{HYDE_LOG_PREFIX} degraded, retrieval will use the digest text without rewriting: {reason}", flush=True)

    def _dense_search(self, embed_text, n_results):
        query_embedding = self.encoder.encode(
            [QUERY_PREFIX + embed_text], convert_to_numpy=True
        ).tolist()
        results = self.collection.query(
            query_embeddings=query_embedding,
            n_results=min(n_results, self.collection.count()),
        )
        ids = results.get("ids", [[]])[0]
        distances = results.get("distances", [[]])[0]
        return [(doc_id, 1 - dist) for doc_id, dist in zip(ids, distances)]

    def _sparse_search(self, raw_text, n_results):
        if not self.bm25:
            return []
        scores = self.bm25.get_scores(_tokenize(raw_text))
        ranked = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:n_results]
        return [(self.corpus_ids[i], scores[i]) for i in ranked if scores[i] > 0]

    def _fuse(self, dense_ranked, sparse_ranked, top_n):
        rrf_scores = {}
        for rank, (doc_id, _) in enumerate(dense_ranked):
            rrf_scores[doc_id] = rrf_scores.get(doc_id, 0.0) + 1.0 / (RRF_K + rank + 1)
        for rank, (doc_id, _) in enumerate(sparse_ranked):
            rrf_scores[doc_id] = rrf_scores.get(doc_id, 0.0) + 1.0 / (RRF_K + rank + 1)
        fused = sorted(rrf_scores.items(), key=lambda kv: kv[1], reverse=True)[:top_n]
        return [doc_id for doc_id, _ in fused]

    def _doc_by_id(self, doc_id):
        idx = self.corpus_ids.index(doc_id)
        return self.corpus_docs[idx], self.corpus_meta[idx]

    def _dense_search_cases(self, embed_text, n_results):
        if not self.cases_collection or self.cases_collection.count() == 0:
            return []
        query_embedding = self.encoder.encode(
            [QUERY_PREFIX + embed_text], convert_to_numpy=True
        ).tolist()
        results = self.cases_collection.query(
            query_embeddings=query_embedding,
            n_results=min(n_results, self.cases_collection.count()),
            include=["documents", "metadatas"],
        )
        ids = results.get("ids", [[]])[0]
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        return list(zip(ids, docs, metas))

    def retrieve_context(self, query_text, max_categories=MAX_CATEGORIES):
        empty = {"candidates": [], "context": None, "category": "UNKNOWN", "raw_category": "UNKNOWN",
                  "confidence": "NONE", "score": 0.0, "dense_similarity": 0.0, "hyde_degraded": False}

        if not self.collection:
            return {**empty, "context": "RAG context is unavailable due to an initialization error."}
        if self.collection.count() == 0:
            return {**empty, "context": "The RAG knowledge base is empty. Please run indexer.py first."}

        embed_text, hyde_degraded = self._hyde_rewrite(query_text)
        empty["hyde_degraded"] = hyde_degraded

        dense_ranked = self._dense_search(embed_text, DENSE_CANDIDATES)
        sparse_ranked = self._sparse_search(query_text, SPARSE_CANDIDATES)

        if not dense_ranked and not sparse_ranked:
            return {**empty, "context": "No relevant context found in the knowledge base."}

        best_dense_similarity = dense_ranked[0][1] if dense_ranked else 0.0

        candidate_ids = self._fuse(dense_ranked, sparse_ranked, FUSION_CANDIDATES)
        pairs = [(embed_text, self._doc_by_id(doc_id)[0]) for doc_id in candidate_ids]

        case_results = self._dense_search_cases(embed_text, CASE_CANDIDATES)
        case_lookup = {case_id: (case_text, case_meta) for case_id, case_text, case_meta in case_results}
        case_pairs = [(embed_text, case_text) for _, case_text, _ in case_results]

        all_pairs = pairs + case_pairs
        all_scores = self.reranker.predict(all_pairs) if all_pairs else []
        doc_scores = list(zip(candidate_ids, all_scores[:len(pairs)]))
        case_scores = list(zip(case_lookup.keys(), all_scores[len(pairs):]))

        ranked = sorted(
            [("doc", doc_id, score) for doc_id, score in doc_scores]
            + [("case", case_id, score) for case_id, score in case_scores],
            key=lambda x: x[2],
            reverse=True,
        )

        if not ranked:
            return {**empty, "context": "No relevant context found in the knowledge base."}

        candidates = []
        seen_categories = set()
        for origin, item_id, score in ranked:
            score = float(score)
            if origin == "doc":
                doc_text, meta = self._doc_by_id(item_id)
            else:
                doc_text, meta = case_lookup[item_id]
            raw_category = meta.get("source", "unknown").replace(".md", "")
            if raw_category in seen_categories or score < MIN_RERANK_SCORE:
                continue
            seen_categories.add(raw_category)
            confidence = "HIGH" if score > 5 else "MEDIUM"
            candidate = {
                "category": raw_category,
                "raw_category": raw_category,
                "confidence": confidence,
                "score": score,
                "dense_similarity": best_dense_similarity,
                "context": doc_text,
                "origin": meta.get("origin", "doc"),
            }
            if candidate["origin"] == "case":
                candidate["approved_at"] = meta.get("approved_at")
            candidates.append(candidate)
            if len(candidates) >= max_categories:
                break

        if not candidates:
            top_origin, top_id, top_score = ranked[0]
            top_score = float(top_score)
            if top_origin == "doc":
                _, meta = self._doc_by_id(top_id)
            else:
                _, meta = case_lookup[top_id]
            raw_category = meta.get("source", "unknown").replace(".md", "")
            return {
                "candidates": [],
                "context": "No sufficiently relevant context found (below confidence threshold).",
                "category": "UNKNOWN",
                "raw_category": raw_category,
                "confidence": "LOW",
                "score": top_score,
                "dense_similarity": best_dense_similarity,
                "hyde_degraded": hyde_degraded,
            }

        top = candidates[0]
        return {
            "candidates": candidates,
            "context": top["context"],
            "category": top["category"],
            "raw_category": top["raw_category"],
            "confidence": top["confidence"],
            "score": top["score"],
            "dense_similarity": top["dense_similarity"],
            "origin": top.get("origin", "doc"),
            "hyde_degraded": hyde_degraded,
        }


def _origin_label(candidate):
    if candidate.get("origin") == "case":
        approved_at = candidate.get("approved_at", "data desconhecida")
        return f"[caso observado, confirmado em {approved_at}]"
    return "[doc curado]"


def format_rag_block(retrieval):
    candidates = retrieval.get("candidates") or []
    if not candidates:
        header = (f"category={retrieval['category']} confidence={retrieval['confidence']} "
                  f"rerank_score={retrieval['score']:.2f} dense_sim={retrieval['dense_similarity']:.2f}")
        return f"{header}\n{retrieval['context']}"
    return "\n\n".join(
        f"[{_origin_label(c)}] category={c['category']} confidence={c['confidence']} "
        f"rerank_score={c['score']:.2f} dense_sim={c['dense_similarity']:.2f}\n{c['context']}"
        for c in candidates
    )


_PID_PATTERNS = [
    re.compile(r'"pid"\s*:\s*(\d+)'),
    re.compile(r'"p"\s*:\s*(\d+)'),
    re.compile(r'\bPID:\s*(\d+)'),
]
_PPID_PATTERNS = [
    re.compile(r'"ppid"\s*:\s*(\d+)'),
    re.compile(r'"pp"\s*:\s*(\d+)'),
    re.compile(r'\bPPID:\s*(\d+)'),
]


def _extract_pid_ppid(line):
    pid = ppid = None
    for pattern in _PID_PATTERNS:
        match = pattern.search(line)
        if match:
            pid = int(match.group(1))
            break
    for pattern in _PPID_PATTERNS:
        match = pattern.search(line)
        if match:
            ppid = int(match.group(1))
            break
    if pid is None or ppid is None:
        return None
    return pid, ppid


def build_process_tree_block(events):
    pid_ppid = {}
    pid_lines = {}
    for line in events:
        if "[ebpf" not in line:
            continue
        parsed = _extract_pid_ppid(line)
        if not parsed:
            continue
        pid, ppid = parsed
        pid_ppid[pid] = ppid
        pid_lines.setdefault(pid, []).append(line)

    if not pid_lines:
        return ("No process ancestry data available for this batch's events "
                "(none of the underlying probes reported a parent PID here). "
                "Infer causality from timing and process names in the chronological log instead.")

    def find_root(pid):
        seen = set()
        current = pid
        while pid_ppid.get(current) in pid_lines and pid_ppid[current] not in seen:
            seen.add(current)
            current = pid_ppid[current]
        return current

    children_by_root = {}
    for pid in pid_lines:
        children_by_root.setdefault(find_root(pid), []).append(pid)

    blocks = []
    for root, pids in children_by_root.items():
        root_ppid = pid_ppid.get(root)
        note = f" (parent PID {root_ppid}, not seen executing anything in this batch)" if root_ppid is not None else ""
        block = [f"Process root: PID {root}{note}"]
        for line in pid_lines[root]:
            block.append(f"  {line}")
        for pid in sorted(pids):
            if pid == root:
                continue
            block.append(f"  -> child PID {pid} (parent PID {pid_ppid.get(pid)})")
            for line in pid_lines[pid]:
                block.append(f"     {line}")
        blocks.append("\n".join(block))
    return "\n\n".join(blocks)


if __name__ == "__main__":
    print("log_watcher.py is a library and no longer runs standalone.")
    print("  - Production pipeline: python virtual_machine/pipeline_web.py")
    print("  - Manual testing:      python log_watcher_injector.py")
