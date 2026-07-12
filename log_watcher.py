import os
import chromadb
import sys
import subprocess
import re
import math
from sentence_transformers import SentenceTransformer, CrossEncoder
from rank_bm25 import BM25Okapi
from llama import send_for_analysis

ANSI_ESCAPE_RE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

SERIAL_DEVICES = ["/dev/pts/0", "/dev/pts/1", "/dev/pts/2", "/dev/pts/3", "/dev/pts/4", "/dev/pts/5", "/dev/pts/6", "/dev/pts/7", "/dev/pts/8", "/dev/pts/9", "/dev/pts/10", "/dev/pts/11", "/dev/pts/12"]
HOST_LISTENER_PATH = "virtual_machine/host_listener"

DB_DIR = "vector_db"
COLLECTION_NAME = "security_docs"
MODEL_NAME = "nomic-ai/nomic-embed-text-v1.5"
RERANK_MODEL_NAME = "cross-encoder/ms-marco-MiniLM-L-6-v2"

# nomic-embed-text-v1.5 requires this task prefix on queries (documents were indexed
# with "search_document: " in indexer.py). Same model, different prefix per side of
# the asymmetric retrieval task -- see indexer.py for the matching document-side prefix.
QUERY_PREFIX = "search_query: "

DENSE_CANDIDATES = 8   # shortlist pulled from the bi-encoder (embedding) index
SPARSE_CANDIDATES = 8  # shortlist pulled from BM25 (lexical) search
FUSION_CANDIDATES = 5  # size of the RRF-fused shortlist handed to the cross-encoder
RRF_K = 60              # standard damping constant for Reciprocal Rank Fusion

# Below this cross-encoder score, the closest fact sheet is still "closest" but not
# actually relevant -- reject it instead of forcing a misleading category onto the
# LLM. NOT a magic number: calibrated by eval_rag.py (Youden's J sweep) against the
# synthetic labeled set, which found this threshold gives 0% false-positive rate at
# 56% recall on 27 known-category examples. Re-run eval_rag.py and update this value
# once real production logs are available -- the synthetic set is a bootstrap only.
MIN_RERANK_SCORE = -5.42

BATCH_SIZE = 1

HYDE_ENABLED = True
# Raw bpftrace/log lines are out-of-distribution for an embedding model trained on
# natural language (the RAG_docs fact sheets). HyDE bridges that domain gap by having
# the LLM restate the log as a descriptive sentence *before* embedding it, so the
# query lands in the same "prose" region of the embedding space as the documents.
# This costs one extra local LLM call per batch; set HYDE_ENABLED=False to trade
# retrieval quality for latency.
HYDE_PROMPT = """### Instruction:
Rewrite the following raw system log line as a single short, plain-English sentence describing what security-relevant action it represents. Do not judge whether it is malicious. Output ONLY the sentence, nothing else.

### Input:
{log_content}

### Response:
"""

PROMPT_TEMPLATE = """### Instruction:
Act as a cybersecurity analyst. Review the logs below for malicious activity based on the provided context.
If you detect a threat (e.g. unauthorized access, suspicious execution, log tampering), mark it as THREAT.
Otherwise, mark it as SAFE.

Format that you need to follow:
VERDICT: <SAFE/THREAT>
SEVERITY: <1-5>
ANALYSIS: <Short explanation>

### Context:
Closest known category: {category} (retrieval confidence: {confidence}, rerank score: {score:.2f})
{rag_context}

### Input Logs:
{log_content}

### Response:
"""


def _tokenize(text):
    return re.findall(r"[a-zA-Z0-9_./-]+", text.lower())


class RagRetriever:
    def __init__(self):
        self.collection = None
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

            if self.collection.count() > 0:
                data = self.collection.get(include=["documents", "metadatas"])
                self.corpus_ids = data["ids"]
                self.corpus_docs = data["documents"]
                self.corpus_meta = data["metadatas"]
                # BM25 catches exact lexical matches (syscall names, paths) that dense
                # embeddings can blur; corpus is small enough to hold entirely in memory.
                self.bm25 = BM25Okapi([_tokenize(d) for d in self.corpus_docs])

            print("RAG retriever is ready.")
        except Exception as e:
            print(f"Error initializing RAG retriever: {e}\nAnalysis will proceed without RAG context.")

    def _hyde_rewrite(self, log_content):
        if not HYDE_ENABLED:
            return log_content
        rewritten = send_for_analysis(HYDE_PROMPT.format(log_content=log_content))
        if not rewritten or rewritten.strip().startswith("[ERROR]"):
            return log_content
        return rewritten.strip()

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
        # chromadb's "cosine" hnsw space reports distance = 1 - cosine_similarity.
        return [(doc_id, 1 - dist) for doc_id, dist in zip(ids, distances)]

    def _sparse_search(self, raw_text, n_results):
        if not self.bm25:
            return []
        scores = self.bm25.get_scores(_tokenize(raw_text))
        ranked = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:n_results]
        return [(self.corpus_ids[i], scores[i]) for i in ranked if scores[i] > 0]

    def _fuse(self, dense_ranked, sparse_ranked, top_n):
        # Reciprocal Rank Fusion combines two rankings whose raw scores live on
        # different, non-comparable scales (cosine similarity vs. BM25) by using only
        # rank position -- no score normalization/calibration needed between them.
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

    def retrieve_context(self, query_text):
        empty = {"context": None, "category": "UNKNOWN", "raw_category": "UNKNOWN", "confidence": "NONE", "score": 0.0, "dense_similarity": 0.0}

        if not self.collection:
            return {**empty, "context": "RAG context is unavailable due to an initialization error."}
        if self.collection.count() == 0:
            return {**empty, "context": "The RAG knowledge base is empty. Please run indexer.py first."}

        embed_text = self._hyde_rewrite(query_text)

        dense_ranked = self._dense_search(embed_text, DENSE_CANDIDATES)
        # BM25 always runs against the raw log text: it matches literal tokens
        # (syscall names, paths) that a HyDE paraphrase could reword or drop.
        sparse_ranked = self._sparse_search(query_text, SPARSE_CANDIDATES)

        if not dense_ranked and not sparse_ranked:
            return {**empty, "context": "No relevant context found in the knowledge base."}

        best_dense_similarity = dense_ranked[0][1] if dense_ranked else 0.0

        candidate_ids = self._fuse(dense_ranked, sparse_ranked, FUSION_CANDIDATES)
        pairs = [(query_text, self._doc_by_id(doc_id)[0]) for doc_id in candidate_ids]
        rerank_scores = self.reranker.predict(pairs) if pairs else []
        ranked = sorted(zip(candidate_ids, rerank_scores), key=lambda x: x[1], reverse=True)

        if not ranked:
            return {**empty, "context": "No relevant context found in the knowledge base."}

        top_id, top_score = ranked[0]
        top_score = float(top_score)
        doc_text, meta = self._doc_by_id(top_id)
        raw_category = meta.get("source", "unknown").replace(".md", "")

        if top_score < MIN_RERANK_SCORE:
            return {
                "context": "No sufficiently relevant context found (below confidence threshold).",
                "category": "UNKNOWN",
                "raw_category": raw_category,
                "confidence": "LOW",
                "score": top_score,
                "dense_similarity": best_dense_similarity,
            }

        confidence = "HIGH" if top_score > 5 else "MEDIUM"

        return {
            "context": doc_text,
            "category": raw_category,
            "raw_category": raw_category,
            "confidence": confidence,
            "score": top_score,
            "dense_similarity": best_dense_similarity,
        }


def format_rag_block(retrieval):
    header = (f"category={retrieval['category']} confidence={retrieval['confidence']} "
              f"rerank_score={retrieval['score']:.2f} dense_sim={retrieval['dense_similarity']:.2f}")
    return f"{header}\n{retrieval['context']}"


def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')


def show_header():
    clear_screen()

    print(" > CERISE <")



def emit_line(message):
    sys.stdout.write(f"\r\033[K{message}\n")
    sys.stdout.flush()


def print_block(tag, title, content):
    emit_line(f"[{tag}] {title}")
    for block_line in content.splitlines():
        emit_line(f"      {block_line}")


def sanitize_output_line(line):
    line = ANSI_ESCAPE_RE.sub('', line)
    line = line.replace('\r', '')
    line = ''.join(ch for ch in line if ch.isprintable() or ch == '\t')
    return line.strip()


def main():
    show_header()

    if not os.path.exists(HOST_LISTENER_PATH) or not os.access(HOST_LISTENER_PATH, os.X_OK):
        print(f"[ERROR] Listener executable not found or not executable at '{HOST_LISTENER_PATH}'.")
        print("Please compile it first, for example:")
        print("  gcc -o virtual_machine/host_listener virtual_machine/host_listener.c -lssl -lcrypto")
        return

    proc = None

    try:
        emit_line(f"[INFO] Starting host_listener for: {', '.join(SERIAL_DEVICES)}")
        emit_line("[INFO] Raw logs and AI analysis will be displayed in this same window.")
        emit_line("[INFO] Press Ctrl+C to stop.")

        rag_retriever = RagRetriever()

        stream_states = {device: {'pending_lines': []} for device in SERIAL_DEVICES}
        if len(SERIAL_DEVICES) == 1:
            stream_states["default"] = {'pending_lines': []}

        command = ['stdbuf', '-o0', HOST_LISTENER_PATH] + SERIAL_DEVICES

        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        use_prefix_parsing = len(SERIAL_DEVICES) > 1

        for line in proc.stdout:
            line = sanitize_output_line(line)
            if not line:
                continue

            emit_line(f"[RAW] {line}")

            if "Waiting for encrypted data" in line or "Connection closed" in line:
                continue

            stream_id = "default"
            log_content = line

            if use_prefix_parsing:
                match = re.match(r'^\[([^\]]+)\]\s*(.*)', line)
                if match:
                    stream_id = match.group(1)
                    log_content = match.group(2).strip()
                else:
                    continue

            if "Attaching " in log_content and "probes" in log_content:
                emit_line(f"[INFO] Skipping bpftrace header for stream '{stream_id}': {log_content}")
                continue

            if stream_id not in stream_states:
                emit_line(f"[WARNING] Received data from an unexpected stream: {stream_id}")
                continue

            state = stream_states[stream_id]
            state['pending_lines'].append(log_content)

            if len(state['pending_lines']) >= BATCH_SIZE:
                batch_to_send = state['pending_lines'][:BATCH_SIZE]
                state['pending_lines'] = state['pending_lines'][BATCH_SIZE:]

                emit_line("")
                emit_line(f"[BATCH] Stream='{stream_id}' | Events={len(batch_to_send)} | Status=ready for analysis")
                log_batch_content = "\n".join(batch_to_send)

                retrieval = rag_retriever.retrieve_context(log_batch_content)

                print_block("RAG", f"Context retrieved for stream '{stream_id}'", format_rag_block(retrieval))

                full_prompt = PROMPT_TEMPLATE.format(
                    category=retrieval["category"],
                    confidence=retrieval["confidence"],
                    score=retrieval["score"],
                    rag_context=retrieval["context"],
                    log_content=log_batch_content,
                )

                emit_line(f"[AI] Starting processing of batch with {len(batch_to_send)} events from stream '{stream_id}'...")
                analysis = send_for_analysis(full_prompt)
                if analysis:
                    print_block("AI", f"Analysis result for stream '{stream_id}'", analysis)

    except KeyboardInterrupt:
        emit_line("")
        emit_line("[INFO] Stopping Cerise Log Watcher.")
    except Exception as e:
        emit_line("")
        emit_line(f"[ERROR] An unexpected error occurred: {e}")
    finally:
        if proc and proc.poll() is None:
            emit_line("[INFO] Terminating the listener process...")
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                emit_line("[WARNING] The listener did not terminate, forcing shutdown.")
                proc.kill()
            emit_line("[INFO] Listener stopped.")

if __name__ == "__main__":
    main()
