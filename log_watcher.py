"""RAG retrieval library for the Cerise pipeline.

This module is not a standalone entry point. Production flow lives in
virtual_machine/pipeline_web.py, which consumes RagRetriever for every
analysis batch. For manual/interactive testing use log_watcher_injector.py.
"""

import os
import re
import chromadb
from sentence_transformers import SentenceTransformer, CrossEncoder
from rank_bm25 import BM25Okapi
from llama import send_for_analysis

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_DIR = os.path.join(_BASE_DIR, "vector_db")
COLLECTION_NAME = "security_docs"
# Fine-tuned from nomic-ai/nomic-embed-text-v1.5 by finetune_embeddings.py
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
HYDE_PROMPT = """### Instruction:
The input below may contain multiple unrelated security-relevant actions mixed with benign noise (background DNS, ICMP, routine service activity). Input lines are tagged [ebpf] for kernel-level syscall traces or [network:...] for captured network packets.
List, one per line, the distinct security-relevant actions present (max 5). Each line: a short, plain-English sentence describing what the action does. Ignore benign/routine noise. Do not judge whether any action is malicious. If there is truly only one relevant action, output one line. Output ONLY the list, nothing else.

### Input:
{log_content}

### Response:
"""

PROMPT_TEMPLATE = """### Instruction:
Act as a cybersecurity analyst. Review the logs below for malicious activity based on the provided context.

Events tagged [ebpf] are kernel-level syscall traces; events tagged [network:...] are captured network packets. When an ebpf event is followed shortly after by related network activity from the same process, treat them as one causal chain, not independent findings.

Each category block under Context is a retrieval hypothesis, not a verified fact. Cross-check it against the raw input logs before trusting it:
- HIGH confidence: treat its Anomaly Patterns as a strong prior, but still confirm they match the actual input.
- MEDIUM confidence: treat it only as a hint; weigh the raw log evidence more heavily than the label.
- LOW confidence, UNKNOWN category, or a Context block saying no relevant context was found: ignore that category label entirely and analyze the affected input using your own security knowledge.
If two or more retrieved categories are both plausible, read their Suggested Correlation sections to judge whether the input matches the pattern of them occurring together.

Mark VERDICT as THREAT when you find clear malicious activity (e.g. unauthorized access, suspicious execution, log tampering), SUSPICIOUS when the input matches a Normal Pattern (common false positive) about as plausibly as it matches an Anomaly Pattern, or when correlation with another category would be needed to be sure, or SAFE otherwise.

SEVERITY must start from the Base Criticality Level of whichever retrieved category you judge most relevant (if any), then adjust up or down based on how strongly the raw logs corroborate its Anomaly Patterns and whether multiple categories correlate together. State that adjustment reasoning in ANALYSIS.

ANALYSIS must (a) state whether you agree with each retrieved category above, and (b) cite at least one concrete piece of evidence from the input (process name, pid, path, ip:port, or similar) supporting the verdict.

Format that you need to follow:
VERDICT: <SAFE/SUSPICIOUS/THREAT>
SEVERITY: <1-5>
ANALYSIS: <Short explanation>

### Context (top matching categories, most to least relevant):
{rag_context}

### Input Logs:
{log_content}

### Response:
"""


def _tokenize(text):
    return re.findall(r"[a-zA-Z0-9_./-]+", text.lower())


class RagRetriever:
    def __init__(self, hyde_llm=send_for_analysis):
        self.hyde_llm = hyde_llm
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
                self.bm25 = BM25Okapi([_tokenize(d) for d in self.corpus_docs])

            print("RAG retriever is ready.")
        except Exception as e:
            print(f"Error initializing RAG retriever: {e}\nAnalysis will proceed without RAG context.")

    def _hyde_rewrite(self, log_content):
        if not HYDE_ENABLED:
            return log_content
        rewritten = self.hyde_llm(HYDE_PROMPT.format(log_content=log_content))
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

    def retrieve_context(self, query_text, max_categories=MAX_CATEGORIES):
        """Returns up to `max_categories` distinct best-matching RAG_docs categories
        (not just the single top chunk), so multi-technique batches can surface more
        than one Anomaly Patterns / Suggested Correlation section to the prompt.
        """
        empty = {"candidates": [], "context": None, "category": "UNKNOWN", "raw_category": "UNKNOWN",
                  "confidence": "NONE", "score": 0.0, "dense_similarity": 0.0}

        if not self.collection:
            return {**empty, "context": "RAG context is unavailable due to an initialization error."}
        if self.collection.count() == 0:
            return {**empty, "context": "The RAG knowledge base is empty. Please run indexer.py first."}

        embed_text = self._hyde_rewrite(query_text)

        dense_ranked = self._dense_search(embed_text, DENSE_CANDIDATES)
        sparse_ranked = self._sparse_search(query_text, SPARSE_CANDIDATES)

        if not dense_ranked and not sparse_ranked:
            return {**empty, "context": "No relevant context found in the knowledge base."}

        best_dense_similarity = dense_ranked[0][1] if dense_ranked else 0.0

        candidate_ids = self._fuse(dense_ranked, sparse_ranked, FUSION_CANDIDATES)
        pairs = [(embed_text, self._doc_by_id(doc_id)[0]) for doc_id in candidate_ids]
        rerank_scores = self.reranker.predict(pairs) if pairs else []
        ranked = sorted(zip(candidate_ids, rerank_scores), key=lambda x: x[1], reverse=True)

        if not ranked:
            return {**empty, "context": "No relevant context found in the knowledge base."}

        candidates = []
        seen_categories = set()
        for doc_id, score in ranked:
            score = float(score)
            doc_text, meta = self._doc_by_id(doc_id)
            raw_category = meta.get("source", "unknown").replace(".md", "")
            # Keep only the best-scoring chunk per category, so max_categories means
            # max_categories distinct docs, not distinct chunks of the same doc.
            if raw_category in seen_categories or score < MIN_RERANK_SCORE:
                continue
            seen_categories.add(raw_category)
            confidence = "HIGH" if score > 5 else "MEDIUM"
            candidates.append({
                "category": raw_category,
                "raw_category": raw_category,
                "confidence": confidence,
                "score": score,
                "dense_similarity": best_dense_similarity,
                "context": doc_text,
            })
            if len(candidates) >= max_categories:
                break

        if not candidates:
            top_id, top_score = ranked[0]
            top_score = float(top_score)
            _, meta = self._doc_by_id(top_id)
            raw_category = meta.get("source", "unknown").replace(".md", "")
            return {
                "candidates": [],
                "context": "No sufficiently relevant context found (below confidence threshold).",
                "category": "UNKNOWN",
                "raw_category": raw_category,
                "confidence": "LOW",
                "score": top_score,
                "dense_similarity": best_dense_similarity,
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
        }


def format_rag_block(retrieval):
    candidates = retrieval.get("candidates") or []
    if not candidates:
        header = (f"category={retrieval['category']} confidence={retrieval['confidence']} "
                  f"rerank_score={retrieval['score']:.2f} dense_sim={retrieval['dense_similarity']:.2f}")
        return f"{header}\n{retrieval['context']}"

    blocks = []
    for c in candidates:
        header = (f"category={c['category']} confidence={c['confidence']} "
                  f"rerank_score={c['score']:.2f} dense_sim={c['dense_similarity']:.2f}")
        blocks.append(f"{header}\n{c['context']}")
    return "\n\n---\n\n".join(blocks)


if __name__ == "__main__":
    print("log_watcher.py is a library and no longer runs standalone.")
    print("  - Production pipeline: python virtual_machine/pipeline_web.py")
    print("  - Manual testing:      python log_watcher_injector.py")
