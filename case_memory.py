import os
from datetime import datetime, timezone

import chromadb
from sentence_transformers import SentenceTransformer

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_DIR = os.path.join(_BASE_DIR, "vector_db")
DOCS_COLLECTION_NAME = "security_docs"
CASES_COLLECTION_NAME = "security_cases"
MODEL_NAME = os.path.join(_BASE_DIR, "models", "cerise-embed-v1")

DOCUMENT_PREFIX = "search_document: "

DEDUP_SIMILARITY_THRESHOLD = 0.95


class DuplicateCaseError(Exception):
    pass


def _load_model():
    return SentenceTransformer(MODEL_NAME, trust_remote_code=True)


def _get_collections(client):
    docs = client.get_or_create_collection(name=DOCS_COLLECTION_NAME, metadata={"hnsw:space": "cosine"})
    cases = client.get_or_create_collection(name=CASES_COLLECTION_NAME, metadata={"hnsw:space": "cosine"})
    return docs, cases


def _closest_similarity(collection, embedding):
    if collection.count() == 0:
        return 0.0, None
    result = collection.query(query_embeddings=[embedding], n_results=1, include=["distances", "documents"])
    distances = result.get("distances", [[]])[0]
    documents = result.get("documents", [[]])[0]
    if not distances:
        return 0.0, None
    return 1.0 - distances[0], (documents[0] if documents else None)


def check_duplicate(summary_text, client=None):
    owns_client = client is None
    client = client or chromadb.PersistentClient(path=DB_DIR)
    docs, cases = _get_collections(client)
    model = _load_model()
    embedding = model.encode([DOCUMENT_PREFIX + summary_text], convert_to_numpy=True).tolist()[0]

    case_sim, case_match = _closest_similarity(cases, embedding)
    doc_sim, doc_match = _closest_similarity(docs, embedding)

    if case_sim >= doc_sim:
        best_sim, best_match = case_sim, case_match
    else:
        best_sim, best_match = doc_sim, doc_match

    return best_sim >= DEDUP_SIMILARITY_THRESHOLD, best_sim, best_match


def approve_case(category, summary_text, batch_id=None, approved_by="human", allow_duplicate=False):
    client = chromadb.PersistentClient(path=DB_DIR)
    docs, cases = _get_collections(client)
    model = _load_model()
    embedding = model.encode([DOCUMENT_PREFIX + summary_text], convert_to_numpy=True).tolist()[0]

    if not allow_duplicate:
        is_dup, similarity, matched_text = check_duplicate(summary_text, client=client)
        if is_dup:
            raise DuplicateCaseError(
                f"Case is {similarity:.3f} cosine-similar to an existing entry "
                f"(threshold {DEDUP_SIMILARITY_THRESHOLD}); not stored. "
                f"Closest match: {matched_text[:200] if matched_text else '?'}"
            )

    approved_at = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    case_id = f"case:{category}:{approved_at}:{cases.count() + 1}"
    cases.upsert(
        ids=[case_id],
        documents=[summary_text],
        embeddings=[embedding],
        metadatas=[{
            "source": f"{category}.md",
            "origin": "case",
            "approved_at": approved_at,
            "approved_by": approved_by,
            "batch_id": batch_id if batch_id is not None else -1,
        }],
    )
    return case_id


def reject_case(reason=""):
    return {"stored": False, "reason": reason}


def list_cases():
    client = chromadb.PersistentClient(path=DB_DIR)
    _, cases = _get_collections(client)
    if cases.count() == 0:
        return []
    data = cases.get(include=["documents", "metadatas"])
    return [
        {"id": doc_id, "text": doc, **meta}
        for doc_id, doc, meta in zip(data["ids"], data["documents"], data["metadatas"])
    ]


if __name__ == "__main__":
    for case in list_cases():
        print(f"[{case['approved_at']}] {case['source']} (batch {case['batch_id']}, "
              f"approved_by={case['approved_by']}): {case['text'][:100]}...")
