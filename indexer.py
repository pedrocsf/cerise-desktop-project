import os
import re
import chromadb
from sentence_transformers import SentenceTransformer
from tqdm import tqdm

DOCS_DIR = "RAG_docs"
DB_DIR = "vector_db"
COLLECTION_NAME = "security_docs"
MODEL_NAME = "nomic-ai/nomic-embed-text-v1.5"

# nomic-embed-text-v1.5 was trained with asymmetric task prefixes: passages must be
# embedded as "search_document: ..." and queries as "search_query: ...". Mixing this up
# (or omitting it) makes the model fall back to a much weaker general-purpose projection.
DOCUMENT_PREFIX = "search_document: "

# All fact sheets in RAG_docs share this exact section structure. Splitting on these
# headings gives passage-level chunks (one concept per vector) instead of one giant,
# semantically-averaged embedding per file.
SECTION_HEADERS = [
    "Script Objective",
    "Anomaly Patterns",
    "Normal Patterns (Common False Positives)",
    "Base Criticality Level",
    "Suggested Correlation",
]
_SECTION_SPLIT_RE = re.compile(
    r'(?=^(?:' + '|'.join(re.escape(h) for h in SECTION_HEADERS) + r')$)',
    re.MULTILINE,
)


def chunk_document(content):
    """Split a fact sheet into one chunk per section, each tagged with its heading."""
    title, _, body = content.strip().partition("\n")
    raw_sections = _SECTION_SPLIT_RE.split(body)

    chunks = []
    for raw in raw_sections:
        raw = raw.strip()
        if not raw:
            continue
        heading, _, _ = raw.partition("\n")
        chunks.append({"text": f"{title}\n\n{raw}", "section": heading.strip()})
    return chunks


def create_or_update_index():
    """
    Reads documents from the RAG_docs folder, transforms them into vectors,
    and stores/updates them in a ChromaDB vector database.
    """
    if not os.path.exists(DOCS_DIR):
        print(f"Error: Document directory '{DOCS_DIR}' not found.")
        return

    print("Initializing the indexer...")
    print(f"Loading embedding model '{MODEL_NAME}'. This may take a while on the first run...")
    model = SentenceTransformer(MODEL_NAME, trust_remote_code=True)

    client = chromadb.PersistentClient(path=DB_DIR)

    # No embedding_function attached: embeddings are computed manually below so that
    # documents and queries can use different task prefixes (see DOCUMENT_PREFIX above
    # and the matching search_query prefix used in the retrievers).
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},
    )

    print(f"Processing documents from directory: '{DOCS_DIR}'...")

    doc_files = [f for f in os.listdir(DOCS_DIR) if f.endswith(".md")]

    for filename in tqdm(doc_files, desc="Indexing documents"):
        filepath = os.path.join(DOCS_DIR, filename)
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        chunks = chunk_document(content)
        if not chunks:
            continue

        ids = [f"{filename}:{i}" for i, _ in enumerate(chunks)]
        documents = [c["text"] for c in chunks]
        metadatas = [{"source": filename, "section": c["section"]} for c in chunks]
        embeddings = model.encode(
            [DOCUMENT_PREFIX + d for d in documents],
            convert_to_numpy=True,
        ).tolist()

        collection.upsert(ids=ids, documents=documents, metadatas=metadatas, embeddings=embeddings)

    print("\nIndexing completed successfully!")
    print(f"Total documents in collection '{COLLECTION_NAME}': {collection.count()}")

if __name__ == "__main__":
    create_or_update_index()
