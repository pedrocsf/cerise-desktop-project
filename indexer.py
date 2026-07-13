import os
import re
import chromadb
from sentence_transformers import SentenceTransformer
from tqdm import tqdm

DOCS_DIR = "RAG_docs"
DB_DIR = "vector_db"
COLLECTION_NAME = "security_docs"
# Fine-tuned from nomic-ai/nomic-embed-text-v1.5 by finetune_embeddings.py
MODEL_NAME = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "cerise-embed-v1")

DOCUMENT_PREFIX = "search_document: "

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
    if not os.path.exists(DOCS_DIR):
        print(f"Error: Document directory '{DOCS_DIR}' not found.")
        return

    print("Initializing the indexer...")
    print(f"Loading embedding model '{MODEL_NAME}'. This may take a while on the first run...")
    model = SentenceTransformer(MODEL_NAME, trust_remote_code=True)

    client = chromadb.PersistentClient(path=DB_DIR)

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
