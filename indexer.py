import os
import chromadb
from chromadb.utils import embedding_functions
from tqdm import tqdm
import re

DOCS_DIR = "RAG_docs"
DB_DIR = "vector_db"
COLLECTION_NAME = "security_docs"
MODEL_NAME = "nomic-ai/nomic-embed-text-v1.5" 

def create_or_update_index():
    """
    Reads documents from the RAG_docs folder, transforms them into vectors,
    and stores/updates them in a ChromaDB vector database.
    """
    if not os.path.exists(DOCS_DIR):
        print(f"Error: Document directory '{DOCS_DIR}' not found.")
        return

    print("Initializing the indexer...")

    # Initialize the ChromaDB client for persistent storage
    client = chromadb.PersistentClient(path=DB_DIR)

    #  Create the embedding function using sentence-transformers
    embedding_function = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=MODEL_NAME,
        trust_remote_code=True
    )

    #  Get or create the collection in the database
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=embedding_function,
        metadata={"hnsw:space": "cosine"} # Using cosine distance, good for text
    )

    print(f"Processing documents from directory: '{DOCS_DIR}'...")

    #  Iterate over the files and process them
    doc_files = [f for f in os.listdir(DOCS_DIR) if f.endswith(".md")]
    
    for filename in tqdm(doc_files, desc="Indexing documents"):
        filepath = os.path.join(DOCS_DIR, filename)
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        #  Split the document into chunks by section (##) for more focused context
        chunks = re.split(r'(?=## )', content)
        chunks = [chunk.strip() for chunk in chunks if chunk.strip()]

        if not chunks:
            continue

        # Prepare the data to be added to the collection
        ids = [f"{filename}:{i}" for i, _ in enumerate(chunks)]
        metadatas = [{"source": filename} for _ in chunks]

        # 7. Add (or update, if the ID already exists) the chunks to the collection
        collection.upsert(ids=ids, documents=chunks, metadatas=metadatas)

    print("\nIndexing completed successfully!")
    print(f"Total documents in collection '{COLLECTION_NAME}': {collection.count()}")

if __name__ == "__main__":
    create_or_update_index()