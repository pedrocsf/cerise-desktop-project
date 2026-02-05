import chromadb
import pprint
import os

DB_DIR = "vector_db"
COLLECTION_NAME = "security_docs"

def read_vector_db():
    """
    Connects to the ChromaDB and prints its contents for verification.
    """
    if not os.path.exists(DB_DIR):
        print(f"Error: Database directory '{DB_DIR}' not found.")
        print("Please run the 'indexer.py' script first to create the database.")
        return

    print(f"Connecting to database in '{DB_DIR}'...")
    try:
        client = chromadb.PersistentClient(path=DB_DIR)
        collection = client.get_collection(name=COLLECTION_NAME)
    except Exception as e:
        print(f"Error connecting to the database: {e}")
        return

    print(f"\nReading all entries from collection '{COLLECTION_NAME}'...\n")
    
    results = collection.get(include=["metadatas", "documents"])

    if not results or not results.get('ids'):
        print("The collection appears to be empty.")
        return

    pprint.pprint(results)
    print(f"\nTotal items found: {len(results['ids'])}")

if __name__ == "__main__":
    read_vector_db()