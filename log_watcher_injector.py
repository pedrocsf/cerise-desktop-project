import os
import chromadb
from chromadb.utils import embedding_functions
import sys
import re
from llama import send_for_analysis 

ANSI_ESCAPE_RE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

DB_DIR = "vector_db"
COLLECTION_NAME = "security_docs"
MODEL_NAME = "nomic-ai/nomic-embed-text-v1.5"
CONTEXT_RESULTS = 1

PROMPT_TEMPLATE = """### Instruction:
Act as a cybersecurity analyst. Review the logs below for malicious activity based on the provided context.
If you detect a threat (e.g. unauthorized access, suspicious execution, log tampering), mark it as THREAT.
Otherwise, mark it as SAFE.

Format that you need to follow:
VERDICT: <SAFE/THREAT>
SEVERITY: <1-5>
ANALYSIS: <Short explanation>

### Context:
{rag_context}

### Input Logs:
{log_content}

### Response:
"""


class RagRetriever:
    def __init__(self):
        self.collection = None
        try:
            print("Initializing RAG retriever...")
            print(f"Loading embedding model '{MODEL_NAME}'. This may take a while on the first run...")
            embedding_function = embedding_functions.SentenceTransformerEmbeddingFunction(
                model_name=MODEL_NAME,
                trust_remote_code=True
            )
            print("Embedding model loaded.")

            print(f"Connecting to vector database at '{DB_DIR}'...")
            client = chromadb.PersistentClient(path=DB_DIR)
            self.collection = client.get_or_create_collection( 
                name=COLLECTION_NAME,
                embedding_function=embedding_function
            )
            print("RAG retriever is ready.")
        except Exception as e:
            print(f"Error initializing RAG retriever: {e}\nAnalysis will proceed without RAG context.")

    def retrieve_context(self, query_text, n_results=CONTEXT_RESULTS):
        if not self.collection:
            return "RAG context is unavailable due to an initialization error."
   
        if self.collection.count() == 0:
            return "The RAG knowledge base is empty. Please run indexer.py first."

        results = self.collection.query(query_texts=[query_text], n_results=n_results)
        context_docs = results.get('documents', [[]])[0]
        if not context_docs:
            return "No relevant context found in the knowledge base."
        return "\n\n---\n\n".join(context_docs)


def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')


def show_header():
    clear_screen()
    print(" > CERISE <")
    print("Type your log input below. Type 'exit' or 'quit' to stop.")
    print("-" * 40)


def emit_line(message):
    sys.stdout.write(f"\r\033[K{message}\n")
    sys.stdout.flush()


def print_block(tag, title, content):
    emit_line(f"[{tag}] {title}")
    for block_line in content.splitlines():
        emit_line(f"      {block_line}")


def main():
    show_header()
    
    rag_retriever = RagRetriever()

    try:
        while True:
            user_input = input("\n[INPUT] Enter log content (or 'exit'/'quit' to stop): ").strip()

            if user_input.lower() in ['exit', 'quit']:
                break
            
            if not user_input:
                emit_line("[INFO] Input is empty. Please enter some log content.")
                continue

            emit_line(f"\n[USER] Processing input: '{user_input}'")

            rag_context = rag_retriever.retrieve_context(user_input)
            print_block("RAG", "Context retrieved", rag_context)

            full_prompt = PROMPT_TEMPLATE.format(rag_context=rag_context, log_content=user_input)

            emit_line("[AI] Starting analysis...")
            analysis = send_for_analysis(full_prompt)
            if analysis:
                print_block("AI", "Analysis result", analysis)
            else:
                emit_line("[AI] No analysis result received.")

    except KeyboardInterrupt:
        emit_line("\n[INFO] Exiting interactive analyzer.")
    except Exception as e:
        emit_line(f"\n[ERROR] An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()