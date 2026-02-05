import os
import time
from llama import send_for_analysis
import chromadb
from chromadb.utils import embedding_functions

LOG_DIR = "logs"
POLL_INTERVAL = 2      
HEADER_SKIP_LINES = 0  

# --- RAG Configuration ---
DB_DIR = "vector_db"
COLLECTION_NAME = "security_docs"
MODEL_NAME = "nomic-ai/nomic-embed-text-v1.5"
CONTEXT_RESULTS = 1


CRITICAL_SCRIPTS = [
    "sensitive_file_access",
    "suspicious_exec",
    "dangerous_syscalls",
    "privilege_escalation",
    "network_suspicious",
    "kernel_module_load",
    "fileless_execution",
    "docker_socket_access",
    "log_tampering",
    "test"
]

BATCH_SIZE = 50

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
{log_batch}

### Response:
"""

class RagRetriever:
    """Handles the connection and querying of the vector database."""
    def __init__(self):
        self.collection = None
        try:
            print("Initializing RAG retriever...")
            client = chromadb.PersistentClient(path=DB_DIR)
            embedding_function = embedding_functions.SentenceTransformerEmbeddingFunction(
                model_name=MODEL_NAME,
                trust_remote_code=True
            )
            self.collection = client.get_collection(
                name=COLLECTION_NAME,
                embedding_function=embedding_function
            )
            print("RAG retriever initialized successfully.")
        except Exception as e:
            print(f"Error initializing RAG retriever: {e}\nAnalysis will proceed without RAG context.")

    def retrieve_context(self, query_text, n_results=CONTEXT_RESULTS):
        if not self.collection:
            return "RAG context is unavailable due to an initialization error."
        
        results = self.collection.query(query_texts=[query_text], n_results=n_results)
        context_docs = results.get('documents', [[]])[0]
        if not context_docs:
            return "No relevant context found in the knowledge base."
        return "\n\n---\n\n".join(context_docs)

def is_critical(log_filename):
    """Checks if the log filename corresponds to a critical script."""
    for script_name in CRITICAL_SCRIPTS:
        if script_name in log_filename:
            return True
    return False

def clear_screen():
    """Clears the terminal screen."""
    os.system('clear' if os.name == 'posix' else 'cls')

def show_header():
    """Displays the program header."""
    clear_screen()
    print("╔════════════════════════════════════════════════════════════╗")
    print("║            CERISE LOG WATCHER - CONTINUOUS ANALYSIS            ║")
    print("╚════════════════════════════════════════════════════════════╝\n")

def main():
    show_header()
    print("Starting Cerise Log Watcher for continuous AI analysis...")
    print(f"Monitoring directory: '{LOG_DIR}'")
    print(f"Critical scripts: {', '.join(CRITICAL_SCRIPTS)}")
    print("Press Ctrl+C to stop.")

    rag_retriever = RagRetriever()
    file_states = {}

    try:
        while True:
            for filename in os.listdir(LOG_DIR):
                if not filename.endswith(".log"):
                    continue

                filepath = os.path.join(LOG_DIR, filename)

                if not is_critical(filename):
                    continue

                state = file_states.setdefault(filepath, {'pos': 0, 'lines_seen': 0, 'pending_lines': []})

                try:
                    with open(filepath, 'r') as f:
                        f.seek(state['pos'])
                        new_lines = f.readlines()
                        state['pos'] = f.tell()

                    if not new_lines:
                        continue

                    for line in new_lines:
                        state['lines_seen'] += 1
                        if state['lines_seen'] > HEADER_SKIP_LINES and line.strip():
                            state['pending_lines'].append(line)

                    while len(state['pending_lines']) >= BATCH_SIZE:
                        batch_to_send = state['pending_lines'][:BATCH_SIZE]
                        state['pending_lines'] = state['pending_lines'][BATCH_SIZE:]

                        print(f"\n--- Batch of {len(batch_to_send)} critical events from '{filename}' ready for analysis ---")
                        
                        log_batch_content = "".join(batch_to_send)

                        # 1. Retrieve relevant context from the vector DB
                        rag_context = rag_retriever.retrieve_context(log_batch_content)
                        
                        # --- DEBUG: Print the retrieved context ---
                        print("═════════ RETRIEVED RAG CONTEXT ═════════")
                        print(rag_context)
                        print("═════════════════════════════════════════")

                        # 2. Augment the prompt with the retrieved context
                        full_prompt = PROMPT_TEMPLATE.format(rag_context=rag_context, log_batch=log_batch_content)

                        print("Analyzing with AI...")
                        analysis = send_for_analysis(full_prompt)
                        if analysis:
                            print("═══════════ AI ANALYSIS ═══════════")
                            print(analysis)
                            print("═══════════════════════════════════")

                except FileNotFoundError:
                    if filepath in file_states:
                        del file_states[filepath]
                    continue
                except Exception as e:
                    print(f"Error processing file {filepath}: {e}")

            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print("\nStopping Cerise Log Watcher.")

if __name__ == "__main__":
    if not os.path.exists(LOG_DIR):
        print(f"Error: Log directory '{LOG_DIR}' not found. Run a background script first.")
    else:
        main()