import os
import chromadb
from chromadb.utils import embedding_functions
import sys
import subprocess
import re
from llama import send_for_analysis

ANSI_ESCAPE_RE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

SERIAL_DEVICES = ["/dev/pts/4", "/dev/pts/5", "/dev/pts/6", "/dev/pts/7"]
HOST_LISTENER_PATH = "virtual_machine/host_listener"

DB_DIR = "vector_db"
COLLECTION_NAME = "security_docs"
MODEL_NAME = "nomic-ai/nomic-embed-text-v1.5"
CONTEXT_RESULTS = 1

BATCH_SIZE = 1

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
            self.collection = client.get_collection(
                name=COLLECTION_NAME,
                embedding_function=embedding_function
            )
            print("RAG retriever is ready.")
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


def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')


def show_header():
    clear_screen()
    print("╔════════════════════════════════════════════════════════════╗")
    print("║            CERISE LOG WATCHER - CONTINUOUS ANALYSIS         ║")
    print("╚════════════════════════════════════════════════════════════╝\n")


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

                rag_context = rag_retriever.retrieve_context(log_batch_content)

                print_block("RAG", f"Context retrieved for stream '{stream_id}'", rag_context)

                full_prompt = PROMPT_TEMPLATE.format(rag_context=rag_context, log_content=log_batch_content)

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