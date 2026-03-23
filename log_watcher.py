import os
import chromadb
from chromadb.utils import embedding_functions
import sys
import subprocess
import re
from llama import send_for_analysis

# --- Configuration ---
SERIAL_DEVICES = ["/dev/pts/4", "/dev/pts/5", "/dev/pts/6", "/dev/pts/7"]
HOST_LISTENER_PATH = "virtual_machine/host_listener"

DB_DIR = "vector_db"
COLLECTION_NAME = "security_docs"
MODEL_NAME = "nomic-ai/nomic-embed-text-v1.5"
CONTEXT_RESULTS = 1

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
{log_content}

### Response:
"""

class RagRetriever:
    """Handles the connection and querying of the vector database."""
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
    """Clears the terminal screen."""
    os.system('clear' if os.name == 'posix' else 'cls')

def show_header():
    """Displays the program header."""
    clear_screen()
    print("╔════════════════════════════════════════════════════════════╗")
    print("║            CERISE LOG WATCHER - CONTINUOUS ANALYSIS            ║")
    print("╚════════════════════════════════════════════════════════════╝\n")

def main():
    """
    Executa o host_listener, captura sua saída ao vivo e a envia em
    lotes para análise de IA.
    """
    show_header()

    if not os.path.exists(HOST_LISTENER_PATH) or not os.access(HOST_LISTENER_PATH, os.X_OK):
        print(f"[ERRO] Executável do listener não encontrado ou não executável em '{HOST_LISTENER_PATH}'.")
        print("Por favor, compile-o primeiro, por exemplo:")
        print("  gcc -o virtual_machine/host_listener virtual_machine/host_listener.c -lssl -lcrypto")
        return

    print(f"Iniciando o host listener para os dispositivos: {', '.join(SERIAL_DEVICES)}")
    print("O watcher agora processará o stream ao vivo para análise contínua por IA...")
    print("Press Ctrl+C to stop.")

    rag_retriever = RagRetriever()

    # Estado para cada fluxo de dados (identificado pela porta serial)
    stream_states = {device: {'pending_lines': []} for device in SERIAL_DEVICES}
    # Adiciona um estado padrão para o modo de dispositivo único (sem prefixos)
    if len(SERIAL_DEVICES) == 1:
        stream_states["default"] = {'pending_lines': []}

    command = ['stdbuf', '-o0', HOST_LISTENER_PATH] + SERIAL_DEVICES
    proc = None

    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, # Redireciona stderr para stdout para capturar tudo
            text=True,
            bufsize=1  # Buffer por linha
        )

        use_prefix_parsing = len(SERIAL_DEVICES) > 1

        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue

            if "Waiting for encrypted data" in line or "Connection closed" in line:
                print(f"[INFO] {line}")
                continue

            stream_id = "default"
            log_content = line

            if use_prefix_parsing:
                match = re.match(r'^\[([^\]]+)\]\s*(.*)', line)
                if match:
                    stream_id = match.group(1)
                    log_content = match.group(2).strip()
                else:
                    print(f"[AVISO] Linha sem prefixo em modo multi-dispositivo: {line}")
                    continue

            if "Attaching " in log_content and "probes" in log_content:
                print(f"[INFO] Pulando cabeçalho do bpftrace para o stream '{stream_id}': {log_content}")
                continue

            # Imprime a linha de log que será processada
            print(line)

            if stream_id not in stream_states:
                print(f"[AVISO] Recebidos dados de um stream inesperado: {stream_id}")
                continue

            state = stream_states[stream_id]
            state['pending_lines'].append(log_content)

            if len(state['pending_lines']) >= BATCH_SIZE:
                batch_to_send = state['pending_lines'][:BATCH_SIZE]
                state['pending_lines'] = state['pending_lines'][BATCH_SIZE:]

                print(f"\n--- Lote de {len(batch_to_send)} eventos do stream '{stream_id}' pronto para análise ---")
                log_batch_content = "\n".join(batch_to_send)
                rag_context = rag_retriever.retrieve_context(log_batch_content)

                print("═════════ CONTEXTO RAG RECUPERADO ═════════")
                print(rag_context)
                print("═════════════════════════════════════════")

                full_prompt = PROMPT_TEMPLATE.format(rag_context=rag_context, log_content=log_batch_content)

                print("Analisando com IA...")
                analysis = send_for_analysis(full_prompt)
                if analysis:
                    print("═══════════ ANÁLISE DA IA ═══════════")
                    print(analysis)
                    print("═══════════════════════════════════")

    except KeyboardInterrupt:
        print("\nParando o Cerise Log Watcher.")
    except Exception as e:
        print(f"\nOcorreu um erro inesperado: {e}")
    finally:
        if proc and proc.poll() is None:
            print("Encerrando o processo do listener...")
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                print("O listener não encerrou, forçando o encerramento.")
                proc.kill()
            print("Listener parado.")

if __name__ == "__main__":
    main()