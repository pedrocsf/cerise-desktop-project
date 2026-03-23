import os
import chromadb
from chromadb.utils import embedding_functions
import sys
import subprocess
import re
from llama import send_for_analysis

ANSI_ESCAPE_RE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

# --- Configuration ---
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
    print("║            CERISE LOG WATCHER - CONTINUOUS ANALYSIS         ║")
    print("╚════════════════════════════════════════════════════════════╝\n")

def emit_line(message):
    """Escreve sempre no início da linha, limpando resíduos visuais do terminal."""
    sys.stdout.write(f"\r\033[K{message}\n")
    sys.stdout.flush()

def print_block(tag, title, content):
    """Prints a multiline block with consistent indentation."""
    emit_line(f"[{tag}] {title}")
    for block_line in content.splitlines():
        emit_line(f"      {block_line}")

def sanitize_output_line(line):
    """Normaliza uma linha para evitar desalinhamento visual no terminal."""
    # Remove sequências ANSI, CR e outros controles invisíveis que quebram o cursor.
    line = ANSI_ESCAPE_RE.sub('', line)
    line = line.replace('\r', '')
    line = ''.join(ch for ch in line if ch.isprintable() or ch == '\t')
    return line.strip()

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

    proc = None

    try:
        emit_line(f"[INFO] Iniciando host_listener para: {', '.join(SERIAL_DEVICES)}")
        emit_line("[INFO] Logs brutos e análise da IA serão exibidos nesta mesma janela.")
        emit_line("[INFO] Pressione Ctrl+C para parar.")

        rag_retriever = RagRetriever()

        # Estado para cada fluxo de dados
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

            # Sempre exibe o log bruto recebido do host_listener.
            emit_line(f"[RAW] {line}")

            if "Waiting for encrypted data" in line or "Connection closed" in line:
                # Já foi exibida em [RAW], evita duplicidade visual.
                continue

            stream_id = "default"
            log_content = line

            if use_prefix_parsing:
                match = re.match(r'^\[([^\]]+)\]\s*(.*)', line)
                if match:
                    stream_id = match.group(1)
                    log_content = match.group(2).strip()
                else:
                    # Linha sem prefixo (provavelmente do próprio listener), já foi para o log.
                    continue

            if "Attaching " in log_content and "probes" in log_content:
                emit_line(f"[INFO] Pulando cabeçalho do bpftrace para o stream '{stream_id}': {log_content}")
                continue

            if stream_id not in stream_states:
                emit_line(f"[AVISO] Recebidos dados de um stream inesperado: {stream_id}")
                continue

            state = stream_states[stream_id]
            state['pending_lines'].append(log_content)

            if len(state['pending_lines']) >= BATCH_SIZE:
                batch_to_send = state['pending_lines'][:BATCH_SIZE]
                state['pending_lines'] = state['pending_lines'][BATCH_SIZE:]

                emit_line("")
                emit_line(f"[BATCH] Stream='{stream_id}' | Eventos={len(batch_to_send)} | Status=pronto para análise")
                log_batch_content = "\n".join(batch_to_send)

                rag_context = rag_retriever.retrieve_context(log_batch_content)

                print_block("RAG", f"Contexto recuperado para stream '{stream_id}'", rag_context)

                full_prompt = PROMPT_TEMPLATE.format(rag_context=rag_context, log_content=log_batch_content)

                emit_line(f"[IA] Iniciando processamento do lote de {len(batch_to_send)} eventos do stream '{stream_id}'...")
                analysis = send_for_analysis(full_prompt)
                if analysis:
                    print_block("IA", f"Resultado da análise do stream '{stream_id}'", analysis)

    except KeyboardInterrupt:
        emit_line("")
        emit_line("[INFO] Parando o Cerise Log Watcher.")
    except Exception as e:
        emit_line("")
        emit_line(f"[ERRO] Ocorreu um erro inesperado: {e}")
    finally:
        if proc and proc.poll() is None:
            emit_line("[INFO] Encerrando o processo do listener...")
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                emit_line("[AVISO] O listener não encerrou, forçando o encerramento.")
                proc.kill()
            emit_line("[INFO] Listener parado.")

if __name__ == "__main__":
    main()