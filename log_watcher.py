import os
import time
import json
from llama import send_for_analysis

LOG_DIR = "logs"
POLL_INTERVAL = 2      
BATCH_SIZE = 30       
HEADER_SKIP_LINES = 5  


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
]

PROMPT_TEMPLATE = """### Instruction:
FOR EACH ANOMALY DETECTED, PROVIDE A SEVERETY NUMBER FROM 1 (LOW) TO 5 (CRITICAL).
Analyze the following batch of Linux security logs for anomalies, patterns, or coordinated malicious activity.
Focus on identifying sequences of events that might indicate an attack, such as privilege escalation followed by file modification.
Output ONLY a concise analysis result in plain text.
Do NOT output any "INFO", "DEBUG", or timestamped logs describing your thought process.
Do NOT simulate a system log.
If everything looks normal, say "No anomalies detected".


### Input:
{log_batch}

### Response:
"""

def is_critical(log_filename):
    """Verifica se o nome do arquivo de log corresponde a um script crítico."""
    for script_name in CRITICAL_SCRIPTS:
        if script_name in log_filename:
            return True
    return False

def clear_screen():
    """Limpa a tela do terminal."""
    os.system('clear' if os.name == 'posix' else 'cls')

def show_header():
    """Mostra o cabeçalho do programa."""
    clear_screen()
    print("╔════════════════════════════════════════════════════════════╗")
    print("║           CERISE LOG WATCHER - ANÁLISE CONTÍNUA            ║")
    print("╚════════════════════════════════════════════════════════════╝\n")

def main():
    show_header()
    print("Iniciando o Cerise Log Watcher para análise contínua com IA...")
    print(f"Monitorando o diretório: '{LOG_DIR}'")
    print(f"Scripts críticos: {', '.join(CRITICAL_SCRIPTS)}")
    #print(f"Enviando logs para análise em lotes de {BATCH_SIZE} eventos (após pular {HEADER_SKIP_LINES} linhas iniciais).")
    print("Pressione Ctrl+C para parar.")

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

                        log_batch_content = "".join(batch_to_send)
                        full_prompt = PROMPT_TEMPLATE.format(log_batch=log_batch_content)

                        print(f"\n--- Lote de {len(batch_to_send)} eventos críticos de '{filename}' pronto para análise ---")
                        print("Analisando com IA...")
                        analysis = send_for_analysis(full_prompt)
                        if analysis:
                            print("═════════ ANÁLISE DA IA ═════════")
                            print(analysis)
                            print("═════════════════════════════════")

                except FileNotFoundError:
                    if filepath in file_states:
                        del file_states[filepath]
                    continue
                except Exception as e:
                    print(f"Erro ao processar o arquivo {filepath}: {e}")

            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print("\nParando o Cerise Log Watcher.")

if __name__ == "__main__":
    if not os.path.exists(LOG_DIR):
        print(f"Erro: Diretório de logs '{LOG_DIR}' não encontrado. Execute um script em background primeiro.")
    else:
        main()