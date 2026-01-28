import sys
import json
import urllib.request
import urllib.error
import os

def analyze_log(filepath):
    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' not found.")
        return

    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()
            content = "".join(lines[-50:])
    except Exception as e:
        print(f"Erro ao ler arquivo: {e}")
        return

    if not content.strip():
        print("O arquivo de log está vazio.")
        return

    prompt = f"""### Instruction:
    Analyze the following Linux logs for security anomalies.
    Output ONLY the analysis result in plain text.
    Do NOT output any "INFO", "DEBUG", or timestamped logs describing your thought process.
    Do NOT simulate a system log.
    If everything looks normal, say "No anomalies detected".

    ### Input:
    {content}

    ### Response:
    """


    url = "http://localhost:11434/api/generate"
    data = {
        "model": "llama2",
        "prompt": prompt,
        "stream": False
    }
    
    try:
        json_data = json.dumps(data).encode('utf-8')
        req = urllib.request.Request(url, data=json_data, headers={'Content-Type': 'application/json'})
        
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode('utf-8'))
            print("═════════ ANALYSIS ═════════")
            print(result.get("response", "No response from the model.").strip())
            
    except urllib.error.URLError:
        print("\n[ERROR] Could not connect to Ollama (http://localhost:11434).")
        print("Make sure Ollama is running and the 'tinyllama' model is installed.")
        print("Dica: Execute 'ollama run tinyllama' no terminal antes.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 LLAMA.py <log_file_path>")
    else:
        analyze_log(sys.argv[1])
