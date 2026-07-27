import sys
import json
import urllib.request
import urllib.error
import os

LOCAL_LLM_URL = os.environ.get("CERISE_LOCAL_LLM_URL", "http://127.0.0.1:1234/v1/chat/completions")
LOCAL_LLM_MODEL = os.environ.get("CERISE_LOCAL_LLM_MODEL", "local-model")


def send_for_analysis(prompt):
    """Sends a complete prompt to the local OpenAI-compatible server and returns the response."""
    if not prompt:
        return

    data = {
        "model": LOCAL_LLM_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "temperature": 0.0,
    }

    try:
        json_data = json.dumps(data).encode('utf-8')
        req = urllib.request.Request(LOCAL_LLM_URL, data=json_data, headers={'Content-Type': 'application/json'})

        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode('utf-8'))
            message = result["choices"][0]["message"]
            return (message.get("content") or "No response from the model.").strip()

    except urllib.error.URLError as e:
        error_message = f"\n[ERROR] Could not connect to the local model server ({LOCAL_LLM_URL}).\n" \
                        "Make sure llama-server (or your local inference server) is running with a matching --host/--port.\n" \
                        f"Detail: {e}"
        return error_message
    except Exception as e:
        return f"[ERROR] An unexpected error occurred during analysis: {str(e)}"

def analyze_log_file(filepath):
    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' not found.")
        return

    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()
            content = "".join(lines[-50:])
    except Exception as e:
        print(f"Error reading file: {e}")
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

    analysis_result = send_for_analysis(prompt)
    if analysis_result:
        print("═════════ ANALYSIS ═════════")
        print(analysis_result)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 llama.py <log_file_path>")
    else:
        analyze_log_file(sys.argv[1])
