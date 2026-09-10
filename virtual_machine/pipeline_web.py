#!/usr/bin/env python3
import http.server
import json
import re
import subprocess
import threading
import queue
import time
import os
import sys
import urllib.request
import urllib.error
import socketserver
import pathlib
import zipfile
import io

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from log_watcher import RagRetriever, PROMPT_TEMPLATE, format_rag_block, build_process_tree_block

SERIAL_PORTS_FILE = "serial_ports.list"
BATCH_INTERVAL = 30
OLLAMA_URL = "http://localhost:11434"
WEB_HOST = "0.0.0.0"
WEB_PORT = 8080


class PipelineState:
    def __init__(self):
        self.ports = []
        self.host_ports = []
        self.supervisor_ports = []
        self.host_proc = None
        self.supervisor_procs = []
        self.host_running = False
        self.supervisor_running_count = 0
        self.events = []
        self.current_batch = []
        self.batches = []
        self.batch_counter = 0
        self.sse_clients = {}
        self.lock = threading.Lock()
        self.analysis_busy = False
        self.analysis_tokens = 0
        self.analysis_start_time = 0
        self.chat_busy = False
        self.chat_tokens = 0
        self.chat_start_time = 0
        self.start_time = time.time()
        self.total_events = 0
        self.last_event_time = None
        self.events_per_port = {}
        self.ebpf_count = 0
        self.network_count = 0
        self.llm_config = {
            "provider": "ollama",
            "model": "llama2",
            "api_key": "",
        }

    def get_status(self):
        with self.lock:
            return {
                "host_running": self.host_running,
                "supervisor_running": self.supervisor_running_count > 0,
                "ports": self.ports,
                "host_ports": self.host_ports,
                "supervisor_ports": self.supervisor_ports,
                "total_events": self.total_events,
                "current_batch_size": len(self.current_batch),
                "batch_count": self.batch_counter,
                "uptime": int(time.time() - self.start_time),
                "last_event_time": self.last_event_time,
                "analysis_busy": self.analysis_busy,
                "analysis_tokens": self.analysis_tokens,
                "analysis_elapsed": round(time.time() - self.analysis_start_time, 1) if self.analysis_busy else 0,
                "chat_busy": self.chat_busy,
                "chat_tokens": self.chat_tokens,
                "chat_elapsed": round(time.time() - self.chat_start_time, 1) if self.chat_busy else 0,
                "events_per_port": dict(self.events_per_port),
                "ebpf_count": self.ebpf_count,
                "network_count": self.network_count,
                "batch_interval": BATCH_INTERVAL,
                "llm_provider": self.llm_config["provider"],
                "llm_model": self.llm_config["model"],
                "rag_ready": rag_ready.is_set() and rag_retriever is not None,
            }


state = PipelineState()

rag_retriever = None
rag_ready = threading.Event()


def load_ports():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    ports_path = os.path.join(script_dir, SERIAL_PORTS_FILE)
    if not os.path.exists(ports_path):
        print(f"[pipeline_web] Error: {ports_path} not found. Start VM via vm_controller first.")
        sys.exit(1)
    entries = []
    with open(ports_path, "r") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) == 2:
                entries.append((parts[0], parts[1]))
    if not entries:
        print("[pipeline_web] Error: No ports found in serial_ports.list")
        sys.exit(1)
    return entries


def spawn_process(binary_name, ports):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    binary_path = os.path.join(script_dir, binary_name)
    if not os.path.exists(binary_path):
        print(f"[pipeline_web] Warning: {binary_path} not found, skipping")
        return None
    cmd = [binary_path] + ports
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    return proc


def broadcast_sse(event_type, data):
    message = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
    encoded = message.encode("utf-8")
    dead_clients = []
    with state.lock:
        for cid, wfile in state.sse_clients.items():
            try:
                wfile.write(encoded)
                wfile.flush()
            except Exception:
                dead_clients.append(cid)
        for cid in dead_clients:
            del state.sse_clients[cid]


def _is_network_event(text):
    return '"packet_number"' in text or '"ethernet"' in text


def reader_thread(proc, source_label, is_supervisor=False):
    for raw_line in iter(proc.stdout.readline, b""):
        try:
            line = raw_line.decode("utf-8", errors="replace").strip()
        except Exception:
            continue
        if not line:
            continue

        port_tag = None
        display_line = line
        if line.startswith("[") and "]" in line:
            bracket_end = line.index("]")
            port_tag = line[1:bracket_end]
            display_line = line[bracket_end + 2:]

        effective_source = "network" if _is_network_event(display_line) else source_label
        tag = f"{effective_source}:{port_tag}" if port_tag else effective_source

        with state.lock:
            state.total_events += 1
            state.last_event_time = time.time()
            state.current_batch.append(f"[{tag}] {display_line}")
            state.events.append({
                "id": state.total_events,
                "timestamp": time.time(),
                "port": tag,
                "source": effective_source,
                "data": display_line
            })
            state.events_per_port[tag] = state.events_per_port.get(tag, 0) + 1
            if effective_source == "network":
                state.network_count += 1
            else:
                state.ebpf_count += 1

        broadcast_sse("event", {
            "id": state.total_events,
            "timestamp": time.time(),
            "port": tag,
            "source": effective_source,
            "data": display_line[:500]
        })

    with state.lock:
        if is_supervisor:
            state.supervisor_running_count = max(0, state.supervisor_running_count - 1)
            still_running = state.supervisor_running_count > 0
        else:
            state.host_running = False
            still_running = False
    broadcast_sse("listener_status", {"source": source_label, "running": still_running})


def _llm_ollama(prompt, model, on_token, on_done):
    data = {"model": model, "prompt": prompt, "stream": True, "options": {"temperature": 0.0}}
    try:
        req = urllib.request.Request(
            f"{OLLAMA_URL}/api/generate",
            data=json.dumps(data).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        full = []
        with urllib.request.urlopen(req) as resp:
            for raw in resp:
                try:
                    chunk = json.loads(raw.decode("utf-8"))
                except Exception:
                    continue
                token = chunk.get("response", "")
                if token:
                    full.append(token)
                    on_token(token)
                if chunk.get("done", False):
                    break
        on_done("".join(full), None)
    except Exception as e:
        print(f"[pipeline_web] Ollama error: {e}", flush=True)
        on_done(None, str(e))


def _llm_openai_compat(prompt, model, api_key, base_url, on_token, on_done):
    messages = [{"role": "user", "content": prompt}]

    def attempt(send_temperature):
        data = {"model": model, "messages": messages, "stream": True}
        if send_temperature:
            data["temperature"] = 0.0
        req = urllib.request.Request(
            base_url,
            data=json.dumps(data).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        )
        full = []
        with urllib.request.urlopen(req) as resp:
            for raw in resp:
                line = raw.decode("utf-8").strip()
                if not line.startswith("data:"):
                    continue
                payload = line[5:].strip()
                if payload == "[DONE]":
                    break
                try:
                    chunk = json.loads(payload)
                except Exception:
                    continue
                token = (chunk.get("choices") or [{}])[0].get("delta", {}).get("content", "")
                if token:
                    full.append(token)
                    on_token(token)
        return "".join(full)

    try:
        try:
            on_done(attempt(True), None)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            if e.code != 400 or "temperature" not in body:
                raise RuntimeError(f"HTTP {e.code}: {body[:300]}")
            print(f"[pipeline_web] {model} rejects temperature; retrying without it", flush=True)
            on_done(attempt(False), None)
    except Exception as e:
        print(f"[pipeline_web] LLM error ({base_url}): {e}", flush=True)
        on_done(None, str(e))


def _llm_claude(prompt, model, api_key, on_token, on_done):
    messages = [{"role": "user", "content": prompt}]
    data = {"model": model, "max_tokens": 2048, "messages": messages, "stream": True}
    try:
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps(data).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            },
        )
        full = []
        with urllib.request.urlopen(req) as resp:
            for raw in resp:
                line = raw.decode("utf-8").strip()
                if not line.startswith("data:"):
                    continue
                payload = line[5:].strip()
                try:
                    chunk = json.loads(payload)
                except Exception:
                    continue
                if chunk.get("type") == "content_block_delta":
                    token = chunk.get("delta", {}).get("text", "")
                    if token:
                        full.append(token)
                        on_token(token)
        on_done("".join(full), None)
    except Exception as e:
        print(f"[pipeline_web] Claude error: {e}", flush=True)
        on_done(None, str(e))


def send_to_llm(prompt, on_token, on_done):
    cfg = state.llm_config
    provider = cfg["provider"]
    model = cfg["model"]
    api_key = cfg["api_key"]

    if provider == "ollama":
        _llm_ollama(prompt, model, on_token, on_done)
    elif provider == "openai":
        _llm_openai_compat(prompt, model, api_key,
                           "https://api.openai.com/v1/chat/completions", on_token, on_done)
    elif provider == "gemini":
        _llm_openai_compat(prompt, model, api_key,
                           f"https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
                           on_token, on_done)
    elif provider == "claude":
        _llm_claude(prompt, model, api_key, on_token, on_done)
    else:
        on_done(None, f"Unknown provider: {provider}")


def _llm_sync(prompt):
    out = {}
    send_to_llm(prompt, lambda _token: None, lambda text, err: out.update({"text": text}))
    return out.get("text")


def init_rag_thread():
    global rag_retriever
    try:
        rag_retriever = RagRetriever(hyde_llm=_llm_sync)
    except Exception as e:
        print(f"[pipeline_web] RAG retriever failed to initialize: {e}", flush=True)
    finally:
        rag_ready.set()
        broadcast_sse("rag_status", {"ready": rag_retriever is not None})


def fetch_ollama_models():
    try:
        req = urllib.request.Request(f"{OLLAMA_URL}/api/tags")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return [m["name"] for m in data.get("models", [])]
    except Exception:
        return []


analysis_queue = queue.Queue()


def analysis_worker_thread():
    while True:
        batch = analysis_queue.get()
        if batch is None:
            break
        try:
            run_analysis(batch)
        except Exception as e:
            print(f"[pipeline_web] Analysis worker error: {e}", flush=True)
        analysis_queue.task_done()


def batch_timer_thread():
    while (state.host_running or state.supervisor_running_count > 0) or (state.host_proc is None and not state.supervisor_procs):
        time.sleep(1)
        if not state.host_running and state.supervisor_running_count <= 0 and (state.host_proc is not None or state.supervisor_procs):
            break

        elapsed = time.time() - (state.batches[-1]["timestamp"] if state.batches else state.start_time)
        if elapsed < BATCH_INTERVAL:
            continue

        with state.lock:
            if not state.current_batch:
                continue
            state.batch_counter += 1
            batch = {
                "id": state.batch_counter,
                "timestamp": time.time(),
                "events": list(state.current_batch),
                "event_count": len(state.current_batch),
                "response": "",
                "status": "queued",
                "tokens": 0,
                "duration": 0,
            }
            state.batches.append(batch)
            state.current_batch = []

        broadcast_sse("batch_created", {
            "id": batch["id"],
            "timestamp": batch["timestamp"],
            "event_count": batch["event_count"],
            "status": "queued"
        })

        analysis_queue.put(batch)


_CLAIM_PATTERNS = {
    "pid": re.compile(r"\bp{0,2}pid\b[^0-9\n]{0,10}(\d+)", re.IGNORECASE),
    "uid": re.compile(r"\buid\b[^0-9\n]{0,10}(\d+)", re.IGNORECASE),
    "port": re.compile(r"\b(?:src|dst)?_?port\b[^0-9\n]{0,10}(\d+)", re.IGNORECASE),
}
_SHARED_PATTERNS = {
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "path": re.compile(r"/(?:[\w.\-]+/)*[\w.\-]+"),
    "hash": re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b"),
}
_ANY_NUMBER = re.compile(r"\b\d+\b")


def extract_claims(text):
    facts = {label: set(pattern.findall(text)) for label, pattern in _CLAIM_PATTERNS.items()}
    facts.update({label: set(pattern.findall(text)) for label, pattern in _SHARED_PATTERNS.items()})
    return facts


def extract_ground_truth(text):
    any_numbers = set(_ANY_NUMBER.findall(text))
    facts = {label: any_numbers for label in _CLAIM_PATTERNS}
    facts.update({label: set(pattern.findall(text)) for label, pattern in _SHARED_PATTERNS.items()})
    return facts


def check_factual_consistency(batch_data, analysis_text):
    ground_truth = extract_ground_truth(batch_data)
    claimed = extract_claims(analysis_text)
    warnings = []
    for label, claimed_values in claimed.items():
        for value in sorted(claimed_values - ground_truth.get(label, set())):
            warnings.append(f"{label.upper()} {value}")
    return warnings


def run_analysis(batch):
    batch_data = "\n".join(batch["events"][-100:])
    process_tree = build_process_tree_block(batch["events"][-100:])

    with state.lock:
        state.analysis_busy = True
        state.analysis_tokens = 0
        state.analysis_start_time = time.time()
        batch["status"] = "analyzing"

    broadcast_sse("analysis_start", {"batch_id": batch["id"]})

    rag_ready.wait()
    if rag_retriever is not None:
        retrieval = rag_retriever.retrieve_context(batch_data)
    else:
        retrieval = {
            "context": "RAG context is unavailable due to an initialization error.",
            "category": "UNKNOWN",
            "confidence": "NONE",
            "score": 0.0,
            "dense_similarity": 0.0,
        }

    with state.lock:
        batch["rag"] = {
            "category": retrieval["category"],
            "confidence": retrieval["confidence"],
            "score": round(float(retrieval["score"]), 2),
            "dense_similarity": round(float(retrieval["dense_similarity"]), 2),
            "categories": [c["category"] for c in (retrieval.get("candidates") or [])],
        }
    broadcast_sse("rag_context", {"batch_id": batch["id"], **batch["rag"]})

    prompt = PROMPT_TEMPLATE.format(
        rag_context=format_rag_block(retrieval),
        process_tree=process_tree,
        log_content=batch_data,
    )

    def on_token(token):
        with state.lock:
            state.analysis_tokens += 1
            batch["tokens"] = state.analysis_tokens
        broadcast_sse("analysis_token", {
            "batch_id": batch["id"],
            "token": token,
            "token_count": state.analysis_tokens,
            "elapsed": round(time.time() - state.analysis_start_time, 1)
        })

    def on_done(text, error):
        with state.lock:
            state.analysis_busy = False
            duration = round(time.time() - state.analysis_start_time, 1)
            if text:
                warnings = check_factual_consistency(batch_data, text)
                if warnings:
                    text = text + "\n\n⚠ Não confirmado no log bruto: " + ", ".join(warnings)
                batch["response"] = text
                batch["status"] = "complete"
                batch["factual_warnings"] = warnings
            else:
                batch["response"] = f"Error: {error}"
                batch["status"] = "error"
                batch["factual_warnings"] = []
            batch["duration"] = duration

        broadcast_sse("analysis_done", {
            "batch_id": batch["id"],
            "status": batch["status"],
            "duration": duration,
            "tokens": batch["tokens"],
            "factual_warnings": batch["factual_warnings"]
        })

    send_to_llm(prompt, on_token, on_done)


def run_chat(message):
    with state.lock:
        state.chat_busy = True
        state.chat_tokens = 0
        state.chat_start_time = time.time()

    broadcast_sse("chat_start", {})

    def on_token(token):
        with state.lock:
            state.chat_tokens += 1
        broadcast_sse("chat_token", {
            "token": token,
            "token_count": state.chat_tokens,
            "elapsed": round(time.time() - state.chat_start_time, 1)
        })

    def on_done(text, error):
        with state.lock:
            state.chat_busy = False
        broadcast_sse("chat_done", {
            "response": text if text else f"Error: {error}",
            "duration": round(time.time() - state.chat_start_time, 1),
            "tokens": state.chat_tokens
        })

    send_to_llm(message, on_token, on_done)


class DashboardHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        if self.path == "/":
            self.serve_dashboard()
        elif self.path == "/api/status":
            self.send_json(state.get_status())
        elif self.path == "/api/batches":
            with state.lock:
                batch_list = [{
                    "id": b["id"],
                    "timestamp": b["timestamp"],
                    "event_count": b["event_count"],
                    "status": b["status"],
                    "duration": b.get("duration", 0),
                    "tokens": b.get("tokens", 0),
                } for b in state.batches]
            self.send_json(batch_list)
        elif self.path.startswith("/api/batch/"):
            try:
                batch_id = int(self.path.split("/")[-1])
            except ValueError:
                self.send_json({"error": "Invalid batch ID"}, 400)
                return
            with state.lock:
                batch = next((b for b in state.batches if b["id"] == batch_id), None)
            if batch:
                self.send_json(batch)
            else:
                self.send_json({"error": "Batch not found"}, 404)
        elif self.path == "/api/export/batches.zip":
            self.handle_export_zip()
        elif self.path == "/api/llm/config":
            with state.lock:
                cfg = dict(state.llm_config)
            cfg["api_key"] = "***" if cfg["api_key"] else ""
            self.send_json(cfg)
        elif self.path == "/api/llm/ollama-models":
            self.send_json({"models": fetch_ollama_models()})
        elif self.path == "/api/stream":
            self.handle_sse()
        elif self.path.startswith("/api/files"):
            self.handle_files()
        elif self.path.startswith("/api/file?"):
            self.handle_file_content()
        elif self.path.endswith(".png"):
            self.serve_static_png()
        else:
            self.send_error(404)

    def _read_json_body(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len)
        return json.loads(body)

    def do_POST(self):
        if self.path == "/api/chat":
            try:
                data = self._read_json_body()
                message = data.get("message", "").strip()
            except Exception:
                self.send_json({"error": "Invalid JSON"}, 400)
                return
            if not message:
                self.send_json({"error": "Empty message"}, 400)
                return
            if state.chat_busy:
                self.send_json({"error": "Chat is busy"}, 429)
                return
            chat_thread = threading.Thread(target=run_chat, args=(message,), daemon=True)
            chat_thread.start()
            self.send_json({"status": "started"})
        elif self.path == "/api/llm/config":
            try:
                data = self._read_json_body()
            except Exception:
                self.send_json({"error": "Invalid JSON"}, 400)
                return
            provider = data.get("provider", "").strip()
            model = data.get("model", "").strip()
            api_key = data.get("api_key", "").strip()
            if provider not in ("ollama", "openai", "gemini", "claude"):
                self.send_json({"error": "Invalid provider"}, 400)
                return
            if not model:
                self.send_json({"error": "Model is required"}, 400)
                return
            with state.lock:
                state.llm_config["provider"] = provider
                state.llm_config["model"] = model
                if api_key and api_key != "***":
                    state.llm_config["api_key"] = api_key
            print(f"[pipeline_web] LLM config updated: provider={provider} model={model}", flush=True)
            broadcast_sse("llm_config", {"provider": provider, "model": model})
            self.send_json({"status": "ok", "provider": provider, "model": model})
        else:
            self.send_error(404)
    def handle_export_zip(self):
        with state.lock:
            batches_snapshot = [dict(b) for b in state.batches]

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for b in batches_snapshot:
                filename = f"batch_{b['id']:04d}.json"
                zf.writestr(filename, json.dumps(b, indent=2, ensure_ascii=False))
            manifest = {
                "exported_at": time.time(),
                "batch_count": len(batches_snapshot),
                "total_events": sum(b.get("event_count", 0) for b in batches_snapshot),
            }
            zf.writestr("manifest.json", json.dumps(manifest, indent=2))

        body = buf.getvalue()
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Disposition", "attachment; filename=\"batches_export.zip\"")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _project_root(self):
        return str(pathlib.Path(os.path.dirname(os.path.abspath(__file__))).parent)

    def handle_files(self):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        rel_path = params.get("path", [""])[0]
        root = self._project_root()
        target = os.path.normpath(os.path.join(root, rel_path))
        if not target.startswith(root):
            self.send_json({"error": "Access denied"}, 403)
            return
        if not os.path.exists(target):
            self.send_json({"error": "Not found"}, 404)
            return
        if os.path.isfile(target):
            self.send_json({"type": "file", "path": rel_path, "name": os.path.basename(target), "size": os.path.getsize(target)})
            return
        entries = []
        try:
            for entry in sorted(os.listdir(target)):
                if entry.startswith('.'):
                    continue
                full = os.path.join(target, entry)
                e_rel = os.path.relpath(full, root)
                is_dir = os.path.isdir(full)
                entries.append({"name": entry, "path": e_rel, "is_dir": is_dir, "size": os.path.getsize(full) if not is_dir else 0})
        except PermissionError:
            pass
        entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
        self.send_json({"type": "directory", "path": rel_path, "entries": entries})

    def handle_file_content(self):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        rel_path = params.get("path", [""])[0]
        root = self._project_root()
        target = os.path.normpath(os.path.join(root, rel_path))
        if not target.startswith(root):
            self.send_json({"error": "Access denied"}, 403)
            return
        if not os.path.isfile(target):
            self.send_json({"error": "Not found"}, 404)
            return
        try:
            size = os.path.getsize(target)
            if size > 500000:
                self.send_json({"error": "File too large", "size": size}, 400)
                return
            with open(target, "r", errors="replace") as f:
                content = f.read()
            self.send_json({"path": rel_path, "name": os.path.basename(target), "content": content, "size": size})
        except Exception as e:
            self.send_json({"error": str(e)}, 500)

    def serve_dashboard(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        html_path = os.path.join(script_dir, "dashboard.html")
        try:
            with open(html_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", len(content))
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_error(500, "dashboard.html not found")

    def serve_static_png(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        filename = os.path.basename(self.path)
        png_path = os.path.abspath(os.path.join(script_dir, filename))
        if not png_path.startswith(script_dir) or not os.path.exists(png_path):
            self.send_error(404)
            return
        try:
            with open(png_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", len(content))
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_error(500, str(e))

    def handle_sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        client_id = id(threading.current_thread())
        with state.lock:
            state.sse_clients[client_id] = self.wfile

        try:
            while True:
                time.sleep(15)
                self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()
        except Exception:
            pass
        finally:
            with state.lock:
                state.sse_clients.pop(client_id, None)


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    print("[pipeline_web] Starting Cerise Pipeline Web Dashboard...")

    threading.Thread(target=init_rag_thread, daemon=True).start()

    entries = load_ports()
    state.ports = [path for _, path in entries]

    for label, path in entries:
        num = int("".join(filter(str.isdigit, label)) or "0")
        if num >= 10:
            state.supervisor_ports.append(path)
        else:
            state.host_ports.append(path)

    print(f"[pipeline_web] Host (eBPF) ports ({len(state.host_ports)}):")
    for p in state.host_ports:
        print(f"  {p}")
    print(f"[pipeline_web] Supervisor (network) ports ({len(state.supervisor_ports)}):")
    for p in state.supervisor_ports:
        print(f"  {p}")

    if state.host_ports:
        state.host_proc = spawn_process("host_listener", state.host_ports)
        if state.host_proc:
            state.host_running = True
            print(f"[pipeline_web] host_listener spawned (PID {state.host_proc.pid})")
            threading.Thread(target=reader_thread, args=(state.host_proc, "ebpf", False), daemon=True).start()

    if state.supervisor_ports:
        for sp in state.supervisor_ports:
            proc = spawn_process("supervisor_listener", [sp])
            if proc:
                state.supervisor_procs.append(proc)
                state.supervisor_running_count += 1
                print(f"[pipeline_web] supervisor_listener spawned on {sp} (PID {proc.pid})")
                threading.Thread(target=reader_thread, args=(proc, "network", True), daemon=True).start()

    threading.Thread(target=analysis_worker_thread, daemon=True).start()
    threading.Thread(target=batch_timer_thread, daemon=True).start()

    server = ThreadedHTTPServer((WEB_HOST, WEB_PORT), DashboardHandler)
    print(f"[pipeline_web] Dashboard available at http://localhost:{WEB_PORT}")
    print(f"[pipeline_web] Batch interval: {BATCH_INTERVAL}s")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[pipeline_web] Shutting down...")
        all_procs = [state.host_proc] + state.supervisor_procs
        for proc in all_procs:
            if proc:
                proc.terminate()
                proc.wait()
        server.shutdown()
        print("[pipeline_web] Done.")


if __name__ == "__main__":
    main()
