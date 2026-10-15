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
import mimetypes
import shutil
import collections
import types

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from log_watcher import RagRetriever, build_prompt_template, format_rag_block, build_process_tree_block
from attack_mapping import map_attack
from search_enrichment import (
    NO_SEARCH_TEXT,
    enrich_automatic,
    enrich_manual,
    format_search_block,
    get_reputation_providers,
)

SERIAL_PORTS_FILE = "serial_ports.list"
BATCH_INTERVAL = 30
OLLAMA_URL = "http://localhost:11434"
WEB_HOST = "0.0.0.0"
WEB_PORT = 8080
VNC_HOST = "127.0.0.1"
VNC_PORT = 5900
NOVNC_WS_PORT = 6080
NOVNC_DIR = "novnc"
TTYD_HOST = "127.0.0.1"
TTYD_PORT = 7682
VM_CONTROLLER_BIN = "vm_controller"
VM_ACTION_TIMEOUT = 30
DEMO_MODE = os.environ.get("MALTRACE_DEMO") == "1"
QEMU_PID_FILE = "qemu_vm.pid"
VM_METRICS_MAXLEN = 90
VM_METRICS_INTERVAL = 2
VM_QCOW2_PATH = "/home/pedro/Downloads/cerise.qcow2"
VM_SHARED_DIRNAME = "vm_shared"


class PipelineState:
    def __init__(self):
        self.ports = []
        self.host_ports = []
        self.supervisor_ports = []
        self.host_proc = None
        self.supervisor_procs = []
        self.host_running = False
        self.supervisor_running_count = 0
        self.vnc_proc = None
        self.vnc_running = False
        self.ttyd_proc = None
        self.vm_running = False
        self.vm_busy = False
        self.vm_last_error = ""
        self.vm_metrics = {
            "timestamps": collections.deque(maxlen=VM_METRICS_MAXLEN),
            "cpu": collections.deque(maxlen=VM_METRICS_MAXLEN),
            "mem_mb": collections.deque(maxlen=VM_METRICS_MAXLEN),
        }
        self.events = []
        self.current_batch = []
        self.batches = []
        self.batch_counter = 0
        self.external_batches = []
        self.external_counter = 0
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
        self.hyde_degraded_count = 0
        self.llm_config = {
            "provider": "ollama",
            "model": "llama2",
            "api_key": "",
        }
        self.vm_config = {"ram_mb": 8192, "cpus": 6}
        self.attack_config = {"enabled": False}
        self.search_config = {
            "mode": "disabled",
            "abuseipdb_api_key": "",
            "virustotal_api_key": "",
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
                "external_busy": external_channel.analysis_busy,
                "external_count": len(self.external_batches),
                "chat_busy": self.chat_busy,
                "chat_tokens": self.chat_tokens,
                "chat_elapsed": round(time.time() - self.chat_start_time, 1) if self.chat_busy else 0,
                "events_per_port": dict(self.events_per_port),
                "ebpf_count": self.ebpf_count,
                "network_count": self.network_count,
                "batch_interval": BATCH_INTERVAL,
                "llm_provider": self.llm_config["provider"],
                "llm_model": self.llm_config["model"],
                "search_mode": self.search_config["mode"],
                "attack_enabled": self.attack_config["enabled"],
                "rag_ready": rag_ready.is_set() and rag_retriever is not None,
                "hyde_degraded_count": self.hyde_degraded_count,
                "vnc_running": self.vnc_running,
                "vnc_ws_port": NOVNC_WS_PORT,
                "vm_running": self.vm_running,
                "vm_busy": self.vm_busy,
                "vm_last_error": self.vm_last_error,
                "demo_mode": DEMO_MODE,
            }


state = PipelineState()
external_channel = types.SimpleNamespace(analysis_busy=False, analysis_tokens=0, analysis_start_time=0)
external_queue = queue.Queue()
EXTERNAL_MAX_LINES = 5000
EXTERNAL_MAX_CHARS = 400000
EXTERNAL_ANALYSIS_LINES = 100

rag_retriever = None
rag_ready = threading.Event()


def load_ports():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    ports_path = os.path.join(script_dir, SERIAL_PORTS_FILE)
    if not os.path.exists(ports_path):
        return []
    entries = []
    with open(ports_path, "r") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) == 2:
                entries.append((parts[0], parts[1]))
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


def spawn_websockify():
    websockify_bin = shutil.which("websockify") or os.path.join(os.path.dirname(sys.executable), "websockify")
    cmd = [
        websockify_bin,
        str(NOVNC_WS_PORT),
        f"{VNC_HOST}:{VNC_PORT}",
    ]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print("[pipeline_web] Warning: websockify not installed, VM screen panel will be unavailable")
        return None
    return proc


def spawn_ttyd():
    ttyd_bin = shutil.which("ttyd")
    if not ttyd_bin:
        print("[pipeline_web] Warning: ttyd not installed, host terminal panel will be unavailable")
        return None
    theme = json.dumps({
        "background": "#000000",
        "foreground": "#ffffff",
        "cursor": "#ffffff",
        "cursorAccent": "#000000",
        "selectionBackground": "#ffffff",
        "selectionForeground": "#000000",
        "black": "#000000",
        "white": "#ffffff",
        "brightBlack": "#000000",
        "brightWhite": "#ffffff",
    })
    cmd = [
        ttyd_bin,
        "-p", str(TTYD_PORT),
        "-i", TTYD_HOST,
        "-t", f"theme={theme}",
        "-W",
        "bash",
    ]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def start_listeners(entries):
    with state.lock:
        if state.host_running or state.supervisor_running_count > 0:
            return
        state.ports = [path for _, path in entries]
        state.host_ports = []
        state.supervisor_ports = []
        for label, path in entries:
            num = int("".join(filter(str.isdigit, label)) or "0")
            if num >= 10:
                state.supervisor_ports.append(path)
            else:
                state.host_ports.append(path)

    if state.host_ports:
        proc = spawn_process("host_listener", state.host_ports)
        if proc:
            state.host_proc = proc
            state.host_running = True
            print(f"[pipeline_web] host_listener spawned (PID {proc.pid})")
            threading.Thread(target=reader_thread, args=(proc, "ebpf", False), daemon=True).start()

    if state.supervisor_ports:
        for sp in state.supervisor_ports:
            proc = spawn_process("supervisor_listener", [sp])
            if proc:
                state.supervisor_procs.append(proc)
                state.supervisor_running_count += 1
                print(f"[pipeline_web] supervisor_listener spawned on {sp} (PID {proc.pid})")
                threading.Thread(target=reader_thread, args=(proc, "network", True), daemon=True).start()


def stop_listeners():
    procs = [state.host_proc] + state.supervisor_procs
    for proc in procs:
        if proc:
            proc.terminate()
    for proc in procs:
        if proc:
            proc.wait()
    with state.lock:
        state.host_proc = None
        state.supervisor_procs = []
        state.host_running = False
        state.supervisor_running_count = 0
        state.host_ports = []
        state.supervisor_ports = []
        state.ports = []


def run_vm_controller(action):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    binary_path = os.path.join(script_dir, VM_CONTROLLER_BIN)
    env = os.environ.copy()
    with state.lock:
        env["CERISE_RAM_MB"] = str(state.vm_config["ram_mb"])
        env["CERISE_CPUS"] = str(state.vm_config["cpus"])
    try:
        result = subprocess.run(
            [binary_path, action],
            cwd=script_dir,
            capture_output=True,
            text=True,
            timeout=VM_ACTION_TIMEOUT,
            env=env,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return False, str(e)
    output = (result.stdout + result.stderr).strip()
    return result.returncode == 0, output


def get_disk_size_gb():
    try:
        result = subprocess.run(
            ["qemu-img", "info", "--output=json", VM_QCOW2_PATH],
            capture_output=True, text=True, timeout=10,
        )
        info = json.loads(result.stdout)
        return round(info["virtual-size"] / (1024 ** 3), 1)
    except Exception:
        return None


GUEST_AUTOMOUNT_MARKER = ".guest_automount_configured"


def ensure_guest_automount():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    marker_path = os.path.join(script_dir, GUEST_AUTOMOUNT_MARKER)
    if os.path.exists(marker_path):
        return True
    virt_customize = shutil.which("virt-customize")
    if not virt_customize:
        print("[pipeline_web] virt-customize not installed, skipping guest auto-mount setup")
        return False
    print("[pipeline_web] Configuring guest auto-mount for the shared folder (one-time, VM disk offline)...")
    try:
        result = subprocess.run(
            [virt_customize, "-a", VM_QCOW2_PATH,
             "--run-command", "mkdir -p /mnt/shared",
             "--append-line", "/etc/fstab:cerise_share /mnt/shared 9p trans=virtio,version=9p2000.L,rw,_netdev,nofail 0 0"],
            capture_output=True, text=True, timeout=300,
        )
    except Exception as e:
        print(f"[pipeline_web] Guest auto-mount setup failed: {e}")
        return False
    if result.returncode != 0:
        print(f"[pipeline_web] Guest auto-mount setup failed: {(result.stdout + result.stderr).strip()}")
        return False
    with open(marker_path, "w") as f:
        f.write("1")
    print("[pipeline_web] Guest auto-mount configured: shared folder will appear at /mnt/shared inside the VM")
    return True


def vm_is_active():
    ok, output = run_vm_controller("status")
    return ok and "[ACTIVE]" in output


def read_qemu_pid():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    pid_path = os.path.join(script_dir, QEMU_PID_FILE)
    try:
        with open(pid_path) as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return None


def sample_qemu_proc(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            fields = f.read().split()
        utime, stime = int(fields[13]), int(fields[14])
        rss_kb = 0
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    rss_kb = int(line.split()[1])
                    break
        return utime + stime, rss_kb / 1024.0
    except (FileNotFoundError, ProcessLookupError, IndexError, ValueError):
        return None


def vm_metrics_thread():
    clk_tck = os.sysconf("SC_CLK_TCK")
    prev_ticks = None
    prev_time = None
    while True:
        time.sleep(VM_METRICS_INTERVAL)
        if DEMO_MODE or not state.vm_running:
            prev_ticks = None
            continue
        pid = read_qemu_pid()
        sample = sample_qemu_proc(pid) if pid else None
        if sample is None:
            prev_ticks = None
            continue
        ticks, rss_mb = sample
        now = time.time()
        cpu_pct = 0.0
        if prev_ticks is not None:
            elapsed = now - prev_time
            if elapsed > 0:
                cpu_pct = round((ticks - prev_ticks) / clk_tck / elapsed * 100, 1)
        prev_ticks, prev_time = ticks, now
        with state.lock:
            state.vm_metrics["timestamps"].append(now)
            state.vm_metrics["cpu"].append(cpu_pct)
            state.vm_metrics["mem_mb"].append(round(rss_mb, 1))


def vm_start_worker():
    with state.lock:
        if state.vm_running or state.vm_busy:
            return
        state.vm_busy = True
        state.vm_last_error = ""
    broadcast_sse("vm_status", {"vm_running": False, "vm_busy": True})

    ensure_guest_automount()

    ok, output = run_vm_controller("start")
    if ok:
        entries = load_ports()
        if entries:
            start_listeners(entries)
            with state.lock:
                state.vm_running = True
        else:
            ok = False
            output = "VM started but no serial ports were detected"

    with state.lock:
        state.vm_busy = False
        if not ok:
            state.vm_last_error = output
    print(f"[pipeline_web] VM start {'succeeded' if ok else 'failed: ' + output}")
    broadcast_sse("vm_status", {"vm_running": state.vm_running, "vm_busy": False})


def vm_stop_worker():
    with state.lock:
        if not state.vm_running or state.vm_busy:
            return
        state.vm_busy = True
    broadcast_sse("vm_status", {"vm_running": True, "vm_busy": True})

    stop_listeners()
    ok, output = run_vm_controller("stop")

    with state.lock:
        state.vm_running = False
        state.vm_busy = False
        state.vm_metrics["timestamps"].clear()
        state.vm_metrics["cpu"].clear()
        state.vm_metrics["mem_mb"].clear()
        if not ok:
            state.vm_last_error = output
    print(f"[pipeline_web] VM stop {'succeeded' if ok else 'failed: ' + output}")
    broadcast_sse("vm_status", {"vm_running": False, "vm_busy": False})


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
        item = analysis_queue.get()
        if item is None:
            break
        batch, force_manual_search = item
        try:
            run_analysis(batch, force_manual_search=force_manual_search)
        except Exception as e:
            print(f"[pipeline_web] Analysis worker error: {e}", flush=True)
        analysis_queue.task_done()


def external_worker_thread():
    while True:
        item = external_queue.get()
        if item is None:
            break
        batch, force_manual_search = item
        try:
            run_analysis(batch, force_manual_search=force_manual_search, external=True)
        except Exception as e:
            print(f"[pipeline_web] External analysis worker error: {e}", flush=True)
        external_queue.task_done()


def create_external_batch(label, text):
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    with state.lock:
        state.external_counter += 1
        batch = {
            "id": state.external_counter,
            "label": label or f"External #{state.external_counter}",
            "timestamp": time.time(),
            "events": lines,
            "event_count": len(lines),
            "analyzed_events": min(len(lines), EXTERNAL_ANALYSIS_LINES),
            "response": "",
            "status": "queued",
            "tokens": 0,
            "duration": 0,
        }
        state.external_batches.append(batch)
    broadcast_sse("ext_batch_created", {
        "id": batch["id"],
        "label": batch["label"],
        "timestamp": batch["timestamp"],
        "event_count": batch["event_count"],
        "analyzed_events": batch["analyzed_events"],
        "status": "queued",
    })
    external_queue.put((batch, False))
    return batch


def batch_timer_thread():
    while True:
        time.sleep(1)
        if not (state.host_running or state.supervisor_running_count > 0):
            continue

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

        analysis_queue.put((batch, False))


_CLAIM_PATTERNS = {
    "pid": re.compile(r"\bp{0,2}pid\b[^0-9\n]{0,10}(\d+)", re.IGNORECASE),
    "uid": re.compile(r"\buid\b[^0-9\n]{0,10}(\d+)", re.IGNORECASE),
    "port": re.compile(r"\b(?:src|dst)?_?port\b[^0-9\n]{0,10}(\d+)", re.IGNORECASE),
}
_SHARED_PATTERNS = {
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "path": re.compile(r"(?<!\d)/(?=[\w.\-/]*[A-Za-z])(?:[\w.\-]+/)*[\w.\-]*[\w\-]"),
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


def run_analysis(batch, force_manual_search=False, external=False):
    chan = external_channel if external else state
    sse = (lambda name, data: broadcast_sse("ext_" + name, data)) if external else broadcast_sse
    window = EXTERNAL_ANALYSIS_LINES if external else 100
    batch_data = "\n".join(batch["events"][-window:])
    process_tree = build_process_tree_block(batch["events"][-window:])

    with state.lock:
        chan.analysis_busy = True
        chan.analysis_tokens = 0
        chan.analysis_start_time = time.time()
        batch["status"] = "analyzing"

    sse("analysis_start", {"batch_id": batch["id"]})

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
            "hyde_degraded": False,
        }

    attack_enabled = state.attack_config["enabled"]
    hyde_degraded = bool(retrieval.get("hyde_degraded"))
    with state.lock:
        batch["rag"] = {
            "category": retrieval["category"],
            "confidence": retrieval["confidence"],
            "score": round(float(retrieval["score"]), 2),
            "dense_similarity": round(float(retrieval["dense_similarity"]), 2),
            "categories": [c["category"] for c in (retrieval.get("candidates") or [])],
            "hyde_degraded": hyde_degraded,
        }
        if hyde_degraded and not external:
            state.hyde_degraded_count += 1
    sse("rag_context", {"batch_id": batch["id"], **batch["rag"]})

    search_result = None
    if force_manual_search or state.search_config["mode"] == "auto":
        reputation_providers = get_reputation_providers(
            state.search_config["abuseipdb_api_key"], state.search_config["virustotal_api_key"]
        )
        if force_manual_search:
            search_result = enrich_manual(batch_data, reputation_providers)
        else:
            search_result = enrich_automatic(batch_data, reputation_providers)

    with state.lock:
        batch["search"] = search_result
    sse("search_context", {"batch_id": batch["id"], "search": search_result})

    prompt = build_prompt_template(attack_enabled).format(
        rag_context=format_rag_block(retrieval),
        process_tree=process_tree,
        search_context=format_search_block(search_result),
        log_content=batch_data,
    )

    def on_token(token):
        with state.lock:
            chan.analysis_tokens += 1
            batch["tokens"] = chan.analysis_tokens
        sse("analysis_token", {
            "batch_id": batch["id"],
            "token": token,
            "token_count": chan.analysis_tokens,
            "elapsed": round(time.time() - chan.analysis_start_time, 1)
        })

    def on_done(text, error):
        with state.lock:
            chan.analysis_busy = False
            duration = round(time.time() - chan.analysis_start_time, 1)
            if text:
                verified_sources = batch_data
                if search_result and search_result.get("performed"):
                    verified_sources = batch_data + "\n" + format_search_block(search_result)
                warnings = check_factual_consistency(verified_sources, text)
                if warnings:
                    text = text + "\n\n⚠ Não confirmado no log bruto: " + ", ".join(warnings)
                if hyde_degraded:
                    text = text + ("\n\n⚠ HyDE indisponível nesta análise: retrieval usou o log bruto "
                                    "em vez do resumo reescrito (o LLM de reescrita não respondeu).")
                batch["response"] = text
                batch["status"] = "complete"
                batch["factual_warnings"] = warnings
                batch["attack"] = map_attack(text) if attack_enabled else None
            else:
                batch["response"] = f"Error: {error}"
                batch["status"] = "error"
                batch["factual_warnings"] = []
                batch["attack"] = None
            batch["duration"] = duration

        sse("analysis_done", {
            "batch_id": batch["id"],
            "status": batch["status"],
            "duration": duration,
            "tokens": batch["tokens"],
            "response": batch["response"],
            "factual_warnings": batch["factual_warnings"],
            "attack": batch["attack"],
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
                    "response": b.get("response", ""),
                    "search_performed": bool((b.get("search") or {}).get("performed")),
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
        elif self.path == "/api/external":
            with state.lock:
                items = [{
                    "id": b["id"],
                    "label": b["label"],
                    "timestamp": b["timestamp"],
                    "event_count": b["event_count"],
                    "analyzed_events": b["analyzed_events"],
                    "status": b["status"],
                    "duration": b.get("duration", 0),
                    "tokens": b.get("tokens", 0),
                    "response": b.get("response", ""),
                    "search_performed": bool((b.get("search") or {}).get("performed")),
                } for b in state.external_batches]
            self.send_json(items)
        elif self.path.startswith("/api/external/"):
            try:
                batch_id = int(self.path.split("/")[-1])
            except ValueError:
                self.send_json({"error": "Invalid batch ID"}, 400)
                return
            with state.lock:
                batch = next((b for b in state.external_batches if b["id"] == batch_id), None)
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
        elif self.path == "/api/vm/metrics":
            with state.lock:
                self.send_json({
                    "timestamps": list(state.vm_metrics["timestamps"]),
                    "cpu": list(state.vm_metrics["cpu"]),
                    "mem_mb": list(state.vm_metrics["mem_mb"]),
                })
        elif self.path == "/api/vm/config":
            with state.lock:
                cfg = dict(state.vm_config)
                cfg["vm_running"] = state.vm_running
            cfg["disk_size_gb"] = get_disk_size_gb()
            self.send_json(cfg)
        elif self.path == "/api/attack/config":
            with state.lock:
                cfg = dict(state.attack_config)
            self.send_json(cfg)
        elif self.path == "/api/search/config":
            with state.lock:
                cfg = dict(state.search_config)
            for key_field in ("abuseipdb_api_key", "virustotal_api_key"):
                cfg[key_field] = "***" if cfg[key_field] else ""
            self.send_json(cfg)
        elif self.path == "/api/stream":
            self.handle_sse()
        elif self.path.startswith("/api/files"):
            self.handle_files()
        elif self.path.startswith("/api/file?"):
            self.handle_file_content()
        elif self.path.endswith(".png") or self.path.endswith(".svg"):
            self.serve_static_png()
        elif self.path.startswith("/novnc/"):
            self.serve_novnc_file()
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
        elif self.path == "/api/vm/start":
            with state.lock:
                busy, running = state.vm_busy, state.vm_running
            if busy or running:
                self.send_json({"error": "VM already running or busy"}, 409)
            else:
                threading.Thread(target=vm_start_worker, daemon=True).start()
                self.send_json({"status": "starting"})
        elif self.path == "/api/vm/stop":
            with state.lock:
                busy, running = state.vm_busy, state.vm_running
            if busy or not running:
                self.send_json({"error": "VM not running or busy"}, 409)
            else:
                threading.Thread(target=vm_stop_worker, daemon=True).start()
                self.send_json({"status": "stopping"})
        elif self.path == "/api/vm/config":
            try:
                data = self._read_json_body()
                ram_mb = int(data.get("ram_mb"))
                cpus = int(data.get("cpus"))
            except Exception:
                self.send_json({"error": "ram_mb and cpus must be integers"}, 400)
                return
            if not (512 <= ram_mb <= 32768):
                self.send_json({"error": "ram_mb out of range (512-32768)"}, 400)
                return
            if not (1 <= cpus <= 16):
                self.send_json({"error": "cpus out of range (1-16)"}, 400)
                return
            with state.lock:
                state.vm_config["ram_mb"] = ram_mb
                state.vm_config["cpus"] = cpus
            self.send_json({"status": "ok", "ram_mb": ram_mb, "cpus": cpus})
        elif self.path == "/api/vm/disk-grow":
            try:
                add_gb = int(self._read_json_body().get("add_gb"))
            except Exception:
                self.send_json({"error": "add_gb must be an integer"}, 400)
                return
            if not (1 <= add_gb <= 500):
                self.send_json({"error": "add_gb out of range (1-500)"}, 400)
                return
            with state.lock:
                running = state.vm_running
            if running:
                self.send_json({"error": "Stop the VM before resizing its disk"}, 409)
                return
            try:
                result = subprocess.run(
                    ["qemu-img", "resize", VM_QCOW2_PATH, f"+{add_gb}G"],
                    capture_output=True, text=True, timeout=30,
                )
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
                return
            if result.returncode != 0:
                self.send_json({"error": (result.stdout + result.stderr).strip()}, 500)
                return
            self.send_json({
                "status": "ok",
                "disk_size_gb": get_disk_size_gb(),
                "note": "Grow the guest partition/filesystem from inside the VM to use the new space",
            })
        elif self.path == "/api/vm/send-file":
            content_type = self.headers.get("Content-Type", "")
            script_dir = os.path.dirname(os.path.abspath(__file__))
            shared_dir = os.path.join(script_dir, VM_SHARED_DIRNAME)
            os.makedirs(shared_dir, exist_ok=True)
            if content_type.startswith("application/json"):
                try:
                    data = self._read_json_body()
                except Exception:
                    self.send_json({"error": "Invalid JSON"}, 400)
                    return
                src_path = (data.get("path") or "").strip()
                if not src_path or not os.path.isfile(src_path):
                    self.send_json({"error": "File not found on host"}, 400)
                    return
                filename = os.path.basename(src_path)
                try:
                    with open(src_path, "rb") as f:
                        content = f.read()
                except Exception as e:
                    self.send_json({"error": str(e)}, 500)
                    return
            else:
                filename = os.path.basename((self.headers.get("X-Filename") or "").strip())
                length = int(self.headers.get("Content-Length") or 0)
                content = self.rfile.read(length)
            if not filename or not content:
                self.send_json({"error": "Missing file"}, 400)
                return
            try:
                with open(os.path.join(shared_dir, filename), "wb") as f:
                    f.write(content)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
                return
            self.send_json({
                "status": "ok",
                "filename": filename,
                "auto_mounted": os.path.exists(os.path.join(script_dir, GUEST_AUTOMOUNT_MARKER)),
                "mount_hint": "sudo mkdir -p /mnt/shared && sudo mount -t 9p -o trans=virtio,version=9p2000.L cerise_share /mnt/shared",
            })
        elif self.path == "/api/attack/config":
            try:
                data = self._read_json_body()
            except Exception:
                self.send_json({"error": "Invalid JSON"}, 400)
                return
            enabled = data.get("enabled")
            if not isinstance(enabled, bool):
                self.send_json({"error": "Invalid value for enabled"}, 400)
                return
            with state.lock:
                state.attack_config["enabled"] = enabled
            if DEMO_MODE:
                apply_demo_attack_variant(enabled)
            print(f"[pipeline_web] ATT&CK mapping config updated: enabled={enabled}", flush=True)
            broadcast_sse("attack_config", {"enabled": enabled, "refresh": DEMO_MODE})
            self.send_json({"status": "ok", "enabled": enabled})
        elif self.path == "/api/search/config":
            try:
                data = self._read_json_body()
            except Exception:
                self.send_json({"error": "Invalid JSON"}, 400)
                return
            mode = data.get("mode", "").strip()
            abuseipdb_api_key = data.get("abuseipdb_api_key", "").strip()
            virustotal_api_key = data.get("virustotal_api_key", "").strip()
            if mode not in ("disabled", "auto", "manual"):
                self.send_json({"error": "Invalid mode"}, 400)
                return
            with state.lock:
                state.search_config["mode"] = mode
                if abuseipdb_api_key and abuseipdb_api_key != "***":
                    state.search_config["abuseipdb_api_key"] = abuseipdb_api_key
                if virustotal_api_key and virustotal_api_key != "***":
                    state.search_config["virustotal_api_key"] = virustotal_api_key
            print(f"[pipeline_web] Search config updated: mode={mode}", flush=True)
            broadcast_sse("search_config", {"mode": mode})
            self.send_json({"status": "ok", "mode": mode})
        elif self.path == "/api/external":
            try:
                data = self._read_json_body()
                text = str(data.get("logs", ""))
                label = str(data.get("label", "")).strip()[:80]
            except Exception:
                self.send_json({"error": "Invalid JSON"}, 400)
                return
            if not text.strip():
                self.send_json({"error": "No log content provided"}, 400)
                return
            if len(text) > EXTERNAL_MAX_CHARS:
                self.send_json({"error": f"Input too large (max {EXTERNAL_MAX_CHARS} characters)"}, 413)
                return
            if len([ln for ln in text.splitlines() if ln.strip()]) > EXTERNAL_MAX_LINES:
                self.send_json({"error": f"Too many lines (max {EXTERNAL_MAX_LINES})"}, 413)
                return
            batch = create_external_batch(label, text)
            self.send_json({"status": "queued", "id": batch["id"]})
        elif self.path.startswith("/api/external/") and self.path.endswith("/search"):
            try:
                batch_id = int(self.path.split("/")[-2])
            except (ValueError, IndexError):
                self.send_json({"error": "Invalid batch ID"}, 400)
                return
            if state.search_config["mode"] != "manual":
                self.send_json({"error": "Search mode is not set to Manual"}, 400)
                return
            with state.lock:
                batch = next((b for b in state.external_batches if b["id"] == batch_id), None)
            if not batch:
                self.send_json({"error": "Batch not found"}, 404)
                return
            if batch["status"] not in ("complete", "error"):
                self.send_json({"error": "Batch is still being analyzed"}, 409)
                return
            batch["status"] = "queued"
            broadcast_sse("ext_batch_requeued", {"id": batch["id"], "status": "queued"})
            external_queue.put((batch, True))
            self.send_json({"status": "queued"})
        elif self.path.startswith("/api/batch/") and self.path.endswith("/search"):
            try:
                batch_id = int(self.path.split("/")[-2])
            except (ValueError, IndexError):
                self.send_json({"error": "Invalid batch ID"}, 400)
                return
            if state.search_config["mode"] != "manual":
                self.send_json({"error": "Search mode is not set to Manual"}, 400)
                return
            with state.lock:
                batch = next((b for b in state.batches if b["id"] == batch_id), None)
            if not batch:
                self.send_json({"error": "Batch not found"}, 404)
                return
            if batch["status"] not in ("complete", "error"):
                self.send_json({"error": "Batch is still being analyzed"}, 409)
                return
            batch["status"] = "queued"
            broadcast_sse("batch_requeued", {"id": batch["id"], "status": "queued"})
            analysis_queue.put((batch, True))
            self.send_json({"status": "queued"})
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
        file_path = os.path.abspath(os.path.join(script_dir, filename))
        if not file_path.startswith(script_dir) or not os.path.exists(file_path):
            self.send_error(404)
            return
        content_type = "image/svg+xml" if filename.endswith(".svg") else "image/png"
        try:
            with open(file_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", len(content))
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_error(500, str(e))

    def serve_novnc_file(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        novnc_root = os.path.abspath(os.path.join(script_dir, NOVNC_DIR))
        rel_path = self.path[len("/novnc/"):].split("?")[0]
        file_path = os.path.abspath(os.path.join(novnc_root, rel_path))
        if not file_path.startswith(novnc_root + os.sep) or not os.path.isfile(file_path):
            self.send_error(404)
            return
        content_type = mimetypes.guess_type(file_path)[0] or "application/octet-stream"
        try:
            with open(file_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
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


DEMO_VARIANTS = {"main": {}, "external": {}}
DEMO_ATTACK_IDS_MAIN = [
    "NONE",
    "T1003.008",
    "T1068",
    "T1620",
    "T1571, T1071",
    "T1611",
    "T1070.002, T1070.003",
]
DEMO_ATTACK_IDS_EXTERNAL = [
    "T1059.012, T1489, T1486",
    "NONE",
]


def _build_demo_variants(response, attack_ids, tokens):
    with_attack = re.sub(r"(SEVERITY: \d\n)", lambda m: m.group(1) + f"ATTACK: {attack_ids}\n", response, count=1)
    return {
        "off": {"response": response, "attack": None, "tokens": tokens},
        "on": {"response": with_attack, "attack": map_attack(with_attack), "tokens": tokens + 10},
    }


def apply_demo_attack_variant(enabled):
    key = "on" if enabled else "off"
    with state.lock:
        for scope, items in (("main", state.batches), ("external", state.external_batches)):
            for b in items:
                variants = DEMO_VARIANTS[scope].get(b["id"])
                if variants:
                    b.update(variants[key])


def seed_demo_batches():
    now = time.time()
    ts = [now - (7 - i) * 40 for i in range(7)]

    net_pkg_1 = (
        '{"packet_number": 201, "timestamp": "2026-09-17T14:18:11.442019+00:00", '
        '"ethernet": {"src_mac": "52:54:00:12:34:56", "dst_mac": "52:55:0a:00:02:02", "type": "0x800"}, '
        '"network": {"version": 4, "src_ip": "10.0.2.15", "dst_ip": "91.189.91.39", "protocol_number": 6, '
        '"protocol_name": "TCP", "ttl": 64, "tos": 0, "identification": 9931, "flags": "DF", '
        '"fragment_offset": 0, "total_length": 60, "header_length": 20}, '
        '"transport": {"protocol": "TCP", "src_port": 47201, "dst_port": 443, "flags": "SYN", "seq": 0, "ack": 0}, '
        '"payload": {"size_bytes": 0, "hex_preview": ""}, '
        '"process": {"pid": 900, "name": "unattended-upgr", "user": "root"}, '
        '"direction": "outbound", "raw_packet_size": 60}'
    )
    net_pkg_beacon = (
        '{"packet_number": 812, "timestamp": "2026-09-17T14:22:41.203981+00:00", '
        '"ethernet": {"src_mac": "52:54:00:12:34:56", "dst_mac": "52:55:0a:00:02:02", "type": "0x800"}, '
        '"network": {"version": 4, "src_ip": "10.0.2.15", "dst_ip": "185.220.101.47", "protocol_number": 6, '
        '"protocol_name": "TCP", "ttl": 64, "tos": 0, "identification": 44821, "flags": "DF", '
        '"fragment_offset": 0, "total_length": 68, "header_length": 20}, '
        '"transport": {"protocol": "TCP", "src_port": 51422, "dst_port": 4444, "flags": "PSH,ACK", "seq": 1, "ack": 1}, '
        '"payload": {"size_bytes": 16, "hex_preview": "4245414e0001000000000000000000"}, '
        '"process": {"pid": 4903, "name": "upd8r", "user": "root"}, '
        '"direction": "outbound", "raw_packet_size": 82}'
    )

    batches_raw = [
        {
            "events": [
                "[ebpf:ch1] 14:18:02  systemd          1        0        execve     /lib/systemd/systemd-udevd",
                "[ebpf:ch1] 14:18:04  cron             612      0        execve     /usr/sbin/cron",
                "[ebpf:ch8] COMM: logrotate        PID: 615      UID: 0       FLAGS: 0x0    FILE: /var/log/syslog",
                "[ebpf:ch9] COMM: run-parts        PID: 618      PPID: 612     UID: 0      PATH: /etc/cron.daily/apt-compat FLAGS:",
                f"[network:ch10] {net_pkg_1}",
            ],
            "response": (
                "VERDICT: SAFE\n"
                "SEVERITY: 1\n"
                "ANALYSIS: All observed activity matches routine system maintenance. cron (PID 612) invoked "
                "logrotate and /etc/cron.daily/apt-compat at their scheduled window, both running as root with "
                "expected parent/child ancestry from systemd -> cron -> run-parts. No sensitive-file, "
                "privilege-escalation, or network anomaly categories were triggered. No further action needed."
            ),
            "rag": {"category": "UNKNOWN", "confidence": "LOW", "score": 0.11, "dense_similarity": 0.14, "categories": [], "hyde_degraded": False},
            "tokens": 162, "duration": 3.8,
        },
        {
            "events": [
                "[ebpf:ch8] COMM: vim              PID: 3312     UID: 1000    FLAGS: 0x0    FILE: /etc/shadow",
                "[ebpf:ch9] COMM: vim              PID: 3312     PPID: 3290    UID: 1000    PATH: /usr/bin/vim.basic FLAGS:",
                "[ebpf:ch1] 14:19:47  bash             3290     1000     openat     /home/cerise/.bash_history",
            ],
            "response": (
                "VERDICT: SUSPICIOUS\n"
                "SEVERITY: 2\n"
                "ANALYSIS: vim (PID 3312, uid 1000) opened /etc/shadow directly, which matches the Sensitive File "
                "Access category (Base Criticality Level 3 in the retrieved doc), but the retrieved category is "
                "MEDIUM confidence and the access pattern (interactive editor, single open, no subsequent write "
                "syscalls or exfiltration) is about as consistent with an administrator auditing local accounts as "
                "with recon. No correlated network or privilege-escalation activity followed within this window. "
                "Recommend monitoring PID 3312's parent shell for follow-up actions before escalating."
            ),
            "rag": {"category": "sensitive_file_access", "confidence": "MEDIUM", "score": 0.58, "dense_similarity": 0.61, "categories": ["sensitive_file_access"], "hyde_degraded": False},
            "tokens": 201, "duration": 4.6,
        },
        {
            "events": [
                "[ebpf:ch9] COMM: cnfg_updater     PID: 4821     PPID: 4790    UID: 1000    PATH: /tmp/.X11-unix/.cache/upd8r FLAGS: [SUSPICIOUS_PATH]",
                "[ebpf:ch7] 14:22:03  cnfg_updater     4821     1000     setresuid  ",
                "[ebpf:ch7] 14:22:03  cnfg_updater     4821     1000     setresuid  ruid=1000, euid=0, suid=0",
                "[ebpf:ch1] 14:22:03  cnfg_updater     4821     0        execve     /tmp/.X11-unix/.cache/upd8r",
            ],
            "response": (
                "VERDICT: THREAT\n"
                "SEVERITY: 4\n"
                "ANALYSIS: Process cnfg_updater (PID 4821, spawned from an interactive bash at PPID 4790, uid 1000) "
                "called setresuid(ruid=1000, euid=0, suid=0), successfully transitioning from an unprivileged shell "
                "to root without going through sudo/pkexec or any setuid binary. This matches the Privilege "
                "Escalation category's core Anomaly Pattern (Base Criticality Level 4) and does not match its "
                "Normal Patterns, which require a known setuid binary in the call path. No corresponding sudo log "
                "entry exists for this uid/pid pair in the batch. Treat PID 4821 and its process tree as "
                "compromised going forward."
            ),
            "rag": {"category": "privilege_escalation", "confidence": "HIGH", "score": 0.84, "dense_similarity": 0.79, "categories": ["privilege_escalation"], "hyde_degraded": False},
            "tokens": 248, "duration": 5.9,
        },
        {
            "events": [
                '[ebpf:ch3] {"e":"fm","c":"upd8r","p":4903,"u":0,"n":"memfd:a3f21c (deleted)"}',
                "[ebpf:ch9] COMM: upd8r            PID: 4903     PPID: 4821    UID: 0       PATH: /proc/self/fd/7 FLAGS: [SUSPICIOUS_PATH] [UNEXPECTED_USER]",
                "[ebpf:ch1] 14:22:39  upd8r            4903     0        mmap       PROT_EXEC|PROT_WRITE",
            ],
            "response": (
                "VERDICT: THREAT\n"
                "SEVERITY: 5\n"
                "ANALYSIS: Immediately after the privilege escalation in the prior window (same COMM cnfg_updater, "
                "now PID 4903, root), the process executed code from an anonymous memfd (memfd:a3f21c (deleted)) "
                "with no backing file on disk, a textbook fileless-execution technique used to evade file-based "
                "AV/EDR. This corroborates the Fileless Execution category's Anomaly Pattern (Base Criticality "
                "Level 5) at HIGH confidence; there is no benign Normal Pattern (e.g. JIT compiler, systemd-run) "
                "that matches an unlinked memfd running as root right after an unauthorized setresuid. Combined "
                "with the privilege escalation in the previous batch, this is a single causal chain: unprivileged "
                "shell -> root escalation -> fileless payload execution."
            ),
            "rag": {"category": "fileless_execution", "confidence": "HIGH", "score": 0.91, "dense_similarity": 0.88, "categories": ["fileless_execution", "privilege_escalation"], "hyde_degraded": False},
            "tokens": 289, "duration": 6.7,
        },
        {
            "events": [
                "[ebpf:ch6] COMM: upd8r      PID: 4903   UID: 0      IP: 3118853167     :4444 FLAGS: SUSPICIOUS",
                f"[network:ch10] {net_pkg_beacon}",
            ],
            "response": (
                "VERDICT: THREAT\n"
                "SEVERITY: 5\n"
                "ANALYSIS: PID 4903 (the same fileless payload from the previous batch, now running as root) "
                "opened an outbound TCP connection from 10.0.2.15:51422 to 185.220.101.47:4444, and the "
                "kernel-level Network Suspicious probe independently flagged the same PID/UID pair on that "
                "destination. The 16-byte payload beginning with the ASCII marker \"BEACON\" is consistent with a "
                "C2 check-in rather than legitimate application traffic, and port 4444 is a common default for "
                "post-exploitation frameworks. Correlating the [ebpf] and [network] events by PID confirms this is "
                "the same process chain as the two prior THREAT batches, not an independent event. Recommend "
                "isolating the host and blocking 185.220.101.47 immediately."
            ),
            "rag": {"category": "network_suspicious", "confidence": "HIGH", "score": 0.87, "dense_similarity": 0.82, "categories": ["network_suspicious", "fileless_execution"], "hyde_degraded": False},
            "tokens": 275, "duration": 6.1,
        },
        {
            "events": [
                '[ebpf:ch2] {"evt":"docker_sock","comm":"curl","pid":5210,"ppid":5188,"uid":1000,"path":"/var/run/docker.sock"}',
                "[ebpf:ch9] COMM: curl             PID: 5210     PPID: 5188    UID: 1000    PATH: /usr/bin/curl FLAGS:",
            ],
            "response": (
                "VERDICT: SUSPICIOUS\n"
                "SEVERITY: 3\n"
                "ANALYSIS: curl (PID 5210, uid 1000, PPID 5188) connected to /var/run/docker.sock, matching the "
                "Docker Socket Access category (Base Criticality Level 3, MEDIUM confidence retrieved). "
                "Unprivileged access to the Docker socket is a known container-escape / privilege-escalation "
                "vector (equivalent to root), but this single event alone doesn't confirm exploitation; no "
                "follow-up container-creation or volume-mount API call was captured in this window, and curl "
                "against the socket can also occur during legitimate local tooling or debugging. Recommend "
                "watching PID 5210's parent (5188) for a subsequent docker create/API call with a mounted host "
                "path before escalating to THREAT."
            ),
            "rag": {"category": "docker_socket_access", "confidence": "MEDIUM", "score": 0.55, "dense_similarity": 0.52, "categories": ["docker_socket_access"], "hyde_degraded": False},
            "tokens": 231, "duration": 5.2,
        },
        {
            "events": [
                '[ebpf:ch5] {"e":"log_tamp","c":"upd8r","p":4903,"u":0,"f":"/var/log/auth.log"}',
                '[ebpf:ch5] {"e":"log_tamp","c":"upd8r","p":4903,"u":0,"f":"/home/cerise/.bash_history"}',
                "[ebpf:ch9] COMM: upd8r            PID: 4903     PPID: 4821    UID: 0       PATH: /usr/bin/truncate FLAGS: [UNEXPECTED_USER]",
            ],
            "response": (
                "VERDICT: THREAT\n"
                "SEVERITY: 4\n"
                "ANALYSIS: The same root-owned process (upd8r, PID 4903, descendant of the PID 4821 chain flagged "
                "as THREAT twice already in this session) truncated /var/log/auth.log and "
                "/home/cerise/.bash_history immediately after the C2 beacon in the prior batch. This matches the "
                "Log Tampering category's Anomaly Pattern at HIGH confidence (Base Criticality Level 4): "
                "legitimate log rotation is performed by logrotate under a cron-owned ancestry (see batch #1 for "
                "the benign baseline), never by a process that just escalated privileges and beaconed to an "
                "external IP. This is consistent anti-forensics behavior closing out a full intrusion chain: "
                "privilege escalation -> fileless execution -> C2 beacon -> log tampering."
            ),
            "rag": {"category": "log_tampering", "confidence": "HIGH", "score": 0.89, "dense_similarity": 0.85, "categories": ["log_tampering"], "hyde_degraded": False},
            "tokens": 267, "duration": 6.0,
        },
    ]

    batches = []
    ebpf_total, network_total = 0, 0
    events_per_port = {}
    for i, b in enumerate(batches_raw):
        for line in b["events"]:
            tag = line[1:line.index("]")]
            events_per_port[tag] = events_per_port.get(tag, 0) + 1
            if tag.startswith("network"):
                network_total += 1
            else:
                ebpf_total += 1
        batches.append({
            "id": i + 1,
            "timestamp": ts[i],
            "events": b["events"],
            "event_count": len(b["events"]),
            "response": b["response"],
            "attack": None,
            "status": "complete",
            "tokens": b["tokens"],
            "duration": b["duration"],
            "rag": b["rag"],
        })

    external_raw = [
        {
            "label": "Sample B - ESXi locker",
            "age": 95,
            "events": [
                "08:02:05.164969 UTC pid=163 procname=xargs func=execve exec_path=./uswW7SbL arg1=--encryption_path=/vmfs/volumes",
                "08:02:05.166286 UTC pid=161 procname=xargs func=fork ret=163",
                "08:02:05.170538 UTC pid=163 procname=uswW7SbL func=readlink buffer=/root/guild/uswW7SbL",
                "08:02:05.249822 UTC pid=163 procname=uswW7SbL func=fork ret=164",
                "08:02:05.301177 UTC pid=164 procname=sh func=execve exec_path=/bin/sh arg1=-c arg2=esxcli vm process list",
                "08:02:05.388410 UTC pid=166 procname=sh func=execve exec_path=/bin/sh arg1=-c arg2=esxcli vm process kill --type=force --world-id=5337229",
                "08:02:05.452903 UTC pid=168 procname=sh func=execve exec_path=/bin/sh arg1=-c arg2=pkill -9 vmx-*",
                "08:02:05.611045 UTC pid=163 procname=uswW7SbL func=open file_path=/vmfs/volumes/53e0ce7b-4dc3d26a/web01/web01.vmdk flags=O_RDWR",
                "08:02:05.611512 UTC pid=163 procname=uswW7SbL func=write fd=3 size=1048576",
                "08:02:05.704288 UTC pid=163 procname=uswW7SbL func=rename old=/vmfs/volumes/53e0ce7b-4dc3d26a/web01/web01.vmdk new=/vmfs/volumes/53e0ce7b-4dc3d26a/web01/web01.vmdk.akira",
                "08:02:05.704901 UTC pid=163 procname=uswW7SbL func=rename old=/vmfs/volumes/53e0ce7b-4dc3d26a/web01/web01.vmx new=/vmfs/volumes/53e0ce7b-4dc3d26a/web01/web01.vmx.akira",
                "08:02:05.705377 UTC pid=163 procname=uswW7SbL func=rename old=/vmfs/volumes/53e0ce7b-4dc3d26a/web01/web01.nvram new=/vmfs/volumes/53e0ce7b-4dc3d26a/web01/web01.nvram.akira",
                "08:02:05.731660 UTC pid=163 procname=uswW7SbL func=open file_path=/vmfs/volumes/53e0ce7b-4dc3d26a/web01/akira_readme.txt flags=O_WRONLY|O_CREAT",
                "08:02:05.790214 UTC pid=163 procname=uswW7SbL func=connect ip=203.0.113.58 port=12132 ret=0",
            ],
            "response": (
                "VERDICT: THREAT\n"
                "SEVERITY: 5\n"
                "ANALYSIS: The log shows the full execution phase of a hypervisor-targeting ransomware. The binary "
                "uswW7SbL (PID 163) was started with --encryption_path=/vmfs/volumes, then its child shells ran "
                "esxcli vm process list, esxcli vm process kill --type=force --world-id=5337229 and pkill -9 vmx-*, "
                "which releases the file locks held by running virtual machines before encryption. The same process "
                "then renamed web01.vmdk, web01.vmx and web01.nvram to the same .akira suffix and created "
                "akira_readme.txt in that directory, matching the ransomware category (Base Criticality Level 5) at "
                "HIGH confidence. A single outbound connect to 203.0.113.58:12132 follows, and the External Search "
                "assessment for that address is malicious, which reinforces the verdict since the raw log shows the "
                "process itself opening the connection. The log shows file writes and renames, but not the content "
                "of the files, so encryption is strongly suspected rather than confirmed, and no data exfiltration "
                "is shown. Isolating the host and its datastore access is the immediate action."
            ),
            "rag": {"category": "ransomware", "confidence": "HIGH", "score": 3.12, "dense_similarity": 0.78, "categories": ["ransomware", "suspicious_exec"], "hyde_degraded": False},
            "search": {
                "performed": True,
                "terms": ["203.0.113.58"],
                "sources": [
                    {
                        "term": "203.0.113.58",
                        "title": "AbuseIPDB assessment: malicious — 96% abuse confidence, 41 report(s) in the last 180 days",
                        "url": "https://www.abuseipdb.com/check/203.0.113.58",
                        "snippet": "ISP: Example Hosting Ltd · Country: NL · Usage: Data Center/Web Hosting/Transit · Last reported: 2026-10-12T09:31:07+00:00",
                    },
                    {
                        "term": "203.0.113.58",
                        "title": "VirusTotal assessment: malicious — 14/94 engines flagged this IP as malicious (3 suspicious)",
                        "url": "https://www.virustotal.com/gui/ip-address/203.0.113.58",
                        "snippet": "AS owner: Example Hosting Ltd · Country: NL · Community reputation: -18",
                    },
                ],
                "note": None,
            },
            "tokens": 318, "duration": 7.4,
        },
        {
            "label": "Sample C - nightly backup job",
            "age": 40,
            "events": [
                "2026-10-14T02:00:01 cron[612]: (backup) CMD (/usr/local/bin/nightly-backup.sh)",
                "2026-10-14T02:00:02 pid=2210 comm=nightly-backup.sh execve /usr/bin/rsync -a --delete /srv/data /mnt/backup/daily",
                "2026-10-14T02:00:02 pid=2211 comm=rsync open /srv/data/reports/q3.xlsx O_RDONLY",
                "2026-10-14T02:00:03 pid=2211 comm=rsync open /srv/data/reports/q3.xlsx O_RDONLY",
                "2026-10-14T02:00:09 pid=2212 comm=rsync write /mnt/backup/daily/reports/q3.xlsx",
                "2026-10-14T02:03:40 pid=2230 comm=tar execve /usr/bin/tar -czf /mnt/backup/weekly/srv-data.tar.gz /srv/data",
                "2026-10-14T02:03:41 pid=2231 comm=gzip write /mnt/backup/weekly/srv-data.tar.gz",
                "2026-10-14T02:09:12 pid=2210 comm=nightly-backup.sh exit status=0",
            ],
            "response": (
                "VERDICT: SAFE\n"
                "SEVERITY: 1\n"
                "ANALYSIS: All activity belongs to a scheduled backup job. cron (PID 612) started "
                "nightly-backup.sh, which ran rsync -a --delete from /srv/data to /mnt/backup/daily and tar -czf to "
                "produce srv-data.tar.gz, then exited with status 0. The files are read from the source and written "
                "to the backup destination under their original names, with no uniform suffix applied to the "
                "source tree, no ransom note, no virtual machine or process termination commands and no outbound "
                "network events. This is consistent with the normal backup and archive patterns, so no category "
                "was triggered. No further action needed."
            ),
            "rag": {"category": "UNKNOWN", "confidence": "LOW", "score": 0.09, "dense_similarity": 0.12, "categories": [], "hyde_degraded": False},
            "search": {"performed": False, "terms": [], "sources": [], "note": "No public indicators found in this batch."},
            "tokens": 156, "duration": 3.9,
        },
    ]
    external_batches = []
    for i, b in enumerate(external_raw):
        external_batches.append({
            "id": i + 1,
            "label": b["label"],
            "timestamp": now - b["age"],
            "events": b["events"],
            "event_count": len(b["events"]),
            "analyzed_events": len(b["events"]),
            "response": b["response"],
            "attack": None,
            "search": b["search"],
            "status": "complete",
            "tokens": b["tokens"],
            "duration": b["duration"],
            "rag": b["rag"],
        })

    for batch, ids in zip(batches, DEMO_ATTACK_IDS_MAIN):
        DEMO_VARIANTS["main"][batch["id"]] = _build_demo_variants(batch["response"], ids, batch["tokens"])
    for batch, ids in zip(external_batches, DEMO_ATTACK_IDS_EXTERNAL):
        DEMO_VARIANTS["external"][batch["id"]] = _build_demo_variants(batch["response"], ids, batch["tokens"])

    with state.lock:
        state.batches = batches
        state.batch_counter = len(batches)
        state.external_batches = external_batches
        state.external_counter = len(external_batches)
        state.total_events = ebpf_total + network_total
        state.ebpf_count = ebpf_total
        state.network_count = network_total
        state.events_per_port = events_per_port
        state.last_event_time = ts[-1]
        state.start_time = now - 8100
        state.host_running = True
        state.supervisor_running_count = 1
        state.ports = [f"/dev/pts/{n}" for n in range(7, 18)]
        state.host_ports = state.ports[:9]
        state.supervisor_ports = state.ports[9:]


def main():
    print("[pipeline_web] Starting Cerise Pipeline Web Dashboard...")

    if DEMO_MODE:
        print("[pipeline_web] DEMO MODE: seeding fake batches/dashboard data; VM Screen stays real.")
        rag_ready.set()
        seed_demo_batches()
    else:
        threading.Thread(target=init_rag_thread, daemon=True).start()

    entries = load_ports()
    if entries and vm_is_active():
        start_listeners(entries)
        state.vm_running = True
        print(f"[pipeline_web] Detected running VM, attached to {len(entries)} serial port(s)")
    else:
        print("[pipeline_web] No VM running yet. Use the dashboard's Start VM button.")

    state.vnc_proc = spawn_websockify()
    if state.vnc_proc:
        state.vnc_running = True
        print(f"[pipeline_web] websockify spawned on port {NOVNC_WS_PORT} (PID {state.vnc_proc.pid})")

    state.ttyd_proc = spawn_ttyd()
    if state.ttyd_proc:
        print(f"[pipeline_web] ttyd spawned on {TTYD_HOST}:{TTYD_PORT} (PID {state.ttyd_proc.pid})")

    threading.Thread(target=analysis_worker_thread, daemon=True).start()
    threading.Thread(target=external_worker_thread, daemon=True).start()
    threading.Thread(target=batch_timer_thread, daemon=True).start()
    threading.Thread(target=vm_metrics_thread, daemon=True).start()

    server = ThreadedHTTPServer((WEB_HOST, WEB_PORT), DashboardHandler)
    print(f"[pipeline_web] Dashboard available at http://localhost:{WEB_PORT}")
    print(f"[pipeline_web] Batch interval: {BATCH_INTERVAL}s")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[pipeline_web] Shutting down...")
        stop_listeners()
        if state.vnc_proc:
            state.vnc_proc.terminate()
            state.vnc_proc.wait()
        if state.ttyd_proc:
            state.ttyd_proc.terminate()
            state.ttyd_proc.wait()
        server.shutdown()
        print("[pipeline_web] Done.")


if __name__ == "__main__":
    main()
