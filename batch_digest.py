import ipaddress
import json
import re
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from typing import Callable, Dict, Iterable, List, Optional, Tuple

SOURCE_EBPF = "ebpf"
SOURCE_NETWORK = "network"
SOURCE_UNKNOWN = "unknown"

SENSOR_SUSPICIOUS_EXEC = "suspicious_exec"
SENSOR_SENSITIVE_FILE = "sensitive_file"
SENSOR_PRIVILEGE_ESCALATION = "privilege_escalation"
SENSOR_DANGEROUS_SYSCALLS = "dangerous_syscalls"
SENSOR_NETWORK_SUSPICIOUS = "network_suspicious"
SENSOR_KERNEL_MODULE = "kernel_module"
SENSOR_FILELESS = "fileless"
SENSOR_LOG_TAMPERING = "log_tampering"
SENSOR_PERSISTENCE_ACTIVITY = "persistence_activity"
SENSOR_DOCKER_SOCKET = "docker_socket"
SENSOR_NETWORK = "network"
SENSOR_BANNER = "banner"
SENSOR_BPFTRACE_RUNTIME = "bpftrace_runtime"
SENSOR_HEARTBEAT = "heartbeat"
SENSOR_UNKNOWN = "unknown"

KIND_UNPARSED = "unparsed"
KIND_BANNER = "banner"
KIND_LOST_EVENTS = "lost_events"
KIND_EXEC = "exec"
KIND_CHMOD = "chmod"
KIND_RENAME_TO_SERVED_DIR = "rename_to_served_dir"
KIND_FILE_OPEN = "file_open"
KIND_NETWORK_CONNECT = "suspicious_connect"
KIND_KERNEL_MODULE_LOAD = "kernel_module_load"
KIND_MEMFD_CREATE = "memfd_create"
KIND_LOG_WRITE = "log_write"
KIND_PERSISTENCE = "persistence"
KIND_MASS_FILE_OPS = "mass_file_ops"
KIND_HEARTBEAT = "heartbeat"
KIND_DOCKER_SOCKET_CONNECT = "docker_socket_connect"
KIND_FLOW = "flow"
KIND_DNS_QUERY = "dns_query"
KIND_DNS_RESPONSE = "dns_response"
KIND_ARP = "arp"

FLAG_CHMOD_CALLED = "CHMOD_CALLED"
FLAG_ROOT_TRANSITION = "ROOT_TRANSITION"
FLAG_EXTERNAL_DEST = "EXTERNAL_DEST"
FLAG_ACCESS_READ = "ACCESS_READ"
FLAG_ACCESS_WRITE = "ACCESS_WRITE"
FLAG_ACCESS_READ_WRITE = "ACCESS_RDWR"
FLAG_TCP_SYN = "TCP_SYN"
FLAG_TCP_RST = "TCP_RST"
FLAG_PERSISTENCE_WRITE = "PERSISTENCE_WRITE"
FLAG_MASS_FILE_OPS = "MASS_FILE_OPS"

SEVERE_FLAGS = frozenset({
    "SUSPICIOUS_PATH",
    "UNEXPECTED_USER",
    "SHELL_INTERPRETER",
    "MOVED_TO_SERVED_DIR",
    "SUSPICIOUS",
    "PATH_TRAVERSAL",
    FLAG_CHMOD_CALLED,
    FLAG_ROOT_TRANSITION,
    FLAG_EXTERNAL_DEST,
    FLAG_ACCESS_WRITE,
    FLAG_ACCESS_READ_WRITE,
    FLAG_PERSISTENCE_WRITE,
    FLAG_MASS_FILE_OPS,
    "O_TRUNC",
})
SEVERE_KINDS = frozenset({
    KIND_KERNEL_MODULE_LOAD,
    KIND_MEMFD_CREATE,
    KIND_LOG_WRITE,
    KIND_DOCKER_SOCKET_CONNECT,
    KIND_RENAME_TO_SERVED_DIR,
    KIND_PERSISTENCE,
    KIND_MASS_FILE_OPS,
    "ptrace",
    "kexec_load",
    "chroot",
    "setns",
    "init_module",
    "finit_module",
    "delete_module",
})

CONTROL_COMMS = frozenset({"bpftrace", "guest_monitor"})
CONTROL_COMM_PREFIXES = ("supervisor_monit",)
SUPERVISOR_INTERPRETER_COMM = "python3"
SUPERVISOR_SCRIPT_MARKER = "supervisor.py"
INIT_PID = 1
STARTUP_EVENT_NAME = "startup"
SANDBOX_ANNOTATION = "[systemd unit sandbox setup]"
SANDBOX_COMM_PREFIX = "("
SANDBOX_COMM_SUFFIX = ")"
SANDBOX_PARENT_PID = INIT_PID
SANDBOX_SYSCALL_KINDS = frozenset({"mount", "umount", "unshare"})
SANDBOX_PRIVILEGE_KINDS = frozenset({"capset"})
HANDOFF_READ_PREFIXES = ("/proc/", "/sys/")
SANDBOX_SUMMARY_MAX_CHARS = 900
SANDBOX_ENTRY_MAX_CHARS = 90
SANDBOX_MAX_PIDS_LISTED = 5
CONTROL_HOST_IP = "10.0.2.2"
GUEST_IP = "10.0.2.15"
SSH_PORT = 22
CONTROL_FLOW_IPS = frozenset({CONTROL_HOST_IP, GUEST_IP})
TCP_PROTOCOL = "TCP"

EPHEMERAL_PORT_START = 32768
EPHEMERAL_PORT_LABEL = "*"
OUTBOUND_DIRECTION = "outbound"

HEARTBEAT_EVENT_NAME = "hb"
SENSOR_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,47}$")
MAX_TRACKED_SENSORS = 32
SENSOR_HEALTH_NOTE = (
    "A sensor that stops reporting, dies or restarts may have been killed or tampered with by the malware. "
    "Treat it as possible defense evasion and say so in the analysis, together with the sensor names, but do not "
    "conclude malicious intent from a restart alone."
)

DIGEST_MAX_CHARS = 12000
GROUPS_SECTION_SHARE = 0.75
FOOTER_RESERVED_CHARS = 350
MAX_SAMPLE_TARGETS = 5
MAX_TOP_DIRECTORIES = 5
MAX_TRACKED_TARGETS = 2000
TARGET_MAX_CHARS = 90
EXAMPLE_LINE_MAX_CHARS = 200
EXAMPLE_GROUPS_MAX = 12
BASELINE_SUMMARY_MAX_CHARS = 1400
BASELINE_ENTRY_MAX_CHARS = 90
UNPARSED_TARGET_MAX_CHARS = 160
TWO_LEVEL_ROOTS = frozenset({"var", "usr", "opt", "run", "lib", "srv"})

OPEN_ACCESS_MASK = 0x3
OPEN_ACCESS_FLAGS = {
    0: FLAG_ACCESS_READ,
    1: FLAG_ACCESS_WRITE,
    2: FLAG_ACCESS_READ_WRITE,
    3: FLAG_ACCESS_READ_WRITE,
}
OPEN_BIT_FLAGS = ((0x40, "O_CREAT"), (0x200, "O_TRUNC"), (0x400, "O_APPEND"))

NORMALIZED_PID = "<pid>"
NORMALIZED_HEX = "<hex>"
NORMALIZED_NUMBER = "<num>"
SIGNATURE_SEPARATOR = "|"

PREFIX_PATTERN = re.compile(r"^\[(ebpf|network)(?::[^\]]*)?\]\s?")
EXEC_PATTERN = re.compile(
    r"^(?:TIME:\s*(?:(\d{2}:\d{2}:\d{2})\s+)?)*COMM:\s*(.+?)\s+PID:\s*(\d+)\s+PPID:\s*(\d+)\s+UID:\s*(\d+)\s+"
    r"(?:PATH:\s*(.+?)\s+|RENAME_TO:\s*(.+?)\s+)?FLAGS:(.*)$"
)
LOST_PATTERN = re.compile(r"^(TIME:\s*)?(?:(\d{2}:\d{2}:\d{2})\s+)?Lost\s+(\d+)\s+events?\b")
FILE_PATTERN = re.compile(
    r"^COMM:\s*(.+?)\s+PID:\s*(\d+)\s+UID:\s*(\d+)\s+FLAGS:\s*0x([0-9a-fA-F]+)\s+FILE:\s*(.*)$"
)
NETWORK_SUSPICIOUS_PATTERN = re.compile(
    r"^COMM:\s*(.+?)\s+PID:\s*(\d+)\s+UID:\s*(\d+)\s+IP:\s*(\d+)\s*:(\d+)\s+FLAGS:\s*(\w+)\s*$"
)
PRIVILEGE_PATTERN = re.compile(
    r"^(\d{2}:\d{2}:\d{2})\s+(.+?)\s+(\d+)\s+(\d+)\s+"
    r"(setuid|setgid|setreuid|setregid|setresuid|setresgid|setfsuid|setfsgid|capset)(?:\s+(.*))?$"
)
SYSCALL_PATTERN = re.compile(
    r"^(\d{2}:\d{2}:\d{2})\s+(.+?)\s+(\d+)\s+(\d+)\s+(\d+)\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s+(.*))?$"
)
BANNER_PATTERN = re.compile(
    r"^(?:Attaching\s+\d+\s+probes?\b.*|Monitoring\s.*|Waiting for encrypted\s.*|TIME\s+COMM\s+PID\b.*)$"
)
TRAILING_FLAGS_PATTERN = re.compile(r"(?:\s+\[\w+\])+\s*$")
BRACKET_FLAG_PATTERN = re.compile(r"\[(\w+)\]")
TRANSITION_PATTERN = re.compile(r"(\d+)\s*->\s*(\d+)")
RESULT_IDS_PATTERN = re.compile(r"(?:ruid|euid|suid|rgid|egid|sgid)=(-?\d+)")
PROC_PID_PATTERN = re.compile(r"/proc/\d+")
HEX_RUN_PATTERN = re.compile(r"(?<![0-9A-Za-z])(?=[0-9a-fA-F]*\d)[0-9a-fA-F]{8,}(?![0-9A-Za-z])")
LONG_NUMBER_PATTERN = re.compile(r"\d{4,}")

HEADER_TEXT = (
    "BATCH DIGEST: this summary covers ALL {total} events of the batch (the raw log is aggregated, not truncated).\n"
    "How to read it: events are grouped by sensor/kind, process name (comm), uid and flags; count is the number of "
    "events (packets for network). Times: eBPF events use the guest local clock (HH:MM:SS); network events are UTC "
    "(suffix Z). A bpftrace sensor prints only the first part of long paths. Groups are ordered: first the ones NOT "
    "in the baseline that carry serious flags (shell interpreters, chmod, root transitions, writes to sensitive "
    "files, external destinations, kernel module/memfd/log/docker events, persistence writes, mass file "
    "operations), then by count. mass_file_ops groups show the SUM of operations (count), the number of 1-second "
    "windows and the number of event lines. Groups seen in the clean baseline capture are marked [baseline] and "
    "listed in one line: treat them as normal background unless their volume or targets are clearly abnormal. "
    "A group marked [systemd unit sandbox setup] is the mount/unshare/capset burst that systemd performs when it "
    "starts a service (parent PID 1, comm in parentheses, nothing else from that PID): it is listed in one line, "
    "not ranked, and is normal unless the same PID does anything else. Monitoring-stack and SSH control-channel "
    "traffic is filtered out and only counted."
)


@dataclass(frozen=True)
class ParsedEvent:
    source: str
    sensor: str
    kind: str
    comm: str = ""
    pid: Optional[int] = None
    ppid: Optional[int] = None
    uid: Optional[int] = None
    target: str = ""
    flags: Tuple[str, ...] = ()
    raw: str = ""
    time: Optional[str] = None
    count: int = 1
    cmdline: str = ""
    operations: int = 0
    window_seconds: int = 0
    protocol: str = ""
    src_ip: str = ""
    src_port: Optional[int] = None
    dst_ip: str = ""
    dst_port: Optional[int] = None
    detail: str = ""
    sequence: Optional[int] = None
    alive: Optional[bool] = None


@dataclass
class SensorHealth:
    heartbeats: int = 0
    last_sequence: Optional[int] = None
    gaps: int = 0
    restarts: int = 0
    dead: bool = False


@dataclass
class BatchDigest:
    text: str
    stats: Dict[str, object]


def _to_int(value) -> Optional[int]:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _split_prefix(line: str) -> Tuple[str, str]:
    match = PREFIX_PATTERN.match(line)
    if match is None:
        return SOURCE_UNKNOWN, line
    return match.group(1), line[match.end():]


def _extract_flags(text: str) -> Tuple[str, ...]:
    return tuple(BRACKET_FLAG_PATTERN.findall(text))


def _open_flags(value: int) -> Tuple[str, ...]:
    names = [OPEN_ACCESS_FLAGS[value & OPEN_ACCESS_MASK]]
    names.extend(name for bit, name in OPEN_BIT_FLAGS if value & bit)
    return tuple(names)


def _is_root_transition(syscall: str, details: str, uid: int) -> bool:
    if uid == 0:
        return False
    transition = TRANSITION_PATTERN.search(details)
    if transition is not None:
        return int(transition.group(2)) == 0
    return any(int(value) == 0 for value in RESULT_IDS_PATTERN.findall(details))


def _parse_exec_line(raw: str, declared: str, text: str) -> Optional[ParsedEvent]:
    match = EXEC_PATTERN.match(text)
    if match is None:
        return None
    clock, comm, pid, ppid, uid, path, rename_to, flag_text = match.groups()
    flags = _extract_flags(flag_text)
    if rename_to is not None:
        kind = KIND_RENAME_TO_SERVED_DIR
    elif FLAG_CHMOD_CALLED in flags:
        kind = KIND_CHMOD
    else:
        kind = KIND_EXEC
    return ParsedEvent(
        source=SOURCE_EBPF, sensor=SENSOR_SUSPICIOUS_EXEC, kind=kind, comm=comm, pid=int(pid),
        ppid=int(ppid), uid=int(uid), target=path or rename_to or "", flags=flags, raw=raw, time=clock,
    )


def _parse_lost_line(raw: str, declared: str, text: str) -> Optional[ParsedEvent]:
    match = LOST_PATTERN.match(text)
    if match is None:
        return None
    exec_marker, clock, lost = match.groups()
    sensor = SENSOR_SUSPICIOUS_EXEC if exec_marker else SENSOR_BPFTRACE_RUNTIME
    return ParsedEvent(
        source=SOURCE_EBPF, sensor=sensor, kind=KIND_LOST_EVENTS, raw=raw, time=clock, count=int(lost),
    )


def _parse_banner_line(raw: str, declared: str, text: str) -> Optional[ParsedEvent]:
    if BANNER_PATTERN.match(text) is None:
        return None
    source = declared if declared != SOURCE_UNKNOWN else SOURCE_EBPF
    return ParsedEvent(source=source, sensor=SENSOR_BANNER, kind=KIND_BANNER, raw=raw, target=_clip(text, 80))


def _parse_file_line(raw: str, declared: str, text: str) -> Optional[ParsedEvent]:
    match = FILE_PATTERN.match(text)
    if match is None:
        return None
    comm, pid, uid, flag_hex, file_text = match.groups()
    path = TRAILING_FLAGS_PATTERN.sub("", file_text)
    trailing = _extract_flags(file_text[len(path):])
    flags = _open_flags(int(flag_hex, 16)) + trailing
    return ParsedEvent(
        source=SOURCE_EBPF, sensor=SENSOR_SENSITIVE_FILE, kind=KIND_FILE_OPEN, comm=comm, pid=int(pid),
        uid=int(uid), target=path, flags=flags, raw=raw,
    )


def _parse_network_suspicious_line(raw: str, declared: str, text: str) -> Optional[ParsedEvent]:
    match = NETWORK_SUSPICIOUS_PATTERN.match(text)
    if match is None:
        return None
    comm, pid, uid, first_octet, port, flag = match.groups()
    return ParsedEvent(
        source=SOURCE_EBPF, sensor=SENSOR_NETWORK_SUSPICIOUS, kind=KIND_NETWORK_CONNECT, comm=comm,
        pid=int(pid), uid=int(uid), target=f"{first_octet}.*.*.*:{port}", flags=(flag,), raw=raw,
    )


def _parse_privilege_line(raw: str, declared: str, text: str) -> Optional[ParsedEvent]:
    match = PRIVILEGE_PATTERN.match(text)
    if match is None:
        return None
    clock, comm, pid, uid, syscall, details = match.groups()
    details = details or ""
    flags = (FLAG_ROOT_TRANSITION,) if _is_root_transition(syscall, details, int(uid)) else ()
    return ParsedEvent(
        source=SOURCE_EBPF, sensor=SENSOR_PRIVILEGE_ESCALATION, kind=syscall, comm=comm, pid=int(pid),
        uid=int(uid), target=details, flags=flags, raw=raw, time=clock,
    )


def _parse_syscall_line(raw: str, declared: str, text: str) -> Optional[ParsedEvent]:
    match = SYSCALL_PATTERN.match(text)
    if match is None:
        return None
    clock, comm, pid, ppid, uid, syscall, details = match.groups()
    return ParsedEvent(
        source=SOURCE_EBPF, sensor=SENSOR_DANGEROUS_SYSCALLS, kind=syscall, comm=comm, pid=int(pid),
        ppid=int(ppid), uid=int(uid), target=details or "", raw=raw, time=clock,
    )


def _parse_banner_json(raw: str, payload: dict) -> ParsedEvent:
    is_startup = payload.get("event") == STARTUP_EVENT_NAME
    return ParsedEvent(
        source=SOURCE_NETWORK, sensor=SENSOR_BANNER, kind=KIND_BANNER, raw=raw,
        target=_clip(str(payload.get("message")), 80),
        pid=_to_int(payload.get("pid")) if is_startup else None,
        ppid=_to_int(payload.get("ppid")) if is_startup else None,
    )


def _parse_persistence_json(raw: str, payload: dict) -> ParsedEvent:
    return ParsedEvent(
        source=SOURCE_EBPF, sensor=SENSOR_PERSISTENCE_ACTIVITY, kind=KIND_PERSISTENCE,
        comm=str(payload.get("c") or ""), pid=_to_int(payload.get("p")), ppid=_to_int(payload.get("pp")),
        uid=_to_int(payload.get("u")), target=str(payload.get("f") or ""), flags=(FLAG_PERSISTENCE_WRITE,),
        raw=raw, detail=str(payload.get("op") or ""),
    )


def _parse_mass_file_ops_json(raw: str, payload: dict) -> ParsedEvent:
    return ParsedEvent(
        source=SOURCE_EBPF, sensor=SENSOR_PERSISTENCE_ACTIVITY, kind=KIND_MASS_FILE_OPS,
        comm=str(payload.get("c") or ""), pid=_to_int(payload.get("p")), uid=_to_int(payload.get("u")),
        flags=(FLAG_MASS_FILE_OPS,), raw=raw, detail=str(payload.get("op") or ""),
        operations=_to_int(payload.get("n")) or 0, window_seconds=_to_int(payload.get("w")) or 0,
    )


def _parse_heartbeat_json(raw: str, payload: dict) -> Optional[ParsedEvent]:
    name = payload.get("s")
    sequence = _to_int(payload.get("q"))
    alive = _to_int(payload.get("a"))
    if not isinstance(name, str) or SENSOR_NAME_PATTERN.match(name) is None:
        return None
    if sequence is None or sequence < 0 or alive not in (0, 1):
        return None
    return ParsedEvent(
        source=SOURCE_EBPF, sensor=SENSOR_HEARTBEAT, kind=KIND_HEARTBEAT, target=name, raw=raw,
        sequence=sequence, alive=bool(alive),
    )


EBPF_CUSTOM_PARSERS = {
    HEARTBEAT_EVENT_NAME: _parse_heartbeat_json,
    "persistence": _parse_persistence_json,
    "mass_file_ops": _parse_mass_file_ops_json,
}

EBPF_JSON_SPECS = {
    "kml": (SENSOR_KERNEL_MODULE, KIND_KERNEL_MODULE_LOAD, "c", "p", "pp", "u", None),
    "fm": (SENSOR_FILELESS, KIND_MEMFD_CREATE, "c", "p", None, "u", "n"),
    "log_tamp": (SENSOR_LOG_TAMPERING, KIND_LOG_WRITE, "c", "p", None, "u", "f"),
    "docker_sock": (SENSOR_DOCKER_SOCKET, KIND_DOCKER_SOCKET_CONNECT, "comm", "pid", "ppid", "uid", "path"),
}


def _parse_ebpf_json(raw: str, payload: dict) -> Optional[ParsedEvent]:
    event_name = payload.get("e") or payload.get("evt")
    custom = EBPF_CUSTOM_PARSERS.get(event_name)
    if custom is not None:
        return custom(raw, payload)
    spec = EBPF_JSON_SPECS.get(event_name)
    if spec is None:
        return None
    sensor, kind, comm_key, pid_key, ppid_key, uid_key, target_key = spec
    return ParsedEvent(
        source=SOURCE_EBPF, sensor=sensor, kind=kind, comm=str(payload.get(comm_key) or ""),
        pid=_to_int(payload.get(pid_key)), ppid=_to_int(payload.get(ppid_key)) if ppid_key else None,
        uid=_to_int(payload.get(uid_key)), target=str(payload.get(target_key) or "") if target_key else "",
        raw=raw,
    )


@lru_cache(maxsize=4096)
def _is_global_address(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return parsed.is_global and not parsed.is_multicast


def _username_to_uid(username) -> Optional[int]:
    if username == "root":
        return 0
    return _to_int(username)


def _port_label(port: Optional[int]) -> str:
    if port is None:
        return ""
    if port >= EPHEMERAL_PORT_START:
        return f":{EPHEMERAL_PORT_LABEL}"
    return f":{port}"


def _flow_target(src_ip: str, src_port: Optional[int], dst_ip: str, dst_port: Optional[int], protocol: str) -> str:
    return f"{src_ip}{_port_label(src_port)} -> {dst_ip}{_port_label(dst_port)}/{protocol}"


def _transport_flags(protocol: str, transport: dict) -> Tuple[str, ...]:
    if protocol == TCP_PROTOCOL:
        tcp_flags = transport.get("flags") or []
        names = [protocol]
        if "SYN" in tcp_flags and "ACK" not in tcp_flags:
            names.append(FLAG_TCP_SYN)
        if "RST" in tcp_flags:
            names.append(FLAG_TCP_RST)
        return tuple(names)
    if protocol == "ICMP":
        return (protocol, f"ICMP_{transport.get('type')}_{transport.get('code')}")
    return (protocol,)


def _dns_names(dns: dict) -> str:
    queries = dns.get("queries") or []
    return ",".join(str(query.get("name")) for query in queries if isinstance(query, dict) and query.get("name"))


def _parse_arp_packet(raw: str, packet: dict) -> ParsedEvent:
    arp = packet.get("arp") or {}
    target = f"{arp.get('sender_ip')} -> {arp.get('target_ip')} {arp.get('operation')}"
    return ParsedEvent(
        source=SOURCE_NETWORK, sensor=SENSOR_NETWORK, kind=KIND_ARP, target=target, flags=("ARP",), raw=raw,
        time=_clock_label(packet.get("timestamp")), protocol="ARP",
    )


def _clock_label(timestamp) -> Optional[str]:
    if not isinstance(timestamp, str) or len(timestamp) < 19 or timestamp[10] != "T":
        return None
    return timestamp[11:19] + "Z"


def _parse_packet(raw: str, packet: dict) -> Optional[ParsedEvent]:
    if "arp" in packet:
        return _parse_arp_packet(raw, packet)
    network = packet.get("network")
    if not isinstance(network, dict):
        return None
    transport = packet.get("transport") or {}
    process = packet.get("process") or {}
    protocol = str(network.get("protocol_name") or "")
    src_ip, dst_ip = str(network.get("src_ip") or ""), str(network.get("dst_ip") or "")
    src_port, dst_port = _to_int(transport.get("src_port")), _to_int(transport.get("dst_port"))
    flags = list(_transport_flags(protocol, transport))
    if packet.get("direction") == OUTBOUND_DIRECTION and _is_global_address(dst_ip):
        flags.append(FLAG_EXTERNAL_DEST)
    flow = _flow_target(src_ip, src_port, dst_ip, dst_port, protocol)
    dns = packet.get("dns")
    names = _dns_names(dns) if isinstance(dns, dict) else ""
    is_dns_packet = bool(names) and protocol in (TCP_PROTOCOL, "UDP")
    kind = KIND_FLOW
    target, detail = flow, names
    if is_dns_packet:
        kind = KIND_DNS_RESPONSE if dns.get("is_response") else KIND_DNS_QUERY
        target, detail = names, flow
    return ParsedEvent(
        source=SOURCE_NETWORK, sensor=SENSOR_NETWORK, kind=kind, comm=str(process.get("name") or ""),
        pid=_to_int(process.get("pid")), ppid=_to_int(process.get("ppid")),
        uid=_username_to_uid(process.get("username")), target=target, flags=tuple(flags), raw=raw,
        time=_clock_label(packet.get("timestamp")),
        cmdline=" ".join(str(part) for part in (process.get("cmdline") or []) if part),
        protocol=protocol, src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, dst_port=dst_port, detail=detail,
    )


def _parse_json_line(raw: str, declared: str, text: str) -> Optional[ParsedEvent]:
    try:
        payload = json.loads(text)
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    if "packet_number" in payload:
        return _parse_packet(raw, payload)
    if "event" in payload and "message" in payload:
        return _parse_banner_json(raw, payload)
    return _parse_ebpf_json(raw, payload)


def _unparsed_event(raw: str, declared: str) -> ParsedEvent:
    return ParsedEvent(
        source=declared, sensor=SENSOR_UNKNOWN, kind=KIND_UNPARSED, raw=raw,
        target=_clip(raw.strip(), UNPARSED_TARGET_MAX_CHARS),
    )


Parser = Callable[[str, str, str], Optional[ParsedEvent]]

TIMED_PARSERS: Tuple[Parser, ...] = (_parse_lost_line, _parse_privilege_line, _parse_syscall_line)
PARSERS_BY_LEADING_CHARACTER: Dict[str, Tuple[Parser, ...]] = {
    "{": (_parse_json_line,),
    "T": (_parse_exec_line, _parse_lost_line, _parse_banner_line),
    "C": (_parse_file_line, _parse_network_suspicious_line, _parse_exec_line),
}
DEFAULT_PARSERS: Tuple[Parser, ...] = (_parse_lost_line, _parse_banner_line)


def _select_parsers(text: str) -> Tuple[Parser, ...]:
    if not text:
        return ()
    leading = text[0]
    if leading.isdigit():
        return TIMED_PARSERS
    return PARSERS_BY_LEADING_CHARACTER.get(leading, DEFAULT_PARSERS)


def parse_event(line: str) -> ParsedEvent:
    if not isinstance(line, str):
        raise TypeError("line must be a string")
    declared, body = _split_prefix(line)
    text = body.strip()
    for parser in _select_parsers(text):
        event = parser(line, declared, text)
        if event is not None:
            return event
    return _unparsed_event(line, declared)


def _is_monitoring_comm(comm: str) -> bool:
    return comm in CONTROL_COMMS or comm.startswith(CONTROL_COMM_PREFIXES)


def _is_supervisor_process(event: ParsedEvent) -> bool:
    return event.comm == SUPERVISOR_INTERPRETER_COMM and SUPERVISOR_SCRIPT_MARKER in event.cmdline


def _is_ssh_control_flow(event: ParsedEvent) -> bool:
    if event.protocol != TCP_PROTOCOL:
        return False
    if {event.src_ip, event.dst_ip} != CONTROL_FLOW_IPS:
        return False
    return SSH_PORT in (event.src_port, event.dst_port)


def _is_supervisor_ebpf_event(event: ParsedEvent, supervisor_pids: frozenset) -> bool:
    if event.source != SOURCE_EBPF or event.comm != SUPERVISOR_INTERPRETER_COMM:
        return False
    return event.pid in supervisor_pids


def is_control_noise(event: ParsedEvent, supervisor_pids: frozenset = frozenset()) -> bool:
    if event.kind in (KIND_BANNER, KIND_HEARTBEAT):
        return True
    if _is_monitoring_comm(event.comm):
        return True
    if _is_supervisor_process(event):
        return True
    if _is_ssh_control_flow(event):
        return True
    return _is_supervisor_ebpf_event(event, supervisor_pids)


def _startup_monitor_pids(event: ParsedEvent) -> List[int]:
    if event.kind != KIND_BANNER or event.pid is None:
        return []
    pids = [event.pid]
    if event.ppid is not None and event.ppid > INIT_PID:
        pids.append(event.ppid)
    return pids


def _collect_supervisor_pids(events: Iterable[ParsedEvent]) -> frozenset:
    discovered = set()
    for event in events:
        if event.source == SOURCE_NETWORK and event.pid is not None and _is_supervisor_process(event):
            discovered.add(event.pid)
        discovered.update(_startup_monitor_pids(event))
    return frozenset(discovered)


@lru_cache(maxsize=65536)
def normalize_target(target: str) -> str:
    collapsed = PROC_PID_PATTERN.sub(f"/proc/{NORMALIZED_PID}", target)
    collapsed = HEX_RUN_PATTERN.sub(NORMALIZED_HEX, collapsed)
    return LONG_NUMBER_PATTERN.sub(NORMALIZED_NUMBER, collapsed)


def event_signature(event: ParsedEvent) -> str:
    parts = (event.sensor, event.kind, event.comm, " ".join(event.flags), normalize_target(event.target))
    return SIGNATURE_SEPARATOR.join(parts)


def _is_signature_candidate(event: ParsedEvent) -> bool:
    return event.kind not in (KIND_UNPARSED, KIND_LOST_EVENTS, KIND_BANNER, KIND_HEARTBEAT)


class BaselineProfile:
    def __init__(self, signatures: Iterable[str] = ()):
        self._signatures = set(signatures)

    @classmethod
    def from_events(cls, lines: Iterable[str], known_monitor_pids: Iterable[int] = frozenset()) -> "BaselineProfile":
        events = [parse_event(line) for line in lines if line and line.strip()]
        supervisor_pids = _collect_supervisor_pids(events) | frozenset(known_monitor_pids)
        signatures = (
            event_signature(event) for event in events
            if _is_signature_candidate(event) and not is_control_noise(event, supervisor_pids)
        )
        return cls(signatures)

    def contains(self, signature: str) -> bool:
        return signature in self._signatures

    def __len__(self) -> int:
        return len(self._signatures)


def top_directory(path: str) -> Optional[str]:
    if not path.startswith("/"):
        return None
    parts = path.split("/", 3)
    first = parts[1]
    if first in TWO_LEVEL_ROOTS and len(parts) > 2 and parts[2]:
        return f"/{first}/{parts[2]}"
    return f"/{first}"


def _is_severe(event: ParsedEvent) -> bool:
    if event.kind in SEVERE_KINDS:
        return True
    return any(flag in SEVERE_FLAGS for flag in event.flags)


def _group_key(event: ParsedEvent, sandbox: bool = False) -> tuple:
    base = (event.sensor, event.kind, event.comm, event.uid, " ".join(event.flags))
    if event.source == SOURCE_NETWORK:
        return base + (event.target,)
    return base + (event.detail, sandbox)


def _is_sandbox_comm(comm: str) -> bool:
    return comm.startswith(SANDBOX_COMM_PREFIX) and comm.endswith(SANDBOX_COMM_SUFFIX)


def _is_sandbox_syscall(event: ParsedEvent) -> bool:
    if event.sensor == SENSOR_DANGEROUS_SYSCALLS:
        return event.kind in SANDBOX_SYSCALL_KINDS
    return event.sensor == SENSOR_PRIVILEGE_ESCALATION and event.kind in SANDBOX_PRIVILEGE_KINDS


def _is_sandbox_candidate(event: ParsedEvent) -> bool:
    if event.pid is None or not _is_sandbox_comm(event.comm) or not _is_sandbox_syscall(event):
        return False
    return event.ppid == SANDBOX_PARENT_PID


def _is_unit_handoff_read(event: ParsedEvent) -> bool:
    if event.sensor != SENSOR_SENSITIVE_FILE or event.flags != (FLAG_ACCESS_READ,):
        return False
    return event.target.startswith(HANDOFF_READ_PREFIXES)


def _keeps_sandbox_annotation(event: ParsedEvent) -> bool:
    if _is_severe(event):
        return False
    if _is_unit_handoff_read(event):
        return True
    if not _is_sandbox_comm(event.comm) or not _is_sandbox_syscall(event):
        return False
    return event.ppid in (None, SANDBOX_PARENT_PID)


def _find_sandbox_pids(events: List[ParsedEvent], supervisor_pids: frozenset) -> frozenset:
    candidates = {event.pid for event in events if _is_sandbox_candidate(event)}
    if not candidates:
        return frozenset()
    disqualified = set()
    for event in events:
        if event.pid not in candidates or event.pid in disqualified:
            continue
        if is_control_noise(event, supervisor_pids) or event.kind == KIND_LOST_EVENTS:
            continue
        if not _keeps_sandbox_annotation(event):
            disqualified.add(event.pid)
    return frozenset(candidates - disqualified)


class _Group:
    __slots__ = (
        "sensor", "kind", "comm", "uid", "flag", "source", "count", "pids", "first_time", "last_time",
        "targets", "target_overflow", "directories", "first_raw", "last_raw", "baseline_hits", "severe",
        "cmdline", "detail", "network_target", "sandbox", "operations", "windows",
    )

    def __init__(self, event: ParsedEvent, sandbox: bool = False):
        self.sandbox = sandbox
        self.operations = 0
        self.windows = 0
        self.sensor = event.sensor
        self.kind = event.kind
        self.comm = event.comm
        self.uid = event.uid
        self.flag = " ".join(event.flags)
        self.source = event.source
        self.count = 0
        self.pids = set()
        self.first_time = None
        self.last_time = None
        self.targets = Counter()
        self.target_overflow = 0
        self.directories = Counter()
        self.first_raw = event.raw
        self.last_raw = event.raw
        self.baseline_hits = 0
        self.severe = _is_severe(event)
        self.cmdline = event.cmdline
        self.detail = event.detail
        self.network_target = event.target if event.source == SOURCE_NETWORK else ""

    def add(self, event: ParsedEvent, in_baseline: bool) -> None:
        self.count += 1
        self.last_raw = event.raw
        if in_baseline:
            self.baseline_hits += 1
        if event.pid is not None:
            self.pids.add(event.pid)
        self.operations += event.operations
        self.windows += event.window_seconds
        self._add_time(event.time)
        if self.source != SOURCE_NETWORK:
            self._add_target(event.target)

    def _add_time(self, clock: Optional[str]) -> None:
        if clock is None:
            return
        if self.first_time is None or clock < self.first_time:
            self.first_time = clock
        if self.last_time is None or clock > self.last_time:
            self.last_time = clock

    def _add_target(self, target: str) -> None:
        if not target:
            return
        if target not in self.targets and len(self.targets) >= MAX_TRACKED_TARGETS:
            self.target_overflow += 1
            return
        self.targets[target] += 1
        directory = top_directory(target)
        if directory is not None:
            self.directories[directory] += 1

    @property
    def fully_in_baseline(self) -> bool:
        return self.baseline_hits == self.count

    @property
    def weight(self) -> int:
        return self.operations or self.count


def _time_interval(group: _Group) -> str:
    if group.first_time is None:
        return ""
    if group.first_time == group.last_time:
        return group.first_time
    return f"{group.first_time}-{group.last_time}"


def _format_counts(counter: Counter, limit: int) -> str:
    parts = []
    for name, number in counter.most_common(limit):
        label = _clip(name, TARGET_MAX_CHARS)
        parts.append(f"{label}({number})" if number > 1 else label)
    return " ".join(parts)


def _identity_text(group: _Group) -> str:
    parts = [f"comm={group.comm or '-'}"]
    if group.uid is not None:
        parts.append(f"uid={group.uid}")
    parts.append(f"flags={group.flag or 'none'}")
    return " ".join(parts)


def _partial_baseline_note(group: _Group) -> str:
    if group.baseline_hits == 0:
        return ""
    return f" [partly baseline: {group.baseline_hits}/{group.count} events]"


def _network_headline(rank: int, group: _Group) -> str:
    segments = [f"#{rank} network/{group.kind} {_clip(group.network_target, TARGET_MAX_CHARS)}"]
    process = group.comm or "-"
    if group.cmdline:
        process += f' cmdline="{_clip(group.cmdline, TARGET_MAX_CHARS)}"'
    segments.append(f"proc={process}")
    if group.flag:
        segments.append(f"flags={group.flag}")
    segments.append(f"count={group.count}")
    interval = _time_interval(group)
    if interval:
        segments.append(f"time={interval}")
    if group.detail:
        segments.append(f"via={_clip(group.detail, TARGET_MAX_CHARS)}")
    return " | ".join(segments) + _partial_baseline_note(group)


def _count_segments(group: _Group) -> List[str]:
    if group.kind != KIND_MASS_FILE_OPS:
        return [f"count={group.count}"]
    return [f"count={group.operations} operations", f"windows={group.windows} x 1s", f"lines={group.count}"]


def _ebpf_headline(rank: int, group: _Group) -> str:
    segments = [f"#{rank} {group.sensor}/{group.kind} {_identity_text(group)}"]
    if group.detail:
        segments.append(f"op={group.detail}")
    segments.extend(_count_segments(group))
    if group.pids:
        segments.append(f"pids={len(group.pids)}")
    interval = _time_interval(group)
    if interval:
        segments.append(f"time={interval}")
    return " | ".join(segments) + _partial_baseline_note(group)


def _targets_lines(group: _Group) -> List[str]:
    if not group.targets:
        return []
    distinct = f"{len(group.targets)}+" if group.target_overflow else str(len(group.targets))
    lines = [f"    targets ({distinct} distinct): {_format_counts(group.targets, MAX_SAMPLE_TARGETS)}"]
    if group.directories:
        lines.append(f"    top dirs: {_format_counts(group.directories, MAX_TOP_DIRECTORIES)}")
    return lines


def _group_block(rank: int, group: _Group) -> str:
    if group.source == SOURCE_NETWORK:
        return _network_headline(rank, group)
    return "\n".join([_ebpf_headline(rank, group)] + _targets_lines(group))


def _baseline_entry(group: _Group) -> str:
    if group.source == SOURCE_NETWORK:
        label = group.network_target
    elif group.targets:
        first = next(iter(group.targets))
        extra = len(group.targets) - 1
        label = first if extra == 0 else f"{first} (+{extra})"
    else:
        label = group.flag or "-"
    entry = f"{group.comm or '-'} {group.sensor}/{group.kind} {label} x{group.count}"
    return _clip(entry, BASELINE_ENTRY_MAX_CHARS)


def _baseline_summary(groups: List[_Group]) -> str:
    if not groups:
        return ""
    ordered = sorted(groups, key=lambda group: -group.count)
    events = sum(group.count for group in groups)
    prefix = f"[baseline] {len(groups)} groups, {events} events already present in the clean baseline: "
    entries, used = [], len(prefix)
    for group in ordered:
        entry = _baseline_entry(group)
        if used + len(entry) + 2 > BASELINE_SUMMARY_MAX_CHARS:
            break
        entries.append(entry)
        used += len(entry) + 2
    omitted = len(ordered) - len(entries)
    suffix = f"; +{omitted} more baseline groups" if omitted else ""
    return prefix + "; ".join(entries) + suffix


def _sandbox_entry(group: _Group) -> str:
    entry = f"{group.comm or '-'} {group.sensor}/{group.kind} x{group.count}"
    return _clip(entry, SANDBOX_ENTRY_MAX_CHARS)


def _sandbox_pid_text(groups: List[_Group]) -> str:
    pids = sorted({pid for group in groups for pid in group.pids})
    shown = " ".join(str(pid) for pid in pids[:SANDBOX_MAX_PIDS_LISTED])
    extra = len(pids) - SANDBOX_MAX_PIDS_LISTED
    return shown if extra <= 0 else f"{shown} (+{extra})"


def _sandbox_summary(groups: List[_Group]) -> str:
    if not groups:
        return ""
    ordered = sorted(groups, key=lambda group: -group.count)
    events = sum(group.count for group in groups)
    prefix = (
        f"{SANDBOX_ANNOTATION} {len(groups)} groups, {events} events, pids={_sandbox_pid_text(groups)}, not ranked "
        f"(comm in parentheses, parent PID 1, only mount/umount/unshare/capset; the same PID ran no other binary and "
        f"had no other sensor events): "
    )
    entries, used = [], len(prefix)
    for group in ordered:
        entry = _sandbox_entry(group)
        if used + len(entry) + 2 > SANDBOX_SUMMARY_MAX_CHARS:
            break
        entries.append(entry)
        used += len(entry) + 2
    omitted = len(ordered) - len(entries)
    suffix = f"; +{omitted} more" if omitted else ""
    return prefix + "; ".join(entries) + suffix


def _rank_groups(groups: List[_Group]) -> List[_Group]:
    return sorted(groups, key=lambda group: (0 if group.severe else 1, -group.weight))


def _select_blocks(ranked: List[_Group], budget: int) -> List[Tuple[int, _Group, str]]:
    selected, used = [], 0
    for rank, group in enumerate(ranked, start=1):
        block = _group_block(rank, group)
        if used + len(block) + 1 > budget:
            break
        selected.append((rank, group, block))
        used += len(block) + 1
    return selected


def _example_lines(rank: int, group: _Group) -> List[str]:
    raws = [group.first_raw]
    if group.count > 1 and group.last_raw != group.first_raw:
        raws.append(group.last_raw)
    return [f"#{rank}: {_clip(raw, EXAMPLE_LINE_MAX_CHARS)}" for raw in raws]


def _select_examples(selected: List[Tuple[int, _Group, str]], budget: int) -> Tuple[List[str], int]:
    lines, used, covered = [], 0, 0
    candidates = [item for item in selected if item[1].source != SOURCE_NETWORK][:EXAMPLE_GROUPS_MAX]
    for rank, group, _ in candidates:
        group_lines = _example_lines(rank, group)
        cost = sum(len(line) + 1 for line in group_lines)
        if used + cost > budget:
            break
        lines.extend(group_lines)
        used += cost
        covered += 1
    return lines, covered


def _count_by_sensor(groups: List[_Group]) -> Counter:
    counter = Counter()
    for group in groups:
        counter[group.sensor] += group.count
    return counter


def _totals_text(stats: Dict[str, int], sensors: Counter, lost: Counter) -> str:
    lines = [
        f"Totals: events={stats['total']} control_noise={stats['control_noise']} "
        f"analysed={stats['total'] - stats['control_noise']} groups={stats['groups']} "
        f"in_baseline={stats['in_baseline']} unparsed={stats['unparsed']}",
    ]
    if sensors:
        lines.append("Events by sensor (after noise filter): " + " ".join(f"{name}={number}" for name, number in sensors.most_common()))
    lines.append(
        f"Control noise filtered out (monitoring stack and SSH control channel): {stats['control_noise']} events, not shown."
    )
    if lost:
        details = " ".join(f"{name}={number}" for name, number in lost.most_common())
        lines.append(
            f"WARNING: bpftrace reported dropped events (counts below are a lower bound): {sum(lost.values())} lost ({details})."
        )
    return "\n".join(lines)


def _omission_note(omitted_groups: List[_Group]) -> str:
    if not omitted_groups:
        return ""
    events = sum(group.count for group in omitted_groups)
    return (
        f"... {len(omitted_groups)} more groups omitted by the size limit ({events} events, lowest relevance "
        f"dropped)."
    )


def _assemble_text(
    head: str, extra_lines: List[str], selected: List[Tuple[int, _Group, str]], omitted: List[_Group],
    examples: List[str], shown_examples_groups: int,
) -> str:
    sections = [head, "== EVENT GROUPS =="]
    sections.extend(block for _, _, block in selected)
    note = _omission_note(omitted)
    if note:
        sections.append(note)
    sections.extend(extra_lines)
    if examples:
        sections.append(f"== RAW EXAMPLES (first/last event of the top {shown_examples_groups} eBPF groups) ==")
        sections.extend(examples)
    return "\n".join(sections)


def _register_heartbeat(health: Dict[str, SensorHealth], event: ParsedEvent) -> None:
    record = health.get(event.target)
    if record is None:
        if len(health) >= MAX_TRACKED_SENSORS:
            return
        record = health[event.target] = SensorHealth()
    record.heartbeats += 1
    record.dead = not event.alive
    previous = record.last_sequence
    record.last_sequence = event.sequence
    if previous is None:
        return
    if event.sequence <= previous:
        record.restarts += 1
        return
    record.gaps += event.sequence - previous - 1


def collect_sensor_health(events: Iterable[ParsedEvent]) -> Dict[str, SensorHealth]:
    health: Dict[str, SensorHealth] = {}
    for event in events:
        if event.kind == KIND_HEARTBEAT and event.sequence is not None:
            _register_heartbeat(health, event)
    return health


def _silent_sensors(health: Dict[str, SensorHealth], expected_sensors: Iterable[str]) -> List[str]:
    return sorted(
        name for name in set(expected_sensors)
        if name not in health and SENSOR_NAME_PATTERN.match(name) is not None
    )


def _sensor_health_stats(health: Dict[str, SensorHealth], silent: List[str]) -> Dict[str, object]:
    return {
        "heartbeat_sensors": sorted(health),
        "silent_sensors": silent,
        "sensor_health": {
            name: {
                "heartbeats": record.heartbeats,
                "last_sequence": record.last_sequence,
                "gaps": record.gaps,
                "restarts": record.restarts,
                "dead": record.dead,
            }
            for name, record in sorted(health.items())
        },
    }


def _sensor_health_text(health: Dict[str, SensorHealth], silent: List[str]) -> str:
    dead = sorted(name for name, record in health.items() if record.dead)
    restarted = sorted(name for name, record in health.items() if record.restarts)
    gapped = sorted(name for name, record in health.items() if record.gaps)
    parts = []
    if silent:
        parts.append("SENSOR SILENT (no heartbeat in this batch): " + ", ".join(silent))
    if dead:
        parts.append("SENSOR DEAD (its bpftrace process exited): " + ", ".join(dead))
    if restarted:
        parts.append("SENSOR RESTARTED (heartbeat sequence went back): " + ", ".join(restarted))
    if gapped:
        parts.append("HEARTBEAT GAPS (missed heartbeats): " + ", ".join(gapped))
    if not parts:
        return ""
    return "SENSOR HEALTH WARNING: " + "; ".join(parts) + ". " + SENSOR_HEALTH_NOTE


def _hard_limit(text: str) -> str:
    if len(text) <= DIGEST_MAX_CHARS:
        return text
    marker = "\n... [digest cut at size limit]"
    return text[: DIGEST_MAX_CHARS - len(marker)] + marker


def _aggregate(
    events: List[ParsedEvent], baseline: Optional[BaselineProfile], supervisor_pids: frozenset,
) -> Tuple[Dict[tuple, _Group], int, Counter]:
    sandbox_pids = _find_sandbox_pids(events, supervisor_pids)
    groups: Dict[tuple, _Group] = {}
    noise_count = 0
    lost: Counter = Counter()
    for event in events:
        if is_control_noise(event, supervisor_pids):
            noise_count += 1
            continue
        if event.kind == KIND_LOST_EVENTS:
            lost[event.sensor] += event.count
            continue
        sandbox = event.pid in sandbox_pids and _is_sandbox_syscall(event)
        key = _group_key(event, sandbox)
        group = groups.get(key)
        if group is None:
            group = groups[key] = _Group(event, sandbox)
        in_baseline = baseline is not None and baseline.contains(event_signature(event))
        group.add(event, in_baseline)
    return groups, noise_count, lost


def _build_stats(
    events: List[ParsedEvent], groups: List[_Group], noise_count: int, lost: Counter, discovered_pids: frozenset,
) -> Dict[str, object]:
    unparsed = sum(1 for event in events if event.kind == KIND_UNPARSED)
    return {
        "total": len(events),
        "control_noise": noise_count,
        "parsed": len(events) - unparsed,
        "unparsed": unparsed,
        "groups": len(groups),
        "in_baseline": sum(group.baseline_hits for group in groups),
        "lost_events": sum(lost.values()),
        "monitor_pids": sorted(discovered_pids),
    }


def build_digest(
    lines: Iterable[str], baseline: Optional[BaselineProfile] = None, known_monitor_pids: Iterable[int] = frozenset(),
    expected_sensors: Iterable[str] = frozenset(),
) -> BatchDigest:
    events = [parse_event(line) for line in lines if line and line.strip()]
    sensor_health = collect_sensor_health(events)
    silent_sensors = _silent_sensors(sensor_health, expected_sensors)
    discovered_pids = _collect_supervisor_pids(events)
    noise_pids = discovered_pids | frozenset(known_monitor_pids)
    grouped, noise_count, lost = _aggregate(events, baseline, noise_pids)
    groups = list(grouped.values())
    stats = _build_stats(events, groups, noise_count, lost, discovered_pids)
    sandbox_groups = [group for group in groups if group.sandbox]
    ordinary = [group for group in groups if not group.sandbox]
    baseline_groups = [group for group in ordinary if group.fully_in_baseline]
    ranked = _rank_groups([group for group in ordinary if not group.fully_in_baseline])
    head = HEADER_TEXT.format(total=stats["total"]) + "\n" + _totals_text(stats, _count_by_sensor(groups), lost)
    extra_lines = [
        line for line in (
            _sensor_health_text(sensor_health, silent_sensors),
            _sandbox_summary(sandbox_groups),
            _baseline_summary(baseline_groups),
        ) if line
    ]
    extra_chars = sum(len(line) + 1 for line in extra_lines)
    available = DIGEST_MAX_CHARS - len(head) - extra_chars - FOOTER_RESERVED_CHARS
    selected = _select_blocks(ranked, int(available * GROUPS_SECTION_SHARE))
    omitted = ranked[len(selected):]
    used = sum(len(block) + 1 for _, _, block in selected)
    examples, covered = _select_examples(selected, max(0, available - used))
    text = _hard_limit(_assemble_text(head, extra_lines, selected, omitted, examples, covered))
    stats.update({
        "groups_shown": len(selected),
        "groups_omitted": len(omitted),
        "baseline_groups": len(baseline_groups),
        "sandbox_groups": len(sandbox_groups),
        "sandbox_events": sum(group.count for group in sandbox_groups),
        "chars": len(text),
    })
    stats.update(_sensor_health_stats(sensor_health, silent_sensors))
    return BatchDigest(text=text, stats=stats)
