#!/usr/bin/env python3
import json
import sys
import time
import os
import signal
import socket
from datetime import datetime, timezone
from collections import OrderedDict

try:
    import psutil
except ImportError:
    sys.exit(1)

try:
    from scapy.all import (
        sniff, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DNSRR,
        Raw, ARP, Ether, conf,
    )
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
except ImportError:
    sys.exit(1)


class ConnectionCache:

    def __init__(self, refresh_interval: float = 0.5):
        self._cache: dict = {}
        self._last_refresh: float = 0.0
        self._refresh_interval = refresh_interval

    def refresh(self):
        now = time.monotonic()
        if now - self._last_refresh < self._refresh_interval:
            return
        self._last_refresh = now

        new_cache: dict = {}
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            connections = []

        for conn in connections:
            if conn.laddr and conn.pid:
                key = (conn.type, conn.laddr.ip, conn.laddr.port)
                proc_info = self._get_process_info(conn.pid)
                if proc_info:
                    new_cache[key] = proc_info

        self._cache = new_cache

    @staticmethod
    def _get_process_info(pid: int) -> dict | None:
        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                info = {
                    "pid": pid,
                    "name": proc.name(),
                    "exe": proc.exe() if proc.exe() else None,
                    "cmdline": proc.cmdline(),
                    "username": proc.username(),
                    "status": proc.status(),
                    "create_time": datetime.fromtimestamp(
                        proc.create_time(), tz=timezone.utc
                    ).isoformat(),
                    "ppid": proc.ppid(),
                }
            return info
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return {"pid": pid}

    def lookup(self, proto_num: int, local_ip: str, local_port: int) -> dict | None:
        self.refresh()

        key = (proto_num, local_ip, local_port)
        if key in self._cache:
            return self._cache[key]

        wildcard_key = (proto_num, "0.0.0.0", local_port)
        if wildcard_key in self._cache:
            return self._cache[wildcard_key]

        wildcard_key6 = (proto_num, "::", local_port)
        if wildcard_key6 in self._cache:
            return self._cache[wildcard_key6]

        return self._fallback_proc_net(proto_num, local_port)

    def _fallback_proc_net(self, proto_num: int, local_port: int) -> dict | None:
        if proto_num == socket.SOCK_STREAM:
            proc_file = "/proc/net/tcp"
        elif proto_num == socket.SOCK_DGRAM:
            proc_file = "/proc/net/udp"
        else:
            return None

        try:
            with open(proc_file, "r") as f:
                lines = f.readlines()[1:]

            port_hex = f"{local_port:04X}"
            for line in lines:
                parts = line.strip().split()
                if len(parts) < 10:
                    continue
                local_addr = parts[1]
                _, lport_hex = local_addr.split(":")
                if lport_hex == port_hex:
                    inode = int(parts[9])
                    pid = self._inode_to_pid(inode)
                    if pid:
                        return self._get_process_info(pid)
        except (FileNotFoundError, PermissionError):
            pass

        return None

    @staticmethod
    def _inode_to_pid(inode: int) -> int | None:
        target = f"socket:[{inode}]"
        for pid_dir in os.listdir("/proc"):
            if not pid_dir.isdigit():
                continue
            fd_dir = f"/proc/{pid_dir}/fd"
            try:
                for fd in os.listdir(fd_dir):
                    try:
                        link = os.readlink(f"{fd_dir}/{fd}")
                        if link == target:
                            return int(pid_dir)
                    except (OSError, ValueError):
                        continue
            except (PermissionError, FileNotFoundError):
                continue
        return None


_conn_cache = ConnectionCache()
_packet_counter = 0


def _resolve_hostname(ip: str) -> str | None:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def _get_protocol_name(proto_num: int) -> str:
    protocols = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        41: "IPv6-encap",
        47: "GRE",
        50: "ESP",
        51: "AH",
        58: "ICMPv6",
        89: "OSPF",
        132: "SCTP",
    }
    return protocols.get(proto_num, f"PROTO_{proto_num}")


def _get_tcp_flags(tcp_layer) -> list[str]:
    flags = []
    flag_map = [
        ("F", "FIN"), ("S", "SYN"), ("R", "RST"), ("P", "PSH"),
        ("A", "ACK"), ("U", "URG"), ("E", "ECE"), ("C", "CWR"),
    ]
    flag_str = str(tcp_layer.flags)
    for char, name in flag_map:
        if char in flag_str:
            flags.append(name)
    return flags


def _extract_dns_info(packet) -> dict | None:
    if not packet.haslayer(DNS):
        return None

    dns = packet[DNS]
    dns_info: dict = {
        "id": dns.id,
        "is_response": bool(dns.qr),
        "opcode": dns.opcode,
        "rcode": dns.rcode,
    }

    if dns.qdcount and dns.haslayer(DNSQR):
        queries = []
        qr = dns[DNSQR]
        for _ in range(dns.qdcount):
            try:
                queries.append({
                    "name": qr.qname.decode(errors="replace").rstrip("."),
                    "type": qr.qtype,
                    "class": qr.qclass,
                })
                qr = qr.payload
            except Exception:
                break
        dns_info["queries"] = queries

    if dns.ancount and dns.haslayer(DNSRR):
        answers = []
        rr = dns[DNSRR]
        for _ in range(dns.ancount):
            try:
                answers.append({
                    "name": rr.rrname.decode(errors="replace").rstrip("."),
                    "type": rr.type,
                    "ttl": rr.ttl,
                    "rdata": (
                        rr.rdata.decode(errors="replace")
                        if isinstance(rr.rdata, bytes)
                        else str(rr.rdata)
                    ),
                })
                rr = rr.payload
            except Exception:
                break
        dns_info["answers"] = answers

    return dns_info


def _extract_http_info(payload_bytes: bytes) -> dict | None:
    try:
        text = payload_bytes.decode("utf-8", errors="replace")
    except Exception:
        return None

    lines = text.split("\r\n")
    if not lines:
        return None

    first_line = lines[0]

    http_methods = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE")
    if any(first_line.startswith(m + " ") for m in http_methods):
        parts = first_line.split(" ", 2)
        http_info: dict = {
            "type": "request",
            "method": parts[0],
            "path": parts[1] if len(parts) > 1 else None,
            "version": parts[2] if len(parts) > 2 else None,
        }
        headers = {}
        for line in lines[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                headers[k] = v
            elif line == "":
                break
        if headers:
            http_info["headers"] = headers
        return http_info

    if first_line.startswith("HTTP/"):
        parts = first_line.split(" ", 2)
        http_info = {
            "type": "response",
            "version": parts[0],
            "status_code": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None,
            "reason": parts[2] if len(parts) > 2 else None,
        }
        headers = {}
        for line in lines[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                headers[k] = v
            elif line == "":
                break
        if headers:
            http_info["headers"] = headers
        return http_info

    return None


def process_packet(packet):
    global _packet_counter
    _packet_counter += 1

    timestamp = datetime.now(tz=timezone.utc).isoformat()
    result: OrderedDict = OrderedDict()
    result["packet_number"] = _packet_counter
    result["timestamp"] = timestamp

    if packet.haslayer(Ether):
        result["ethernet"] = {
            "src_mac": packet[Ether].src,
            "dst_mac": packet[Ether].dst,
            "type": hex(packet[Ether].type),
        }

    if packet.haslayer(ARP):
        arp = packet[ARP]
        result["protocol"] = "ARP"
        result["arp"] = {
            "operation": "request" if arp.op == 1 else "reply",
            "sender_mac": arp.hwsrc,
            "sender_ip": arp.psrc,
            "target_mac": arp.hwdst,
            "target_ip": arp.pdst,
        }
        _print_json(result)
        return

    ip_layer = None
    if packet.haslayer(IP):
        ip = packet[IP]
        ip_layer = ip
        result["network"] = {
            "version": 4,
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "protocol_number": ip.proto,
            "protocol_name": _get_protocol_name(ip.proto),
            "ttl": ip.ttl,
            "tos": ip.tos,
            "identification": ip.id,
            "flags": str(ip.flags),
            "fragment_offset": ip.frag,
            "total_length": ip.len,
            "header_length": ip.ihl * 4,
        }
    elif packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        ip_layer = ip6
        result["network"] = {
            "version": 6,
            "src_ip": ip6.src,
            "dst_ip": ip6.dst,
            "protocol_number": ip6.nh,
            "protocol_name": _get_protocol_name(ip6.nh),
            "traffic_class": ip6.tc,
            "flow_label": ip6.fl,
            "hop_limit": ip6.hlim,
            "payload_length": ip6.plen,
        }
    else:
        return

    src_ip = result["network"]["src_ip"]
    dst_ip = result["network"]["dst_ip"]
    src_port = None
    dst_port = None

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport
        result["transport"] = {
            "protocol": "TCP",
            "src_port": src_port,
            "dst_port": dst_port,
            "flags": _get_tcp_flags(tcp),
            "seq": tcp.seq,
            "ack": tcp.ack,
            "window_size": tcp.window,
            "urgent_pointer": tcp.urgptr,
            "header_length": tcp.dataofs * 4 if tcp.dataofs else None,
            "options": [
                {"kind": opt[0], "value": repr(opt[1])} for opt in tcp.options
            ] if tcp.options else [],
        }

    elif packet.haslayer(UDP):
        udp = packet[UDP]
        src_port = udp.sport
        dst_port = udp.dport
        result["transport"] = {
            "protocol": "UDP",
            "src_port": src_port,
            "dst_port": dst_port,
            "length": udp.len,
            "checksum": udp.chksum,
        }

    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        result["transport"] = {
            "protocol": "ICMP",
            "type": icmp.type,
            "code": icmp.code,
            "checksum": icmp.chksum,
            "id": icmp.id if hasattr(icmp, "id") else None,
            "seq": icmp.seq if hasattr(icmp, "seq") else None,
        }

    dns_info = _extract_dns_info(packet)
    if dns_info:
        result["dns"] = dns_info

    if packet.haslayer(Raw):
        raw_data = bytes(packet[Raw].load)
        result["payload"] = {
            "size_bytes": len(raw_data),
            "hex_preview": raw_data[:128].hex(),
        }
        http_info = _extract_http_info(raw_data)
        if http_info:
            result["http"] = http_info
    else:
        result["payload"] = {"size_bytes": 0}

    if src_port or dst_port:
        services = {}
        for label, port in [("src_service", src_port), ("dst_service", dst_port)]:
            if port:
                try:
                    proto = "tcp" if packet.haslayer(TCP) else "udp"
                    services[label] = socket.getservbyport(port, proto)
                except OSError:
                    services[label] = None
        if any(v for v in services.values()):
            result["services"] = services

    process_info = None
    if src_port is not None:
        sock_type = (
            socket.SOCK_STREAM if packet.haslayer(TCP) else socket.SOCK_DGRAM
        )
        process_info = _conn_cache.lookup(sock_type, src_ip, src_port)
        if not process_info and dst_port is not None:
            process_info = _conn_cache.lookup(sock_type, dst_ip, dst_port)

    result["process"] = process_info if process_info else None

    local_ips = _get_local_ips()
    if src_ip in local_ips:
        result["direction"] = "outbound"
    elif dst_ip in local_ips:
        result["direction"] = "inbound"
    else:
        result["direction"] = "forwarded"

    result["raw_packet_size"] = len(packet)

    _print_json(result)


_local_ips_cache: set[str] | None = None
_local_ips_ts: float = 0.0


def _get_local_ips() -> set[str]:
    global _local_ips_cache, _local_ips_ts
    now = time.monotonic()
    if _local_ips_cache is None or now - _local_ips_ts > 10.0:
        ips = set()
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family in (socket.AF_INET, socket.AF_INET6):
                    ips.add(addr.address)
        ips.add("127.0.0.1")
        ips.add("::1")
        _local_ips_cache = ips
        _local_ips_ts = now
    return _local_ips_cache


def _print_json(data: dict):
    try:
        print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
        sys.stdout.flush()
    except (BrokenPipeError, IOError):
        sys.exit(0)


def main():
    if os.geteuid() != 0:
        sys.exit(1)

    def signal_handler(sig, frame):
        print(f"\n[*] Capture ended. Total packets: {_packet_counter}")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        sniff(
            prn=process_packet,
            store=False,
            iface=None,
        )
    except PermissionError:
        sys.exit(1)


if __name__ == "__main__":
    main()
