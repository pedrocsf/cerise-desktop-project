import glob
import json
import os
import sys
import time
import unittest

REPOSITORY_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPOSITORY_ROOT)

import batch_digest as digest_module
from batch_digest import (
    DIGEST_MAX_CHARS,
    BaselineProfile,
    build_digest,
    is_control_noise,
    parse_event,
)

FIXTURES_ROOT = os.path.join(REPOSITORY_ROOT, "resultados_teste_real")
ENCODER_RUN = os.path.join(FIXTURES_ROOT, "Linux.Encoder.1", "run2_haiku_5.5_high")
WIRENET_RUN = os.path.join(FIXTURES_ROOT, "Linux.Wirenet", "run2_haiku_5.5_high")
WIRENET_RUN3 = os.path.join(FIXTURES_ROOT, "Linux.Wirenet", "run3_digest_haiku_5.5_high")
ENCODER_RUN3 = os.path.join(FIXTURES_ROOT, "Linux.Encoder.1", "run3_digest_haiku_5.5_high")
RUN3_AVAILABLE = os.path.isdir(WIRENET_RUN3) and os.path.isdir(ENCODER_RUN3)
WIRENET_SUPERVISOR_PID = 958
ENCODER_SUPERVISOR_PID = 944
WIRENET_BASELINE_BATCH_IDS = (2, 3, 4, 5)
ENCODER_BASELINE_BATCH_IDS = (3, 4, 5, 6)
SANDBOX_BATCH_ID = 11
SANDBOX_ANNOTATION = "[systemd unit sandbox setup]"
FIXTURES_AVAILABLE = os.path.isdir(ENCODER_RUN) and os.path.isdir(WIRENET_RUN)

CENTRAL_BATCH_ID = 6
BASELINE_BATCH_IDS = (3, 4, 5)
POST_DETONATION_BATCH_IDS = (7, 9, 12, 20, 25)
CENTRAL_BATCH_EVENT_COUNT = 83201
CENTRAL_BATCH_CHMOD_COUNT = 82658
MALWARE_COMM_PREFIX = "18884936"
MAX_DIGEST_SECONDS = 2.0
SUPERVISOR_SIGNATURE_TARGET = "/etc/passwd"
PERIODIC_DNS_NAME = "ntp.ubuntu.com"

LINE_CHMOD = "[ebpf:/dev/pts/10] TIME: 19:41:17  COMM: 18884936d002839  PID: 2297     PPID: 1        UID: 0      FLAGS: [CHMOD_CALLED]"
LINE_SHELL = "[ebpf:/dev/pts/10] TIME: 19:40:23  COMM: sshd             PID: 2293     PPID: 2115     UID: 1000   PATH: /bin/bash FLAGS: [SHELL_INTERPRETER]"
LINE_RENAME = "[ebpf:/dev/pts/10] TIME: 19:40:23  COMM: php-fpm          PID: 801      PPID: 1        UID: 33     RENAME_TO: /var/www/uploads/x.php FLAGS: [MOVED_TO_SERVED_DIR]"
LINE_LOST = "[ebpf:/dev/pts/10] TIME: 19:40:26  Lost 1 events"
LINE_LOST_PLAIN = "[ebpf:/dev/pts/10] Lost 1 events"
LINE_FILE = "[ebpf:/dev/pts/9] COMM: python3          PID: 1015     UID: 0        FLAGS: 0x80000 FILE: /etc/passwd"
LINE_FILE_WRITE = "[ebpf:/dev/pts/9] COMM: rs:main Q:Reg    PID: 802      UID: 102      FLAGS: 0x80541 FILE: /var/log/auth.log"
LINE_FILE_TRAVERSAL = "[ebpf:/dev/pts/9] COMM: gnome-initial-s  PID: 2301     UID: 1000     FLAGS: 0x80000 FILE: /usr/lib/x86_64-linux-gnu/../lib/tls/libedit.so.2 [PATH_TRAVERSAL]"
LINE_PRIVILEGE = "[ebpf:/dev/pts/8] 19:40:23  sudo             2295     1000     setuid     uid: 1000 -> 0"
LINE_PRIVILEGE_BENIGN = "[ebpf:/dev/pts/8] 20:02:46  dpkg             2454     0        setgid     gid: 0 -> 0"
LINE_SYSCALL = "[ebpf:/dev/pts/1] 20:01:20  (imedated)       2446     1        0      mount            dev=, dir=/, type="
LINE_SYSCALL_BPF = "[ebpf:/dev/pts/1] 19:56:17  bpftrace         910      898      0      bpf              cmd=18"
LINE_KERNEL_MODULE = '[ebpf:/dev/pts/5] {"e":"kml","c":"modprobe","p":2510,"pp":216,"u":0}'
LINE_FILELESS = '[ebpf:/dev/pts/4] {"e":"fm","c":"pulseaudio","p":1488,"u":1000,"n":"pulseaudio"}'
LINE_LOG_TAMPERING = '[ebpf:/dev/pts/6] {"e":"log_tamp","c":"logrotate","p":2371,"u":0,"f":"/var/log/apt/term.log"}'
LINE_DOCKER = '[ebpf:/dev/pts/3] {"evt":"docker_sock","comm":"curl","pid":4410,"ppid":4409,"uid":0,"path":"/var/run/docker.sock"}'
LINE_NETWORK_SUSPICIOUS = "[ebpf:/dev/pts/7] COMM: nc         PID: 3321   UID: 0      IP: 203            :4444 FLAGS: SUSPICIOUS"
LINE_BANNER = "[ebpf:/dev/pts/8] Attaching 5 probes..."
LINE_BANNER_HEADER = "[ebpf:/dev/pts/1] TIME       COMM             PID      PPID     UID    SYSCALL          DETAILS"
LINE_PERSISTENCE = '[ebpf:/dev/vport0p11] {"e":"persistence","c":"WIFIADAPT","p":2300,"pp":2230,"u":1000,"op":"open_write","f":"/home/cerise/.config/autostart/WIFIADAPTER.desktop"}'
LINE_MASS_FILE_OPS = '[ebpf:/dev/vport0p11] {"e":"mass_file_ops","c":"18884936d002839","p":2297,"u":0,"op":"chmod","n":5000,"w":1}'
LINE_STARTUP = '[network] {"event": "startup", "message": "Network packet sniffer is running", "pid": 958, "ppid": 941}'
LINE_STARTUP_WITHOUT_PID = '[network] {"event": "startup", "message": "Network packet sniffer is running"}'
LINE_UNKNOWN = "[ebpf:/dev/pts/2] something no sensor ever prints 12345"


def network_line(src_ip, dst_ip, protocol="TCP", src_port=51866, dst_port=22, process=None, dns_name=None,
                 direction="inbound", is_response=False, timestamp="2026-11-22T22:40:23.166235+00:00", tcp_flags=None):
    packet = {
        "packet_number": 1,
        "timestamp": timestamp,
        "ethernet": {"src_mac": "00:00:00:00:00:00", "dst_mac": "00:00:00:00:00:00", "type": "0x800"},
        "network": {"version": 4, "src_ip": src_ip, "dst_ip": dst_ip, "protocol_name": protocol},
        "transport": {"protocol": protocol, "src_port": src_port, "dst_port": dst_port, "flags": tcp_flags or ["PSH", "ACK"]},
        "payload": {"size_bytes": 0},
        "process": process,
        "direction": direction,
    }
    if dns_name:
        packet["dns"] = {"id": 1, "is_response": is_response, "queries": [{"name": dns_name, "type": 1, "class": 1}]}
    return "[network] " + json.dumps(packet)


SSH_PROCESS = {"pid": 2092, "name": "sshd", "cmdline": ["sshd: cerise@notty", "", ""], "username": "cerise", "ppid": 2000}
SUPERVISOR_PROCESS = {
    "pid": 990, "name": "python3", "cmdline": ["/usr/bin/python3", "-u", "./supervisor/supervisor.py"],
    "username": "root", "ppid": 987,
}
RESOLVED_PROCESS = {
    "pid": 727, "name": "systemd-resolved", "cmdline": ["/lib/systemd/systemd-resolved"], "username": "systemd-resolve",
}

_BATCH_CACHE = {}


def load_events(run_directory, batch_id):
    path = os.path.join(run_directory, f"batch_{batch_id}.json")
    if path not in _BATCH_CACHE:
        with open(path, encoding="utf-8") as handle:
            _BATCH_CACHE[path] = json.load(handle)["events"]
    return _BATCH_CACHE[path]


def load_encoder_events(batch_ids):
    events = []
    for batch_id in batch_ids:
        events.extend(load_events(ENCODER_RUN, batch_id))
    return events


class ParseEventTests(unittest.TestCase):
    def test_chmod_line_from_suspicious_exec(self):
        event = parse_event(LINE_CHMOD)
        self.assertEqual(
            (event.source, event.sensor, event.kind, event.comm, event.pid, event.ppid, event.uid),
            ("ebpf", "suspicious_exec", "chmod", "18884936d002839", 2297, 1, 0),
        )
        self.assertEqual(event.flags, ("CHMOD_CALLED",))
        self.assertEqual(event.time, "19:41:17")
        self.assertEqual(event.raw, LINE_CHMOD)

    def test_shell_interpreter_line_keeps_path_as_target(self):
        event = parse_event(LINE_SHELL)
        self.assertEqual((event.kind, event.target, event.flags), ("exec", "/bin/bash", ("SHELL_INTERPRETER",)))

    def test_rename_to_served_directory_line(self):
        event = parse_event(LINE_RENAME)
        self.assertEqual((event.kind, event.target, event.uid), ("rename_to_served_dir", "/var/www/uploads/x.php", 33))
        self.assertEqual(event.flags, ("MOVED_TO_SERVED_DIR",))

    def test_lost_events_line_carries_the_count(self):
        event = parse_event("[ebpf:/dev/pts/10] TIME: Lost 119 events")
        self.assertEqual((event.kind, event.count, event.sensor), ("lost_events", 119, "suspicious_exec"))
        self.assertEqual(parse_event(LINE_LOST).count, 1)
        self.assertEqual(parse_event(LINE_LOST_PLAIN).sensor, "bpftrace_runtime")

    def test_sensitive_file_read(self):
        event = parse_event(LINE_FILE)
        self.assertEqual((event.sensor, event.kind, event.comm, event.pid, event.uid), ("sensitive_file", "file_open", "python3", 1015, 0))
        self.assertEqual((event.target, event.flags), ("/etc/passwd", ("ACCESS_READ",)))

    def test_sensitive_file_write_flags_are_decoded(self):
        event = parse_event(LINE_FILE_WRITE)
        self.assertEqual(event.comm, "rs:main Q:Reg")
        self.assertEqual(event.flags, ("ACCESS_WRITE", "O_CREAT", "O_APPEND"))

    def test_sensitive_file_path_traversal_flag(self):
        event = parse_event(LINE_FILE_TRAVERSAL)
        self.assertEqual(event.target, "/usr/lib/x86_64-linux-gnu/../lib/tls/libedit.so.2")
        self.assertIn("PATH_TRAVERSAL", event.flags)

    def test_privilege_escalation_root_transition(self):
        event = parse_event(LINE_PRIVILEGE)
        self.assertEqual((event.sensor, event.kind, event.comm, event.pid, event.uid), ("privilege_escalation", "setuid", "sudo", 2295, 1000))
        self.assertEqual((event.target, event.flags), ("uid: 1000 -> 0", ("ROOT_TRANSITION",)))
        self.assertEqual(parse_event(LINE_PRIVILEGE_BENIGN).flags, ())

    def test_dangerous_syscall_mount(self):
        event = parse_event(LINE_SYSCALL)
        self.assertEqual((event.sensor, event.kind, event.comm, event.pid, event.ppid, event.uid), ("dangerous_syscalls", "mount", "(imedated)", 2446, 1, 0))
        self.assertEqual(event.target, "dev=, dir=/, type=")

    def test_kernel_module_json(self):
        event = parse_event(LINE_KERNEL_MODULE)
        self.assertEqual((event.sensor, event.kind, event.comm, event.pid, event.ppid, event.uid), ("kernel_module", "kernel_module_load", "modprobe", 2510, 216, 0))

    def test_fileless_json(self):
        event = parse_event(LINE_FILELESS)
        self.assertEqual((event.sensor, event.kind, event.comm, event.target), ("fileless", "memfd_create", "pulseaudio", "pulseaudio"))

    def test_log_tampering_json(self):
        event = parse_event(LINE_LOG_TAMPERING)
        self.assertEqual((event.sensor, event.kind, event.comm, event.target), ("log_tampering", "log_write", "logrotate", "/var/log/apt/term.log"))

    def test_docker_socket_json(self):
        event = parse_event(LINE_DOCKER)
        self.assertEqual((event.sensor, event.kind, event.comm, event.pid, event.ppid, event.uid), ("docker_socket", "docker_socket_connect", "curl", 4410, 4409, 0))
        self.assertEqual(event.target, "/var/run/docker.sock")

    def test_network_suspicious_line(self):
        event = parse_event(LINE_NETWORK_SUSPICIOUS)
        self.assertEqual((event.sensor, event.kind, event.comm, event.pid, event.uid), ("network_suspicious", "suspicious_connect", "nc", 3321, 0))
        self.assertEqual((event.target, event.flags), ("203.*.*.*:4444", ("SUSPICIOUS",)))

    def test_banners_are_recognised(self):
        self.assertEqual(parse_event(LINE_BANNER).kind, "banner")
        self.assertEqual(parse_event(LINE_BANNER_HEADER).kind, "banner")
        self.assertEqual(parse_event("[network] Waiting for encrypted JSON supervisor data on /dev/pts/11...").kind, "banner")
        self.assertEqual(parse_event('[network] {"event": "startup", "message": "Network packet sniffer is running"}').kind, "banner")

    def test_dns_query_packet(self):
        line = network_line("127.0.0.1", "127.0.0.53", "UDP", 36560, 53, RESOLVED_PROCESS, PERIODIC_DNS_NAME, "outbound")
        event = parse_event(line)
        self.assertEqual((event.source, event.sensor, event.kind, event.comm, event.pid), ("network", "network", "dns_query", "systemd-resolved", 727))
        self.assertEqual((event.target, event.protocol, event.time), (PERIODIC_DNS_NAME, "UDP", "22:40:23Z"))
        self.assertNotIn("EXTERNAL_DEST", event.flags)

    def test_tcp_flow_packet_collapses_ephemeral_port(self):
        event = parse_event(network_line("10.0.2.2", "10.0.2.15", "TCP", 51866, 22, SSH_PROCESS))
        self.assertEqual((event.kind, event.target), ("flow", "10.0.2.2:* -> 10.0.2.15:22/TCP"))
        self.assertEqual(event.cmdline, "sshd: cerise@notty")
        self.assertEqual((event.src_ip, event.dst_ip, event.src_port, event.dst_port), ("10.0.2.2", "10.0.2.15", 51866, 22))

    def test_external_destination_is_flagged(self):
        event = parse_event(network_line("10.0.2.15", "93.184.216.34", "TCP", 40000, 443, None, direction="outbound", tcp_flags=["SYN"]))
        self.assertIn("EXTERNAL_DEST", event.flags)
        self.assertIn("TCP_SYN", event.flags)

    def test_arp_packet(self):
        line = '[network] {"packet_number": 3211, "timestamp": "2026-11-22T23:03:55.772786+00:00", "ethernet": {}, "protocol": "ARP", "arp": {"operation": "request", "sender_ip": "10.0.2.15", "target_ip": "10.0.2.2"}}'
        event = parse_event(line)
        self.assertEqual((event.kind, event.target), ("arp", "10.0.2.15 -> 10.0.2.2 request"))

    def test_unknown_line_becomes_generic_event(self):
        event = parse_event(LINE_UNKNOWN)
        self.assertEqual((event.kind, event.sensor), ("unparsed", "unknown"))
        self.assertEqual(event.raw, LINE_UNKNOWN)
        self.assertIn("something no sensor ever prints", event.target)

    def test_malformed_json_is_not_discarded(self):
        event = parse_event('[ebpf:/dev/pts/6] {"e":"log_tamp","c":"logrotate"')
        self.assertEqual(event.kind, "unparsed")

    def test_unprefixed_line_is_accepted(self):
        event = parse_event("COMM: python3          PID: 1015     UID: 0        FLAGS: 0x0    FILE: /etc/passwd")
        self.assertEqual((event.sensor, event.source), ("sensitive_file", "ebpf"))

    def test_non_string_raises_explicit_error(self):
        with self.assertRaises(TypeError):
            parse_event(None)


class ExecLineVariantTests(unittest.TestCase):
    def test_duplicated_time_prefix_is_parsed(self):
        line = "[ebpf:/dev/pts/10] TIME: 21:02:31  TIME: 21:02:31  COMM: 18884936d002839  PID: 2213     PPID: 1        UID: 0      FLAGS: [CHMOD_CALLED]"
        event = parse_event(line)
        self.assertEqual((event.sensor, event.kind, event.pid, event.time), ("suspicious_exec", "chmod", 2213, "21:02:31"))

    def test_line_without_time_prefix_is_parsed(self):
        line = "[ebpf:/dev/pts/10] COMM: 18884936d002839  PID: 2213     PPID: 1        UID: 0      FLAGS: [CHMOD_CALLED]"
        event = parse_event(line)
        self.assertEqual((event.sensor, event.kind, event.pid, event.time), ("suspicious_exec", "chmod", 2213, None))


class ControlNoiseTests(unittest.TestCase):
    def test_ssh_control_channel_both_directions(self):
        inbound = parse_event(network_line("10.0.2.2", "10.0.2.15", "TCP", 51866, 22, SSH_PROCESS))
        outbound = parse_event(network_line("10.0.2.15", "10.0.2.2", "TCP", 22, 51866, SSH_PROCESS, direction="outbound"))
        self.assertTrue(is_control_noise(inbound))
        self.assertTrue(is_control_noise(outbound))

    def test_other_tcp_flows_are_not_noise(self):
        other_port = parse_event(network_line("10.0.2.2", "10.0.2.15", "TCP", 51866, 8080))
        other_host = parse_event(network_line("10.0.2.15", "10.0.2.99", "TCP", 40000, 22, direction="outbound"))
        self.assertFalse(is_control_noise(other_port))
        self.assertFalse(is_control_noise(other_host))

    def test_monitoring_stack_comms(self):
        self.assertTrue(is_control_noise(parse_event(LINE_SYSCALL_BPF)))
        guest_monitor = LINE_FILE.replace("python3         ", "guest_monitor   ")
        self.assertEqual(parse_event(guest_monitor).comm, "guest_monitor")
        self.assertTrue(is_control_noise(parse_event(guest_monitor)))
        supervisor_monitor = LINE_FILE.replace("python3         ", "supervisor_monit")
        self.assertTrue(is_control_noise(parse_event(supervisor_monitor)))

    def test_supervisor_process_in_network_event(self):
        event = parse_event(network_line("127.0.0.1", "127.0.0.53", "UDP", 35057, 53, SUPERVISOR_PROCESS, "example.com", "outbound"))
        self.assertTrue(is_control_noise(event))

    def test_python3_without_supervisor_cmdline_is_not_noise(self):
        process = dict(SUPERVISOR_PROCESS, cmdline=["/usr/bin/python3", "-m", "http.server"])
        event = parse_event(network_line("10.0.2.15", "10.0.2.99", "TCP", 40000, 8000, process, direction="outbound"))
        self.assertFalse(is_control_noise(event))
        self.assertFalse(is_control_noise(parse_event(LINE_FILE)))

    def test_ebpf_events_of_supervisor_pid_are_noise(self):
        event = parse_event(LINE_FILE)
        self.assertFalse(is_control_noise(event))
        self.assertTrue(is_control_noise(event, frozenset({1015})))

    def test_banner_is_noise_and_chmod_is_not(self):
        self.assertTrue(is_control_noise(parse_event(LINE_BANNER)))
        self.assertFalse(is_control_noise(parse_event(LINE_CHMOD)))

    def test_digest_counts_noise_without_showing_it(self):
        lines = [
            network_line("10.0.2.2", "10.0.2.15", "TCP", 51866, 22, SSH_PROCESS),
            network_line("127.0.0.1", "127.0.0.53", "UDP", 35057, 53, SUPERVISOR_PROCESS, "example.com", "outbound"),
            LINE_SYSCALL_BPF,
            LINE_FILE,
        ]
        result = build_digest(lines)
        self.assertEqual((result.stats["total"], result.stats["control_noise"], result.stats["groups"]), (4, 3, 1))
        self.assertNotIn("example.com", result.text)
        self.assertNotIn("bpftrace", result.text.split("== EVENT GROUPS ==")[1])


class BaselineProfileTests(unittest.TestCase):
    def test_signature_ignores_pid_and_collapses_numbers(self):
        first = digest_module.event_signature(parse_event(LINE_FILE))
        second = digest_module.event_signature(parse_event(LINE_FILE.replace("1015", "990")))
        self.assertEqual(first, second)
        journal = '[ebpf:/dev/pts/6] {"e":"log_tamp","c":"systemd-journal","p":316,"u":0,"f":"/var/log/journal/fe682a37a6886420f6b0b969a346a688/fss"}'
        other_machine = journal.replace("fe682a37a6886420f6b0b969a346a688", "0123456789abcdef0123456789abcdef")
        self.assertEqual(
            digest_module.event_signature(parse_event(journal)),
            digest_module.event_signature(parse_event(other_machine)),
        )

    def test_signature_differs_by_comm_and_target(self):
        base = digest_module.event_signature(parse_event(LINE_FILE))
        self.assertNotEqual(base, digest_module.event_signature(parse_event(LINE_FILE.replace("python3", "perl   "))))
        self.assertNotEqual(base, digest_module.event_signature(parse_event(LINE_FILE.replace("/etc/passwd", "/etc/shadow"))))

    def test_from_events_and_contains(self):
        profile = BaselineProfile.from_events([LINE_FILE, LINE_SYSCALL_BPF, LINE_BANNER, LINE_UNKNOWN])
        self.assertEqual(len(profile), 1)
        self.assertTrue(profile.contains(digest_module.event_signature(parse_event(LINE_FILE))))
        self.assertFalse(profile.contains(digest_module.event_signature(parse_event(LINE_CHMOD))))

    def test_baseline_marks_group_and_summarises_it_in_one_line(self):
        profile = BaselineProfile.from_events([LINE_FILE])
        result = build_digest([LINE_FILE, LINE_FILE, LINE_CHMOD], profile)
        self.assertEqual((result.stats["groups"], result.stats["in_baseline"], result.stats["baseline_groups"]), (2, 2, 1))
        baseline_lines = [line for line in result.text.splitlines() if line.startswith("[baseline]")]
        self.assertEqual(len(baseline_lines), 1)
        self.assertIn("/etc/passwd", baseline_lines[0])
        groups_section = result.text.split("== EVENT GROUPS ==")[1].split("[baseline]")[0]
        self.assertIn("chmod", groups_section)
        self.assertNotIn("/etc/passwd", groups_section)

    def test_serious_non_baseline_group_comes_before_larger_common_group(self):
        lines = [LINE_FILE] * 50 + [LINE_SHELL]
        result = build_digest(lines)
        groups_section = result.text.split("== EVENT GROUPS ==")[1]
        self.assertLess(groups_section.index("SHELL_INTERPRETER"), groups_section.index("/etc/passwd"))


@unittest.skipUnless(FIXTURES_AVAILABLE, "real batch fixtures not available")
class EncoderCentralBatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lines = load_events(ENCODER_RUN, CENTRAL_BATCH_ID)
        started = time.perf_counter()
        cls.result = build_digest(cls.lines)
        cls.elapsed = time.perf_counter() - started

    def first_group_line(self):
        return self.result.text.split("== EVENT GROUPS ==\n")[1].splitlines()[0]

    def test_batch_has_expected_size(self):
        self.assertEqual(len(self.lines), CENTRAL_BATCH_EVENT_COUNT)
        self.assertEqual(self.result.stats["total"], CENTRAL_BATCH_EVENT_COUNT)

    def test_first_group_is_the_malware_chmod(self):
        first = self.first_group_line()
        self.assertIn("suspicious_exec/chmod", first)
        self.assertIn(f"comm={MALWARE_COMM_PREFIX}", first)
        self.assertIn("CHMOD_CALLED", first)
        self.assertIn(f"count={CENTRAL_BATCH_CHMOD_COUNT}", first)

    def test_text_respects_limit(self):
        self.assertLessEqual(len(self.result.text), DIGEST_MAX_CHARS)
        self.assertEqual(self.result.stats["chars"], len(self.result.text))

    def test_stats_are_consistent(self):
        stats = self.result.stats
        self.assertEqual(stats["total"], stats["parsed"] + stats["unparsed"])
        self.assertEqual(stats["unparsed"], 0)
        self.assertEqual(stats["in_baseline"], 0)
        self.assertGreater(stats["groups"], 0)
        self.assertEqual(stats["groups_shown"] + stats["groups_omitted"] + stats["baseline_groups"], stats["groups"])

    def test_dropped_events_warning_is_present(self):
        self.assertGreater(self.result.stats["lost_events"], 0)
        self.assertIn("dropped events", self.result.text)

    def test_noise_is_only_counted(self):
        self.assertGreater(self.result.stats["control_noise"], 0)
        self.assertIn("Control noise filtered out", self.result.text)
        self.assertNotIn("10.0.2.2:* -> 10.0.2.15:22", self.result.text)

    def test_digest_is_fast(self):
        self.assertLess(self.elapsed, MAX_DIGEST_SECONDS)

    def test_raw_examples_follow_the_groups(self):
        self.assertIn("== RAW EXAMPLES", self.result.text)
        self.assertIn("COMM: 18884936d002839", self.result.text.split("== RAW EXAMPLES")[1])


@unittest.skipUnless(FIXTURES_AVAILABLE, "real batch fixtures not available")
class EncoderBaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baseline = BaselineProfile.from_events(load_encoder_events(BASELINE_BATCH_IDS))

    def test_baseline_is_not_empty(self):
        self.assertGreater(len(self.baseline), 5)

    def test_periodic_noise_is_baseline_or_control_noise_after_detonation(self):
        for batch_id in POST_DETONATION_BATCH_IDS:
            with self.subTest(batch=batch_id):
                lines = load_events(ENCODER_RUN, batch_id)
                events = [parse_event(line) for line in lines]
                supervisor_pids = digest_module._collect_supervisor_pids(events)
                for event in events:
                    if event.sensor == "sensitive_file" and event.comm == "python3" and event.target == SUPERVISOR_SIGNATURE_TARGET:
                        covered = is_control_noise(event, supervisor_pids) or self.baseline.contains(digest_module.event_signature(event))
                        self.assertTrue(covered)
                    if event.kind == "dns_query" and event.target == PERIODIC_DNS_NAME:
                        covered = is_control_noise(event, supervisor_pids) or self.baseline.contains(digest_module.event_signature(event))
                        self.assertTrue(covered)

    def test_post_detonation_digests_hide_periodic_noise_from_groups(self):
        for batch_id in POST_DETONATION_BATCH_IDS:
            with self.subTest(batch=batch_id):
                result = build_digest(load_events(ENCODER_RUN, batch_id), self.baseline)
                groups_section = result.text.split("== EVENT GROUPS ==")[1].split("[baseline]")[0].split("== RAW EXAMPLES")[0]
                self.assertNotIn(f"dns_query {PERIODIC_DNS_NAME}", groups_section)
                self.assertNotIn("comm=python3 uid=0 flags=ACCESS_READ", groups_section)
                self.assertGreater(result.stats["in_baseline"] + result.stats["control_noise"], 0)

    def test_malware_chmod_is_never_in_baseline(self):
        result = build_digest(load_events(ENCODER_RUN, CENTRAL_BATCH_ID), self.baseline)
        first = result.text.split("== EVENT GROUPS ==\n")[1].splitlines()[0]
        self.assertIn(f"comm={MALWARE_COMM_PREFIX}", first)
        self.assertNotIn("partly baseline", first)


@unittest.skipUnless(FIXTURES_AVAILABLE, "real batch fixtures not available")
class AllFixturesTests(unittest.TestCase):
    def test_no_line_is_unparsed_and_every_digest_fits(self):
        paths = [
            path
            for run_name in ("run2_haiku_5.5_high", "run3_digest_haiku_5.5_high")
            for path in glob.glob(os.path.join(FIXTURES_ROOT, "*", run_name, "**", "batch_*.json"), recursive=True)
        ]
        self.assertGreater(len(paths), 50)
        for path in paths:
            with open(path, encoding="utf-8") as handle:
                lines = json.load(handle)["events"]
            if not isinstance(lines, list):
                continue
            result = build_digest(lines)
            with self.subTest(path=os.path.relpath(path, FIXTURES_ROOT)):
                self.assertEqual(result.stats["unparsed"], 0)
                self.assertLessEqual(len(result.text), DIGEST_MAX_CHARS)
                self.assertEqual(result.stats["total"], len(lines))


class TruncationTests(unittest.TestCase):
    def make_many_groups(self, amount):
        return [
            f"[ebpf:/dev/pts/9] COMM: proc{index:05d}       PID: {1000 + index}     UID: 0        FLAGS: 0x80000 FILE: /etc/file{index}"
            for index in range(amount)
        ]

    def test_text_is_bounded_and_reports_omitted_groups(self):
        result = build_digest(self.make_many_groups(800))
        self.assertLessEqual(len(result.text), DIGEST_MAX_CHARS)
        self.assertGreater(result.stats["groups_omitted"], 0)
        self.assertEqual(result.stats["groups"], 800)
        self.assertEqual(result.stats["groups_shown"] + result.stats["groups_omitted"], 800)
        self.assertIn(f"{result.stats['groups_omitted']} more groups omitted", result.text)

    def test_truncation_is_deterministic(self):
        lines = self.make_many_groups(300)
        self.assertEqual(build_digest(lines).text, build_digest(lines).text)

    def test_distinct_targets_and_top_directories(self):
        lines = [
            f"[ebpf:/dev/pts/9] COMM: enc              PID: 10       UID: 0        FLAGS: 0x80241 FILE: /home/user/doc{index}.txt"
            for index in range(1200)
        ] + [
            f"[ebpf:/dev/pts/9] COMM: enc              PID: 10       UID: 0        FLAGS: 0x80241 FILE: /var/www/html/page{index}.php"
            for index in range(34)
        ]
        result = build_digest(lines)
        self.assertIn("/home(1200)", result.text)
        self.assertIn("/var/www(34)", result.text)
        self.assertIn("1234 distinct", result.text)

    def test_blank_lines_are_ignored_and_empty_input_works(self):
        self.assertEqual(build_digest(["", "   "]).stats["total"], 0)
        result = build_digest([])
        self.assertEqual(result.stats["groups"], 0)
        self.assertLessEqual(len(result.text), DIGEST_MAX_CHARS)

    def test_network_flows_are_aggregated_per_flow_and_dns_per_name(self):
        lines = [network_line("10.0.2.15", "10.0.2.99", "TCP", 40000 + index, 8080, None, direction="outbound") for index in range(30)]
        lines += [network_line("127.0.0.1", "127.0.0.53", "UDP", 35000 + index, 53, RESOLVED_PROCESS, "evil.example.org", "outbound") for index in range(7)]
        result = build_digest(lines)
        self.assertEqual(result.stats["groups"], 2)
        self.assertIn("10.0.2.15:* -> 10.0.2.99:8080/TCP", result.text)
        self.assertIn("count=30", result.text)
        self.assertIn("dns_query evil.example.org", result.text)
        self.assertIn("count=7", result.text)


if __name__ == "__main__":
    unittest.main()


def sandbox_lines(pid, ppid=1, comm="(imedated)", mounts=20):
    lines = [f"[ebpf:/dev/pts/1] 21:21:55  {comm:<16} {pid:<8} {ppid:<8} 0      unshare          flags=0x20000"]
    lines.extend(
        f"[ebpf:/dev/pts/1] 21:21:55  {comm:<16} {pid:<8} {ppid:<8} 0      mount            dev=, dir=/, type="
        for _ in range(mounts)
    )
    lines.append(f"[ebpf:/dev/pts/1] 21:21:55  {comm:<16} {pid:<8} {ppid:<8} 0      umount           target=/run/user/1000")
    lines.append(f"[ebpf:/dev/pts/8] 21:21:55  {comm:<16} {pid:<8} 0        capset     capabilities modified")
    return lines


def sandbox_summary_lines(text):
    return [line for line in text.splitlines() if line.startswith(SANDBOX_ANNOTATION)]


def ranked_headlines(text):
    return [line for line in text.splitlines() if line.startswith("#")]


class MonitorPidParsingTests(unittest.TestCase):
    def test_startup_event_carries_pid_and_ppid(self):
        event = parse_event(LINE_STARTUP)
        self.assertEqual((event.kind, event.pid, event.ppid), ("banner", 958, 941))

    def test_startup_event_without_pid_still_parses(self):
        event = parse_event(LINE_STARTUP_WITHOUT_PID)
        self.assertEqual((event.kind, event.pid, event.ppid), ("banner", None, None))

    def test_monitor_pids_are_discovered_from_startup_event(self):
        result = build_digest([LINE_STARTUP, LINE_FILE])
        self.assertEqual(result.stats["monitor_pids"], [941, 958])

    def test_monitor_pids_are_discovered_from_supervisor_cmdline(self):
        line = network_line("10.0.2.15", "8.8.8.8", process=SUPERVISOR_PROCESS, direction="outbound")
        self.assertEqual(build_digest([line]).stats["monitor_pids"], [990])

    def test_monitor_pids_are_empty_without_evidence_and_sorted_otherwise(self):
        self.assertEqual(build_digest([LINE_CHMOD]).stats["monitor_pids"], [])
        later = '[network] {"event": "startup", "message": "x", "pid": 30, "ppid": 1}'
        earlier = '[network] {"event": "startup", "message": "x", "pid": 20}'
        self.assertEqual(build_digest([later, earlier]).stats["monitor_pids"], [20, 30])

    def test_known_pids_are_not_reported_as_discovered(self):
        result = build_digest([LINE_FILE], known_monitor_pids=frozenset({1015}))
        self.assertEqual(result.stats["monitor_pids"], [])

    def test_known_pid_turns_supervisor_events_into_noise(self):
        without = build_digest([LINE_FILE, LINE_CHMOD])
        known = build_digest([LINE_FILE, LINE_CHMOD], known_monitor_pids=frozenset({1015}))
        self.assertEqual(without.stats["control_noise"], 0)
        self.assertEqual(known.stats["control_noise"], 1)
        self.assertNotIn("sensitive_file", known.text.split("== EVENT GROUPS ==")[1])

    def test_known_pid_only_applies_to_python3_events(self):
        other = LINE_FILE.replace("python3", "cat    ")
        result = build_digest([other], known_monitor_pids=frozenset({1015}))
        self.assertEqual(result.stats["control_noise"], 0)

    def test_baseline_profile_accepts_known_pids(self):
        profile = BaselineProfile.from_events([LINE_FILE], known_monitor_pids=frozenset({1015}))
        self.assertEqual(len(profile), 0)

    def test_batch_pids_and_known_pids_are_combined(self):
        other = LINE_FILE.replace("PID: 1015", "PID: 958")
        result = build_digest([LINE_STARTUP, LINE_FILE, other], known_monitor_pids=frozenset({1015}))
        self.assertEqual(result.stats["control_noise"], 3)


@unittest.skipUnless(RUN3_AVAILABLE, "run3 fixtures not available")
class SupervisorBaselineRegressionTests(unittest.TestCase):
    def collect(self, run_directory, batch_ids, supervisor_pid):
        for batch_id in batch_ids:
            lines = load_events(run_directory, batch_id)
            without = build_digest(lines)
            known = build_digest(lines, known_monitor_pids=frozenset({supervisor_pid}))
            yield batch_id, without, known

    def assert_supervisor_reads_are_noise(self, run_directory, batch_ids, supervisor_pid):
        for batch_id, without, known in self.collect(run_directory, batch_ids, supervisor_pid):
            with self.subTest(batch=batch_id):
                self.assertIn("sensitive_file/file_open comm=python3", without.text)
                self.assertNotIn("sensitive_file/file_open comm=python3", known.text)
                self.assertGreater(known.stats["control_noise"], without.stats["control_noise"])
                self.assertEqual(known.stats["groups"], without.stats["groups"] - 1)

    def test_wirenet_supervisor_reads_become_control_noise(self):
        self.assert_supervisor_reads_are_noise(WIRENET_RUN3, WIRENET_BASELINE_BATCH_IDS, WIRENET_SUPERVISOR_PID)

    def test_encoder_supervisor_reads_become_control_noise(self):
        self.assert_supervisor_reads_are_noise(ENCODER_RUN3, ENCODER_BASELINE_BATCH_IDS, ENCODER_SUPERVISOR_PID)

    def test_supervisor_reads_are_not_a_ranked_group_when_known(self):
        lines = load_events(WIRENET_RUN3, 4)
        known = build_digest(lines, known_monitor_pids=frozenset({WIRENET_SUPERVISOR_PID}))
        self.assertFalse([line for line in ranked_headlines(known.text) if "comm=python3" in line])

    def test_unrelated_python3_pid_is_still_reported(self):
        lines = load_events(WIRENET_RUN3, 4)
        result = build_digest(lines, known_monitor_pids=frozenset({1}))
        self.assertIn("sensitive_file/file_open comm=python3", result.text)


class SyntheticSandboxTests(unittest.TestCase):
    def test_burst_from_pid_one_child_is_annotated_and_not_ranked(self):
        result = build_digest(sandbox_lines(2405))
        self.assertEqual(ranked_headlines(result.text), [])
        self.assertEqual(len(sandbox_summary_lines(result.text)), 1)
        self.assertEqual(result.stats["sandbox_groups"], 4)
        self.assertEqual(result.stats["sandbox_events"], 23)
        self.assertIn("(imedated) dangerous_syscalls/mount x20", result.text)
        self.assertIn("pids=2405", result.text)

    def test_other_parent_pid_stays_suspicious(self):
        result = build_digest(sandbox_lines(2405, ppid=1234))
        self.assertEqual(sandbox_summary_lines(result.text), [])
        self.assertEqual(result.stats["sandbox_groups"], 0)
        self.assertTrue(any("dangerous_syscalls/mount" in line for line in ranked_headlines(result.text)))

    def test_comm_without_parentheses_stays_suspicious(self):
        result = build_digest(sandbox_lines(2405, comm="imedated"))
        self.assertEqual(result.stats["sandbox_groups"], 0)
        self.assertTrue(ranked_headlines(result.text))

    def test_same_pid_running_another_binary_is_not_annotated(self):
        exec_line = "[ebpf:/dev/pts/10] TIME: 21:21:56  COMM: sh               PID: 2405     PPID: 1        UID: 0      PATH: /bin/sh FLAGS: [SHELL_INTERPRETER]"
        result = build_digest(sandbox_lines(2405) + [exec_line])
        self.assertEqual(result.stats["sandbox_groups"], 0)
        self.assertTrue(any("dangerous_syscalls/mount" in line for line in ranked_headlines(result.text)))

    def test_same_pid_with_events_of_other_sensors_is_not_annotated(self):
        for extra in (
            LINE_FILE.replace("python3", "(imedated)").replace("PID: 1015", "PID: 2405").replace("/etc/passwd", "/etc/shadow"),
            LINE_NETWORK_SUSPICIOUS.replace("PID: 3321", "PID: 2405"),
            LINE_LOG_TAMPERING.replace('"p":2371', '"p":2405'),
            LINE_PERSISTENCE.replace('"p":2300', '"p":2405'),
        ):
            with self.subTest(extra=extra[:60]):
                result = build_digest(sandbox_lines(2405) + [extra])
                self.assertEqual(result.stats["sandbox_groups"], 0)
                self.assertEqual(sandbox_summary_lines(result.text), [])

    def test_readonly_proc_read_after_the_handoff_keeps_the_annotation(self):
        handoff = "[ebpf:/dev/pts/9] COMM: systemd-timedat  PID: 2405     UID: 0        FLAGS: 0x80000 FILE: /proc/cmdline"
        result = build_digest(sandbox_lines(2405) + [handoff])
        self.assertEqual(result.stats["sandbox_groups"], 4)
        self.assertIn("sensitive_file/file_open comm=systemd-timedat", result.text)

    def test_annotation_applies_per_pid(self):
        exec_line = "[ebpf:/dev/pts/10] TIME: 21:21:56  COMM: sh               PID: 2500     PPID: 1        UID: 0      PATH: /bin/sh FLAGS: [SHELL_INTERPRETER]"
        lines = sandbox_lines(2405) + sandbox_lines(2500) + [exec_line]
        result = build_digest(lines)
        self.assertEqual(result.stats["sandbox_groups"], 4)
        self.assertIn("pids=2405", result.text)
        self.assertNotIn("2500", sandbox_summary_lines(result.text)[0])

    def test_sandbox_burst_never_outranks_a_real_threat(self):
        result = build_digest(sandbox_lines(2405, mounts=500) + [LINE_CHMOD])
        self.assertTrue(ranked_headlines(result.text)[0].startswith("#1 suspicious_exec/chmod"))

    def test_sandbox_groups_are_still_listed_not_hidden(self):
        result = build_digest(sandbox_lines(2405, mounts=500))
        self.assertIn("x500", result.text)
        self.assertIn("capset", result.text)
        self.assertEqual(result.stats["total"], 503)


@unittest.skipUnless(RUN3_AVAILABLE, "run3 fixtures not available")
class WirenetSandboxBatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lines = load_events(WIRENET_RUN3, SANDBOX_BATCH_ID)
        cls.result = build_digest(cls.lines, known_monitor_pids=frozenset({WIRENET_SUPERVISOR_PID}))

    def test_real_batch_has_the_annotated_line(self):
        self.assertEqual(len(sandbox_summary_lines(self.result.text)), 1)
        self.assertEqual(self.result.stats["sandbox_events"], 78)
        self.assertIn("(imedated) dangerous_syscalls/mount x73", self.result.text)
        self.assertIn("pids=2405", self.result.text)

    def test_real_batch_has_no_ranked_sandbox_group(self):
        headlines = ranked_headlines(self.result.text)
        self.assertFalse([line for line in headlines if "(imedated)" in line])
        self.assertFalse([line for line in headlines if "dangerous_syscalls/mount" in line])

    def test_real_batch_top_group_is_not_the_sandbox_burst(self):
        self.assertNotIn("(imedated)", ranked_headlines(self.result.text)[0])

    def test_real_batch_keeps_the_post_handoff_read_visible(self):
        self.assertIn("comm=systemd-timedat", self.result.text)

    def test_run2_batch_behaves_the_same(self):
        lines = load_events(WIRENET_RUN, SANDBOX_BATCH_ID)
        result = build_digest(lines, known_monitor_pids=frozenset({990}))
        self.assertEqual(result.stats["sandbox_events"], 78)
        self.assertFalse([line for line in ranked_headlines(result.text) if "(imedated)" in line])


class PersistenceEventTests(unittest.TestCase):
    def test_persistence_event_parse(self):
        event = parse_event(LINE_PERSISTENCE)
        self.assertEqual(
            (event.source, event.sensor, event.kind, event.comm, event.pid, event.ppid, event.uid),
            ("ebpf", "persistence_activity", "persistence", "WIFIADAPT", 2300, 2230, 1000),
        )
        self.assertEqual(event.target, "/home/cerise/.config/autostart/WIFIADAPTER.desktop")
        self.assertEqual(event.flags, ("PERSISTENCE_WRITE",))
        self.assertEqual(event.detail, "open_write")

    def test_persistence_ops_are_kept(self):
        for operation in ("open_write", "rename", "unlink", "symlink", "chmod"):
            with self.subTest(operation=operation):
                line = LINE_PERSISTENCE.replace("open_write", operation)
                self.assertEqual(parse_event(line).detail, operation)

    def test_mass_file_ops_parse(self):
        event = parse_event(LINE_MASS_FILE_OPS)
        self.assertEqual(
            (event.sensor, event.kind, event.comm, event.pid, event.uid, event.operations, event.window_seconds),
            ("persistence_activity", "mass_file_ops", "18884936d002839", 2297, 0, 5000, 1),
        )
        self.assertEqual((event.flags, event.detail), (("MASS_FILE_OPS",), "chmod"))

    def test_new_flags_and_kinds_are_severe(self):
        self.assertIn("PERSISTENCE_WRITE", digest_module.SEVERE_FLAGS)
        self.assertIn("MASS_FILE_OPS", digest_module.SEVERE_FLAGS)
        self.assertIn("persistence", digest_module.SEVERE_KINDS)
        self.assertIn("mass_file_ops", digest_module.SEVERE_KINDS)

    def test_autostart_written_by_wifiadapt_is_ranked_first(self):
        noise = [LINE_FILE.replace("PID: 1015", f"PID: {3000 + index}").replace("python3", "cat") for index in range(300)]
        result = build_digest(noise + [LINE_PERSISTENCE])
        first = ranked_headlines(result.text)[0]
        self.assertTrue(first.startswith("#1 persistence_activity/persistence"), first)
        self.assertIn("comm=WIFIADAPT", first)
        self.assertIn("flags=PERSISTENCE_WRITE", first)
        self.assertIn("op=open_write", first)
        self.assertIn(".config/autostart/WIFIADAPTER.desktop", result.text)

    def test_twelve_mass_windows_sum_to_sixty_thousand(self):
        lines = [LINE_MASS_FILE_OPS] * 12
        result = build_digest(lines)
        first = ranked_headlines(result.text)[0]
        self.assertIn("count=60000 operations", first)
        self.assertIn("windows=12 x 1s", first)
        self.assertIn("lines=12", first)
        self.assertIn("flags=MASS_FILE_OPS", first)
        self.assertIn("op=chmod", first)
        self.assertIn("pids=1", first)
        self.assertEqual(result.stats["groups"], 1)

    def test_mass_file_ops_rank_by_operations_not_lines(self):
        heavy = LINE_MASS_FILE_OPS.replace('"n":5000', '"n":90000')
        other = LINE_MASS_FILE_OPS.replace('"p":2297', '"p":2299').replace('"c":"18884936d002839"', '"c":"other"')
        result = build_digest([other] * 5 + [heavy])
        headlines = ranked_headlines(result.text)
        self.assertIn("count=90000 operations", headlines[0])
        self.assertIn("count=25000 operations", headlines[1])

    def test_different_operations_form_different_groups(self):
        unlink = LINE_MASS_FILE_OPS.replace('"op":"chmod"', '"op":"unlink"')
        result = build_digest([LINE_MASS_FILE_OPS, unlink])
        self.assertEqual(result.stats["groups"], 2)

    def test_mass_file_ops_missing_fields_do_not_crash(self):
        event = parse_event('[ebpf:/dev/vport0p11] {"e":"mass_file_ops","c":"x"}')
        self.assertEqual((event.kind, event.operations, event.window_seconds, event.pid), ("mass_file_ops", 0, 0, None))

    def test_persistence_beats_larger_common_groups(self):
        common = [LINE_FILE.replace("python3", "cat").replace("PID: 1015", "PID: 2") for _ in range(50)]
        result = build_digest(common + [LINE_PERSISTENCE])
        self.assertIn("persistence_activity", ranked_headlines(result.text)[0])


class LegacyOpenEventTests(unittest.TestCase):
    def test_legacy_open_probe_uses_the_current_sensitive_file_format(self):
        legacy = "[ebpf:/dev/pts/9] COMM: 18884936d002839  PID: 2297     UID: 0        FLAGS: 0x241 FILE: /etc/passwd"
        event = parse_event(legacy)
        self.assertEqual((event.sensor, event.kind, event.comm, event.pid, event.uid), ("sensitive_file", "file_open", "18884936d002839", 2297, 0))
        self.assertEqual(event.target, "/etc/passwd")
        self.assertEqual(event.flags, ("ACCESS_WRITE", "O_CREAT", "O_TRUNC"))

    def test_legacy_and_openat_events_share_signature(self):
        legacy = LINE_FILE.replace("PID: 1015", "PID: 7")
        self.assertEqual(digest_module.event_signature(parse_event(legacy)), digest_module.event_signature(parse_event(LINE_FILE)))
