Fact Sheet: sensor_tamper
Script Objective

This detection identifies attempts to blind, disable, or deceive the monitoring sensors themselves. Attackers who gain sufficient privileges frequently try to neutralize the telemetry sources (the eBPF/bpftrace sensors, guest_monitor, and supervisor_monit) before or during malicious activity, so that later actions are never observed. A second technique is to forge or replay telemetry sent to the analysis pipeline so that fabricated or stale events hide the real activity.

This covers two signal families. The first is process-level interference with sensor processes: SIGKILL, SIGTERM, or SIGSTOP signals delivered to bpftrace, guest_monitor, or supervisor_monit, reported as {"e":"sensor_tamper",...} events, together with per-sensor heartbeats that become silent or are reported as dead. The second is authentication failure of the telemetry channel, reported as {"e":"auth_fail","why":"bad_mac"} or {"e":"auth_fail","why":"replay"}, indicating messages with an invalid authentication code or previously seen messages being resent.

The objective of this script is to surface loss of visibility and integrity of telemetry, which usually signals deliberate defense evasion rather than an accidental fault.

Anomaly Patterns

SIGKILL, SIGTERM, or SIGSTOP sent to a bpftrace sensor process, guest_monitor, or supervisor_monit, especially when the sender is a shell, an interactive session, or any process other than systemd or the supervisor.

A sensor_tamper event naming a sensor process as the target of a signal, particularly when the sending uid is 0 reached through a recent privilege escalation, or when the sender is an unexpected binary such as kill, pkill, killall, or a script interpreter.

A sensor heartbeat that stops arriving, is reported as silent or dead, or does not resume after the expected restart interval, especially while other system activity continues.

SIGSTOP followed by no SIGCONT, leaving a sensor frozen: the process still exists but produces no events.

Multiple sensors silenced in a short time window, or one sensor silenced shortly before suspicious execution, file access, or network activity.

auth_fail events with why=bad_mac, indicating telemetry whose authentication code does not verify and may have been forged or altered in transit.

auth_fail events with why=replay, indicating previously accepted telemetry messages being resent, which can be used to mask real activity with stale benign events.

Repeated or bursty auth_fail events from the same source, or auth_fail events appearing right after a sensor restart or a sensor_tamper event.

Normal Patterns (Common False Positives)

systemd stopping and restarting a sensor service as part of a normal service restart, unit reload, or package or configuration update, with the sensor heartbeat resuming promptly afterwards.

Orderly system shutdown or reboot, during which all sensors receive SIGTERM and heartbeats stop for every sensor at once.

The supervisor restarting a sensor it manages after a crash or planned reload, with a matching restart and recovery sequence.

A single isolated auth_fail immediately around a sensor restart or clock adjustment, with no repetition and normal telemetry afterwards.

Planned maintenance or snapshot and pause operations on the virtual machine, which can briefly silence heartbeats for all sensors simultaneously.

Base Criticality Level

4 to 5 (High to Critical) – Termination or suspension of a sensor by a non-systemd process, and any auth_fail event, are treated as high criticality because they indicate active defense evasion or forged telemetry. Criticality should be raised to 5 when several sensors are silenced together, when the signal sender is a root shell, or when auth_fail events coincide with other suspicious activity. Silent heartbeats alone, without a matching signal and with a plausible restart or shutdown cause, can be rated lower.

Suggested Correlation

Sensor tampering is usually part of a defense evasion stage and should be correlated with:

kernel_module_load events, since a rootkit module may be loaded to hide activity or disable the eBPF sensors.

privilege_escalation events that give the attacker the rights to signal root-owned sensor processes.

fileless_execution activity occurring while a sensor is silent or stopped, which may represent actions deliberately kept out of view.

log_tampering events, since attackers often blind both the sensors and the logs in the same window.

Gaps in telemetry or drops in event volume that coincide with other indicators of compromise, and auth_fail events following any of the above.

When analyzed in sequence, sensor_tamper and auth_fail alerts mark the point where visibility was lost or corrupted, and events after that point should be treated as potentially incomplete or untrustworthy.
