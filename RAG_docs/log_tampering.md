Fact Sheet: log_tampering
Script Objective

This detection identifies attempts to alter, delete, suppress, or otherwise interfere with system and user-level logging mechanisms. Log tampering is a common post-exploitation technique used by attackers to erase forensic evidence, evade detection, and complicate incident response and attribution.

This includes direct modification or deletion of log files (commonly located in /var/log), changes to logging configuration that reduce or disable log generation, and redirection of log output to non-persistent or null destinations such as /dev/null. In addition to system logs, attackers often target shell history and audit trails to obscure the sequence of executed commands.

The objective of this script is to surface abnormal interactions with logging infrastructure that indicate deliberate attempts to hide malicious activity already performed on the system.

Anomaly Patterns

Opening or modifying log files with write permissions by processes other than the system’s authorized logging daemons (such as syslogd, rsyslogd, or journald), particularly when initiated by interactive shells or application processes.

Execution of destructive or log-manipulation commands such as shred, truncate, sed -i, or rm targeting critical log files like auth.log, syslog, secure, messages, or audit logs.

Stopping, disabling, or forcefully terminating logging services using service managers or signals (e.g., service rsyslog stop, systemctl stop systemd-journald, killall -9 syslogd).

Unauthorized modification of logging configuration files (e.g., /etc/rsyslog.conf, /etc/rsyslog.d/*, /etc/syslog.conf) to suppress specific facilities, reduce log verbosity, or redirect output away from persistent storage.

Redirection of logging output to /dev/null or ephemeral locations that do not retain data across reboots.

Editing, truncating, or deleting shell history files such as .bash_history, .zsh_history, or .ash_history, as well as unsetting or modifying environment variables like HISTFILE, HISTSIZE, or HISTCONTROL to prevent command logging.

Clearing or disabling audit frameworks (e.g., auditd) or modifying audit rules to exclude attacker activity.

Normal Patterns (Common False Positives)

The logrotate process rotating, compressing, and archiving older log files according to scheduled retention policies.

System administrators or support personnel viewing logs using read-only tools such as less, more, cat, or journalctl.

System updates, configuration management tools, or package installations that temporarily restart logging services as part of normal maintenance.

Automated cleanup or housekeeping scripts removing very old, archived, or compressed log files (typically .gz or .xz files) in accordance with retention policies.

Legitimate changes to logging configuration during troubleshooting or planned system hardening activities, usually accompanied by change records or maintenance windows.

Base Criticality Level

4 (High) – Attempts to tamper with logs strongly suggest that malicious activity has already occurred or is actively underway. Attackers typically do not attempt to erase or suppress logs unless there is behavior they wish to conceal. As such, log tampering often marks a late stage in an attack lifecycle and warrants immediate investigation.

Suggested Correlation

Log tampering is frequently one of the final steps in an intrusion, occurring after the attacker has achieved their primary objectives. Alerts should be correlated with:

privilege_escalation events that grant the attacker the necessary permissions to modify system logs.

suspicious_exec activity involving shells, scripting engines, or uncommon binaries executed shortly before logs are altered or cleared.

sensitive_file_access detections targeting credential stores, configuration files, or other high-value assets preceding the loss of logging visibility.

Gaps or sudden drops in log volume that coincide with other indicators of compromise.

When analyzed in sequence, log tampering alerts can help reconstruct attacker timelines and confirm the presence of deliberate anti-forensic behavior.