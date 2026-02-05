Fact Sheet: sensitive_file_access
Script Objective

This detection monitors read and write access to highly sensitive system files that store credentials, security policies, authentication data, and critical configuration. These files are foundational to the security model of a Linux system and are normally accessed only by a small set of trusted system components and administrators.

Unauthorized access to files such as /etc/shadow, /etc/sudoers, SSH private keys, and cron configurations can enable attackers to:

Steal password hashes and attempt offline cracking.

Escalate privileges by modifying authentication or authorization rules.

Create see persistence by adding users, backdoors, or scheduled tasks.

Harvest operational intelligence by reviewing command history or configuration secrets.

Bypass user-space protections by reading raw system memory.

The objective of this script is to identify abnormal or unexpected access to these files, especially when performed by processes that do not normally require such privileges.

Anomaly Patterns

A network-facing or application process (such as nginx, apache, or application servers) attempting to read highly restricted files like /etc/shadow, /etc/gshadow, or /etc/sudoers.

An unprivileged user or process accessing private SSH keys (id_rsa, id_ed25519, etc.) belonging to another user or to the root account.

Read or write access to sensitive security configuration files outside of expected maintenance windows, package updates, or explicit administrator activity.

Attempts to write to identity and authorization files such as /etc/passwd, /etc/group, /etc/shadow, or /etc/crontab, which may indicate account creation, privilege manipulation, or persistence mechanisms.

Reading shell history files (e.g., /root/.bash_history or /home/*/.bash_history) to harvest cleartext passwords, tokens, internal hostnames, or previously executed administrative commands.

Accessing low-level system interfaces such as /proc/kcore or /dev/mem, which can expose the contents of physical memory and potentially reveal credentials, encryption keys, or kernel data structures.

Normal Patterns (Common False Positives)

Authentication-related processes (login, sshd, PAM modules) reading /etc/shadow or related files as part of normal user authentication.

The sudo command accessing /etc/sudoers to evaluate authorization rules.

System backup processes or snapshot agents reading configuration and credential files for backup and recovery purposes.

Security scanning and compliance tools (e.g., Nessus, OpenVAS) performing controlled reads of sensitive files during authorized assessments.

Configuration management and automation tools (such as Puppet, Chef, or Ansible) accessing and modifying configuration files as part of approved deployments.

The passwd utility modifying credential files during legitimate password changes.

Base Criticality Level

4 (High) – Improper access to sensitive system files is often a precursor to, or direct evidence of, system compromise. Even read-only access can have severe consequences, as stolen credentials and configuration details frequently enable further escalation, persistence, and lateral movement.

Suggested Correlation

Alerts from this detection are especially high-risk when correlated with other attack stages:

An alert from privilege_escalation followed closely by sensitive file access is extremely suspicious and should be treated as critical, as it suggests the attacker is leveraging newly acquired privileges.

If sensitive file access is followed by network_suspicious activity, it may indicate exfiltration of stolen credentials, password hashes, or configuration secrets.

Correlation with log_tampering may indicate attempts to erase evidence of credential theft or unauthorized configuration changes.

When viewed in sequence, sensitive file access alerts can provide clear insight into attacker intent and progression through the compromise lifecycle.