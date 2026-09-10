Fact Sheet: sensitive_file_access
Script Objective

This detection monitors read and write access to highly sensitive system files that store credentials, security policies, authentication data, and critical configuration. These files are foundational to the security model of a Linux system and are normally accessed only by a small set of trusted system components and administrators.

Unauthorized access to files such as /etc/shadow, /etc/sudoers, SSH private keys, and cron configurations can enable attackers to:

Steal password hashes and attempt offline cracking.

Escalate privileges by modifying authentication or authorization rules.

Create see persistence by adding users, backdoors, or scheduled tasks.

Harvest operational intelligence by reviewing command history or configuration secrets.

Bypass user-space protections by reading raw system memory.

A recurring delivery mechanism for this category is path traversal: a filename or path segment supplied by an untrusted source (a request parameter, an archive entry name, a request format/extension) containing `../` sequences, so that a file operation intended to stay inside one directory escapes to an arbitrary location. Traversal appears in both directions — reading files that should be unreachable, and writing over files that should be protected — and the resolved path, not the requested one, is what reveals the target.

The objective of this script is to identify abnormal or unexpected access to these files, especially when performed by processes that do not normally require such privileges, and to catch the traversal mechanisms that produce such access.

Anomaly Patterns

A network-facing or application process (such as nginx, apache, or application servers) attempting to read highly restricted files like /etc/shadow, /etc/gshadow, or /etc/sudoers.

An unprivileged user or process accessing private SSH keys (id_rsa, id_ed25519, etc.) belonging to another user or to the root account.

Read or write access to sensitive security configuration files outside of expected maintenance windows, package updates, or explicit administrator activity.

Attempts to write to identity and authorization files such as /etc/passwd, /etc/group, /etc/shadow, or /etc/crontab, which may indicate account creation, privilege manipulation, or persistence mechanisms.

Reading shell history files (e.g., /root/.bash_history or /home/*/.bash_history) to harvest cleartext passwords, tokens, internal hostnames, or previously executed administrative commands.

Accessing low-level system interfaces such as /proc/kcore or /dev/mem, which can expose the contents of physical memory and potentially reveal credentials, encryption keys, or kernel data structures.

An archive extraction process (zip, tar, or similar) opening a file for write whose resolved path — after following `../` path traversal segments embedded in the archive entry's own name — lies outside the intended extraction directory, especially when the resolved target is a sensitive system file such as `/etc/passwd`, `/etc/shadow`, or a file under `/etc/cron.d`. This is the "Zip Slip" pattern: the archive itself, not the extracting process, is the attack payload, and the write typically appears as `O_CREAT|O_TRUNC|O_WRONLY` on a path whose original (pre-resolution) name contains repeated `../` components.

A web application process (e.g., an app server serving a static-asset or file-download route) opening a file for read whose resolved path contains repeated `../` traversal segments derived from a request parameter, especially when the resolved target is a sensitive system file — and the file's content is then read and written back out (served or cached) to the requesting client. This is the read-side counterpart of Zip Slip: a request parameter meant to select a file within one directory is used unsanitized, letting it escape to arbitrary paths on the host.

Normal Patterns (Common False Positives)

Authentication-related processes (login, sshd, PAM modules) reading /etc/shadow or related files as part of normal user authentication.

The sudo command accessing /etc/sudoers to evaluate authorization rules.

System backup processes or snapshot agents reading configuration and credential files for backup and recovery purposes.

Security scanning and compliance tools (e.g., Nessus, OpenVAS) performing controlled reads of sensitive files during authorized assessments.

Configuration management and automation tools (such as Puppet, Chef, or Ansible) accessing and modifying configuration files as part of approved deployments.

The passwd utility modifying credential files during legitimate password changes.

Archive extraction that stays entirely within the intended upload/extraction directory — every written file's resolved path remains a descendant of that directory, with no `../` segment in the archive entry name causing the path to escape it.

An application's static-asset or file-serving route resolving requested paths strictly within its configured base directory, with no `../` traversal segments appearing in the resolved filesystem path.

Base Criticality Level

4 (High) – Improper access to sensitive system files is often a precursor to, or direct evidence of, system compromise. Even read-only access can have severe consequences, as stolen credentials and configuration details frequently enable further escalation, persistence, and lateral movement.

Suggested Correlation

Alerts from this detection are especially high-risk when correlated with other attack stages:

An alert from privilege_escalation followed closely by sensitive file access is extremely suspicious and should be treated as critical, as it suggests the attacker is leveraging newly acquired privileges.

If sensitive file access is followed by network_suspicious activity, it may indicate exfiltration of stolen credentials, password hashes, or configuration secrets.

Correlation with log_tampering may indicate attempts to erase evidence of credential theft or unauthorized configuration changes.

When the access arrived through a traversal path, correlate by mechanism rather than by process: the same `../` technique appears in archive extraction, static-asset routes, and request format/extension handling, so a traversal detection in one component should prompt checking whether the same input source reaches others.

A traversal that *writes* to an identity file (e.g., `/etc/passwd`) should be escalated well above a traversal that reads one — the write establishes potential persistence and account creation, and should be correlated forward with privilege_escalation and with any subsequent authentication activity.

When viewed in sequence, sensitive file access alerts can provide clear insight into attacker intent and progression through the compromise lifecycle.