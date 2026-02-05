Fact Sheet: suspicious_exec
Script Objective

This detection identifies the execution of processes from universally writable, temporary, or otherwise unusual filesystem locations, such as /tmp, /var/tmp, /dev/shm, or application upload directories. These paths are commonly writable by any user or service and are therefore frequently abused by attackers as staging areas for malicious payloads.

Attackers often drop scripts or compiled binaries into these locations because doing so does not require elevated privileges and avoids modifying protected system directories. Execution from these paths is a hallmark of initial access, post-exploitation tooling, and transient malware designed to minimize persistence and forensic artifacts.

The objective of this script is to detect execution patterns that deviate from normal software behavior and indicate the presence of attacker-delivered payloads.

Anomaly Patterns

Execution of any binary or script directly from globally writable directories such as /tmp, /var/tmp, or shared memory locations like /dev/shm.

A network-facing service (for example, a web server or application runtime) executing a process from its uploads or user-controlled content directory, which often indicates remote code execution exploitation.

Execution of hidden files (filenames starting with a dot) in these directories, such as /tmp/.X11-unix/<binary>, which may be used to conceal malicious payloads.

Invocation of interpreters (python, perl, bash, sh, php, etc.) to execute script files located in temporary or memory-backed directories.

Rapid file lifecycle behavior, where a file is created, executed, and deleted in quick succession, suggesting an attempt to evade detection and leave minimal forensic evidence.

Execution of binaries with random, meaningless, or automatically generated names that do not match known software patterns.

Normal Patterns (Common False Positives)

Legitimate software installation or update scripts that temporarily unpack files into /tmp or similar directories and execute helper binaries during setup.

Software development, testing, or compilation workflows that use temporary directories for build artifacts.

Package managers (such as apt, yum, or dnf) executing pre-installation or post-installation scripts as part of normal package lifecycle operations.

System utilities or maintenance tasks that rely on temporary execution as part of their internal logic.

Just-in-time (JIT) compilation mechanisms that create executable code dynamically, although modern implementations often use memory-backed execution (memfd_create) rather than filesystem paths.

Base Criticality Level

3 (Medium) – Execution from writable or temporary locations is a very common malware technique, but it also occurs in legitimate operational scenarios. The true severity depends heavily on the identity of the executing process, the origin of the file, and the surrounding behavioral context.

Suggested Correlation

This detection gains significant value when correlated with other indicators of compromise:

If combined with network_suspicious, it may indicate that a payload was downloaded and immediately executed.

If followed or preceded by privilege_escalation, it suggests the payload is being used to gain higher-level access.

Correlation with fileless_execution is particularly important when the executed file is deleted immediately after running, indicating a hybrid on-disk/in-memory evasion technique.

Additional context from sensitive_file_access or log_tampering can further confirm malicious intent.

When analyzed in combination with execution source, process lineage, and network behavior, suspicious execution provides early and actionable insight into active compromise.