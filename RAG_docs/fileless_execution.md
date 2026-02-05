Fact Sheet: fileless_execution
Script Objective

This detection identifies the use of the memfd_create system call, a modern Linux technique commonly leveraged for so-called “fileless” execution. With this approach, a program creates an anonymous, memory-backed file descriptor and writes an executable payload directly into memory, executing it without ever persisting the binary to disk.

Because the payload never exists as a traditional file on the filesystem, this technique can see bypasses of many legacy security controls, including file-based antivirus scanning, on-access malware detection, and integrity monitoring solutions. Fileless execution is frequently observed in advanced attacks, red team tooling, and post-exploitation frameworks aiming to reduce forensic artifacts and increase stealth.

The objective of this script is to detect unexpected or anomalous use of memfd_create and related execution patterns that indicate in-memory payload staging and execution.

Anomaly Patterns

Invocation of the memfd_create syscall by processes that do not normally require memory-backed executable files, such as web servers, application servers, office-style applications, cron jobs, or basic system utilities.

A process calling memfd_create that itself was launched from a suspicious or non-standard location (e.g., /tmp, /dev/shm, user-writable directories, or container volumes).

Subsequent execution via execve or fexecve pointing to /proc/self/fd/<fd> or /proc/<pid>/fd/<fd>, where the referenced file descriptor maps to an anonymous or memory-backed file.

Processes whose executable path (/proc/<pid>/exe) resolves to (deleted) or an unusual, ephemeral path indicative of in-memory or transient execution.

Short-lived processes that appear, execute, and exit rapidly without leaving a corresponding binary on disk.

Multiple stages of memfd_create usage in a short timeframe, suggesting loader or stager behavior.

Normal Patterns (Common False Positives)

Modern language runtimes and virtual machines (such as Go, Java, or JVM-based applications) that may use memfd_create internally for performance optimizations, JIT compilation, or sandboxing mechanisms.

Web browsers and browser sandboxes using memory-backed files for isolation, shared memory, or plugin execution.

Container runtimes and low-level components (such as runc, Docker, or CRI implementations) that use memfd_create for securely passing configuration data or sealing container state.

Audio and multimedia services (e.g., PulseAudio) using shared memory segments for efficient inter-process communication.

systemd and related init components using memfd_create for file descriptor passing, service activation, or secure temporary data handling.

Base Criticality Level

4 (High) – While memfd_create has legitimate and increasingly common uses in modern software, it remains a powerful evasion and stealth technique. Its presence in unexpected application contexts is a strong warning sign of malicious activity, particularly when combined with execution behavior that avoids the filesystem and traditional monitoring controls.

Suggested Correlation

Alerts for fileless execution should be analyzed in conjunction with related behavioral signals, as this technique is rarely used in isolation. Common correlations include:

network_suspicious events indicating payload download or command-and-control communication prior to in-memory execution.

suspicious_exec detections involving unusual process trees, abnormal parent-child relationships, or execution from network-facing services.

Parent processes that are shells, scripting engines, or exposed services (such as apache, nginx, or application servers) that should not normally spawn in-memory executables.

Evidence of lateral movement, credential access, or persistence attempts following the fileless payload execution.

When correlated with upstream access vectors and downstream impact indicators, memfd_create usage can provide high-confidence detection of advanced, stealth-focused intrusion activity.