Fact Sheet: privilege_escalation
Script Objective

This detection identifies attempts to escalate privileges on a Linux system, moving from a low-privileged user context to a higher-privileged one, most critically to root. Privilege escalation is a pivotal phase in most attacks, as it enables full control over the system, access to sensitive data, and the ability to disable security controls.

The script monitors:

Direct privilege-changing system calls such as setuid(), setgid(), setresuid(), and setresgid().

Use and abuse of privilege delegation tools like sudo and su.

Exploitation of SUID (Set User ID) binaries that run with elevated privileges.

Known kernel-level privilege escalation vulnerabilities (e.g., Dirty COW, Dirty Pipe, OverlayFS flaws), which allow attackers to bypass user-space restrictions entirely.

The objective is to detect both brute-force and stealthy privilege escalation techniques, whether they rely on misconfiguration, vulnerable software, or kernel exploitation.

Anomaly Patterns

A low-privilege process or service account (e.g., www-data, nobody, or an application-specific user) attempting to invoke setuid() or related syscalls to transition to root or another high-privilege user.

Multiple failed sudo authentication attempts followed by a successful one from the same terminal, session, or originating process, which may indicate password guessing or brute-force activity.

A child process gaining higher privileges, additional capabilities, or a different effective UID/GID than its parent process, violating expected privilege inheritance.

Abuse of ptrace by non-debugger processes to attach to or inject code into a privileged process, potentially hijacking its execution context.

Execution of known “GTFOBins” (legitimate binaries that can be abused to bypass local security controls) with sudo privileges or in contexts where elevated execution is unexpected.

Unexpected or unauthorized changes to Linux file capabilities using tools like setcap, especially granting powerful capabilities such as cap_sys_admin, cap_setuid, or cap_dac_override.

Exploit execution patterns associated with known local privilege escalation vulnerabilities, including abnormal memory access, rapid process crashes, or kernel warnings preceding a privilege change.

Normal Patterns (Common False Positives)

System administrators using sudo or su for legitimate maintenance, troubleshooting, or deployment tasks.

Legitimate SUID binaries (such as passwd, ping, or mount) operating as designed and within expected usage patterns.

System daemons that intentionally drop privileges after startup (e.g., starting as root and switching to a dedicated service user), which involves similar syscalls but represents the inverse of escalation.

Developers or operators using debugging and tracing tools such as gdb or strace in environments where such activity is expected and approved.

Configuration management or automation tools executing commands with elevated privileges as part of routine system management.

Base Criticality Level

5 (Critical) – A successful, unauthorized privilege escalation fundamentally breaks the system’s security model. Once elevated privileges are obtained, attackers can access all data, install persistent malware, tamper with logs, disable defenses, and pivot to other systems. Any confirmed malicious escalation attempt should be treated as a high-severity security incident.

Suggested Correlation

Privilege escalation is a central and highly informative event in an attack chain. Alerts should be correlated both backward and forward in time:

Often preceded by suspicious_exec or network_suspicious, such as downloading exploit code, exploit toolkits, or reconnaissance scripts.

Frequently followed by high-impact actions like sensitive_file_access, kernel_module_load, or log_tampering, indicating consolidation of control and attempts to hide activity.

May also precede persistence mechanisms, lateral movement, or container escape attempts in complex environments.

When combined with execution, network, and post-escalation behaviors, privilege escalation detections provide strong evidence of an active and advancing compromise.