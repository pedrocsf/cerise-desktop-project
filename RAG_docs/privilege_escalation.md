Fact Sheet: privilege_escalation
Script Objective

This detection identifies attempts to escalate privileges on a Linux system, moving from a low-privileged user context to a higher-privileged one, most critically to root. Privilege escalation is a pivotal phase in most attacks, as it enables full control over the system, access to sensitive data, and the ability to disable security controls.

The script monitors:

Direct privilege-changing system calls such as setuid(), setgid(), setresuid(), and setresgid().

Use and abuse of privilege delegation tools like sudo and su.

Exploitation of SUID (Set User ID) binaries that run with elevated privileges.

Known kernel-level privilege escalation vulnerabilities (e.g., Dirty COW, Dirty Pipe, OverlayFS flaws), which allow attackers to bypass user-space restrictions entirely.

Authentication bypasses at the service level, where a flawed credential check (for example a comparison that can return a false match) lets an attacker obtain a privileged account on a network service — such as a database administrator account — without ever possessing the correct credential. The privilege gained is application-level rather than OS-level, but the security consequence is equivalent within that service's scope.

The objective is to detect both brute-force and stealthy privilege escalation techniques, whether they rely on misconfiguration, vulnerable software, kernel exploitation, or broken authentication logic.

Anomaly Patterns

A low-privilege process or service account (e.g., www-data, nobody, or an application-specific user) attempting to invoke setuid() or related syscalls to transition to root or another high-privilege user.

Multiple failed sudo authentication attempts followed by a successful one from the same terminal, session, or originating process, which may indicate password guessing or brute-force activity.

A child process gaining higher privileges, additional capabilities, or a different effective UID/GID than its parent process, violating expected privilege inheritance.

Abuse of ptrace by non-debugger processes to attach to or inject code into a privileged process, potentially hijacking its execution context.

Execution of known “GTFOBins” (legitimate binaries that can be abused to bypass local security controls) with sudo privileges or in contexts where elevated execution is unexpected.

Unexpected or unauthorized changes to Linux file capabilities using tools like setcap, especially granting powerful capabilities such as cap_sys_admin, cap_setuid, or cap_dac_override.

Exploit execution patterns associated with known local privilege escalation vulnerabilities, including abnormal memory access, rapid process crashes, or kernel warnings preceding a privilege change.

A burst of dozens to hundreds of authentication failures against the same privileged network service (e.g., a database daemon) in a very short window, all for the same high-privilege account (e.g., `root`) from the same source, followed — with no change in the credential material presented — by one attempt in that same burst succeeding. The discriminating element is this failure-burst-then-success sequence: it indicates exploitation of a broken or probabilistic credential comparison (a check that can return a false match) rather than a correct password finally being supplied.

Note that the administrative commands issued after such a success (schema creation, configuration changes) are **not** themselves the signal — a legitimate application may run schema setup or migrations against the same service as part of normal startup. Those commands establish the *impact* of the bypass; the preceding authentication-failure burst is what establishes that a bypass occurred.

Normal Patterns (Common False Positives)

System administrators using sudo or su for legitimate maintenance, troubleshooting, or deployment tasks.

Legitimate SUID binaries (such as passwd, ping, or mount) operating as designed and within expected usage patterns.

System daemons that intentionally drop privileges after startup (e.g., starting as root and switching to a dedicated service user), which involves similar syscalls but represents the inverse of escalation.

Developers or operators using debugging and tracing tools such as gdb or strace in environments where such activity is expected and approved.

Configuration management or automation tools executing commands with elevated privileges as part of routine system management.

Applications maintaining a connection pool to a database or backend service: a handful of long-lived connections handling many sequential queries, without repeated connect/authenticate cycles or authentication failures.

An application performing privileged schema or configuration operations (creating databases/tables, running migrations, seeding data) against its backend as part of normal startup or deployment. Such commands are routine in healthy systems and carry no implication of escalation on their own — what matters is whether the session that issued them was established normally or after a burst of failed authentications.

Base Criticality Level

5 (Critical) – A successful, unauthorized privilege escalation fundamentally breaks the system’s security model. Once elevated privileges are obtained, attackers can access all data, install persistent malware, tamper with logs, disable defenses, and pivot to other systems. Any confirmed malicious escalation attempt should be treated as a high-severity security incident.

Suggested Correlation

Privilege escalation is a central and highly informative event in an attack chain. Alerts should be correlated both backward and forward in time:

Often preceded by suspicious_exec or network_suspicious, such as downloading exploit code, exploit toolkits, or reconnaissance scripts. A connection-burst pattern from network_suspicious against the same privileged service immediately preceding a successful authentication is a particularly strong precursor signal for this category.

Frequently followed by high-impact actions like sensitive_file_access, kernel_module_load, or log_tampering, indicating consolidation of control and attempts to hide activity.

May also precede persistence mechanisms, lateral movement, or container escape attempts in complex environments.

When combined with execution, network, and post-escalation behaviors, privilege escalation detections provide strong evidence of an active and advancing compromise.