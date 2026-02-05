Fact Sheet: kernel_module_load
Script Objective

This detection tracks the loading of Linux kernel modules (.ko files), a powerful and high-impact operation that directly modifies kernel behavior. Malicious kernel modules are a common mechanism for installing persistent kernel-level rootkits, enabling attackers to execute code in Ring 0 (kernel mode), the highest privilege level in the operating system.

Rootkits operating at this level can:

Fully bypass user-space security controls.

Intercept, modify, or suppress system calls and kernel events.

Hide processes, files, network connections, and even the module itself.

Disable or tamper with logging, monitoring, and security agents.

Establish long-term persistence that survives reboots and system updates.

The objective of this script is to detect both explicit and stealthy kernel module loading activity, highlighting deviations from expected system behavior that may indicate a compromise of the operating system’s core integrity.

Anomaly Patterns

Loading a kernel module using insmod, modprobe, or direct syscalls from an unusual or user-writable directory (such as /tmp, /var/tmp, /dev/shm, or application-specific paths).

Insertion of kernel modules that are unsigned or improperly signed on systems that enforce or support module signature verification.

Kernel module names that appear obfuscated, randomly generated, misleading, or intentionally similar to legitimate modules to evade notice.

Direct use of low-level syscalls such as finit_module or init_module by processes that are not standard system utilities or part of the normal boot and module management workflow.

Unexpected changes in kernel taint flags (observable via /proc/sys/kernel/tainted), which can indicate the loading of proprietary, out-of-tree, or potentially unsafe modules.

Evidence of anti-forensics behavior, such as the module being hidden from /proc/modules, lsmod, or other kernel introspection interfaces immediately after being loaded.

Rapid loading and unloading of modules, potentially indicating testing, probing, or evasion attempts.

Normal Patterns (Common False Positives)

Loading of legitimate kernel modules during system startup or service initialization, typically managed by modprobe and system configuration files.

Automatic driver loading triggered by the connection of new hardware devices (e.g., USB peripherals, network interfaces, or storage devices).

DKMS (Dynamic Kernel Module Support) workflows compiling and installing modules as part of kernel upgrades or software installations (such as VirtualBox, NVIDIA drivers, or other third-party kernel components).

Filesystem, network, or storage drivers being loaded when mounting disks or accessing filesystems that require additional kernel support.

Vendor-provided security or monitoring agents that rely on kernel modules for advanced visibility or enforcement.

Base Criticality Level

5 (Critical) – The unauthorized loading of a kernel module represents a complete compromise of the operating system’s trust boundary. Kernel-level rootkits undermine the integrity, confidentiality, and availability of the system and can render traditional detection and remediation tools ineffective. Any suspicious module load should be treated as a severe security incident requiring immediate containment and forensic analysis.

Suggested Correlation

Kernel module loading almost always requires root-level privileges or equivalent kernel capabilities. As a result, this detection is commonly preceded by alerts related to:

privilege_escalation, such as abuse of SUID binaries, kernel exploits, or misconfigured sudo permissions.

dangerous_syscalls, particularly those enabling kernel interaction or namespace manipulation.

Unusual process execution or file modification activity involving module binaries.

Following the module load, additional suspicious behavior may include:

log_tampering or suppression of audit events as the rootkit attempts to hide its presence.

Disabling or interfering with security agents and monitoring services.

Network anomalies, such as hidden backdoor listeners or covert communication channels.

When correlated with privilege escalation and stealth techniques, kernel module loading provides one of the highest-confidence indicators of a deeply compromised system.