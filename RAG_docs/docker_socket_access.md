Fact Sheet: docker_socket_access
Script Objective

This detection monitors access to the Docker daemon Unix socket (/var/run/docker.sock), a highly sensitive control interface that exposes full Docker API functionality. Any entity with read/write access to this socket can effectively control the Docker daemon, which typically runs with root privileges on the host system.

If this socket is exposed to or accessible from within a container, it enables a well-known and severe security risk commonly referred to as a “container escape.” Through the Docker API, an attacker can:

Start new privileged containers.

Mount arbitrary host directories into containers.

Execute commands on the host filesystem.

Read or modify sensitive host files.

Gain full root-level control of the host operating system.

The objective of this script is to detect unauthorized, unexpected, or risky access patterns to the Docker socket, particularly those originating from containerized workloads or unprivileged host processes.

Anomaly Patterns

Any process running inside a container attempting to open, read from, write to, or otherwise interact with /var/run/docker.sock.

Access attempts originating from application containers that are not explicitly designed for container orchestration or host management.

Use of the Docker socket by processes running as non-root or unprivileged users on the host.

Access initiated by binaries located in unusual paths (e.g., temporary directories, writable volumes, or application-specific folders).

Automated or scripted interaction with the Docker API that deviates from normal operational patterns, such as rapid container creation or execution requests.

Docker socket access shortly after exploitation of a containerized application, suggesting post-compromise escalation behavior.

Normal Patterns (Common False Positives)

Execution of the docker CLI or Docker Compose on the host by system administrators or automation tools.

Container management and orchestration components (such as Portainer, Kubernetes components like Kubelet, or CI/CD runners) that legitimately require Docker daemon access.

Monitoring, backup, or security agents installed on the host that interface with Docker for inventory, telemetry, or enforcement purposes.

Trusted administrative containers intentionally deployed with Docker socket access for operational tasks, such as node management or debugging.

Scheduled automation or infrastructure-as-code workflows that interact with Docker as part of normal system operations.

Base Criticality Level

5 (Critical) – Unauthorized access to the Docker socket represents a complete security boundary failure. A successful exploitation path using this interface is functionally equivalent to a privilege escalation to root on the host, allowing full system compromise, persistence, and lateral movement. Any confirmed misuse should be treated as an incident requiring immediate response.

Suggested Correlation

This detection is especially powerful when correlated with earlier-stage compromise indicators. It often represents a follow-on action after an attacker gains initial access to a containerized application. Correlate alerts with:

Application-level exploitation events within containers (e.g., RCE, deserialization flaws).

Abnormal process execution or file writes inside containers.

Privilege escalation attempts within the container prior to socket access.

Creation of new containers with elevated privileges or suspicious configurations.

Host-level changes following socket interaction, such as new services, cron jobs, or modified system binaries.

When combined with upstream compromise signals, Docker socket access provides a high-confidence indicator of active container escape attempts or successful host takeover.