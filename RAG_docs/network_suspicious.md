Fact Sheet: network_suspicious
Script Objective

This detection monitors suspicious and anomalous network activity that may indicate active exploitation, remote control, or data exfiltration. A primary focus is identifying network connections initiated by processes that typically do not perform network communication, such as interactive shells or local system utilities.

Such activity is often associated with reverse shells, bind shells, or Command and Control (C2) communication, where an attacker establishes an outbound connection from a compromised system to maintain remote access. Attackers frequently leverage non-standard ports, uncommon protocols, or covert DNS-based techniques to evade traditional perimeter defenses.

The objective of this script is to identify network behavior that deviates from the expected role of the initiating process and to surface potential signs of live attacker interaction or malware communication.

Anomaly Patterns

Interactive shell processes (bash, sh, zsh, or similar) initiating outbound TCP or UDP connections, which may indicate reverse shells or interactive backdoors.

Outbound connections to non-standard, uncommon, or high-risk ports (such as 4444, 1337, 5555, or randomly chosen high ports) by processes that are not expected to perform network communication.

Network activity initiated shortly after process execution events, particularly when the parent process is a shell, scripting engine, or network-facing service.

Repeated connection attempts to the same external IP address or domain, suggesting beaconing or persistent C2 communication.

DNS queries to domains known to be malicious, recently registered, algorithmically generated, or associated with threat actor infrastructure.

Use of raw sockets or unusual network protocols by user-space processes.

Normal Patterns (Common False Positives)

Command-line network utilities such as curl, wget, ftp, or package managers making outbound connections as part of legitimate downloads or updates.

System administrators or automation scripts using tools like netcat, socat, or SSH for legitimate maintenance, testing, or troubleshooting tasks.

Monitoring, backup, or configuration management agents that periodically communicate with central servers.

Application processes that legitimately use non-standard ports as part of their documented operation.

Development or testing environments where experimental network activity is expected and approved.

Base Criticality Level

3 (Medium) – Network anomalies are highly context-dependent and require careful analysis of the initiating process, destination, timing, and surrounding activity. While suspicious connections can indicate active compromise, similar patterns may also occur during legitimate administrative or development tasks.

Suggested Correlation

This detection is most valuable when analyzed in sequence with other behavioral indicators. Strong confidence of malicious activity exists when:

An alert from suspicious_exec or fileless_execution is followed closely by suspicious network activity.

Network connections originate from processes spawned by exploited services or unexpected parent processes.

Suspicious network activity coincides with privilege escalation, credential access, or persistence mechanisms.

Network connections persist or reoccur despite process restarts or system reboots.

When correlated with execution and privilege signals, suspicious network activity often represents the moment an attacker transitions from exploitation to active control of the compromised system.