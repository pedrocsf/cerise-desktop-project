Fact Sheet: network_suspicious
Script Objective

This detection monitors suspicious and anomalous network activity that may indicate active exploitation, remote control, or data exfiltration. A primary focus is identifying network connections initiated by processes that typically do not perform network communication, such as interactive shells or local system utilities.

Such activity is often associated with reverse shells, bind shells, or Command and Control (C2) communication, where an attacker establishes an outbound connection from a compromised system to maintain remote access. Attackers frequently leverage non-standard ports, uncommon protocols, or covert DNS-based techniques to evade traditional perimeter defenses.

A second focus is inbound abuse of authentication surfaces: automated credential guessing, connection floods against a service's login path, and other high-volume probing that is distinguishable from legitimate client behavior by its rate, its source concentration, and the artificial composition of the credentials attempted.

The objective of this script is to identify network behavior that deviates from the expected role of the initiating process, and inbound patterns that deviate from how real clients use a service — surfacing both live attacker interaction and automated attack tooling.

Anomaly Patterns

Interactive shell processes (bash, sh, zsh, or similar) initiating outbound TCP or UDP connections, which may indicate reverse shells or interactive backdoors.

Outbound connections to non-standard, uncommon, or high-risk ports (such as 4444, 1337, 5555, or randomly chosen high ports) by processes that are not expected to perform network communication.

Network activity initiated shortly after process execution events, particularly when the parent process is a shell, scripting engine, or network-facing service.

Repeated connection attempts to the same external IP address or domain, suggesting beaconing or persistent C2 communication.

DNS queries to domains known to be malicious, recently registered, algorithmically generated, or associated with threat actor infrastructure.

Use of raw sockets or unusual network protocols by user-space processes.

A burst of many new connections (tens within a window of milliseconds to a few seconds) from the same source address to the same privileged service port, each followed by a full protocol/authentication handshake — a signature of automated credential guessing or exploitation of a broken authentication check, distinct from normal client reconnect behavior.

Repeated HTTP requests to the same protected/authenticated endpoint from a single source, each carrying a different username drawn from a credential wordlist, occurring many times within the same one-second window — the signature of an automated HTTP Basic/Digest authentication brute-force tool. The wordlist composition is itself diagnostic: it mixes generic privileged account names (`admin`, `root`, `manager`, `user`, `system`, `sys`, `security`), network-appliance default accounts (`cisco`, `apc`, `sitecom`, `private`, `connect`), and development/stack defaults (`wampp`, `vagrant`, `newuser`, `pass`) — a spread no legitimate user population produces.

A source that repeatedly authenticates against a protected endpoint but never performs the operation that endpoint exists for — for example, issuing only `GET` requests against an upload or admin endpoint, dozens of times, while legitimate authenticated sessions from other sources actually `POST` to it. Authentication attempts decoupled from any real use of the resource indicate credential probing rather than usage.

All authentication attempts in the burst originating from a single source address, while legitimate authenticated activity in the same period comes from several different source addresses with per-session, non-generic account names.

Normal Patterns (Common False Positives)

Command-line network utilities such as curl, wget, ftp, or package managers making outbound connections as part of legitimate downloads or updates.

System administrators or automation scripts using tools like netcat, socat, or SSH for legitimate maintenance, testing, or troubleshooting tasks.

Monitoring, backup, or configuration management agents that periodically communicate with central servers.

Application processes that legitimately use non-standard ports as part of their documented operation.

Development or testing environments where experimental network activity is expected and approved.

Connection pool warm-up or health-check probes from a known application server, which open a bounded, small number of connections rather than an unbounded rapid burst, and do not repeatedly fail authentication.

A small number of distinct, non-generic (e.g., randomly generated or account-specific) usernames authenticating against a protected endpoint over the course of a normal session — as opposed to a wordlist of common administrative account names being cycled through rapidly by a single source.

Base Criticality Level

3 (Medium) – Network anomalies are highly context-dependent and require careful analysis of the initiating process, destination, timing, and surrounding activity. While suspicious connections can indicate active compromise, similar patterns may also occur during legitimate administrative or development tasks.

Suggested Correlation

This detection is most valuable when analyzed in sequence with other behavioral indicators. Strong confidence of malicious activity exists when:

An alert from suspicious_exec or fileless_execution is followed closely by suspicious network activity.

Network connections originate from processes spawned by exploited services or unexpected parent processes.

Suspicious network activity coincides with privilege escalation, credential access, or persistence mechanisms. A connection-burst pattern against a privileged service that culminates in one successful authentication followed by administrative commands should be escalated as privilege_escalation, not treated as network noise.

Network connections persist or reoccur despite process restarts or system reboots.

When correlated with execution and privilege signals, suspicious network activity often represents the moment an attacker transitions from exploitation to active control of the compromised system.