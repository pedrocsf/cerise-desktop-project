Fact Sheet: memory_disclosure
Script Objective

This detection covers process memory disclosure through protocol-level implementation bugs (the CVE-2014-0160/"Heartbleed" class of heap over-read vulnerabilities), where a malformed request causes a service to return the contents of its own process memory instead of, or in addition to, the expected response.

Unlike file-based credential theft, this class extracts sensitive material (private keys, session tokens, passwords, other in-process secrets) directly from a running process's memory, over the network, without touching the filesystem and without spawning any child process. It therefore leaves no artifact for file-access or execution-based detections.

This detection is deliberately conservative about what host-level (syscall) telemetry can prove. When the vulnerable protocol is encrypted (TLS), a syscall trace observes only opaque byte counts in and out; the malicious heartbeat request and its oversized reply are not structurally distinguishable from ordinary encrypted traffic at that layer. Reliable identification requires protocol-level (TLS record) visibility. The objective here is to describe the true indicators, and equally to prevent misattribution of ordinary large transfers to this attack class.

Anomaly Patterns

At protocol/packet visibility (reliable): a TLS heartbeat request whose declared payload length is far larger than the payload actually sent, answered by a heartbeat response carrying that inflated length. This length mismatch is the definitive Heartbleed signature; the response body typically contains fragments of unrelated session data (other users' requests, cookies, key material) rather than protocol-appropriate content.

At protocol/packet visibility: repeated heartbeat records on the same or successive connections with no accompanying application-layer request/response exchange — the attacker looping the over-read to harvest successive regions of memory.

At host/syscall visibility (weak, corroborating only): an elevated rate of new connections to a TLS service that is not matched by a proportional increase in application-level request volume (e.g., access-log entries or content file reads). In the LID-DS-2019 Heartbleed scenario this signal is real but overlapping — attack recordings showed a higher median connection count than normal ones, with ranges that still overlap substantially, so it must never be treated as sufficient on its own.

Sensitive material appearing later in a context that no observed activity explains — for example, a successful authentication with a session token or credential that was never observed being created, read from disk, or transmitted in clear — is retrospective evidence that a memory-disclosure attack may have succeeded earlier.

Normal Patterns (Common False Positives)

Large responses at or near the maximum TLS record size (approximately 16 KB) are **normal**, not anomalous: any sizeable file download, image, media stream, or bulk API response is transmitted as a sequence of full-size records. Measured across the LID-DS-2019 Heartbleed scenario, benign recordings produced the same dominant response sizes, in comparable volumes, as attack recordings. Response size alone — including many repeated identical large sizes — must not be used to infer memory disclosure.

Bulk data export, backup, or streaming endpoints that intentionally transmit large payloads as part of documented functionality.

Load-testing or benchmarking activity that opens many connections and generates large responses in staging or test environments.

Connection bursts from legitimate clients such as connection pool warm-up, health checks, or a page load that opens several parallel connections for assets.

Base Criticality Level

5 (Critical) – A successful memory disclosure can leak private keys, session tokens, and credentials directly from server memory, compromising the confidentiality of the entire service, with no file or process artifact left behind. The criticality is high because of impact, but a verdict of THREAT for this category requires protocol-level evidence (the length mismatch described above); host-level indicators alone justify at most SUSPICIOUS.

Suggested Correlation

Frequently a standalone or reconnaissance-stage attack with no follow-on process activity in the same window — the attacker harvests memory contents for later offline analysis rather than acting immediately. The absence of subsequent suspicious_exec or sensitive_file_access activity does not lower the likelihood of this category.

If a later event shows a successful authentication or session reuse whose credentials cannot be traced to any observed sensitive_file_access or privilege_escalation event, an earlier memory_disclosure detection is a strong candidate explanation for the credential's origin.

Correlate with the version of the cryptographic library the service runs. Because host-level indicators for this class are weak, knowing that the service links a version affected by a published heap over-read CVE contributes more to the verdict than any single behavioural signal.

Distinguish carefully from network_suspicious: an elevated connection rate toward a TLS service with no application-layer request growth points here, whereas an elevated connection rate accompanied by repeated authentication attempts points to credential brute-forcing instead.
