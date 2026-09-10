Fact Sheet: suspicious_exec
Script Objective

This detection identifies the execution of processes from universally writable, temporary, or otherwise unusual filesystem locations, such as /tmp, /var/tmp, /dev/shm, or application upload directories. These paths are commonly writable by any user or service and are therefore frequently abused by attackers as staging areas for malicious payloads.

Attackers often drop scripts or compiled binaries into these locations because doing so does not require elevated privileges and avoids modifying protected system directories. Execution from these paths is a hallmark of initial access, post-exploitation tooling, and transient malware designed to minimize persistence and forensic artifacts.

Beyond execution from suspicious locations, this detection also covers execution that is *triggered through content* rather than through a dropped binary: a web shell uploaded into an application's content directory and then invoked by an HTTP request, or a crafted document/image whose embedded script is executed by the very tool that parses it. In these cases the payload never needs an unusual filesystem path — what betrays it is the process tree, where a service or converter becomes the parent of a shell interpreter.

The objective of this script is to detect execution patterns that deviate from normal software behavior and indicate the presence of attacker-delivered payloads, whether delivered as a file on disk or as content processed by a trusted program.

Anomaly Patterns

Execution of any binary or script directly from globally writable directories such as /tmp, /var/tmp, or shared memory locations like /dev/shm.

A network-facing service (for example, a web server or application runtime) executing a process from its uploads or user-controlled content directory, which often indicates remote code execution exploitation.

Execution of hidden files (filenames starting with a dot) in these directories, such as /tmp/.X11-unix/<binary>, which may be used to conceal malicious payloads.

Invocation of interpreters (python, perl, bash, sh, php, etc.) to execute script files located in temporary or memory-backed directories.

Rapid file lifecycle behavior, where a file is created, executed, and deleted in quick succession, suggesting an attempt to evade detection and leave minimal forensic evidence.

Execution of binaries with random, meaningless, or automatically generated names that do not match known software patterns.

A file created in a private temporary location (e.g., `/tmp/phpXXXXXX`, matching a web framework's default upload staging pattern) being renamed/moved into a directory served directly by the web application (e.g., an uploads or media folder), followed shortly after by a `chmod` on that same path — a strong indicator that an uploaded file just crossed from a non-executable staging area into a web-reachable, potentially executable location.

A web server process directly spawning a shell (`sh -c '<command>'`) that runs reconnaissance commands (`id`, `uname`, `whoami`) or fetches additional tooling (`wget`, `curl`), with the shell's parent process being the web server itself rather than a legitimate admin session — the signature of a web shell dropped via file upload being invoked through an HTTP request.

A document or media processing utility (image converter, PostScript/PDF interpreter, archive extractor) spawning a shell interpreter as a child process while converting or rendering a user-supplied file, especially when running with elevated privileges (e.g., uid 0). This indicates the input file's content was crafted to exploit the interpreter's own embedded scripting capability rather than a legitimate rendering operation — the file itself is the exploit delivery mechanism, not merely its filename or extension. The decisive observation is the process tree: the converter becoming a parent of `sh`/`bash`, which legitimate conversion never requires.

Regarding unsafe interpreter flags (e.g., Ghostscript invoked with `-dWRITESYSTEMDICT` or `-dDELAYBIND`, which weaken its sandbox): treat these as an *enabling condition*, not as evidence of attack. Conversion pipelines routinely pass such flags on every invocation, benign or not, so their presence alone must not raise a verdict. They raise the prior probability that a malicious input file can succeed; the attack is evidenced by what the interpreter then does.

Normal Patterns (Common False Positives)

Legitimate software installation or update scripts that temporarily unpack files into /tmp or similar directories and execute helper binaries during setup.

Software development, testing, or compilation workflows that use temporary directories for build artifacts.

Package managers (such as apt, yum, or dnf) executing pre-installation or post-installation scripts as part of normal package lifecycle operations.

System utilities or maintenance tasks that rely on temporary execution as part of their internal logic.

Just-in-time (JIT) compilation mechanisms that create executable code dynamically, although modern implementations often use memory-backed execution (memfd_create) rather than filesystem paths.

Normal request handling by a web server or application runtime, which reads/writes files and serves content but does not itself spawn shell interpreters as child processes — a web server process forking `sh`/`bash` is inherently rare in legitimate operation, unlike, e.g., CGI scripts explicitly designed to do so.

Document/media conversion tools (image converters, PDF renderers, format converters) reading, parsing, and writing files as part of their normal pipeline, without ever spawning a shell interpreter as a child process — legitimate conversion work stays within the tool's own process tree.

Base Criticality Level

3 (Medium) – Execution from writable or temporary locations is a very common malware technique, but it also occurs in legitimate operational scenarios. The true severity depends heavily on the identity of the executing process, the origin of the file, and the surrounding behavioral context.

Suggested Correlation

This detection gains significant value when correlated with other indicators of compromise:

If combined with network_suspicious, it may indicate that a payload was downloaded and immediately executed.

If followed or preceded by privilege_escalation, it suggests the payload is being used to gain higher-level access.

Correlation with fileless_execution is particularly important when the executed file is deleted immediately after running, indicating a hybrid on-disk/in-memory evasion technique.

Additional context from sensitive_file_access or log_tampering can further confirm malicious intent.

When the executing payload arrived through an upload, correlate backward to the request that delivered it: a file written to a staging path, moved into a served directory, and then executed within seconds is a single causal chain, not three independent findings. The reverse also holds — an upload without any subsequent execution is far weaker evidence and may be entirely legitimate.

When the execution came from a document/media interpreter, correlate with sql_injection and sensitive_file_access rather than with file-drop indicators: these attacks deliver code inside data, so there is often no anomalous file path anywhere in the chain.

When analyzed in combination with execution source, process lineage, and network behavior, suspicious execution provides early and actionable insight into active compromise.