Fact Sheet: sql_injection
Script Objective

This detection identifies SQL injection attempts against a web application backed by a database, where request parameters that should carry simple scalar values (numeric IDs, short tokens) instead carry SQL syntax fragments, causing the application to pass attacker-controlled query logic through to the database engine.

The script focuses on the boundary crossing that defines this class of vulnerability: SQL-specific syntax (keywords, quotes, comment sequences, function calls) appearing inside an inbound application request, and that same syntax subsequently appearing in the raw query text executed by the database process. Automated SQL injection tools (such as sqlmap) additionally leave a distinctive behavioral signature: many requests in rapid succession, each systematically testing a different injection technique against the same parameter.

The objective of this script is to surface both successful and attempted SQL injection, particularly automated/tool-driven probing, before it results in data exfiltration or further compromise.

Anomaly Patterns

An HTTP (or other application-layer) request parameter containing SQL syntax elements — keywords such as SELECT, UNION, CASE WHEN, comment sequences (--, #), or unescaped quotes — where the application normally expects a simple scalar value (a number, a short identifier, a fixed enum). Note that these arrive URL-encoded on the wire (`%20` for space, `%27` for quote, `%3D` for `=`, `%3B` for `;`), so detection must account for encoded forms.

Many distinct requests to the same endpoint and parameter in rapid succession (tens of requests within seconds), each carrying a *different* injection technique against the same input — the signature of an automated SQL injection tool systematically probing techniques rather than a human submitting one query. The technique families to expect together in such a sweep:

- Boolean tautology pairs, submitting a true and a false comparison in sequence to compare responses (`AND 1=1` vs `AND 9653=9669`).
- Boolean-based blind extraction using conditional expressions (`CASE WHEN (8833=8833) THEN ... ELSE ... END`).
- Time-based blind extraction using delay functions (`SLEEP(5)`, `BENCHMARK(5000000,MD5(...))`, `WAITFOR DELAY`, `pg_sleep()`) — the mere presence of these function names in user-supplied input is anomalous regardless of whether the delay is separately observed.
- UNION-based extraction appending an attacker-controlled result set (`UNION ALL SELECT NULL,CONCAT(...)`).
- Stacked queries terminating the original statement and appending a second one (`;SELECT SLEEP(5)#`).
- Comment terminators (`--`, `#`, often followed by junk) used to truncate the remainder of the original query.
- Error-based extraction abusing functions that leak data through error messages (EXTRACTVALUE, UPDATEXML, GTID_SUBSET) — a well-known technique family that may appear in the same sweep.

Schema enumeration queries reaching the database process — notably reads against `information_schema` (`SELECT table_schema, table_name FROM information_schema.tables`) — issued by an application database account that normally only queries the application's own tables. This is a particularly reliable signal because it is observed at the query-execution layer, already decoded, so it does not depend on recognizing URL-encoded payloads on the HTTP side.

SQL syntax fragments appearing in the raw bytes read by the database process (e.g., mysqld, postgres) shortly after the same fragments appear in an inbound request to the application server that fronts it — direct evidence that unsanitized request content reached the query execution layer. The executed query text often shows the injection structurally, such as an application query ending in an attacker-supplied statement separator (`SELECT first_name, last_name FROM users WHERE user_id = '5478';`).

Data-exfiltration or file-write escalation attempts appended to an injection, such as `INTO OUTFILE`/`INTO DUMPFILE` (writing attacker-controlled content to the filesystem through the database) or invocation of database command-execution features — these convert a read-only data disclosure into code execution or persistence.

Normal Patterns (Common False Positives)

Request parameters whose values are simple scalars (numbers, short alphanumeric tokens) with no SQL keywords, quotes, or comment sequences, and no more than one query issued per user action.

Legitimate search, filter, or reporting features where a free-text field may incidentally contain SQL-like words in plain English (e.g., a user searching for the word "select") without full SQL syntax or structural injection patterns — content and structure matter more than the presence of a single keyword.

Database administration or ORM-generated queries containing complex SQL syntax as part of their normal, expected operation, issued by known administrative tools or the application's own data layer rather than derived from unsanitized end-user input.

Base Criticality Level

4 (High) – Successful SQL injection can expose or modify the entire contents of a database, including credentials and sensitive business data, and frequently serves as the entry point for further compromise (credential theft, privilege escalation, or in some database configurations, command execution). Even unsuccessful, automated probing indicates active reconnaissance/exploitation attempts against the application.

Suggested Correlation

Often followed by evidence of data exfiltration matching a sensitive_file_access-style pattern (extraction of credential or user tables) once an injection technique succeeds.

If extracted credentials are subsequently used to authenticate elsewhere, correlate with privilege_escalation — a successful SQL injection followed by a new, previously-unseen successful login is a strong compromise indicator.

May co-occur with a network_suspicious connection-burst pattern when injection testing is part of a broader automated scanning campaign against multiple parameters or endpoints.

In database configurations that support command execution or file write features (e.g., `INTO OUTFILE`, `xp_cmdshell`), a successful injection may be followed by suspicious_exec or fileless_execution activity as the attacker escalates from data access to code execution.
