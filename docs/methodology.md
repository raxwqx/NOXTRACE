# NOXTRACE methodology and limits

## Analysis categories

- **Local/static:** IP classification, URL parsing, domain syntax, indicator syntax, file hashing, password heuristics, source-code pattern review, Maven XML inventory, log-pattern matching, and classic-PCAP metadata inventory.
- **Resolver-based:** DNS lookups and an explicitly requested PTR lookup use the local system's configured resolver.
- **Active, bounded:** TCP connect scans, a single HTTP `HEAD` header audit, and a TLS handshake require the `--authorized` confirmation in the CLI.

## Input normalization and validation

- Hostnames and domains accept exactly one trailing dot for compatibility with fully qualified names. Multiple trailing dots are rejected rather than silently trimmed.
- Internationalized hostnames are normalized to their IDNA ASCII form for domains and URL reports.
- DNS, domain, URL, scan, TLS, and OSV inputs are rejected when they contain whitespace or terminal control characters. This prevents untrusted text from injecting terminal escape sequences or malformed network requests.
- PTR lookup requires an IP address. Requesting PTR for a hostname produces an explanatory note instead of an invalid reverse lookup.
- File, log, Maven, and source-audit paths are expanded safely. Unresolvable `~user` paths and embedded NUL bytes return an error report instead of raising an exception.
- Maven XML is capped at 5 MB, log triage requires a positive line limit, and source review is bounded by file and byte limits.
- OSV ecosystems are validated before a request is sent. Malformed advisory rows are skipped, counted, and excluded from the parsed advisory list.

## Evidence language

An open TCP port only proves that a TCP connection was accepted at the time of the check. A missing HTTP header is a configuration review item. A version string is not proof of a vulnerable build. Syntax classification and password entropy estimates are heuristics. Each report should be interpreted in its stated scope.

## Automation exit status

Report-producing commands return `0` when the command completed without findings, `2` when the command could not complete or a report could not be written, and `3` when `--fail-on-findings` was supplied and the report contains findings. Exit code `2` takes precedence over `3`. A finding remains a review lead; automation should attach the report for human review rather than treating a non-zero code as proof of exploitability.

## Operational limits

The Python and Go TCP scanners limit each scan to 256 unique ports, cap worker concurrency, and use short configurable timeouts. Web header review performs one `HEAD` request and does not follow redirects. The TLS module validates certificates with the operating system/Python trust store and does not silently disable verification. The Rust engine reads classic PCAP files offline and does not support PCAPNG in this version.

## Reports

JSON and HTML reports are written atomically through a temporary file in the destination directory, so an interrupted write does not truncate an existing report. Human-readable output strips ANSI and terminal control sequences from untrusted report fields. Reports can still contain target hostnames, paths, local metadata, or analyst notes; review them before sharing.

## Privacy

No telemetry or upload service is implemented. Local reports can still contain hostnames, local machine metadata, file paths, or analyst notes. Inspect them before sharing. Password test values are not copied to report fields or echoed by the CLI.
