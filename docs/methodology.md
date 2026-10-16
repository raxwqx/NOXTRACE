# NOXTRACE methodology and limits

## Analysis categories

- **Local/static:** IP classification, URL parsing, domain syntax, indicator syntax, file hashing, password heuristics, source-code pattern review, Maven XML inventory, log-pattern matching, and classic-PCAP metadata inventory.
- **Resolver-based:** DNS lookups and an explicitly requested PTR lookup use the local system's configured resolver.
- **Active, bounded:** TCP connect scans, a single HTTP `HEAD` header audit, and a TLS handshake require the `--authorized` confirmation in the CLI.

## Evidence language

An open TCP port only proves that a TCP connection was accepted at the time of the check. A missing HTTP header is a configuration review item. A version string is not proof of a vulnerable build. Syntax classification and password entropy estimates are heuristics. Each report should be interpreted in its stated scope.

## Operational limits

The Python and Go TCP scanners limit each scan to 256 unique ports, cap worker concurrency, and use short configurable timeouts. Web header review performs one `HEAD` request and does not follow redirects. The TLS module validates certificates with the operating system/Python trust store and does not silently disable verification. The Rust engine reads classic PCAP files offline and does not support PCAPNG in this version.

## Privacy

No telemetry or upload service is implemented. Local reports can still contain hostnames, local machine metadata, file paths, or analyst notes. Inspect them before sharing. Password test values are not copied to report fields or echoed by the CLI.
