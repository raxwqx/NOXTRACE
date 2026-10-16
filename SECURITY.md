# Security Policy

## Intended scope

NOXTRACE is intended for defensive security education, local analysis, and authorized assessments. Active network features must only be used against owned systems or systems for which explicit permission exists.

## Out of scope

This project will not add DDoS/flooding functions, stealth/evasion techniques, credential guessing or theft, unauthorized persistence, exploit delivery, or automatic exploitation of vulnerabilities.

## Reporting an issue

Do not publish a sensitive exploit or real private target data in a public issue. Provide a minimal reproduction with secrets, tokens, personal data, and public target identifiers removed. Prefer a local lab example.

## Data handling

NOXTRACE has no telemetry or central report upload. Network behavior is limited to the selected module. Review the module description and generated report; DNS queries use the machine's configured resolver, the web audit sends one `HEAD` request, TLS inspection establishes a handshake, and TCP scanning attempts connections to the specified ports.
