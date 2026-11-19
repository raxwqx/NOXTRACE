# Changelog

## 0.2.0 - 2026-11-19

### Added

- `--fail-on-findings` for every report-producing command. When the report contains findings the process exits with code `3`; command errors return `2`; a completed report without findings returns `0`. The flag works together with `--json`, `--output`, and `--html`.
- Turkish and English documentation for automation exit codes and the new hardening behavior.

### Fixed

- DNS and domain normalization now accept exactly one trailing dot and reject repeated trailing dots instead of silently trimming them.
- PTR lookups require an IP address. A hostname PTR request now receives an explicit note, and resolver failures are handled without crashing.
- Unresolvable `~user` paths and embedded NUL bytes in file, log, Maven, and source-audit paths return an error report instead of raising an exception.
- JSON and HTML reports are written atomically; invalid or unwritable destinations return a clear error and exit code `2`.
- DNS names, domains, URLs, scan targets, TLS hosts, and OSV coordinates containing whitespace or terminal control characters are rejected before use.
- URL reports now use normalized IDNA and trailing-dot hostnames. Malformed percent escapes and backslashes are flagged.
- `web-audit` rejects control characters before building a request, avoiding an unhandled `InvalidURL` exception.
- `log --max-lines` rejects zero, negative, and non-integer limits.
- `pom-audit` enforces a 5 MB file-size cap and handles NUL/parse errors cleanly.
- OSV checks reject unsupported ecosystems before any network request, skip malformed advisory rows, count them in the report, and validate alias/severity shapes.
- TLS inspection handles a missing peer certificate object without crashing.
- Local resolver addresses are sorted numerically with IPv4 before IPv6.
- Case notes enforce length limits and reject terminal control characters while still allowing line breaks and tabs in observations.
- Terminal output strips ANSI and control sequences from untrusted report values.
- CLI scan port-parse errors now produce a complete report envelope with `tool`, `version`, and `timestamp_utc`.

### Changed

- Python CI now runs on Ubuntu, Windows, and macOS across Python 3.10-3.13. The Go, Rust, C, and Java smoke jobs are retained.
- The README, English guide, methodology, operations notes, and security policy were updated for the new feature and fixes.

## 0.1.1 - 2026-10-16

- Reworked the main README as a detailed Turkish onboarding guide and kept the English guide in `README_EN.md`.
- Added terminal captures for the interactive menu, local IP classification, and bounded loopback port check.
- Expanded installation, troubleshooting, command examples, optional engine requirements, and safety explanations.
- Added the README screenshot assets under `assets/screenshots/`.

- Added an original animated cyber-fox/skull startup GIF and a matching offline truecolor terminal animation.
- Added `--no-intro` and `NOXTRACE_NO_INTRO=1` controls to skip the splash.
- Included pre-rendered terminal frames so startup animation requires no image library or internet access.
- Added tests for bundled animation assets and the skip flag.

## 0.1.0 - 2026-10-16

- Initial public-ready NOXTRACE workbench scaffold.
- Added Python CLI, numbered dark-terminal UI, JSON/HTML reporting, DNS/IP/domain/URL, bounded TCP scanning, web header and TLS review, file fingerprinting, log triage, source-pattern audit, Maven dependency inventory, IOC classification, local password heuristic, and case notes.
- Added optional Go, Rust, C, Java, and Bash engines.
- Added offline Python unit tests and GitHub Actions workflows.
