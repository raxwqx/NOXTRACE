# Changelog

## 5.0.0 - 2026-11-15

- Added `--fail-on-findings` for automation that needs a non-zero result when findings are present.
- OSV checks now reject unsupported ecosystems and safely skip malformed advisory records.
- Updated package and report version to 5.0.0.


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
