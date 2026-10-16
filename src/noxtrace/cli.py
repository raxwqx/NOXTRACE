"""NOXTRACE command-line interface and interactive menu."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence

from noxtrace import __version__
from noxtrace.modules.casenote import create_case_note
from noxtrace.modules.codeaudit import audit_source
from noxtrace.modules.dnsintel import analyze_dns
from noxtrace.modules.domain import analyze_domain
from noxtrace.modules.filehash import analyze_file
from noxtrace.modules.ioc import classify_ioc
from noxtrace.modules.ipintel import analyze_ip
from noxtrace.modules.localinfo import collect_local_info
from noxtrace.modules.logtriage import triage_log
from noxtrace.modules.passwordaudit import audit_password
from noxtrace.modules.pomaudit import audit_pom
from noxtrace.modules.osvcheck import check_osv, SUPPORTED_ECOSYSTEMS
from noxtrace.modules.portscan import parse_ports, scan_tcp
from noxtrace.modules.tlscheck import inspect_tls
from noxtrace.modules.urlintel import analyze_url
from noxtrace.modules.webaudit import audit_url
from noxtrace.reporting import json_text, write_html, write_json
from noxtrace.ui import P, banner, print_report, prompt_authorization


def project_root() -> Path:
    env = os.environ.get("NOXTRACE_ROOT")
    if env and (Path(env) / "engines").is_dir():
        return Path(env).resolve()
    return Path(__file__).resolve().parents[2]


def add_report_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="print result as JSON")
    parser.add_argument("--output", metavar="PATH", help="save a JSON copy to PATH")
    parser.add_argument("--html", metavar="PATH", help="save a self-contained HTML report to PATH")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="noxtrace",
        description="NOXTRACE: dark-themed, modular defensive security workbench.",
        epilog="Only scan or audit systems you own or are explicitly authorized to test.",
    )
    parser.add_argument("--version", action="version", version=f"NOXTRACE {__version__}")
    parser.add_argument("--no-intro", action="store_true", help="skip the animated startup splash")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("ip", help="classify an IP address locally")
    p.add_argument("address"); p.add_argument("--ptr", action="store_true", help="request a reverse DNS/PTR lookup")
    add_report_options(p)

    p = sub.add_parser("dns", help="query DNS records via the configured resolver")
    p.add_argument("hostname"); p.add_argument("--types", nargs="+", default=["A", "AAAA", "MX", "NS", "TXT"], help="record types: A AAAA MX NS TXT CNAME PTR")
    add_report_options(p)

    p = sub.add_parser("domain", help="validate domain syntax offline")
    p.add_argument("hostname"); add_report_options(p)
    p = sub.add_parser("url", help="inspect URL syntax without opening it")
    p.add_argument("url"); add_report_options(p)

    p = sub.add_parser("scan", help="bounded TCP connect scan (authorized targets only)")
    p.add_argument("target"); p.add_argument("--ports", default=None, help="comma list/ranges, e.g. 22,80,443,8000-8010 (max 256)")
    p.add_argument("--timeout", type=float, default=0.4, help="per-port timeout, 0.05-3 seconds")
    p.add_argument("--authorized", action="store_true", required=True, help="confirm ownership or explicit permission")
    add_report_options(p)

    p = sub.add_parser("web-audit", help="single HEAD-request security-header review")
    p.add_argument("url"); p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--authorized", action="store_true", required=True, help="confirm ownership or explicit permission")
    add_report_options(p)

    p = sub.add_parser("tls", help="validate a TLS certificate and report negotiated version")
    p.add_argument("host"); p.add_argument("--port", type=int, default=443); p.add_argument("--timeout", type=float, default=4.0)
    p.add_argument("--authorized", action="store_true", required=True, help="confirm ownership or explicit permission")
    add_report_options(p)

    p = sub.add_parser("hash", help="fingerprint a local file")
    p.add_argument("path"); add_report_options(p)
    p = sub.add_parser("log", help="triage a local log file with privacy-aware rule matches")
    p.add_argument("path"); p.add_argument("--max-lines", type=int, default=200000); add_report_options(p)
    p = sub.add_parser("code-audit", help="review source code for risky patterns offline")
    p.add_argument("path"); p.add_argument("--max-files", type=int, default=5000); add_report_options(p)
    p = sub.add_parser("pom-audit", help="review a local Java/Maven pom.xml offline")
    p.add_argument("path"); add_report_options(p)
    p = sub.add_parser("osv-check", help="query public OSV data for one package/version (online opt-in)")
    p.add_argument("package"); p.add_argument("version"); p.add_argument("--ecosystem", choices=SUPPORTED_ECOSYSTEMS, default="PyPI")
    p.add_argument("--online", action="store_true", required=True, help="explicitly allow sending package coordinates to OSV.dev")
    add_report_options(p)
    p = sub.add_parser("local-info", help="show local host and Python runtime metadata")
    add_report_options(p)
    p = sub.add_parser("ioc", help="classify an IP, domain, URL, or hash syntax locally")
    p.add_argument("value"); add_report_options(p)
    p = sub.add_parser("password-audit", help="estimate a test password's strength locally")
    p.add_argument("value", nargs="?", help="optional test phrase; omit to enter it without terminal echo")
    add_report_options(p)
    p = sub.add_parser("case-note", help="create a structured observation report")
    p.add_argument("case_name"); p.add_argument("observation", nargs="+"); add_report_options(p)
    sub.add_parser("engines", help="show available polyglot engine sources and local compilers")
    p = sub.add_parser("engine", help="run an optional Go/Rust/C/Java/Bash engine")
    engine_sub = p.add_subparsers(dest="engine_command", required=True)
    g = engine_sub.add_parser("go-scan", help="run the Go bounded TCP scanner")
    g.add_argument("target"); g.add_argument("ports", help="e.g. 22,80,443")
    g.add_argument("--authorized", action="store_true", required=True)
    g.add_argument("--timeout", default="500ms", help="Go duration, e.g. 500ms; allowed 100ms-3s")
    r = engine_sub.add_parser("rust-pcap", help="inspect classic PCAP metadata offline with Rust")
    r.add_argument("path")
    engine_sub.add_parser("c-system", help="run the C local system snapshot")
    j = engine_sub.add_parser("java-pom", help="run the Java offline Maven inventory")
    j.add_argument("path")
    engine_sub.add_parser("bash-check", help="check local lab tool availability using Bash")
    sub.add_parser("about", help="show scope and safety philosophy")
    return parser


def display_report(report: dict, args: argparse.Namespace) -> int:
    if getattr(args, "output", None):
        path = write_json(report, args.output)
        print(f"JSON saved to {path}", file=sys.stderr if getattr(args, "json", False) else sys.stdout)
    if getattr(args, "html", None):
        path = write_html(report, args.html)
        print(f"HTML saved to {path}", file=sys.stderr if getattr(args, "json", False) else sys.stdout)
    if getattr(args, "json", False):
        print(json_text(report))
    else:
        print_report(report)
    return 2 if report.get("status") == "error" else 0


def engine_status() -> dict:
    root = project_root()
    commands = {
        "Python": ("python3", "Main CLI and analysis modules"),
        "Go": ("go", "Optional bounded TCP scanner"),
        "Rust": ("cargo", "Optional offline classic-PCAP metadata engine"),
        "C": ("cc", "Optional local system snapshot"),
        "Java": ("java", "Optional offline Maven dependency inventory; Java 11+ recommended"),
        "Bash": ("bash", "Local lab readiness script"),
    }
    rows = []
    for name, (command, purpose) in commands.items():
        exe = shutil.which(command)
        if name == "Bash":
            present = (root / "engines/bash/lab-check.sh").is_file() and bool(exe)
        elif name == "Python":
            present = bool(exe)
        else:
            present = bool(exe)
        rows.append({"language": name, "available": present, "command": exe or "not installed", "purpose": purpose})
    compiled = {"go_binary": (root / "engines/go/noxtrace-go").exists(), "c_binary": (root / "engines/c/noxtrace-c").exists()}
    return {"tool": "NOXTRACE", "engine_sources": rows, "compiled_binaries": compiled, "note": "Python is the main CLI. Other engines are optional and are built only when requested."}


def _run_engine(args: argparse.Namespace) -> int:
    root = project_root()
    command = args.engine_command
    if command == "bash-check":
        return subprocess.run(["bash", str(root / "engines/bash/lab-check.sh")], cwd=root, check=False).returncode
    if command == "go-scan":
        engine_dir = root / "engines/go"
        binary = engine_dir / "noxtrace-go"
        if not binary.exists():
            go = shutil.which("go")
            if not go:
                print("Go is not installed. Install Go or use the Python 'scan' command.", file=sys.stderr); return 2
            result = subprocess.run([go, "build", "-o", str(binary), "."], cwd=engine_dir, check=False)
            if result.returncode:
                return result.returncode
        cmd = [str(binary), "scan", "--authorized", "--timeout", args.timeout, args.target, args.ports]
        return subprocess.run(cmd, cwd=root, check=False).returncode
    if command == "rust-pcap":
        cargo = shutil.which("cargo")
        if not cargo:
            print("Rust/Cargo not found. Install the Rust toolchain to use this optional engine.", file=sys.stderr); return 2
        return subprocess.run([cargo, "run", "--quiet", "--manifest-path", str(root / "engines/rust/Cargo.toml"), "--", "pcap", args.path], cwd=root, check=False).returncode
    if command == "c-system":
        source = root / "engines/c/system_audit.c"
        binary = root / "engines/c/noxtrace-c"
        cc = shutil.which("cc")
        if not cc:
            print("C compiler not found.", file=sys.stderr); return 2
        result = subprocess.run([cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(binary)], cwd=root, check=False)
        if result.returncode:
            return result.returncode
        return subprocess.run([str(binary)], cwd=root, check=False).returncode
    if command == "java-pom":
        java = shutil.which("java")
        if not java:
            print("Java runtime/JDK not found.", file=sys.stderr); return 2
        return subprocess.run([java, str(root / "engines/java/NoxtracePomAudit.java"), args.path], cwd=root, check=False).returncode
    print(f"Unknown engine: {command}", file=sys.stderr)
    return 2


def _interactive() -> int:
    if not sys.stdin.isatty():
        build_parser().print_help(); return 0
    while True:
        banner()
        options = [
            "IP intelligence", "DNS record lookup", "Domain syntax check", "URL syntax check",
            "TCP port scan (authorized target only)", "Web security headers (single HEAD request)",
            "TLS certificate inspection", "File fingerprint", "Local log triage",
            "Source-code pattern audit", "Java/Maven dependency inventory", "IOC syntax classifier", "Password test-value audit",
            "Local system information", "Case note", "OSV known-vulnerability lookup (online)", "Polyglot engine status", "Exit",
        ]
        for idx, label in enumerate(options, 1):
            print(f"  {P.blue}[{idx:02d}]{P.reset} {label}")
        try:
            choice = input(f"\n  {P.white}noxtrace > {P.reset}").strip()
            if choice in {"18", "0", "q", "quit", "exit"}:
                print("\n  Trace responsibly. Stay curious.\n"); return 0
            if choice == "1":
                report = analyze_ip(input("  IP: ").strip(), input("  Request PTR lookup? [y/N]: ").strip().lower() == "y")
            elif choice == "2":
                host = input("  Hostname: ").strip(); types = input("  Types [A AAAA MX NS TXT]: ").strip().split() or ["A", "AAAA", "MX", "NS", "TXT"]
                report = analyze_dns(host, types)
            elif choice == "3": report = analyze_domain(input("  Domain: ").strip())
            elif choice == "4": report = analyze_url(input("  URL: ").strip())
            elif choice == "5":
                if not prompt_authorization(): print("  Cancelled. No scan performed.\n"); continue
                target = input("  Target: ").strip(); spec = input("  Ports [default list]: ").strip() or None
                ports = parse_ports(spec); timeout = float(input("  Timeout seconds [0.4]: ").strip() or "0.4")
                report = scan_tcp(target, ports, timeout)
            elif choice == "6":
                if not prompt_authorization(): print("  Cancelled. No request performed.\n"); continue
                report = audit_url(input("  URL: ").strip())
            elif choice == "7":
                if not prompt_authorization(): print("  Cancelled. No connection performed.\n"); continue
                host = input("  Host: ").strip(); port = int(input("  Port [443]: ").strip() or "443"); report = inspect_tls(host, port)
            elif choice == "8": report = analyze_file(input("  File path: ").strip())
            elif choice == "9": report = triage_log(input("  Log path: ").strip())
            elif choice == "10": report = audit_source(input("  Source file/directory: ").strip())
            elif choice == "11": report = audit_pom(input("  pom.xml path: ").strip())
            elif choice == "12": report = classify_ioc(input("  Indicator: ").strip())
            elif choice == "13": report = audit_password(getpass.getpass("  Enter a TEST phrase (not a real/reused password; input hidden): "))
            elif choice == "14": report = collect_local_info()
            elif choice == "15": report = create_case_note(input("  Case name: "), input("  Observation: "))
            elif choice == "16":
                if input("  Send package name/version to public OSV API? Type ONLINE to continue: ").strip() != "ONLINE":
                    print("  Cancelled. No external query performed.\n"); continue
                package = input("  Package name: ").strip(); version = input("  Package version: ").strip()
                ecosystem = input("  Ecosystem [PyPI]: ").strip() or "PyPI"
                report = check_osv(package, version, ecosystem)
            elif choice == "17":
                print(json_text(engine_status())); input("  Press Enter to return..."); continue
            else:
                print("  Choose one of the listed numbers.\n"); continue
            print_report(report)
            destination = input("  Save JSON path (Enter to skip): ").strip()
            if destination: print(f"  Saved: {write_json(report, destination)}\n")
        except (EOFError, KeyboardInterrupt):
            print("\n  Exiting NOXTRACE.\n"); return 0
        except (ValueError, OSError) as exc:
            print(f"  {P.white}Input/operation error:{P.reset} {exc}\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        if not args.no_intro and sys.stdin.isatty():
            from noxtrace.intro import play_intro

            if not play_intro():
                return 130
        return _interactive()
    if args.command == "about":
        banner()
        print("NOXTRACE is a modular defensive-security workbench.")
        print("Active network actions require an explicit --authorized flag.")
        print("No DDoS, stealth, credential theft, or automated exploitation modules are included.")
        return 0
    if args.command == "engines":
        print(json.dumps(engine_status(), indent=2)); return 0
    if args.command == "engine":
        return _run_engine(args)
    if args.command == "ip": report = analyze_ip(args.address, args.ptr)
    elif args.command == "dns": report = analyze_dns(args.hostname, args.types)
    elif args.command == "domain": report = analyze_domain(args.hostname)
    elif args.command == "url": report = analyze_url(args.url)
    elif args.command == "scan":
        try: ports = parse_ports(args.ports)
        except ValueError as exc: report = {"module": "TCP Port Scan", "target": args.target, "status": "error", "summary": str(exc), "data": {}, "findings": [], "notes": []}
        else: report = scan_tcp(args.target, ports, args.timeout)
    elif args.command == "web-audit": report = audit_url(args.url, args.timeout)
    elif args.command == "tls": report = inspect_tls(args.host, args.port, args.timeout)
    elif args.command == "hash": report = analyze_file(args.path)
    elif args.command == "log": report = triage_log(args.path, args.max_lines)
    elif args.command == "code-audit":
        report = audit_source(args.path, args.max_files)
    elif args.command == "pom-audit": report = audit_pom(args.path)
    elif args.command == "osv-check": report = check_osv(args.package, args.version, args.ecosystem)
    elif args.command == "local-info": report = collect_local_info()
    elif args.command == "ioc": report = classify_ioc(args.value)
    elif args.command == "password-audit":
        value = args.value if args.value is not None else getpass.getpass("Enter a TEST phrase (not a real/reused password; input hidden): ")
        report = audit_password(value)
    elif args.command == "case-note": report = create_case_note(args.case_name, " ".join(args.observation))
    else: parser.print_help(); return 0
    return display_report(report, args)


if __name__ == "__main__":
    raise SystemExit(main())
