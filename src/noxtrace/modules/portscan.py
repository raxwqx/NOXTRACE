"""Conservative TCP connect scanner with explicit authorization and a hard cap."""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from noxtrace.reporting import make_report

DEFAULT_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]
MAX_PORTS = 256
MAX_WORKERS = 32
SERVICE_HINTS = {21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb", 587: "submission", 993: "imaps", 995: "pop3s", 1433: "ms-sql", 1521: "oracle-db", 3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb"}


def parse_ports(spec: str | None) -> list[int]:
    if not spec:
        return DEFAULT_PORTS.copy()
    ports: set[int] = set()
    for part in spec.split(","):
        token = part.strip()
        if not token:
            raise ValueError("Empty port element in port list.")
        if "-" in token:
            pieces = token.split("-")
            if len(pieces) != 2:
                raise ValueError(f"Invalid port range: {token}")
            start, end = (int(item) for item in pieces)
            if end < start:
                raise ValueError(f"Port range end is smaller than start: {token}")
            if end - start + 1 > MAX_PORTS:
                raise ValueError(f"A single range cannot exceed {MAX_PORTS} ports.")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(token))
        if len(ports) > MAX_PORTS:
            raise ValueError(f"A scan is limited to {MAX_PORTS} unique ports.")
    if any(port < 1 or port > 65535 for port in ports):
        raise ValueError("Ports must be between 1 and 65535.")
    if not ports:
        raise ValueError("Specify at least one port.")
    return sorted(ports)


def scan_tcp(target: str, ports: list[int], timeout: float = 0.4, workers: int = MAX_WORKERS) -> dict:
    """Connect to a bounded port list. No stealth, evasion, or exploitation is used."""
    if not target or any(ch.isspace() for ch in target):
        return make_report("TCP Port Scan", target, "error", "Enter one hostname or IP address.")
    if len(set(ports)) > MAX_PORTS or any(p < 1 or p > 65535 for p in ports):
        return make_report("TCP Port Scan", target, "error", f"Port list must contain at most {MAX_PORTS} ports in range 1-65535.")
    if not 0.05 <= timeout <= 3.0:
        return make_report("TCP Port Scan", target, "error", "Timeout must be between 0.05 and 3.0 seconds.")
    try:
        resolved = sorted({item[4][0] for item in socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)})
    except socket.gaierror as exc:
        return make_report("TCP Port Scan", target, "error", f"Target resolution failed: {exc}")
    if not resolved:
        return make_report("TCP Port Scan", target, "error", "Target did not resolve to an address.")

    start = time.monotonic()
    open_ports: list[dict] = []
    checked = 0

    def check(address: str, port: int) -> tuple[str, int, bool]:
        sock = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            return address, port, sock.connect_ex((address, port)) == 0
        except OSError:
            return address, port, False
        finally:
            sock.close()

    tasks = []
    with ThreadPoolExecutor(max_workers=max(1, min(int(workers), MAX_WORKERS))) as pool:
        for address in resolved[:4]:  # Avoid multiplying work on unusually large DNS answer sets.
            for port in ports:
                tasks.append(pool.submit(check, address, port))
        for future in as_completed(tasks):
            address, port, is_open = future.result()
            checked += 1
            if is_open:
                open_ports.append({"address": address, "port": port, "state": "open", "service_hint": SERVICE_HINTS.get(port, "unknown")})
    open_ports.sort(key=lambda row: (row["address"], row["port"]))
    elapsed = round(time.monotonic() - start, 3)
    status = "ok" if open_ports else "warning"
    findings = [{"severity": "INFO", "title": "Open TCP port", "detail": f"{row['address']}:{row['port']} accepted a TCP connection."} for row in open_ports]
    return make_report("TCP Port Scan", target, status, f"Checked {checked} address/port combinations; found {len(open_ports)} open TCP port(s).", {"resolved_addresses": resolved[:4], "ports_requested": sorted(set(ports)), "checked_combinations": checked, "open_ports": open_ports, "timeout_seconds": timeout, "elapsed_seconds": elapsed}, findings, ["TCP connect checks only: no service exploitation, stealth, or UDP scanning.", "Open ports are not automatically vulnerabilities."])
