"""
Seed script — generates sample log files and loads them into LogSentinel.

Usage:
    python -m scripts.seed
"""

import os
import random
import socket
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Ensure the project root is on sys.path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from app.config import SAMPLE_LOGS_DIR


def detect_device_ip() -> str:
    """Detect the active local IPv4 address of this laptop/phone hotspot network."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def _derive_neighbor_ips(device_ip: str) -> list[str]:
    """Generate nearby private-network IPv4 addresses for realistic baseline traffic."""
    if device_ip.count(".") != 3:
        return ["172.16.0.10", "172.16.0.11", "10.1.1.50", "10.1.1.51"]

    octets = device_ip.split(".")
    base = ".".join(octets[:3])
    last = int(octets[3])

    candidates = [
        f"{base}.{max(2, min(253, last - 2))}",
        f"{base}.{max(2, min(253, last - 1))}",
        f"{base}.{max(2, min(253, last + 1))}",
        f"{base}.{max(2, min(253, last + 2))}",
    ]
    unique_neighbors = [ip for ip in dict.fromkeys(candidates) if ip != device_ip]
    return unique_neighbors or ["172.16.0.10", "172.16.0.11", "10.1.1.50", "10.1.1.51"]


def generate_auth_log(device_ip: str) -> str:
    """Generate auth.log with brute-force activity from the current device IP."""
    lines: list[str] = []
    base_ts = datetime(2026, 3, 3, 8, 12, 1)
    normal_ips = _derive_neighbor_ips(device_ip)

    # Brute force from the detected device IP (triggers SSH rule)
    for i in range(10):
        ts = base_ts + timedelta(seconds=i * 2)
        lines.append(
            f"{ts.strftime('%b %e %H:%M:%S')} webserver sshd[{12340 + i}]: "
            f"Failed password for admin from {device_ip} port {52341 + i} ssh2"
        )

    # Normal successful logins
    success_ts = base_ts + timedelta(minutes=3)
    for i, user in enumerate(["deploy", "admin"]):
        ts = success_ts + timedelta(minutes=i)
        lines.append(
            f"{ts.strftime('%b %e %H:%M:%S')} webserver sshd[{12400 + i}]: "
            f"Accepted password for {user} from {random.choice(normal_ips)} port {44000 + i} ssh2"
        )

    # Another suspicious source to keep data realistic
    suspicious_ip = random.choice(normal_ips)
    suspicious_ts = base_ts + timedelta(minutes=8)
    for i, user in enumerate(["test", "guest", "ubuntu", "oracle", "postgres", "root"]):
        ts = suspicious_ts + timedelta(seconds=i * 2)
        lines.append(
            f"{ts.strftime('%b %e %H:%M:%S')} webserver sshd[{12450 + i}]: "
            f"Failed password for invalid user {user} from {suspicious_ip} port {33210 + i} ssh2"
        )

    lines.sort()
    return "\n".join(lines) + "\n"


def generate_nginx_access_log(device_ip: str) -> str:
    """Generate a realistic nginx access log with flood traffic from the current device IP."""
    lines: list[tuple[datetime, str]] = []
    base_time = datetime(2026, 3, 3, 10, 0, 0)

    # ── Normal traffic (various IPs, spread over time) ───────────────────
    normal_ips = _derive_neighbor_ips(device_ip)
    paths = [
        "/", "/about", "/contact", "/api/health", "/login",
        "/dashboard", "/static/style.css", "/static/app.js",
        "/images/logo.png", "/api/v1/users",
    ]
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        "curl/7.88.1",
        "python-requests/2.31.0",
    ]

    for i in range(80):
        ip = random.choice(normal_ips)
        ts = base_time + timedelta(seconds=random.randint(0, 3600))
        path = random.choice(paths)
        status = random.choice([200, 200, 200, 301, 304, 404])
        size = random.randint(200, 15000)
        ua = random.choice(user_agents)
        line = _format_nginx_line(ip, ts, "GET", path, status, size, ua)
        lines.append((ts, line))

    # ── Flood pattern: 220 requests from current device IP in 90 seconds ──
    attacker_ip = device_ip
    flood_start = base_time + timedelta(minutes=15)
    attack_paths = [
        "/admin", "/wp-login.php", "/xmlrpc.php", "/.env",
        "/api/v1/users", "/config.php", "/phpmyadmin",
        "/login", "/api/token", "/debug",
    ]
    for i in range(220):
        ts = flood_start + timedelta(seconds=random.uniform(0, 90))
        path = random.choice(attack_paths)
        status = random.choice([200, 403, 404, 500])
        size = random.randint(100, 5000)
        ua = "Mozilla/5.0 (compatible; Scrapy/2.11)"
        line = _format_nginx_line(attacker_ip, ts, "GET", path, status, size, ua)
        lines.append((ts, line))

    # ── More normal traffic after the flood ──────────────────────────────
    for i in range(40):
        ip = random.choice(normal_ips)
        ts = base_time + timedelta(minutes=random.randint(20, 60))
        path = random.choice(paths)
        status = random.choice([200, 200, 304])
        size = random.randint(200, 8000)
        ua = random.choice(user_agents)
        line = _format_nginx_line(ip, ts, "GET", path, status, size, ua)
        lines.append((ts, line))

    # Sort by timestamp for realism
    lines.sort(key=lambda x: x[0])
    return "\n".join(l[1] for l in lines) + "\n"


def _format_nginx_line(
    ip: str, ts: datetime, method: str, path: str,
    status: int, size: int, ua: str,
) -> str:
    """Format a single nginx combined log line."""
    ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return (
        f'{ip} - - [{ts_str}] "{method} {path} HTTP/1.1" '
        f'{status} {size} "-" "{ua}"'
    )


def main() -> None:
    """Generate sample logs and optionally seed the database."""
    print("╔══════════════════════════════════════════════╗")
    print("║   LogSentinel — Sample Log Generator         ║")
    print("╚══════════════════════════════════════════════╝")

    device_ip = detect_device_ip()
    print(f"  ✓ Detected current device IP: {device_ip}")

    # Generate auth.log dynamically
    auth_content = generate_auth_log(device_ip)
    auth_path = SAMPLE_LOGS_DIR / "auth.log"
    auth_path.write_text(auth_content, encoding="utf-8")
    print(f"  ✓ Generated {auth_path}  ({auth_content.count(chr(10))} lines)")

    # Generate nginx access.log dynamically
    nginx_content = generate_nginx_access_log(device_ip)
    nginx_path = SAMPLE_LOGS_DIR / "access.log"
    nginx_path.write_text(nginx_content, encoding="utf-8")
    print(f"  ✓ Generated {nginx_path}  ({nginx_content.count(chr(10))} lines)")

    print()
    print("To load these into LogSentinel:")
    print("  1. Start the server:  python run.py")
    print("  2. Open http://localhost:8000/upload")
    print("  3. Upload sample_logs/auth.log  (type: auth)")
    print("  4. Upload sample_logs/access.log (type: nginx)")
    print()

    # Auto-seed via API if server is running
    try:
        import httpx  # type: ignore

        print("Attempting to auto-seed via API…")
        base = "http://localhost:8000"

        for fname, ltype in [("auth.log", "auth"), ("access.log", "nginx")]:
            fpath = SAMPLE_LOGS_DIR / fname
            with open(fpath, "rb") as f:
                resp = httpx.post(
                    f"{base}/api/upload/?log_type={ltype}",
                    files={"file": (fname, f, "text/plain")},
                    timeout=30,
                )
            if resp.status_code == 200:
                data = resp.json()
                print(f"  ✓ {fname}: {data['events_parsed']} events, {data['alerts_generated']} alerts")
            else:
                print(f"  ✗ {fname}: {resp.status_code} — {resp.text[:200]}")

        print("\nDone! Visit http://localhost:8000 to view the dashboard.")

    except ImportError:
        print("(httpx not installed — skipping auto-seed. Upload files manually.)")
    except Exception as e:
        print(f"(Server not reachable: {e} — Upload files manually from the UI.)")


if __name__ == "__main__":
    main()
