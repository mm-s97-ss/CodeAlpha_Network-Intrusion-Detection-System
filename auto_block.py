#!/usr/bin/env python3
"""
auto_block.py -- Automated response mechanism for the Suricata NIDS project.

Tails Suricata's eve.json, watches for "alert" events, and automatically
blocks the offending source IP with iptables the first time it is seen at
or above a configured severity level. All actions are logged to
block_actions.log.

Run only on your own authorized lab network / VM.

Usage:
    sudo python3 auto_block.py
    sudo python3 auto_block.py --eve /var/log/suricata/eve.json --severity 2 --dry-run
"""

import argparse
import json
import subprocess
import time
from datetime import datetime
from pathlib import Path

BLOCKED_IPS_FILE = Path("blocked_ips.txt")
ACTION_LOG_FILE = Path("block_actions.log")


def load_blocked_ips():
    if BLOCKED_IPS_FILE.exists():
        return set(BLOCKED_IPS_FILE.read_text().splitlines())
    return set()


def persist_blocked_ip(ip):
    with BLOCKED_IPS_FILE.open("a") as f:
        f.write(ip + "\n")


def log_action(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"
    print(line)
    with ACTION_LOG_FILE.open("a") as f:
        f.write(line + "\n")


def block_ip(ip, dry_run=False):
    if dry_run:
        log_action(f"[DRY-RUN] Would block IP {ip}")
        return
    try:
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True,
        )
        log_action(f"Blocked malicious IP {ip} via iptables")
    except subprocess.CalledProcessError as exc:
        log_action(f"Failed to block IP {ip}: {exc}")
    except FileNotFoundError:
        log_action("iptables not found -- run on Linux with iptables installed")


def follow(filepath):
    """Generator that yields new lines appended to a file (tail -f style)."""
    with open(filepath, "r") as f:
        f.seek(0, 2)  # seek to end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def main():
    parser = argparse.ArgumentParser(description="Auto-block IPs from Suricata eve.json alerts.")
    parser.add_argument("--eve", default="/var/log/suricata/eve.json", help="Path to Suricata eve.json")
    parser.add_argument("--severity", type=int, default=2, help="Block alerts with severity <= this value (1=high)")
    parser.add_argument("--dry-run", action="store_true", help="Log actions without actually blocking")
    args = parser.parse_args()

    blocked_ips = load_blocked_ips()
    log_action(f"Starting auto-responder, watching {args.eve} (severity <= {args.severity})")

    for raw_line in follow(args.eve):
        try:
            event = json.loads(raw_line)
        except json.JSONDecodeError:
            continue

        if event.get("event_type") != "alert":
            continue

        alert = event.get("alert", {})
        severity = alert.get("severity", 3)
        src_ip = event.get("src_ip")
        signature = alert.get("signature", "unknown signature")

        if not src_ip or src_ip in blocked_ips:
            continue

        if severity <= args.severity:
            log_action(f"ALERT matched (severity {severity}): '{signature}' from {src_ip}")
            block_ip(src_ip, dry_run=args.dry_run)
            blocked_ips.add(src_ip)
            persist_blocked_ip(src_ip)


if __name__ == "__main__":
    main()
