#!/usr/bin/env python3
"""
analyze.py - Read a tshark CSV, find suspicious source IPs using thresholds,
and show the result on the command line (plus save an alerts CSV).

Usage:
  python3 analyze.py ../captures/full_run_20260101_120000.csv
  python3 analyze.py file.csv --config config.json --target 192.168.100.129
"""
import argparse
import csv
import datetime
import json
import os
import sys
from collections import Counter, defaultdict

USE_COLOR = sys.stdout.isatty()
RED, YELLOW, GREEN, CYAN, BOLD, RESET = (
    ("\033[91m", "\033[93m", "\033[92m", "\033[96m", "\033[1m", "\033[0m")
    if USE_COLOR else ("", "", "", "", "", "")
)

# (stat key, threshold key in config.json, alert name, explanation)
RULES = [
    ("unique_ports", "port_scan_unique_ports", "PORT SCAN",
     "one IP touched many different destination ports"),
    ("syn_count", "syn_count", "HIGH SYN RATE",
     "one IP opened a very large number of TCP connections"),
    ("icmp_echo", "icmp_echo_count", "ICMP FLOOD",
     "one IP sent a large number of ping requests"),
    ("ssh_syn", "ssh_new_connections", "SSH BRUTE FORCE?",
     "one IP made many new connections to port 22"),
    ("http_syn", "http_new_connections", "HTTP FLOOD?",
     "one IP made many new connections to port 80"),
    ("peak_pps", "peak_packets_per_second", "TRAFFIC BURST",
     "one IP sent a very high packets-per-second burst"),
    ("packets", "total_packets", "TOP TALKER",
     "one IP sent a very large total number of packets"),
]


def to_int(value, base=10):
    try:
        return int(value, base)
    except (TypeError, ValueError):
        return None


def load_config(path):
    with open(path) as f:
        return json.load(f)


def analyze(csv_path, target, ignore):
    stats = defaultdict(lambda: {
        "packets": 0, "bytes": 0, "ports": set(), "syn_count": 0,
        "icmp_echo": 0, "ssh_syn": 0, "http_syn": 0, "pps": Counter(),
    })
    total, first_ts, last_ts = 0, None, None

    with open(csv_path, newline="") as f:
        for row in csv.DictReader(f):
            src, dst = row.get("ip.src", ""), row.get("ip.dst", "")
            if not src or not dst:
                continue
            total += 1
            ts = float(row["frame.time_epoch"])
            first_ts = ts if first_ts is None else first_ts
            last_ts = ts

            # Only look at traffic going TOWARD the target, from outside IPs.
            if src in ignore or (target and dst != target):
                continue

            s = stats[src]
            s["packets"] += 1
            s["bytes"] += to_int(row.get("frame.len")) or 0
            s["pps"][int(ts)] += 1

            dport = to_int(row.get("tcp.dstport"))
            if dport is None:
                dport = to_int(row.get("udp.dstport"))
            if dport is not None:
                s["ports"].add(dport)

            flags = to_int(row.get("tcp.flags"), 16)
            if flags is not None and (flags & 0x02) and not (flags & 0x10):
                s["syn_count"] += 1          # SYN set, ACK not set = new connection
                if dport == 22:
                    s["ssh_syn"] += 1
                if dport == 80:
                    s["http_syn"] += 1

            if row.get("icmp.type") == "8":   # ICMP echo request (ping)
                s["icmp_echo"] += 1

    # Flatten the stats into simple rows
    rows = []
    for ip, s in stats.items():
        rows.append({
            "ip": ip, "packets": s["packets"], "bytes": s["bytes"],
            "unique_ports": len(s["ports"]), "syn_count": s["syn_count"],
            "icmp_echo": s["icmp_echo"], "ssh_syn": s["ssh_syn"],
            "http_syn": s["http_syn"],
            "peak_pps": max(s["pps"].values()) if s["pps"] else 0,
        })
    rows.sort(key=lambda r: r["packets"], reverse=True)
    duration = (last_ts - first_ts) if first_ts is not None else 0
    return rows, total, duration


def find_alerts(rows, thresholds):
    alerts = []
    for r in rows:
        for stat_key, th_key, name, why in RULES:
            limit = thresholds.get(th_key)
            if limit is None:
                continue
            value = r[stat_key]
            if value >= limit:
                severity = "HIGH" if value >= 3 * limit else "MEDIUM"
                alerts.append({"ip": r["ip"], "alert": name, "value": value,
                               "threshold": limit, "severity": severity, "why": why})
    return alerts


def print_report(csv_path, target, rows, total, duration, alerts):
    line = "=" * 78
    print(f"\n{BOLD}{line}\n  NETWORK TRAFFIC INVESTIGATION REPORT\n{line}{RESET}")
    print(f"  File      : {csv_path}")
    print(f"  Target    : {target or 'all traffic'}")
    print(f"  Packets   : {total}   Duration: {duration:.1f}s")
    print(f"  Time      : {datetime.datetime.now():%Y-%m-%d %H:%M:%S}")

    if not rows:
        print(f"\n  {YELLOW}[!] No packets were addressed to {target}.{RESET}")
        print("      Check target_ip in config.json (run 'ip a' on the RHEL VM).")
    print(f"\n{BOLD}  TOP SOURCE IPs (traffic toward target){RESET}")
    print(f"  {'IP ADDRESS':<18}{'PACKETS':>9}{'BYTES':>10}{'PORTS':>7}{'SYN':>7}"
          f"{'PING':>7}{'PEAK/s':>8}")
    print("  " + "-" * 74)
    for r in rows[:10]:
        print(f"  {r['ip']:<18}{r['packets']:>9}{r['bytes']:>10}{r['unique_ports']:>7}"
              f"{r['syn_count']:>7}{r['icmp_echo']:>7}{r['peak_pps']:>8}")

    print(f"\n{BOLD}  ALERTS (thresholds from config.json){RESET}")
    if not alerts:
        print(f"  {GREEN}[OK] No source IP crossed any threshold.{RESET}")
    else:
        print(f"  {'SEVERITY':<9}{'IP ADDRESS':<18}{'ALERT':<18}{'VALUE':>7}{'LIMIT':>7}")
        print("  " + "-" * 74)
        for a in alerts:
            color = RED if a["severity"] == "HIGH" else YELLOW
            print(f"  {color}{a['severity']:<9}{a['ip']:<18}{a['alert']:<18}"
                  f"{a['value']:>7}{a['threshold']:>7}{RESET}")
            print(f"  {CYAN}          -> {a['why']}{RESET}")

    suspects = sorted({a["ip"] for a in alerts})
    print(f"\n{BOLD}  VERDICT{RESET}")
    if suspects:
        print(f"  {RED}Suspicious IPs: {', '.join(suspects)}{RESET}")
        print("  Next step: open the matching .pcap in Wireshark and filter on these IPs.")
    else:
        print(f"  {GREEN}Traffic looks normal for the configured thresholds.{RESET}")
    print(BOLD + line + RESET + "\n")


def save_alerts(alerts, out_dir, csv_path):
    os.makedirs(out_dir, exist_ok=True)
    name = os.path.splitext(os.path.basename(csv_path))[0]
    path = os.path.join(out_dir, f"alerts_{name}.csv")
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["severity", "ip", "alert", "value",
                                          "threshold", "why"])
        w.writeheader()
        for a in alerts:
            w.writerow({k: a[k] for k in w.fieldnames})
    print(f"  [+] Alerts saved to {path}")


def main():
    ap = argparse.ArgumentParser(description="Threshold-based traffic analysis")
    ap.add_argument("csv_file", help="CSV produced by capture.py")
    ap.add_argument("-c", "--config", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "config.json"))
    ap.add_argument("--target", help="override target_ip from config")
    ap.add_argument("-o", "--outdir", default="../reports", help="where to save alerts CSV")
    args = ap.parse_args()

    if not os.path.exists(args.csv_file):
        sys.exit(f"[!] CSV not found: {args.csv_file}")
    cfg = load_config(args.config)
    target = args.target or cfg.get("target_ip")
    ignore = set(cfg.get("ignore_ips", []))
    thresholds = cfg["thresholds"]

    rows, total, duration = analyze(args.csv_file, target, ignore)
    alerts = find_alerts(rows, thresholds)
    print_report(args.csv_file, target, rows, total, duration, alerts)
    save_alerts(alerts, args.outdir, args.csv_file)


if __name__ == "__main__":
    main()

