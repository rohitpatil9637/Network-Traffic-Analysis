#!/usr/bin/env python3
"""
capture.py - Capture packets with tshark and convert them to CSV.

Run on the RHEL (target/analysis) VM.

Examples:
  python3 capture.py -i ens160 -d 30 -n case2_portscan
  python3 capture.py -i ens160 -d 60 -n full_run --filter "host 192.168.100.128" --analyze
"""
import argparse
import datetime
import os
import shutil
import subprocess
import sys

# The tshark fields that become CSV columns. analyze.py expects these names.
FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ip.proto",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "udp.dstport",
    "icmp.type",
    "frame.len",
]


def check_tshark():
    path = shutil.which("tshark")
    if not path:
        sys.exit("[!] tshark not found. Install it:  sudo dnf install -y wireshark-cli")
    return path


def capture(tshark, interface, duration, pcap_path, bpf_filter):
    """Capture live traffic to a pcap file for 'duration' seconds."""
    cmd = [tshark, "-i", interface, "-a", f"duration:{duration}", "-w", pcap_path]
    if bpf_filter:
        cmd += ["-f", bpf_filter]
    print(f"[*] Capturing on {interface} for {duration}s ...")
    print(f"    {' '.join(cmd)}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        sys.exit("[!] Capture failed. Check the interface name (ip a) and permissions "
                 "(see Troubleshooting: add yourself to the 'wireshark' group, or use sudo).")
    if not os.path.exists(pcap_path) or os.path.getsize(pcap_path) == 0:
        sys.exit("[!] The pcap file is empty - no packets were captured.")
    print(f"[+] Saved pcap: {pcap_path}")


def pcap_to_csv(tshark, pcap_path, csv_path):
    """Convert a pcap file to CSV using tshark's field extraction."""
    cmd = [tshark, "-r", pcap_path, "-Y", "ip", "-T", "fields",
           "-E", "header=y", "-E", "separator=,", "-E", "quote=d",
           "-E", "occurrence=f"]
    for field in FIELDS:
        cmd += ["-e", field]
    print("[*] Converting pcap to CSV ...")
    with open(csv_path, "w") as out:
        result = subprocess.run(cmd, stdout=out)
    if result.returncode != 0:
        sys.exit("[!] tshark conversion failed.")
    with open(csv_path) as f:
        rows = sum(1 for _ in f) - 1
    print(f"[+] Saved CSV : {csv_path}  ({rows} IPv4 packets)")


def main():
    ap = argparse.ArgumentParser(description="Capture traffic with tshark and export CSV")
    ap.add_argument("-i", "--interface", required=True, help="interface name, e.g. ens160")
    ap.add_argument("-d", "--duration", type=int, default=30,
                    help="capture seconds (default 30)")
    ap.add_argument("-n", "--name", default="capture", help="base name for output files")
    ap.add_argument("-f", "--filter", default="",
                    help='capture filter, e.g. "host 192.168.100.128"')
    ap.add_argument("-o", "--outdir", default="../captures", help="output directory")
    ap.add_argument("--analyze", action="store_true", help="run analyze.py after conversion")
    args = ap.parse_args()

    tshark = check_tshark()
    os.makedirs(args.outdir, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.join(args.outdir, f"{args.name}_{stamp}")
    pcap_path, csv_path = base + ".pcap", base + ".csv"

    capture(tshark, args.interface, args.duration, pcap_path, args.filter)
    pcap_to_csv(tshark, pcap_path, csv_path)

    if args.analyze:
        here = os.path.dirname(os.path.abspath(__file__))
        subprocess.run([sys.executable, os.path.join(here, "analyze.py"), csv_path])
    else:
        print(f"[i] Next:  python3 analyze.py {csv_path}")


if __name__ == "__main__":
    main()

