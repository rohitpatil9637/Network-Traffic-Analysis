#!/usr/bin/env bash
# traffic_gen.sh - Generate FAKE lab traffic from Kali toward your OWN RHEL target VM.
# Usage: ./traffic_gen.sh <target_ip> <scenario>
# Scenarios: baseline | portscan | icmp | ssh | http | all
# LAB USE ONLY. The script refuses to run against non-private IP addresses.

TARGET="${1:-}"
SCENARIO="${2:-}"

usage() {
  echo "Usage: $0 <target_ip> <baseline|portscan|icmp|ssh|http|all>"
  exit 1
}

is_private() {
  [[ "$1" =~ ^10\. ]] || [[ "$1" =~ ^192\.168\. ]] ||
    [[ "$1" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]]
}

[[ -z "$TARGET" || -z "$SCENARIO" ]] && usage
if ! is_private "$TARGET"; then
  echo "[!] $TARGET is not a private lab address. Refusing to run."
  exit 1
fi

scenario_baseline() {
  echo "[*] CASE 1 - Baseline: 5 web requests + 5 pings"
  for i in $(seq 1 5); do curl -s -o /dev/null "http://$TARGET/"; sleep 1; done
  ping -c 5 "$TARGET" > /dev/null
}

scenario_portscan() {
  echo "[*] CASE 2 - Port scan: SYN scan of ports 1-1000"
  sudo nmap -sS -p 1-1000 -T4 "$TARGET" > /dev/null
}

scenario_icmp() {
  echo "[*] CASE 3 - ICMP burst: 300 pings, 10 ms apart"
  sudo ping -c 300 -i 0.01 -q "$TARGET" > /dev/null
}

scenario_ssh() {
  echo "[*] CASE 4 - SSH failures: 25 login attempts with wrong passwords"
  for i in $(seq 1 25); do
    sshpass -p "wrongpass$i" ssh -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 \
      fakeuser@"$TARGET" exit > /dev/null 2>&1
  done
}

scenario_http() {
  echo "[*] CASE 5 - HTTP burst: 300 web requests as fast as possible"
  for i in $(seq 1 300); do curl -s -o /dev/null "http://$TARGET/?id=$i"; done
}

case "$SCENARIO" in
  baseline) scenario_baseline ;;
  portscan) scenario_portscan ;;
  icmp)     scenario_icmp ;;
  ssh)      scenario_ssh ;;
  http)     scenario_http ;;
  all)
    scenario_baseline; sleep 5
    scenario_portscan; sleep 5
    scenario_icmp;     sleep 5
    scenario_ssh;      sleep 5
    scenario_http ;;
  *) usage ;;
esac
echo "[+] Done: $SCENARIO"
