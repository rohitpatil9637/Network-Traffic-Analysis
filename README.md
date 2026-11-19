# Network Traffic Investigation

A small hands-on lab where I create fake network attacks between two virtual machines, watch them in Wireshark, and then write Python scripts that spot the same attacks automatically.


## What this project does

1. **Kali Linux** (the "attacker") sends harmless fake traffic to **RHEL** (the "target").
2. On RHEL, I study the traffic by hand in **Wireshark**.
3. A Python script captures packets with **tshark** and saves them as a **CSV** file.
4. A second Python script reads the CSV, counts what each IP address did, compares the counts with **thresholds**, and prints a colour report in the terminal.

```
 Kali VM  ──fake traffic──>  RHEL VM
 (attacker)                  ├─ Wireshark   (look at packets by hand)
                             └─ capture.py  ─> .pcap ─> .csv ─> analyze.py ─> report + alerts.csv
```

## The five cases

| # | Case | What Kali does | Alert |
|---|------|----------------|-------------------------------|
| 1 | Quiet Network | 5 web requests and 5 pings (normal use) | None |
| 2 | Curious Scanner | Port scan of ports 1-1000 | PORT SCAN, HIGH SYN RATE |
| 3 | Ping Storm | 300 pings, 10 ms apart | ICMP FLOOD |
| 4 | Door Knocker | 25 SSH logins with wrong passwords | SSH BRUTE FORCE? |
| 5 | Page Hammer | 300 web requests in a row | HTTP FLOOD? |


Default thresholds:

| Setting | Default |
|---------|---------|
| `port_scan_unique_ports` | 15 |
| `syn_count` | 200 |
| `icmp_echo_count` | 100 |
| `ssh_new_connections` | 10 |
| `http_new_connections` | 100 |
| `peak_packets_per_second` | 300 |
| `total_packets` | 3000 |

These numbers are a starting point for own lab.


