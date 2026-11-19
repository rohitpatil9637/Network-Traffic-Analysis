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

| # | Case | What Kali does | Alert the script should raise |
|---|------|----------------|-------------------------------|
| 1 | Quiet Network | 5 web requests and 5 pings (normal use) | None |
| 2 | Curious Scanner | Port scan of ports 1-1000 | PORT SCAN, HIGH SYN RATE |
| 3 | Ping Storm | 300 pings, 10 ms apart | ICMP FLOOD |
| 4 | Door Knocker | 25 SSH logins with wrong passwords | SSH BRUTE FORCE? |
| 5 | Page Hammer | 300 web requests in a row | HTTP FLOOD? |

Case 1 is the control test: normal traffic must **not** trigger anything.

## What's in this repo

```
.
├── attacker/
│   └── traffic_gen.sh      # run on Kali: creates the fake traffic
├── scripts/
│   ├── capture.py          # run on RHEL: capture with tshark, save .pcap and .csv
│   ├── analyze.py          # run on RHEL: read the CSV, apply thresholds, show report
│   └── config.json         # target IP and thresholds (edit this)
├── docs/
│   ├── Network_Traffic_Investigation_Casebook.pdf   # full step-by-step build guide
│   └── Case_Reports.md                              # my filled-in case reports
├── examples/
│   └── sample_alerts_full_run.csv                   # real output from one run
├── LICENSE
└── README.md
```

The PDF in `docs/` has every step from installing VMware to running the final investigation, so start there if you are building the lab from scratch.

## What you need

- A computer that can run two VMs (I used a MacBook with VMware Fusion)
- **VM 1:** Kali Linux with `nmap`, `curl` and `sshpass`
- **VM 2:** RHEL 9 (or Rocky/Alma 9) with `wireshark`, `wireshark-cli`, `httpd`, `python3`
- Both VMs on the same virtual network (NAT worked fine)

Python packages: none. Only the standard library is used.

## Quick start

**1. Get the files onto the VMs**

```bash
git clone https://github.com/<your-username>/network-traffic-investigation-casebook.git
```

Copy `attacker/traffic_gen.sh` to Kali, and `scripts/` to `~/casebook/scripts` on RHEL.

**2. Edit the config on RHEL**

Open `scripts/config.json` and set `target_ip` to your RHEL VM's IP address (find it with `ip -br a`).

**3. Start a capture on RHEL**

```bash
cd ~/casebook/scripts
python3 capture.py -i ens160 -d 60 -n case2_portscan --filter "host <KALI_IP>" --analyze
```

`ens160` is the network interface name (check with `tshark -D`). The `--analyze` flag runs the report straight after the capture.

**4. Generate traffic on Kali** (right after step 3 starts)

```bash
chmod +x traffic_gen.sh
./traffic_gen.sh <TARGET_IP> portscan
```

Options: `baseline`, `portscan`, `icmp`, `ssh`, `http`, or `all`.

**5. Read the report**

When the capture ends, the terminal shows the top source IPs and any alerts. A CSV copy is saved in the `reports/` folder.

## How the detection works

`analyze.py` only looks at packets going **to** the target, groups them by source IP, and counts:

- how many different ports each IP touched
- how many new TCP connections it opened (SYN packets)
- how many pings it sent
- how many new connections went to port 22 (SSH) and port 80 (web)
- its busiest second

If a count reaches the limit in `config.json`, it raises an alert. If the count is 3 times the limit or more, the severity is HIGH, otherwise MEDIUM.

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

These numbers are a starting point. Run the baseline first, then tune them for your own lab.

## Example result

From a run with all five scenarios in one capture (`examples/sample_alerts_full_run.csv`):

| Severity | Alert | Value | Limit |
|----------|-------|-------|-------|
| HIGH | PORT SCAN | 1000 | 15 |
| HIGH | HIGH SYN RATE | 2295 | 200 |
| HIGH | ICMP FLOOD | 305 | 100 |
| HIGH | HTTP FLOOD? | 306 | 100 |
| HIGH | TRAFFIC BURST | 1249 | 300 |
| MEDIUM | TOP TALKER | 4146 | 3000 |

## Things I learned (and a few gotchas)

- **A port scan produces more packets than you'd guess.** Scanning 1000 ports gave about 2000 SYN packets, not 1000. RHEL's firewall answers closed ports with an ICMP "unreachable" message, and `nmap` retries those probes.
- **Closed ports don't always send a reset.** With `firewalld` running, closed ports get ICMP replies instead of TCP RST packets.
- **Wireshark can't see passwords.** SSH is encrypted. The packets show how often someone tried to log in, but the server log (`/var/log/secure`) shows the actual failed attempts.
- **Run one scenario at a time.** If you run a second scenario while a capture is still going, its traffic ends up in the wrong case. Wait for each one to finish.
- **Check your tools.** `traffic_gen.sh` now stops with a clear message if `nmap`, `curl` or `sshpass` is missing.
- **IP addresses can change** after a reboot. Check `ip -br a` and update `config.json`.

## Troubleshooting

| Problem | Fix |
|---------|-----|
| "You don't have permission to capture" | `sudo usermod -aG wireshark <your-user>`, then log out and back in |
| Capture is empty | Check the interface name with `tshark -D` and make sure the traffic really goes to the RHEL IP |
| Report says "No packets were addressed to ..." | `target_ip` in `config.json` is wrong |
| No SSH alert | Check `sshpass` is installed on Kali and look for "Failed password" in `/var/log/secure` on RHEL |
| Alerts on the baseline | Another scenario was running during the capture; repeat it |

## Safety

Only run this between VMs you own. Port scans, ping floods and password guessing against other people's systems can be illegal. `traffic_gen.sh` refuses to run against anything except private IP addresses (10.x, 172.16-31.x, 192.168.x) as a safety guard. Please don't remove that check.

## Ideas to extend it

- Add a whitelist of trusted IPs (the `ignore_ips` setting already exists)
- Add a new rule, for example a UDP flood
- Draw a chart of packets per IP with `matplotlib`
- Run `capture.py` on a schedule with `cron` and email the alerts

## License

MIT. See [LICENSE](LICENSE).
