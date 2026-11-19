# Network Traffic Investigation Casebook - Case Reports

**Source of data:** the six `alerts_*.csv` files produced by `analyze.py`.
**Suspect IP in every file:** `172.16.21.138` (the Kali attacker VM).
**Fields marked `[CONFIRM]`** are not in the alert CSVs (target IP, timing, Wireshark counts, log lines). Fill them from your capture reports, Wireshark and server logs. Nothing in this file was invented.

## Summary: expected versus observed

| Case | Scenario | Alerts expected | Alerts observed | Match? |
|---|---|---|---|---|
| 1 | Baseline | None | PORT SCAN (1000), HIGH SYN RATE (1994), TRAFFIC BURST (758) | **No** - this looks like a port scan |
| 2 | Port scan | PORT SCAN, HIGH SYN RATE | None (empty file) | **No** - nothing was flagged |
| 3 | ICMP burst | ICMP FLOOD | ICMP FLOOD (300) plus HIGH SYN RATE, HTTP FLOOD?, TRAFFIC BURST | **Partly** - HTTP traffic also present |
| 4 | SSH failures | SSH BRUTE FORCE? | HIGH SYN RATE, HTTP FLOOD?, TRAFFIC BURST - no SSH alert | **No** - looks like HTTP traffic |
| 5 | HTTP burst | HTTP FLOOD? | HTTP FLOOD? (300), HIGH SYN RATE (300), TRAFFIC BURST (957) | **Yes** |
| Full run | All five | PORT SCAN, SYN, ICMP, HTTP, BURST, SSH | All of those except SSH, plus TOP TALKER | **Mostly** - SSH missing |

**Main findings**

1. **Only Case 5 is clean.** Case 3 shows its own scenario with extra HTTP traffic mixed in.
2. **SSH never produced an alert**, in Case 4 or in the full run. Fewer than 10 new connections to port 22 reached the target. The most likely cause is that the SSH step did not run properly on Kali. See "Fixes" at the end.
3. **Cases 1 and 2 look swapped or mislabelled.** The file named `baseline` contains the port scan, and the file named `portscan` is empty. The port scan file is dated 17 Nov, the others 19 Nov, so it was probably an earlier attempt, for example with a wrong `target_ip`.
4. **SYN counts are higher than the casebook predicted.** A scan of ports 1-1000 produced about 1994 SYNs, not about 1000. The RHEL firewall answers closed ports with ICMP "unreachable", which `nmap` treats as "filtered", so it likely retransmits each probe. My casebook text said "about 1000"; the real figure is about 2000. Confirm in Wireshark with the SYN filter in Case 1/2.

---

## Case 1 - Quiet Network (baseline)

| Field | Entry |
|---|---|
| Case number and name | #1 Quiet Network (baseline) |
| Date / analyst | 2026-11-19 / `[CONFIRM: your name]` |
| Capture file(s) | `case1_baseline_20261119_135926.csv` (and matching `.pcap`) |
| Source IP (suspect) | 172.16.21.138 |
| Target IP and service(s) | `[CONFIRM: RHEL IP on 172.16.21.0/24]`, ports probed 1-1000 |
| Start time / duration | `[CONFIRM: from the analyze.py report header]` |
| What happened | **Expected a clean baseline, but the capture contains a port scan.** One source IP touched 1000 different destination ports and opened 1994 TCP connections, with a peak of 758 packets in one second. No ping or web-request alerts fired, so the traffic is scan-only. |
| Evidence in Wireshark | `tcp.flags.syn==1 && tcp.flags.ack==0` should show about 1994 packets. `tcp.flags.syn==1 && tcp.flags.ack==1` should show 2 (ports 22 and 80). `[CONFIRM counts]` |
| Evidence from logs | Not applicable for a scan. `[CONFIRM: firewall/journal if desired]` |
| Python alerts raised | PORT SCAN (1000 vs 15, HIGH); HIGH SYN RATE (1994 vs 200, HIGH); TRAFFIC BURST (758 vs 300, MEDIUM) |
| Severity and reasoning | HIGH. A real baseline should raise nothing, so this capture **cannot be used as a baseline**. |
| Recommended action | Treat this file as the port scan evidence (rename it to `case2_portscan`). Redo the baseline: run `./traffic_gen.sh <TARGET_IP> baseline` during a fresh capture and confirm the report says no threshold was crossed. |

## Case 2 - The Curious Scanner (port scan)

| Field | Entry |
|---|---|
| Case number and name | #2 The Curious Scanner (port scan) |
| Date / analyst | 2026-11-17 / `[CONFIRM: your name]` |
| Capture file(s) | `case2_portscan_20261117_220205.csv` (and matching `.pcap`) |
| Source IP (suspect) | Not identified - no alerts were raised (`172.16.21.138` expected) |
| Target IP and service(s) | `[CONFIRM]` |
| Start time / duration | `[CONFIRM]` |
| What happened | **No source IP crossed any threshold.** The alerts file is empty, so this capture did not contain the scan. Likely causes: the scan was not running during the capture, or `target_ip` in `config.json` did not match the RHEL address on 17 Nov (the report would then say "No packets were addressed to ..."). |
| Evidence in Wireshark | Open the `.pcap` and apply `tcp.flags.syn==1 && tcp.flags.ack==0`. Count the packets. `[CONFIRM]` |
| Evidence from logs | None expected. |
| Python alerts raised | None |
| Severity and reasoning | Inconclusive. This is a missed detection or a bad capture, not a clean network. |
| Recommended action | Re-run `analyze.py` on this CSV with `--target <RHEL IP>`. If it is still empty, discard this file and use the scan found in Case 1's file as the Case 2 evidence. |

## Case 3 - Ping Storm (ICMP burst)

| Field | Entry |
|---|---|
| Case number and name | #3 Ping Storm (ICMP burst) |
| Date / analyst | 2026-11-19 / `[CONFIRM: your name]` |
| Capture file(s) | `case3_icmp_20261119_140600.csv` (and matching `.pcap`) |
| Source IP (suspect) | 172.16.21.138 |
| Target IP and service(s) | `[CONFIRM]`, ICMP echo and HTTP (port 80) |
| Start time / duration | `[CONFIRM]` |
| What happened | One source sent exactly 300 ping requests, matching the scenario. The same source also opened 300 new connections to port 80, so **web-request traffic is mixed into this capture**. The peak of 957 packets per second is far above what pings 10 ms apart can produce (about 100 per second), so it most likely comes from the HTTP traffic. |
| Evidence in Wireshark | `icmp.type==8` should show 300 packets. `http.request` should show about 300 packets. `[CONFIRM counts]` |
| Evidence from logs | `sudo wc -l /var/log/httpd/access_log` can confirm the extra web requests. `[CONFIRM]` |
| Python alerts raised | ICMP FLOOD (300 vs 100, HIGH); HTTP FLOOD? (300 vs 100, HIGH); HIGH SYN RATE (301 vs 200, MEDIUM); TRAFFIC BURST (957 vs 300, HIGH) |
| Severity and reasoning | HIGH for the ICMP burst: the count is exactly 3 times the limit. The HTTP and SYN alerts belong to a different scenario. |
| Recommended action | Rate-limit ICMP in the firewall. For the lab, repeat the capture without running the HTTP scenario so Case 3 contains pings only. |

## Case 4 - The Door Knocker (SSH failures)

| Field | Entry |
|---|---|
| Case number and name | #4 The Door Knocker (SSH failures) |
| Date / analyst | 2026-11-19 / `[CONFIRM: your name]` |
| Capture file(s) | `case4_ssh_20261119_140641.csv` (and matching `.pcap`) |
| Source IP (suspect) | 172.16.21.138 |
| Target IP and service(s) | `[CONFIRM]`, HTTP (port 80); SSH (port 22) not seen |
| Start time / duration | `[CONFIRM]` |
| What happened | **The expected SSH brute-force pattern is absent.** No SSH alert fired, meaning fewer than 10 new connections to port 22. The alerts show 300 new connections to port 80 with a 957 packets-per-second peak, the same numbers as the Case 5 HTTP capture. This capture contains HTTP traffic, not SSH failures. |
| Evidence in Wireshark | `tcp.dstport==22 && tcp.flags.syn==1 && tcp.flags.ack==0` should show 25 packets in a correct run; check how many you actually have. `[CONFIRM]` |
| Evidence from logs | `sudo grep -i "failed password" /var/log/secure \| tail -n 8` should list the attempts for `fakeuser`. If it prints nothing, the SSH attempts never reached the server. `[CONFIRM]` |
| Python alerts raised | HIGH SYN RATE (301 vs 200, MEDIUM); HTTP FLOOD? (300 vs 100, HIGH); TRAFFIC BURST (957 vs 300, HIGH) |
| Severity and reasoning | The HTTP burst is HIGH, but it is not what this case is meant to show. No SSH attack was detected. |
| Recommended action | Repeat the case after fixing the SSH step (see "Fixes" below). Real recommendation for SSH: key-only login, disable password login, fail2ban. |

## Case 5 - Page Hammer (HTTP burst)

| Field | Entry |
|---|---|
| Case number and name | #5 Page Hammer (HTTP burst) |
| Date / analyst | 2026-11-19 / `[CONFIRM: your name]` |
| Capture file(s) | `case5_http_20261119_140826.csv` (and matching `.pcap`) |
| Source IP (suspect) | 172.16.21.138 |
| Target IP and service(s) | `[CONFIRM]`, HTTP on port 80 |
| Start time / duration | `[CONFIRM]` |
| What happened | One source opened 300 new connections to the web port, matching the 300 requests in the scenario. The peak was 957 packets in one second. No port scan, ping or SSH alerts, so the capture is clean. **This case matches the expected result.** |
| Evidence in Wireshark | `http.request` should show about 300 GET requests with `?id=1` to `?id=300`. `tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.dstport==80` should show about 300 packets. `[CONFIRM counts]` |
| Evidence from logs | `sudo awk '{print $1}' /var/log/httpd/access_log \| sort \| uniq -c \| sort -rn \| head` should list 172.16.21.138 at the top. `[CONFIRM]` |
| Python alerts raised | HTTP FLOOD? (300 vs 100, HIGH); HIGH SYN RATE (300 vs 200, MEDIUM); TRAFFIC BURST (957 vs 300, HIGH) |
| Severity and reasoning | HIGH. Single-source automated requests with sequential `id` values at a very high rate. |
| Recommended action | Rate-limit at the web server or proxy, add caching, consider a web application firewall. |

## Full Run - all five scenarios in one capture

| Field | Entry |
|---|---|
| Case number and name | Full investigation run (`traffic_gen.sh <TARGET_IP> all`) |
| Date / analyst | 2026-11-19 / `[CONFIRM: your name]` |
| Capture file(s) | `full_run_20261119_132717.csv` (and matching `.pcap`) |
| Source IP (suspect) | 172.16.21.138 |
| Target IP and service(s) | `[CONFIRM]`, ports 1-1000 probed, ICMP, HTTP (port 80) |
| Start time / duration | `[CONFIRM]` |
| What happened | One source scanned 1000 ports, sent 305 pings (300 plus 5 from the baseline step), made 306 new connections to port 80 (300 plus the baseline requests), and generated 4146 packets in total with a 1249 packets-per-second peak. **The SSH brute-force alert is missing**, so the SSH step did not produce at least 10 connections to port 22. |
| Evidence in Wireshark | SYN filter (scan and web), `icmp.type==8`, `http.request`, and `tcp.dstport==22` (this one should show about 25 packets; check what you got). `[CONFIRM counts]` |
| Evidence from logs | `/var/log/secure` for `Failed password` lines; `/var/log/httpd/access_log` for the web burst. `[CONFIRM]` |
| Python alerts raised | PORT SCAN (1000 vs 15, HIGH); HIGH SYN RATE (2295 vs 200, HIGH); ICMP FLOOD (305 vs 100, HIGH); HTTP FLOOD? (306 vs 100, HIGH); TRAFFIC BURST (1249 vs 300, HIGH); TOP TALKER (4146 vs 3000, MEDIUM) |
| Severity and reasoning | HIGH. Several attack behaviours from one IP; port scan, ping burst and HTTP burst are all confirmed. SSH is not. |
| Recommended action | Block or rate-limit the source at the firewall, close unused ports, rate-limit ICMP and web requests. Fix and repeat the SSH step. |

---

## Fixes to get a complete, clean set of cases

1. **Check the SSH step on Kali.** The script hides errors, so run it by hand and read the output:
   ```bash
   which sshpass
   sshpass -p wrongpass1 ssh -o StrictHostKeyChecking=no fakeuser@<TARGET_IP> exit
   ```
   If `sshpass` is missing, run `sudo apt install -y sshpass`. After a good run, the RHEL log should show `Failed password for invalid user fakeuser`.
2. **Re-capture Case 1 (baseline).** Run only `baseline` and make sure no other scenario is running. Expected result: no alerts.
3. **Re-capture Case 2 (port scan).** Run only `portscan`. Also confirm `target_ip` in `config.json` matches the RHEL address. Expected alerts: PORT SCAN and HIGH SYN RATE.
4. **Re-capture Case 3 (ICMP)** with nothing else running. Expected alert: ICMP FLOOD.
5. **Re-capture Case 4 (SSH)** after fixing step 1. Expected alert: SSH BRUTE FORCE? with about 25 connections.
6. **Wait for each scenario to finish before stopping the capture**, and start the next capture only after the previous traffic has fully ended.
