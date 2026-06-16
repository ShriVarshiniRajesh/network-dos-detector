# Network DoS Detector (Windows)

A lightweight, real-time network traffic monitor that sniffs live packets on Windows and flags potential Denial-of-Service (DoS) activity based on per-IP packet rate - built with Python and Scapy.

This project is detection-only by design: it identifies and alerts on suspicious traffic patterns without modifying any firewall rules or system configuration, making it safe to run and experiment with on a personal machine.

## What it does

The script monitors live network traffic on the host machine, tracks how many packets each source IP sends per second, and raises an alert when any single IP exceeds a configurable threshold - a simple but real heuristic used in actual intrusion detection systems for spotting traffic floods.

```
THRESHOLD: 40
Monitoring network traffic...
[ALERT] Possible DoS detected from 192.168.1.55 — packet rate: 55.55 pkts/sec
```

## How it works

1. **Packet capture** : `scapy.sniff()` captures live IP packets from the active network interface in real time, powered by the Npcap packet-capture driver.
2. **Per-IP rate tracking** : every packet's source IP is tallied in a `defaultdict(int)` counter as it arrives.
3. **Sliding 1-second window** : once a full second has elapsed, the script computes each tracked IP's packets-per-second rate and resets the counters for the next window.
4. **Threshold check** : any IP exceeding the configured rate (default: 40 pkts/sec) triggers a one-time alert and is recorded in a `flagged_ips` set so it isn't repeatedly re-flagged every cycle.
5. **Privilege check** : the script verifies it's running with Administrator rights before attempting to sniff, since raw packet capture requires elevated access on Windows.

## I did this simulation in Windows and this is what I've learnt:

Most DoS-detection tutorials and reference implementations are written for Linux, where root access, `iptables`, and native packet capture are built in. Porting this to Windows surfaced several platform-specific obstacles that aren't well documented, each of which had to be diagnosed and solved individually:

**No native packet capture driver.** Windows doesn't expose raw sockets the way Linux does. Scapy depends on a capture driver to read packets off the wire at all : without one, `sniff()` fails immediately. This was resolved by installing [Npcap](https://npcap.com/), configured in WinPcap-compatible mode for broader library support.

**No `os.geteuid()` or `iptables` on Windows.** The original Linux-style script checked for root using `os.geteuid()` and would have blocked IPs via `iptables`. Neither exists on Windows. The privilege check was rewritten using `ctypes.windll.shell32.IsUserAnAdmin()`, the standard way to detect elevation on Windows from Python.

**Loopback traffic is effectively invisible to Npcap.** The first instinct for safe, self-contained testing was flooding `127.0.0.1` and sniffing on the `\Device\NPF_Loopback` interface scapy exposes. In practice, this produced zero captured packets — a known limitation, since Windows loopback traffic doesn't traverse the NDIS layer Npcap hooks into the same way real adapter traffic does. Confirmed by isolating the test to a minimal sniff-and-print script before concluding the limitation was environmental, not a bug in the detection logic.

**Distributed traffic defeats per-IP rate detection by design.** An internet speed test was tried next, on the theory that a large download/upload burst would trip the threshold. It didn't — and for a legitimate reason: speed test traffic arrives from many different CDN/server IPs simultaneously, so no single source IP individually crosses the per-IP rate threshold, even though aggregate throughput is high. This mirrors a real, known weakness of naive per-IP rate limiting against distributed traffic, rather than indicating broken logic.

**The fix: concentrate traffic on a single real source IP.** Rather than testing against `127.0.0.1` (invisible to the capture driver) or the open internet (traffic too distributed across IPs), the working test flooded the machine's actual LAN-facing IP address (found via `ipconfig`) using a high-volume, high-payload ping (`ping 192.168.1.55 -n 500 -l 1024`). Because this traffic both originates from and targets the same real network adapter scapy is listening on, it concentrates cleanly under one IP in the counter — and reliably crosses the threshold, confirming the full pipeline works end-to-end.

## Tech stack

| Component | Purpose |
|---|---|
| Python 3 | Core script logic |
| [Scapy](https://scapy.net/) | Packet sniffing and parsing |
| [Npcap](https://npcap.com/) | Low-level packet capture driver for Windows |
| `ctypes` | Windows admin-privilege detection |
| `collections.defaultdict` | Per-IP packet counting |

## Setup

**Prerequisites**
- Python 3.x, with **Add to PATH** enabled during install
- [Npcap](https://npcap.com/#download) installed (WinPcap-compatible mode recommended)

**Install dependencies**
```bash
pip install scapy
```

**Run (must be run as Administrator)**

Packet capture on Windows requires elevated privileges. Right-click your terminal or VS Code and select **Run as administrator**, then:
```bash
python firewall_dos.py
```

If the script isn't run elevated, it exits immediately with:
```
This script requires administrator privileges.
```

## Configuration

The detection sensitivity is controlled by a single constant at the top of the script:
```python
THRESHOLD = 40  # packets per second from a single IP before flagging
```
Lower it to increase sensitivity (more false positives from normal traffic bursts); raise it to reduce noise on busier networks.

## Testing it yourself

Since the detector only flags traffic actually captured on a real network interface, testing requires generating genuine, concentrated packet load — not just any traffic.

1. Find your machine's LAN IP:
   ```bash
   ipconfig
   ```
   Note the **IPv4 Address** (e.g. `192.168.1.55`).

2. In a second terminal, flood that IP with a high-volume ping:
   ```bash
   ping 192.168.1.55 -n 500 -l 1024
   ```

3. Watch the detector terminal for an alert once the rate crosses the threshold:
   ```
   [ALERT] Possible DoS detected from 192.168.1.55 — packet rate: 55.55 pkts/sec
   ```

This keeps all traffic self-contained on the local machine — nothing is sent to the public internet or to any other device.

## Design decisions

**Detection-only, no enforcement.** An earlier iteration of this script considered automatically blocking flagged IPs via `netsh advfirewall`. That capability was deliberately left out of this version: automatically writing live Windows Firewall rules from a learning project risks unintended self-lockout (e.g. blocking a legitimate spike from your router or another device on the network) for no real benefit in a single-machine testing context. The current version alerts and logs only, leaving any response decision to the user.

**Per-IP rate over raw packet count.** Tracking packets-per-second per source IP, rather than a global packet count, more closely mirrors how real DoS/DDoS detection systems work — distinguishing one IP hammering the network from many IPs producing normal aggregate traffic (as the speed-test testing phase incidentally demonstrated).

## Known limitations

- Per-IP rate detection cannot identify distributed (multi-IP) flooding patterns, since no single source crosses the threshold individually — a fundamental tradeoff of this detection strategy, not an implementation bug.
- Loopback (`127.0.0.1`) traffic is not reliably visible to Npcap on Windows, so self-testing must target a real network-facing IP instead.
- Requires Administrator privileges to run at all, due to Windows' restrictions on raw packet capture.

## Potential next steps

- Persist alerts to a log file with timestamps for historical analysis
- Add a per-IP cooldown so sustained floods don't need re-triggering logic beyond the existing one-time flag
- Track rolling/multi-window averages instead of single 1-second snapshots, to reduce sensitivity to brief legitimate bursts
- Optional, explicitly user-confirmed enforcement mode using `netsh advfirewall`, gated behind a clear opt-in flag

## License

MIT
