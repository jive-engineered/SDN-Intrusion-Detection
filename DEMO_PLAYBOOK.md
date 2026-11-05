# SDN IDS + IPS — Single-Laptop Execution Playbook (Deliverable 2)

**Project:** SDN-Based Intrusion Detection System (IDS) with inline Intrusion
Prevention System (IPS) hardware mitigation, built on Ryu + Open vSwitch + Mininet.

- **IDS layer** — the detection engine (`controller/ids_engine.py`): classifies
  TCP traffic across seven behavioural rules and emits `[IDS ALERT]` events.
- **IPS layer** — the automatic mitigation (`controller/ids_controller.py`):
  on every alert installs a hardware DROP rule via `OFPFlowMod` within a few
  milliseconds, and evicts it automatically on `idle_timeout`.

**Setup:** Ubuntu 22.04, Python 3.10, venv at `~/ryu-venv`, one laptop (`127.0.0.1`).

**Topology (single mode) — realistic 13-host office LAN (2 attackers):**

| Host | IP | Role | Services (if server) |
|---|---|---|---|
| **h1** | 10.0.0.1 | 🔴 Attacker #1 | — |
| **h10** | 10.0.0.13 | 🔴 Attacker #2 (coordinated-attack demo) | — |
| **h2** | 10.0.0.2 | 🛡️ Primary app server | 22, 80, 443, 5000 |
| **srv2** | 10.0.0.10 | 🛡️ File server | 21, 445, 8080 |
| **srv3** | 10.0.0.11 | 🛡️ Database | 3306, 5432 |
| **srv4** | 10.0.0.12 | 🛡️ Mail / DNS | 25, 53, 143 |
| h3 | 10.0.0.3 | ✅ Heartbeat client (steady 2 req/s) | — |
| h4–h9 | 10.0.0.4–9 | ✅ Employee workstations (randomised chatter) | — |

**Background traffic:** `apps/background_traffic.py` runs on every h3–h9. Each
client hits a random server on a random service port every 0.3–2.5 s (with
occasional 3-5-request "page load" bursts). ~50-100 legit TCP flows/sec at any
moment. During an attack the dashboard shows 7 green lines humming and 1 red
line spiking → getting cut — "zero collateral damage" is visual, not claimed.

**Live dashboard (full-traffic view):** every host's sent/recv packets-per-second and totals are read straight from the switch port counters (so ALL traffic shows - allowed, dropped, legit, attacker), plus a live 'who talks to whom' connection table, traffic-by-service bars, an all-traffic activity feed (connection OPEN/CLOSE + IDS alerts) and the full OVS flow table. Chart has a linear/log toggle.

**Live dashboard (details):** `sudo python3 tools/sdn_cli.py sdn-ui` → browse to
`http://127.0.0.1:8080`. Real-time per-host status grid, per-source-IP packet-
rate chart, active quarantine list with TTL countdown, and a scrolling event
feed showing every alert / block / recovery with latency.

> One-laptop fix: `run_attacker.sh` and `tools/sdn_cli.py` auto-detect that
> there is no standalone `attacker` netns and transparently run every attack
> inside Mininet host `h1` via `tools/mininet_host_exec.sh h1`.

---

## OPTION 1 — The 1-click demo (recommended for the evaluation)

```bash
cd ~/Desktop/sdn-ids
./selftest.sh                              # confirm READY ✅ before you commit
source ~/ryu-venv/bin/activate             # so ryu-manager is on PATH
sudo ./auto_demo.sh
```

That single command:
1. launches the Ryu controller + single-laptop Mininet in `tmux` (if not already running),
2. starts the legit `h3 → h2:5000` client,
3. runs all six attack vectors, after each printing the **live OVS DROP rules**, proving **h1 = 100 % loss** and **h3 = 0 % loss**,
4. demonstrates IPS self-healing (automatic DROP eviction), and
5. prints the final `report.py` benchmark and exports `logs/deliverable2_results.csv`.

Useful variants:
```bash
sudo ./auto_demo.sh --no-launch         # controller + Mininet already running in their own terminals
sudo ./auto_demo.sh --heal-wait 35      # really wait for idle_timeout eviction instead of sdn-unblock
sudo KEEP_UP=1 ./auto_demo.sh           # leave the tmux sessions up afterwards
```
Watch the controller live in another terminal: `tmux attach -t sdn-brain` (detach with `Ctrl-b d`).

---

## OPTION 2 — Manual, terminal-by-terminal (recommended for live presentation)

### One-time install of the short commands (optional but handy)
```bash
cd ~/Desktop/sdn-ids
sudo ./tools/install_cli_shortcuts.sh    # gives you sdn-flows, atk-scan, atk-rate, ... globally
```

### Terminal 1 — Controller (the IDS/IPS "brain")
```bash
cd ~/Desktop/sdn-ids
source ~/ryu-venv/bin/activate
sudo ./run_controller.sh
```
Leave it running. You will watch `[IDS ALERT]`, `[IDS RESPONSE ... MITIGATED]`,
`[FLOW-STATS]` and `[IDS RECOVERY]` lines appear here. **Point to this terminal
during each attack — it is the money shot.**

### Terminal 2 — Switch + hosts (Mininet, single mode)
```bash
cd ~/Desktop/sdn-ids
sudo ./run_switch.sh 127.0.0.1
```
Wait for `*** Switch connected to controller`. This also auto-starts the server
on `h2`. Leave it at the `mininet>` prompt (that keeps `h1/h2/h3` alive).

### Terminal 3 — Attack console (what you type on)
Start the legitimate background traffic first:
```bash
cd ~/Desktop/sdn-ids
sudo python3 tools/sdn_cli.py legit-start     # or:  legit-start   (if shortcuts installed)
```

Run each vector, and after each one show the flow table + the two SLA checks:

```bash
# --- Group A: stateful IDS/IPS vectors (Packet-In detection path) --------

# 1) Stealth illegal TCP flags (NULL / XMAS / SYN+FIN)  -> invalid_flags
sudo ./run_attacker.sh invalid_flags --count 6
sudo python3 tools/sdn_cli.py sdn-flows        # see Priority-100 ip,nw_src=10.0.0.1 actions=drop

# 2) Port-scan reconnaissance                           -> port_scan
sudo python3 tools/sdn_cli.py sdn-unblock
sudo ./run_attacker.sh scan --ports 1-40 --delay 0.1
sudo python3 tools/sdn_cli.py sdn-flows

# 3) Multi-IP spoof from one host (ingress-port quarantine) -> multi_ip_spoof
sudo python3 tools/sdn_cli.py sdn-unblock
sudo ./run_attacker.sh spoof --count 25
sudo python3 tools/sdn_cli.py sdn-flows        # see Priority-200 in_port=1 actions=drop

# --- Group B: heavy-traffic / volumetric (flow-counter polling path) ----

# 4) High-rate SYN connection flood                     -> conn_flood
sudo python3 tools/sdn_cli.py sdn-unblock
sudo ./run_attacker.sh flood --rate 80 --duration 12
sudo python3 tools/sdn_cli.py sdn-flows

# 5) Slow-and-low state exhaustion (>=40 held flows)    -> concurrent_flows
sudo python3 tools/sdn_cli.py sdn-unblock
sudo ./run_attacker.sh concurrent                       # = conn_flood --hold --rate 5 --duration 30
sudo python3 tools/sdn_cli.py sdn-flows

# 6) Volumetric high-PPS flood                          -> packet_rate
sudo python3 tools/sdn_cli.py sdn-unblock
sudo ./run_attacker.sh packet_rate --flows 4 --duration 15
sudo python3 tools/sdn_cli.py sdn-flows
```

Prove zero collateral damage at any point:
```bash
sudo python3 tools/sdn_cli.py test-h1          # attacker: 100% packet loss (blocked at edge)
sudo python3 tools/sdn_cli.py test-h3          # legit  :   0% packet loss (SLA intact)
```

IPS self-healing (automatic eviction):
```bash
# stop attacking and wait ~30s; Terminal 1 logs: [IDS RECOVERY] 10.0.0.1 UNBLOCKED (idle timeout)
sudo python3 tools/sdn_cli.py sdn-flows        # DROP rule is gone
sudo python3 tools/sdn_cli.py sdn-unblock      # (manual equivalent if you don't want to wait)
```

Final numbers:
```bash
sudo python3 tools/sdn_cli.py sdn-report --csv logs/deliverable2_results.csv
```

With shortcuts installed, Terminal 3 becomes:
`legit-start` · `atk-flags` · `atk-scan` · `atk-spoof` · `atk-flood` ·
`atk-concurrent` · `atk-rate` · `sdn-flows` · `sdn-unblock` · `test-h1` ·
`test-h3` · `sdn-report` — or just `sdn-autopilot`.

---

## The six rules and how each is proven

| # | Vector (command) | IDS rule | Detection path | IPS mitigation flow |
|---|---|---|---|---|
| 1 | `invalid_flags` | `invalid_flags` | Packet-In, flag classification (real time) | Priority-100 `ip,nw_src=10.0.0.1 drop` |
| 2 | `scan` | `port_scan` | Packet-In, distinct-dport counter | Priority-100 IP drop |
| 3 | `spoof` | `multi_ip_spoof` | Packet-In, one MAC rotating many IPs | Priority-200 ingress-**port** quarantine |
| 4 | `flood` | `conn_flood` | Packet-In, SYN-rate window (< 200 ms) | Priority-100 IP drop |
| 5 | `concurrent` | `concurrent_flows` | **Flow-counter polling** (`OFPFlowStatsRequest`) | Priority-100 IP drop |
| 6 | `packet_rate` | `packet_rate` | **Flow-counter polling** (pps delta) | Priority-100 IP drop |

Vectors 5 and 6 are the heavy-traffic proof: established connections are
offloaded to the OVS kernel fast-path (Priority-20 exact 5-tuple), so only
the initial SYN ever reaches the controller (Priority-5 → CONTROLLER). The
volumetric surge is caught by **asynchronous counter polling**, not by flooding
the Ryu control plane — that is what keeps the controller CPU flat under load.

---

## IDS vs IPS — the viva answer

- **IDS = detection only.** Watches traffic, raises alerts, logs incidents.
  Does not act. In this project: `controller/ids_engine.py` + the `[IDS ALERT]`
  lines + `logs/ids_events.jsonl`.
- **IPS = detection + automatic mitigation inline on the data path.** Everything
  the IDS does, plus it drops the offending traffic in real time.
  In this project: `controller/ids_controller.py` installs an `OFPFlowMod`
  DROP rule in OVS within milliseconds of the alert, and removes it on
  `idle_timeout` via `OFPFlowRemoved`.

Put together: this is an **inline network IDS/IPS**, with the SDN controller as
the detection and decision point and OVS flow tables as the enforcement point.

---

## Quick troubleshooting

| Symptom | Fix |
|---|---|
| `auto_demo.sh` hangs at "Timed out waiting for controller listening on :6653" | Fixed in this build — `run_controller.sh` now resolves `~/ryu-venv` via `SUDO_USER` even under sudo. If it still happens: `tmux attach -t sdn-brain` to see the real error, or `tail -n 40 logs/controller.out`. |
| `Cannot open network namespace "attacker"` | Fixed. Ensure Mininet is up so host `h1` exists: `sudo ./run_switch.sh 127.0.0.1`. |
| `No attacker environment found` | Terminal 2 must be at the `mininet>` prompt (that keeps `h1` alive). |
| `ryu-manager: command not found` | `source ~/ryu-venv/bin/activate` before `run_controller.sh`, or set `RYU_VENV=/absolute/path/to/venv`. |
| Switch never connects | `sudo python3 tools/sdn_cli.py sdn-sync 127.0.0.1`, and check `sudo ufw allow 6653/tcp`. |
| Rule won't re-trigger | `sudo python3 tools/sdn_cli.py sdn-unblock` (resets engine state on FLOW_REMOVED). |
| `tmux not found` (auto_demo) | `sudo apt install -y tmux`, or run OPTION 2 manually and use `sudo ./auto_demo.sh --no-launch`. |
| Scapy missing (spoof / invalid_flags) | `~/ryu-venv/bin/pip install scapy` |
