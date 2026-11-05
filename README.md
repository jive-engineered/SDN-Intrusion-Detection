# SDN-Based Intrusion Detection & Prevention System

An **IDS + IPS** prototype for a software-defined network, built with **Ryu (OpenFlow 1.3) + Open vSwitch + Mininet**.
The controller watches every new TCP connection and the switch's own flow counters, detects seven kinds of
abnormal behaviour, and **blocks the attacker inside the switch** with a DROP rule, while legitimate hosts keep
working with 0 % packet loss. Detection time and response time are measured and reported.

Everything runs on **one Ubuntu 22.04 laptop** (a 13-host virtual office LAN). A three-laptop distributed
mode is also included (see [Distributed mode](#9-distributed-three-laptop-mode)).

> **Lab use only.** The attack scripts are controlled test-traffic generators for an isolated Mininet network.
> Never point them at systems you do not own.

---

## Contents

1. [What it does](#1-what-it-does)
2. [The lab network](#2-the-lab-network)
3. [How detection and prevention work](#3-how-detection-and-prevention-work)
4. [Quick start (four terminals)](#4-quick-start-four-terminals)
5. [Terminal 4: the attack menu](#5-terminal-4-the-attack-menu)
6. [The live telemetry dashboard](#6-the-live-telemetry-dashboard)
7. [Command-line tools](#7-command-line-tools)
8. [Automated demo, self-test and unit tests](#8-automated-demo-self-test-and-unit-tests)
9. [Distributed (three-laptop) mode](#9-distributed-three-laptop-mode)
10. [Project layout](#10-project-layout)
11. [Troubleshooting](#11-troubleshooting)
12. [Documentation](#12-documentation)
13. [Limitations and ideas](#13-limitations-and-ideas)

---

## 1. What it does

| Part | What it is | Where |
|---|---|---|
| **IDS** (detect) | Seven rules over per-source sliding windows and OpenFlow flow statistics | `controller/ids_engine.py` |
| **IPS** (prevent) | Installs DROP flows in the switch, confirms them with an OpenFlow barrier, removes them automatically when the attacker goes quiet | `controller/ids_controller.py` |
| **Attack generators** | Six controlled attacks, run from two attacker hosts (`h1`, `h10`) | `apps/attack_*.py`, `t4_attacker.sh` |
| **Telemetry dashboard** | Live web page: every host, every packet, graphs, blocks, event feed | `tools/telemetry_panel.py` |
| **CLI suite** | `sdn-flows`, `sdn-unblock`, `test-h1`, `sdn-report`, ... | `tools/sdn_cli.py` |
| **Report** | Detection / response time table from the event log | `tools/report.py` |

---

## 2. The lab network

One switch `s1` and 13 hosts on `10.0.0.0/24`. Each host sits on its own switch port.

| Host | IP | Role | Switch port |
|---|---|---|---|
| `h1` | 10.0.0.1 | **attacker** (primary) | 1 |
| `h2` | 10.0.0.2 | app server (ports 22, 80, 443, 5000) | 2 |
| `srv2` | 10.0.0.10 | file server (21, 445, 8080) | 3 |
| `srv3` | 10.0.0.11 | database (3306, 5432) | 4 |
| `srv4` | 10.0.0.12 | mail / DNS (25, 53, 143) | 5 |
| `h3` to `h9` | 10.0.0.3 to 10.0.0.9 | legitimate clients, generate background traffic | 6 to 12 |
| `h10` | 10.0.0.13 | **attacker** (second) | 13 |

The servers and the seven clients are listed in `protected_hosts` so normal office traffic is never blocked.
Both attackers stay subject to detection.

---

## 3. How detection and prevention work

### Detection rules (`controller/ids_rules.json`, hot-reloaded, no restart needed)

| Rule | Detects | Default threshold | Data source | Action |
|---|---|---|---|---|
| `invalid_flags` | illegal TCP flag combinations (NULL, XMAS, SYN+FIN, ...) | 3 packets in 10 s | Packet-In | block source IP |
| `port_scan` | many different destination ports from one source | 8 ports in 10 s | Packet-In | block source IP |
| `conn_flood` | too many new TCP connections | 20 SYN in 3 s | Packet-In | block source IP |
| `multi_ip_spoof` | one MAC using many source IPs | more than 2 IPs in 4 s | Packet-In | **quarantine the whole port** |
| `port_flood` | too many Packet-Ins from one switch port | 35 in 3 s | Packet-In | **quarantine the whole port** |
| `concurrent_flows` | "slow and low": too many simultaneous flows | 40 flows | flow statistics (polled every 3 s) | block source IP |
| `packet_rate` | volumetric flood: packets per second | 3000 pps | flow statistics (polled every 3 s) | block source IP |

### Flow table on `s1`

| Priority | Match | Action | Installed by |
|---|---|---|---|
| **200** | `in_port = N` | **DROP** (port quarantine), idle timeout 30 s | IPS, on `multi_ip_spoof` / `port_flood` |
| **100** | `ipv4_src = attacker` (or `eth_src` as fallback) | **DROP**, idle timeout 30 s | IPS, on detection |
| 20 | exact TCP 5-tuple, both directions | forward, idle timeout 10 s | controller, per connection |
| 5 | any TCP packet | send to controller | at switch connect |
| 1 | `in_port + eth_dst + eth_src` | forward | learning switch (ARP, ICMP, ...) |
| 0 | table miss | send to controller | at switch connect |

A **new** connection has a new 5-tuple, so its first packet (SYN) goes to the controller, which counts it and
installs the priority-20 rules. The rest of that connection is switched in the datapath, so the controller sees
connection attempts, not every packet. Priorities 100 and 200 beat everything, so a blocked host is dropped
at the switch edge and can no longer load the controller.

### Prevention and recovery

1. **Alert**: a rule fires and an `ALERT` event is logged with the detection latency.
2. **Mitigate**: the controller installs the DROP flow(s), then sends an OpenFlow **barrier request**. The barrier
   reply proves the switch applied the rule, so the logged response time is honest (`BLOCK_INSTALLED`).
3. **Self-heal**: the DROP flow has an idle timeout of 30 s and `SEND_FLOW_REM`. If the attacker stays silent,
   the switch removes the rule, sends `OFPFlowRemoved`, and the controller clears its state (`UNBLOCKED`).
4. **Manual release**: `sdn-unblock` (menu key **8**) deletes the DROP rules immediately.

Priorities 100 and 200 are reserved for IDS blocks in this repository.

---

## 4. Quick start (four terminals)

**Requirements:** Ubuntu 22.04 (Python 3.10), Open vSwitch, Mininet, Ryu in `~/ryu-venv`, scapy.
First-time install: `./tools/install_ubuntu.sh all`. Then check readiness (no sudo needed): `./selftest.sh`.

> **Start order matters: data plane first, controller second.** Mininet's startup cleanup kills any running
> `ryu-manager`, so starting the controller first gets it terminated.

Run each command in its **own terminal**, from the project folder (`cd ~/Desktop/sdn-ids`).

| Terminal | Command | You should see |
|---|---|---|
| **T1** data plane | `sudo ./t1_dataplane.sh` | the `mininet>` prompt. Leave it open. |
| **T2** controller | `sudo -E ./t2_controlplane.sh` | `[SWITCH] s1 connected`. Alerts print here live. |
| **T3** dashboard | `sudo ./t3_telemetry.sh` | open <http://127.0.0.1:8080> in a browser |
| **T4** attacker | `sudo ./t4_attacker.sh` | the attack menu |

Run T1, T2 and T3 once and leave them open. Only T4 is interactive.

**Clean restart** (if anything gets stuck):

```bash
sudo pkill -f '[t]opology/topo.py'; sudo pkill -f '[r]yu-manager'; sudo mn -c
```

then start T1, T2, T3, T4 again in that order.

---

## 5. Terminal 4: the attack menu

Every attack key first clears old blocks, runs the attack from the selected attacker, waits for detection to settle,
then shows the switch's DROP rules, whether the attacker is blocked, and whether the legitimate client `h3` is untouched.

| Key | Attack | Rule it should trigger |
|---|---|---|
| **1** | Illegal TCP flags (6 malformed packets) | `invalid_flags` |
| **2** | Port scan, ports 1 to 40 | `port_scan` |
| **3** | Multi-IP spoof (25 packets, rotating source IPs) | `multi_ip_spoof` (port quarantine) |
| **4** | SYN connection flood, 80 conn/s for 12 s | `conn_flood` |
| **5** | Slow-and-low, held-open connections for up to 30 s | `concurrent_flows` |
| **6** | Volumetric flood, 4 flows at very high packet rate | `packet_rate` |
| **c** | Coordinated: `h1` connection flood and `h10` volumetric flood at once | two blocks |
| **7** | Run attacks 1 to 6 in sequence (about 2 to 3 minutes; Ctrl+C returns to the menu) | all |
| **a** | Toggle the attacker between `h1` and `h10` | |
| **8** | Clear blocks (`sdn-unblock`) | |
| **9** | Show the flow table | |
| **0** | Verify SLA: ping from `h1`, `h10` and the legit client `h3` | |
| **s** | Make sure servers and background traffic are running | |
| **r** | Final report (writes `logs/deliverable2_results.csv`) | |
| **q** | Quit the menu (T1 to T3 keep running) | |

A good demo flow: press **s**, then **6** (watch the dashboard peak and the block), **0** (attacker blocked, `h3` fine),
**8** (release), **0** (attacker reachable again), then **4**, **3** and **5**.

---

## 6. The live telemetry dashboard

`http://127.0.0.1:8080`, served by `tools/telemetry_panel.py` (Python standard library only, no external assets).
It refreshes every 1.5 s and reads the switch's own port and flow counters, so it shows **all** traffic, not only blocked traffic.

| Panel | Shows |
|---|---|
| Threat banner | the active block, which rule fired, whether a whole port is quarantined |
| Stat strip | alerts, blocked hosts, network packets/s, throughput, live connections, **dropped by IPS** |
| Traffic chart | packets/s sent by every host (linear or log), dashed line = `packet_rate` threshold |
| Hosts table | all 13 nodes: sent/recv rate, packet totals, connections, dropped, state |
| Live connections | who is talking to whom, per client and service |
| Traffic by service | packets/s per destination port |
| Active blocks | each DROP rule, the rule that caused it, idle time left |
| Activity feed | all traffic, or IDS events only (`ALERT`, `BLOCK`, `RECOVER`) |

"Dropped by IPS" counts the blocked host's packets that the switch discarded. The total is kept after the block is released and
resets when the page is reloaded or T3 is restarted. After changing `telemetry_panel.py`, restart T3 and hard-refresh the browser (Ctrl+Shift+R).

---

## 7. Command-line tools

Run through `python3 tools/sdn_cli.py <command>`, or install global shortcuts once with `sudo ./tools/install_cli_shortcuts.sh`
and run `sdn-help`.

| Command | What it does |
|---|---|
| `sdn-flows` | Colour-coded flow table. DROP rules are always shown; add `--all` for every rule. |
| `sdn-unblock` | Delete all IDS DROP rules (priority 100 and 200) so blocked hosts can send again. |
| `test-h1` | Ping the server from the attacker `h1`. 100 % loss means blocked. |
| `test-h3` | Ping the server from the legitimate client. Should always be 0 % loss. |
| `legit-start` | Start servers and background client traffic. |
| `sdn-report --csv <file>` | Detection / response time table. |
| `sdn-ui` | Start the dashboard (what T3 runs). |

Attack scripts can also be run directly: `sudo ./run_attacker.sh {scan|flood|concurrent|packet_rate|spoof|invalid_flags|ping}`.
Set `SDN_ATTACKER=h10` to launch from the second attacker.
The full command reference is in [`DELIVERABLE2_CLI_RUNBOOK.md`](DELIVERABLE2_CLI_RUNBOOK.md).

---

## 8. Automated demo, self-test and unit tests

```bash
./selftest.sh                       # readiness check, prints READY / NOT READY
sudo ./auto_demo.sh                 # hands-free: every attack, flow-table proof, SLA proof, final report
sudo ./auto_demo.sh --no-launch     # assume T1 and T2 are already running
sudo ./diag.sh                      # one-shot diagnosis if an attack is not detected or blocked
```

Unit tests (no Mininet or OVS needed):

```bash
python3 -m unittest tests.test_engine tests.test_telemetry_panel tests.test_cli_suite -v
# controller tests need Ryu, so run them inside the venv:
source ~/ryu-venv/bin/activate && python3 -m unittest tests.test_controller_mock -v
```

---

## 9. Distributed (three-laptop) mode

The same code runs across three laptops: **A** (Ryu controller), **B** (switch + servers), **C** (attacker, tunnelled into `s1` over VXLAN).

```bash
./run_controller.sh                                   # Laptop A
sudo ./run_switch.sh <A_IP> <C_IP>                    # Laptop B
sudo ./topology/attacker_node.sh up <B_IP>            # Laptop C
sudo ./run_attacker.sh ping                           # Laptop C: must reply from 10.0.0.2
```

Start A, then B, then C. Ports and firewall: TCP 6653 open on A, UDP 4789 open on B and C. Configuration, SSH options and the SOC workflow
are in [`DELIVERABLE2_CLI_RUNBOOK.md`](DELIVERABLE2_CLI_RUNBOOK.md); the telemetry options are in [`TELEMETRY_RUNBOOK.md`](TELEMETRY_RUNBOOK.md).

---

## 10. Project layout

```
sdn-ids/
├── README.md
├── t1_dataplane.sh          T1  switch + 13-host network (Mininet)
├── t2_controlplane.sh       T2  Ryu IDS/IPS controller
├── t3_telemetry.sh          T3  web dashboard
├── t4_attacker.sh           T4  attack menu
├── run_switch.sh · run_controller.sh · run_attacker.sh    building blocks used by the scripts above
├── auto_demo.sh             hands-free demo
├── selftest.sh · diag.sh    readiness check · one-shot diagnosis
├── controller/
│   ├── ids_controller.py    Ryu app: learning switch, flow stats, IPS reaction, barrier-verified mitigation
│   ├── ids_engine.py        detection engine (pure Python, unit-tested)
│   ├── ids_rules.json       thresholds and protected hosts (hot-reloaded)
│   └── ids_rules_team.json  alternative rules for the legacy team scripts
├── topology/
│   ├── topo.py              Mininet topology (single and distributed modes)
│   └── attacker_node.sh     Laptop C: OVS bridge + VXLAN + attacker namespace
├── apps/                    traffic generators and servers
│   ├── tcp_server.py · tcp_client.py · background_traffic.py
│   └── attack_port_scan.py · attack_conn_flood.py · attack_invalid_flags.py
│       attack_spoof_flood.py · attack_packet_rate.py
├── tools/
│   ├── sdn_cli.py           the sdn-* / atk-* command suite
│   ├── telemetry_panel.py   live dashboard (panel.py is the older, simpler panel)
│   ├── mininet_host_exec.sh run a command inside a Mininet host
│   ├── report.py · plot_results.py · preflight.sh
│   └── install_ubuntu.sh · install_cli_shortcuts.sh · sdn-cli.conf.example
├── tests/                   test_engine, test_telemetry_panel, test_cli_suite, test_controller_mock
├── docs/                    guides (PDF), architecture diagram, sample results
├── logs/                    runtime output: ids_events.jsonl, flow_stats.csv, status.json (not committed)
└── team_files_fixed/        legacy scripts from an earlier team layout (kept for reference)
```

---

## 11. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `ovs-ofctl: s1 is not a bridge or a socket` | The network is not running. Start T1 first (`sudo ./t1_dataplane.sh`). |
| `Found multiple Mininet shells for hN` | Two topologies are running, or an old copy of the host-exec script is in use. Do a [clean restart](#4-quick-start-four-terminals). Make sure `tools/mininet_host_exec.sh` is the current version (it matches host names exactly, so `h1` does not match `h10`). |
| Controller gets terminated right after starting | The controller was started before T1. Start T1, wait for `mininet>`, then start T2. |
| An attack is not detected or blocked | Run `sudo ./diag.sh` and read it top to bottom. Check that T2 shows `[SWITCH] s1 connected`. |
| Attacker looks blocked when you did not expect it | A block from an earlier attack is still active (30 s idle timeout). Press **8**, then **0**. |
| `sdn-unblock` prints `unknown keyword priority` | Old `sdn_cli.py`. The current version deletes each DROP rule with `ovs-ofctl --strict`. |
| Dashboard shows old behaviour after an update | Restart T3 and hard-refresh the browser (Ctrl+Shift+R). |
| Dashboard port 8080 already in use | Another dashboard is running. Stop it, or use `python3 tools/telemetry_panel.py --port 8081`. |
| `ryu-manager: command not found` | Run through `run_controller.sh` / `t2_controlplane.sh` (they activate `~/ryu-venv`), or `./tools/install_ubuntu.sh controller`. |
| `ImportError` for `eventlet` / `imp` | Python is too new. Use Ubuntu 22.04 and `pip install eventlet==0.30.2` inside `~/ryu-venv`. |
| `RTNETLINK answers: File exists`, stale Mininet | `sudo mn -c`, then start again. |

---

## 12. Documentation

| File | Contents |
|---|---|
| [`DEMO_PLAYBOOK.md`](DEMO_PLAYBOOK.md) | Step-by-step demo script and talking points |
| [`DELIVERABLE2_CLI_RUNBOOK.md`](DELIVERABLE2_CLI_RUNBOOK.md) | CLI suite, three-laptop configuration, SOC unblock workflow, report |
| [`TELEMETRY_RUNBOOK.md`](TELEMETRY_RUNBOOK.md) | Dashboard operation, distributed OVS-over-SSH option, troubleshooting |
| [`docs/SDN_IDS_IPS_Concepts_and_Guide.pdf`](docs/SDN_IDS_IPS_Concepts_and_Guide.pdf) | Concepts, IDS/IPS logic start to end, each dashboard panel explained, one-page command guide |
| [`docs/SDN_IDS_IPS_Dashboard_Changes_per_Attack.pdf`](docs/SDN_IDS_IPS_Dashboard_Changes_per_Attack.pdf) | What changes on the dashboard for each attack key |
| [`CONTROLLER_LOGGING_AUDIT.patch`](CONTROLLER_LOGGING_AUDIT.patch) | Logging audit patch (reference) |

---

## 13. Limitations and ideas

* The controller is a single point of failure. Existing flows keep working if it stops, but new connections and new detection do not.
* Blocking by source IP or port can be bypassed by an attacker who spoofs addresses, which is why `multi_ip_spoof` and `port_flood`
  quarantine the whole port instead.
* Only TCP is inspected. The same pattern extends to UDP and ICMP (for example an ICMP flood rule).
* Possible extensions: OpenFlow meters for a rate-limit stage before blocking, threshold tuning per host role,
  per-rule metrics export.

## Team Contributions

| Member | Role | Contributions |
|---|---|---|
| **Jivesh R M (SRN: PES1UG25CS229)** | Data plane and network topology | • Designed the 13-host Mininet topology (attackers h1/h10, servers, legitimate clients) on a single Open vSwitch `s1`<br>• Built the data-plane startup script (`t1_dataplane.sh`) and the topology files<br>• Created the legitimate traffic generators: the h3 heartbeat client and the h4–h9 background chatter<br>• Developed the live telemetry dashboard (`telemetry_panel.py`, port 8080)<br>• Wrote the documentation: README, architecture diagram, command sheet and demo playbook |
| **Karakkagari Jayasimha (SRN: PES1UG25CS241)** | Control plane: IDS and IPS logic | • Developed the Ryu OpenFlow 1.3 controller (`ids_controller.py`) with Packet-In handling and L2 learning<br>• Implemented the 7-rule detection engine (`ids_engine.py`) using sliding windows and 3-second flow-stats polling<br>• Implemented mitigation: priority-100 IP drops and priority-200 port quarantine, barrier-verified (`BLOCK_INSTALLED`)<br>• Implemented self-healing through FlowRemoved and idle timeouts<br>• Designed the flow-table priorities and timeouts |
| **Keerthana Vasanthakumar (SRN: PES1UG25CS248)** | Attack simulation, telemetry and testing | • Built the attack console (`t4_attacker.sh`, `run_attacker.sh`) covering six attack types plus the coordinated h1 + h10 attack<br>• Wrote the unit tests and ran the end-to-end validation<br>• Built the CLI tools (`sdn_cli.py`), including flow inspection, unblock and the final report<br>• Verified the SLA: 0% packet loss for legitimate traffic during attacks<br>|

*All members took part in design discussions, integration testing and the final demonstration.*
