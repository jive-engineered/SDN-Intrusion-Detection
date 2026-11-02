# SDN Network Intrusion Detection & Response (Project 25 – TCP)

An intrusion-detection **and prevention** prototype built with **Ryu + OpenFlow 1.3 + Open vSwitch + Mininet**.
It watches TCP traffic, detects abnormal behaviour (connection floods, port scans, illegal TCP flags, slow
"hold-open" attacks) and **blocks the attacker inside the switch** by installing a priority-100 DROP rule –
while legitimate users keep working with 0 % loss. Detection time and response time are measured and reported.

---------------------------------------------------------------------------------------------------------

## 1. Requirements → where they are implemented

| # | Project expectation | Implementation |
|---|---|---|
| 1 | Generate controlled TCP security-test traffic | `apps/attack_port_scan.py`, `apps/attack_conn_flood.py` (+ legit `apps/tcp_client.py`, victim `apps/tcp_server.py`) |
| 2 | Monitor connection rates | Every new TCP connection (SYN) reaches the controller → per-source sliding window in `controller/ids_engine.py` |
| 3 | Collect flow statistics | `OFPFlowStatsRequest` poller in `ids_controller.py` (`_monitor`, `_process_stats`), writes `logs/flow_stats.csv` |
| 4 | Define intrusion-detection rules | 5 rules (table in §4), editable in `controller/ids_rules.json` (hot-reloaded, no restart) |
| 5 | Detect abnormal connection behaviour | `IDSEngine.observe_tcp()` (real-time) + `IDSEngine.evaluate_stats()` (statistics) |
| 6 | Simulate controlled scanning | `attack_port_scan.py` – connect scan, plus optional SYN/FIN/NULL/XMAS scans (scapy) |
| 7 | Dynamically block suspicious sources | `_react()` → `OFPFlowMod` priority 100, `actions=[]` (drop), `idle_timeout=30`, auto-recovery via `OFPFlowRemoved` |
| 8 | Measure detection and response time | `BLOCK_INSTALLED` events (OpenFlow **barrier** confirms the rule is active) → `python3 tools/report.py` |

---------------------------------------------------------------------------------------------------------

## 2. Architecture (3 laptops)

```
 LAPTOP A  (controller)                LAPTOP B  (network)                          LAPTOP C  (attacker)
 ┌───────────────────────┐   OpenFlow  ┌──────────────────────────────┐   VXLAN     ┌───────────────────────┐
 │ Ryu  ids_controller.py│◄───1.3─────►│  Open vSwitch  s1            │◄══tunnel═══►│ OVS bridge br-att     │
 │  • L2 learning        │  TCP 6653   │     │              │         │  UDP 4789   │   │                   │
 │  • IDS engine         │             │  h2 server       h3 legit     │             │ namespace "attacker"  │
 │  • flow-stats poller  │             │  10.0.0.2        10.0.0.3     │             │ 10.0.0.1              │
 │  • DROP rule installer│             │  (Mininet)       (Mininet)    │             │ port-scan / flood     │
 └───────────────────────┘             └──────────────────────────────┘             └───────────────────────┘
```

* **One logical LAN `10.0.0.0/24`** – the attacker on Laptop C is tunnelled (VXLAN) into switch `s1` on Laptop B, so it
  appears to the controller as a normal host on switch port 10. Works over Wi-Fi/Ethernet, any IP network.
* The three laptops only need **IP reachability** to each other (same router / phone hotspot).

| Laptop | Role | Runs | Needs installed |
|---|---|---|---|
| **A** | SDN controller | `./run_controller.sh` | Ryu |
| **B** | Network / victim side | `sudo ./run_switch.sh <A_IP> <C_IP>` | Mininet, Open vSwitch |
| **C** | Attacker | `sudo ./topology/attacker_node.sh up <B_IP>` then `sudo ./run_attacker.sh …` | Open vSwitch (+scapy optional) |

### Flow-table design (the key idea)

| Priority | Match | Action | Installed by |
|---|---|---|---|
| **100** | `ipv4_src = attacker` | **DROP** (no actions), idle-timeout 30 s | IDS, on detection |
| 20 | exact TCP 5-tuple (both directions) | output port, idle-timeout 10 s | controller, per connection |
| 5 | any TCP packet | → controller | at switch connect |
| 1 | in_port + eth_dst + eth_src | output port | learning switch (ARP/ICMP/…) |
| 0 | table-miss | → controller | at switch connect |

A **new** TCP connection has a **new 5-tuple**, so its first packet (SYN) misses priority 20, hits priority 5 and goes to
the controller. The controller counts it, installs the two priority-20 rules and forwards. All remaining packets of that
connection are switched at line rate – the controller only ever sees *connection attempts*, not every packet
(much more scalable than sending all traffic to the controller). Priority 100 beats everything, so a blocked host is
dropped inside the switch and can no longer overload the controller.

---------------------------------------------------------------------------------------------------------

## 3. Setup

### 3.1 Use Ubuntu 22.04 on all three laptops
Ryu is old software; it works well with Ubuntu 22.04 (Python 3.10). On Ubuntu 24.04 (Python 3.12) Ryu 4.34 + eventlet
fail to import – do **not** use 24.04 for Laptop A (install 22.04, or a 22.04 VM/dual-boot).

### 3.2 Network
1. Connect the three laptops to the **same network** (best: one phone hotspot or a small router; cable if possible).
   Campus Wi-Fi often has *client isolation* (laptops cannot see each other) – then use a hotspot.
2. Find each laptop's IP: `hostname -I` → call them `A_IP`, `B_IP`, `C_IP`.
3. Check: from each laptop `ping <other IPs>`.
4. If `ufw` is active:
   * Laptop A: `sudo ufw allow 6653/tcp`
   * Laptop B and C: `sudo ufw allow 4789/udp`
   (or simply `sudo ufw disable` for the demo).

### 3.3 Copy the project to every laptop
Unzip `sdn-ids.zip` (USB stick, `scp`, or git) so the same folder exists on all three, e.g. `~/sdn-ids`.

### 3.4 Install (once, needs internet)
```bash
cd ~/sdn-ids
./tools/install_ubuntu.sh controller   # Laptop A  (Ryu in ~/ryu-venv)
./tools/install_ubuntu.sh switch       # Laptop B  (Mininet + Open vSwitch)
./tools/install_ubuntu.sh attacker     # Laptop C  (Open vSwitch + scapy)
```
Then check each laptop (add the IPs of the others to also test connectivity):
```bash
./tools/preflight.sh controller <B_IP> <C_IP>     # on A
./tools/preflight.sh switch     <A_IP> <C_IP>     # on B
./tools/preflight.sh attacker   <A_IP> <B_IP>     # on C
```

### 3.5 Start-up order (A → B → C)

**Laptop A – controller**
```bash
cd ~/sdn-ids
./run_controller.sh
```
Wait for `IDS controller started`. Leave this window visible – it is your live IDS console.

**Laptop B – network** (terminal 1)
```bash
cd ~/sdn-ids
sudo ./run_switch.sh <A_IP> <C_IP>
```
You should see `*** Switch connected to controller` and on Laptop A: `[SWITCH] s1 connected …`.
You are now in the `mininet>` prompt. (If the CLI shows `Switch NOT connected` → §7.)

**Laptop C – attacker**
```bash
cd ~/sdn-ids
sudo ./topology/attacker_node.sh up <B_IP>
sudo ./run_attacker.sh ping            # must show replies from 10.0.0.2
```
(The ping works only after Laptop B is running.) ✔ **Setup finished.**

Optional extra terminals on Laptop B (nice on the projector):
```bash
tail -f ~/sdn-ids/logs/legit.out                                   # legitimate user view
tail -f ~/sdn-ids/logs/server.log                                  # victim server view
watch -n1 "sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | grep -E 'priority=100|priority=5,'"   # DROP rule appears live
```

---------------------------------------------------------------------------------------------------------

## 4. IDS rules (`controller/ids_rules.json`)

| Rule | Detects | Default | Source of data |
|---|---|---|---|
| `conn_flood` | too many **new TCP connections** from one source | ≥ 20 SYN in 3 s | packet-in (real time) |
| `port_scan` | many **different destination ports** from one source | ≥ 8 distinct ports in 10 s | packet-in (real time) |
| `invalid_flags` | illegal flag combos: NULL, XMAS, SYN+FIN, SYN+RST, FIN-only | ≥ 3 packets in 10 s (packets are dropped immediately) | packet-in (real time) |
| `concurrent_flows` | "slow and low" attack: too many **simultaneous flows** from one source | ≥ 40 active flows | **OpenFlow flow statistics** |
| `packet_rate` | volumetric: packets/second from one source (delta of flow counters) | ≥ 3000 pps | **OpenFlow flow statistics** |

`protected_hosts` (default `10.0.0.2`, the server) are never blocked. `block_idle_timeout` = 30 s: if the attacker stays silent
for 30 s the switch removes the DROP rule itself and the controller logs `UNBLOCKED` (automatic recovery).
Thresholds are re-read every few seconds – you can change them live during the presentation.

Legit user: 1–2 connections/s to **one** port → far below every limit.

---------------------------------------------------------------------------------------------------------

## 5. Demo script (≈ 10 minutes)

Before starting: `python3 tools/report.py --clear` (on A) for clean logs.

### Step 0 – baseline (Laptop B, `mininet>` prompt)
```
mininet> h3 python3 apps/tcp_client.py --server 10.0.0.2 --port 5000 --duration 300 > logs/legit.out 2>&1 &
```
`tail -f logs/legit.out` shows `OK rtt=…ms`. Laptop A prints `[FLOW-STATS] 10.0.0.3 flows=… | blocked: -`.
*Say:* "This is a normal user. The controller sees one new connection per 0.5 s – normal."

### Step 1 – port scan (Laptop C)
```bash
sudo ./run_attacker.sh scan --ports 1-1024 --delay 0.05
```
Expected: scan starts, **Laptop A shows a red `[IDS ALERT] 10.0.0.1 | rule=port_scan | 8 distinct destination ports …`**,
then `[IDS RESPONSE] … BLOCKED in switch | detection=… ms | response=… ms`. The scanner prints
`*** BLOCKED *** 10 consecutive probes dropped` and finds **no open ports** (22/80/443/5000 are open on the server).
On Laptop B the `watch` window now shows the `priority=100 … nw_src=10.0.0.1 actions=drop` rule with a growing packet counter.
The legit client keeps printing `OK`.

### Step 2 – recovery
Stop attacking and wait ~30 s. Laptop A: `[IDS RECOVERY] 10.0.0.1 UNBLOCKED (idle timeout)`. The DROP rule disappears.
Check: `sudo ./run_attacker.sh ping` works again.

### Step 3 – connection flood (Laptop C)
```bash
sudo ./run_attacker.sh flood --rate 60 --duration 20
```
Expected output: first second ≈ `connected(+19)`, then `connected(+0) dropped/timeout(+60)` per second and
`*** BLOCKED ***`. Laptop A: `rule=conn_flood | 20 new TCP connections in 3.0s`, detection ≈ 300 ms, response ≈ 1–5 ms.

### Step 4 – slow attack that evades the rate rule, caught by flow statistics
Wait until unblocked (≈ 30 s after the flood), then:
```bash
sudo ./run_attacker.sh flood --rate 5 --hold --duration 40
```
5 conn/s is below the flood limit, so no alert for ~8–10 s, until the **flow-statistics poll** sees ≥ 40 active flows:
`rule=concurrent_flows | 44 active flows (limit 40)`. *Say:* "Different data source – the switch's own flow counters."

### Step 5 – (optional) stealth scan with illegal flags
```bash
sudo ./run_attacker.sh scan --mode xmas --ports 20-80 --delay 0.1
```
`rule=invalid_flags … XMAS-scan`. Illegal-flag packets are never forwarded; the 3rd one blocks the source.

### Step 6 – results
On Laptop A (or B):
```bash
python3 tools/report.py            # detection / response table
python3 tools/report.py --csv results.csv
```
Stop the legit client (`Ctrl+C` in its terminal or end of `--duration`) and show its summary:
`success: N failed: 0 loss: 0.0%`.

Typical numbers measured in testing: detection 0.3–1.2 s (depends on attack rate and thresholds), **response (alert → DROP rule
confirmed by the switch) 1–5 ms**, legitimate-client loss 0 %.

---------------------------------------------------------------------------------------------------------

## 6. Backup plan – everything on ONE laptop
If networking fails on the day, run the whole demo on one Ubuntu 22.04 laptop (`./tools/install_ubuntu.sh all` once):

```bash
# terminal 1
./run_controller.sh
# terminal 2
sudo ./run_switch.sh 127.0.0.1            # single mode: h1 = attacker, h2 = server, h3 = legit client
mininet> h3 python3 apps/tcp_client.py --duration 300 > logs/legit.out 2>&1 &
mininet> h1 python3 apps/attack_port_scan.py --target 10.0.0.2
mininet> h1 python3 apps/attack_conn_flood.py --target 10.0.0.2 --rate 60
```
Same controller, same rules, same results – only the attacker is virtual instead of a real laptop.
**Rehearse both versions.**

---------------------------------------------------------------------------------------------------------

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| `Switch NOT connected to the controller` | Laptop A: is `run_controller.sh` running? `ss -ltn \| grep 6653`. Firewall: `sudo ufw allow 6653/tcp`. Correct `A_IP`? On B: `sudo ovs-vsctl show` → `is_connected: true`. |
| `ryu-manager: command not found` | `source ~/ryu-venv/bin/activate` (run_controller.sh does this). Re-run `./tools/install_ubuntu.sh controller`. |
| `ImportError: cannot import name 'ALREADY_HANDLED'` / `No module named 'imp'` | Wrong eventlet / Python too new → use Ubuntu 22.04 and `pip install eventlet==0.30.2` inside `~/ryu-venv`. |
| Attacker ping fails (Laptop C) | Laptop B must be running first. `sudo ./topology/attacker_node.sh status`. UDP 4789 open on B and C? On B run `sudo tcpdump -ni any udp port 4789` while pinging – you must see packets from `C_IP`. Wi-Fi client isolation → use hotspot. Check `ovs-vsctl show` on B contains `vxlan0` (`remote_ip=C_IP`) and on C `vx0` (`remote_ip=B_IP`). |
| `RTNETLINK answers: File exists` / stale Mininet | `sudo mn -c`, then start again. |
| `modprobe: openvswitch not found` | `sudo apt install openvswitch-switch` ; reboot after a kernel update. |
| Scan is not detected | `python3 tests/test_engine.py`; check `controller/ids_rules.json` (`enabled: true`); is the controller log showing `[FLOW-STATS]` lines (switch connected)? |
| Legit client also blocked | Only if you changed thresholds too low. Raise them in `ids_rules.json`, or add the IP to the allow-listed `protected_hosts`. |
| Attacker still blocked at the start of a new demo | Wait 30 s (idle timeout) or restart `run_controller.sh` (it wipes the flow table on switch connect). |
| Messy `mininet>` output | Always redirect client output to files (`> logs/legit.out 2>&1 &`) and `tail -f` in another terminal. |

---------------------------------------------------------------------------------------------------------

## 8. How to explain it (talking points for the presentation)

**Suggested split (3 members, ~12 min):**
* **Member 1 – Concept & controller (Laptop A):** SDN control/data-plane separation, flow-table design (§2), why only SYNs hit the controller.
* **Member 2 – Network & traffic (Laptop B):** topology, legit user, how the DROP rule appears with `ovs-ofctl dump-flows`, flow statistics.
* **Member 3 – Attacks & results (Laptop C):** scan/flood/slow attack live demo, `tools/report.py` numbers, limitations.

**Key points to say**
1. *Why SDN for security?* Central view of all connections + ability to program every switch instantly (one `FlowMod`).
2. *Detection:* sliding-window counters per source IP (rate, distinct ports, illegal flags) + the switch's own flow counters (concurrent flows, pps).
3. *Response:* priority-100 flow with **no actions** = drop at wire speed inside Open vSwitch; protects the victim **and** the controller.
4. *Recovery:* `idle_timeout`; switch sends `OFPFlowRemoved`; controller clears state → no manual cleanup, TCAM freed.
5. *No collateral damage:* only the offending **source IP** is matched; other hosts untouched (show legit summary 0 % loss).
6. *Measurement:* detection = first packet → alert; response = alert → barrier reply from the switch (rule really active); total.

**Likely questions**
* *Why not send every packet to the controller (like the ICMP version)?* Doesn't scale; per-connection rules mean only SYNs are inspected.
* *Why barrier request?* `FlowMod` is asynchronous; the barrier reply proves the switch applied it, so response time is honest.
* *Can the attacker spoof IPs?* Yes – limitation. Mitigation ideas: ingress filtering / port-binding of IP-MAC, rate-limit per port.
* *False positives (NAT, busy proxies)?* Tune thresholds, allow-list, or add a first "rate-limit/meter" stage before blocking.
* *Single point of failure?* Yes – controller; production uses clustered controllers. Existing flows keep working if it dies.
* *Why TCP only?* Project scope; the same pattern extends to UDP/ICMP (see ICMP rule in the previous deliverable).
* *Why idle- and not hard-timeout?* An attacker who keeps attacking stays blocked; one who stops is released automatically.

---------------------------------------------------------------------------------------------------------

## 9. Project layout

```
sdn-ids/
├── README.md
├── run_controller.sh        Laptop A   start Ryu
├── run_switch.sh            Laptop B   start Mininet (distributed or single mode)
├── run_attacker.sh          Laptop C   scan / flood / ping inside the attacker namespace
├── controller/
│   ├── ids_controller.py    Ryu app: learning switch + flow stats + IDS reaction + metrics
│   ├── ids_engine.py        pure-Python detection engine (unit-tested)
│   └── ids_rules.json       thresholds (hot-reloaded)
├── topology/
│   ├── topo.py              Mininet: s1, h2 (server), h3 (legit) [+ h1 in single mode] + VXLAN port
│   └── attacker_node.sh     Laptop C: OVS bridge + VXLAN + "attacker" namespace
├── apps/
│   ├── tcp_server.py        victim service (ports 22 80 443 5000)
│   ├── tcp_client.py        legitimate user, reports loss & RTT
│   ├── attack_port_scan.py  controlled scan (connect / syn / fin / null / xmas)
│   └── attack_conn_flood.py controlled connection flood (--hold = slow variant)
├── tools/
│   ├── install_ubuntu.sh · preflight.sh · report.py
├── tests/
│   ├── test_engine.py · test_controller_mock.py
└── logs/                    ids_events.jsonl, flow_stats.csv, server.log, legit.out
```

## 11. Using the team's own files (Person A scripts: server on h1, client h2, attacker h3)

`team_files_fixed/` contains the team's `tcp_server.py`, `tcp_client.py`, `port_scanner.py`, `connection_burst.py`,
`traffic_measurement.py`, `attack.py` with three small fixes (see the review notes). To run them with this controller:

```bash
# Laptop A / single laptop: use the rules file that matches the team contract (>5 ports in 3 s, >20 connections per 1 s)
IDS_RULES=controller/ids_rules_team.json ./run_controller.sh
```
`ids_rules_team.json` also sets `protected_hosts` to **10.0.0.1** (the server in that layout). This matters: the default
(`10.0.0.2`) would leave the server unprotected and the flow-statistics rules could wrongly block it.
The team's topology script (h1 server, h2 client, h3 attacker) works unchanged with this controller; for the 3-laptop
version use `topology/topo.py` and swap the roles/IPs accordingly.

**Detection time** = start of the offending burst (oldest event inside the rule's window) -> alert.

## 10. Ethics / safety
The attack scripts are for **your own isolated lab network** (Mininet + your three laptops) as required by the course.
They use ordinary sockets (no spoofing, no amplification). Never point them at systems you do not own.

## Live telemetry dashboard

A self-contained, auto-updating dashboard is provided in `tools/telemetry_panel.py`; see [`TELEMETRY_RUNBOOK.md`](TELEMETRY_RUNBOOK.md) for the four-terminal demo, exact attack commands, distributed switch SSH option, logging audit, and troubleshooting. It uses Python's standard library and does not require external JavaScript/CDN assets.

```bash
python3 tools/telemetry_panel.py
# If Open vSwitch queries require root on this local demo machine:
sudo -E python3 tools/telemetry_panel.py
```

Open `http://127.0.0.1:8080`. For the distributed three-laptop setup, run the panel beside the controller logs and use `--ovs-ssh <switch-user>@<switch-ip>` to query the switch flow table remotely; SSH key authentication and non-interactive permission to run `ovs-ofctl` are required. By default, the panel binds to loopback only.
