# SDN-Based Intrusion Detection & Hardware Mitigation System (TCP)

An enterprise-grade intrusion detection and prevention platform built using **Ryu + OpenFlow 1.3 + Open vSwitch (OVS) + Mininet**. 

The system inspects Layer 3/4 headers across transport connections, detects malicious traffic patterns (horizontal port scans, TCP SYN connection floods, and multi-IP source address spoofing), and dynamically deploys **hardware-level OpenFlow quarantine rules (`Priority 200/100 DROP`)** directly into the OVS kernel datapath. Malicious nodes are isolated at line rate with zero control-plane saturation, while legitimate host traffic runs with **0% packet loss**.

---

## 1. System Architecture & Topology

The entire platform runs locally on a single machine running **Ubuntu 22.04 LTS**. Mininet creates a virtual software-defined network isolated using Linux network namespaces (`netns`), coordinated by a central Ryu SDN controller over an OpenFlow 1.3 control channel (`TCP 6653`).

```text
                    +---------------------------------------------+
                    |        MANAGEMENT & TELEMETRY PLANE         |
                    |    Telemetry Web Dashboard (Port 8080)      |
                    +----------------------▲----------------------+
                                           │ Live Polling / Stats
                    +----------------------▼----------------------+
                    |                CONTROL PLANE                |
                    |             Ryu SDN Controller              |
                    |  - L2 Learning & Proactive MAC Tracking     |
                    |  - Sliding-Window Telemetry Engine          |
                    |  - Reactive Flow-Mod Hardware Mitigation    |
                    +----------------------▲----------------------+
                                           │ OpenFlow 1.3 (TCP 6653)
+------------------------------------------▼------------------------------------------+
|                         DATA PLANE (Open vSwitch Kernel)                            |
|                                                                                     |
|   +-----------------------+     +-----------------------+     +------------------+  |
|   |   Host 1: Attacker    |     |    Host 2: Server     |     |  Host 3: Client  |  |
|   |      (10.0.0.1)       |     |      (10.0.0.2)       |     |    (10.0.0.3)    |  |
|   |  Port Scan / Floods   |     | Target Ports: 22, 80, |     | Benign Traffic   |  |
|   |  & Multi-IP Spoofing  |     |       443, 5000       |     |  (0% Loss Goal)  |  |
|   +-----------┬-----------+     +-----------┬-----------+     +--------┬---------+  |
|               │ (veth1)                     │ (veth2)                  │ (veth3)    |
|               ▼                             ▼                          ▼            |
|         [ Switch Port 1 ]             [ Switch Port 2 ]          [ Switch Port 3 ]  |
|   +-----------------------------------------------------------------------------+   |
|   |                       Open vSwitch Bridge (s1)                              |   |
|   +-----------------------------------------------------------------------------+   |
+-------------------------------------------------------------------------------------+
```

### Topology & Host Roles

| Node | IP Address | MAC Address | Switch Port | Role & Function |
| :--- | :--- | :--- | :--- | :--- |
| **`s1`** | N/A | Open vSwitch | Datapath | OpenFlow 1.3 switch executing line-rate forwarding and kernel drops. |
| **`h1`** | `10.0.0.1` | `00:00:00:00:00:01` | `Port 1` | **Malicious Attacker:** Generates port scans, SYN floods, and multi-IP spoofed packets. |
| **`h2`** | `10.0.0.2` | `00:00:00:00:00:02` | `Port 2` | **Protected Victim Server:** Hosts active TCP services on ports `22`, `80`, `443`, and `5000`. |
| **`h3`** | `10.0.0.3` | `00:00:00:00:00:03` | `Port 3` | **Legitimate Client:** Sends continuous background traffic to verify 0% collateral packet loss. |

---

## 2. OpenFlow Flow-Table Hierarchy

To protect the controller's CPU capacity from table-miss saturation, the switch implements tiered priority matching:

| Priority | Match Criteria | Switch Action | Installed By | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **200** | `in_port = 1` | **`DROP`** | Controller (`FlowMod`) | **Hardware Quarantine:** Drops all incoming frames directly at the physical switch wire. |
| **100** | `dl_src = 00:00:00:00:00:01` | **`DROP`** | Controller (`FlowMod`) | **L2 Identity Blacklist:** Drops frames matching the attacker's hardware MAC address. |
| **20** | Exact TCP 5-Tuple Match | `OUTPUT: <port>` | Controller (`FlowMod`) | Fast-path bidirectional line-rate switching (`idle_timeout = 10s`). |
| **10** | `ipv4_src = 10.0.0.1` | **`DROP`** | Controller (`FlowMod`) | **L3 Network Drop:** Drops packets originating from an offending Layer 3 IP address. |
| **5** | Layer 4 TCP Traffic | `CONTROLLER` | Default at Boot | Diverts new TCP handshake requests (`SYN`) to the controller for IDS window inspection. |
| **1** | `eth_dst` + `eth_src` | `OUTPUT: <port>` | Controller (`FlowMod`) | Normal L2 unicast and broadcast learning switch forwarding (ARP, ICMP). |
| **0** | `*` (Table-Miss) | `CONTROLLER` | Default at Boot | Baseline rule sending unknown flows to the controller via OpenFlow `Packet-In`. |

---

## 3. Threat Detection Engine & Sliding-Window Rules

The detection engine maintains in-memory sliding-window queues populated by `OFPPacketIn` metadata: `(timestamp, in_port, dl_src, nw_src, nw_dst, tp_dst)`. Stale timestamps are evicted dynamically on every packet arrival.

```text
[ Inbound Packet ]
       │
       ▼
(Table-Miss / TCP SYN) ──► [ Intercepted by Ryu Controller ]
                                   │
                                   ▼
                   [ Append Metadata to Sliding Window ]
                                   │
      ┌────────────────────────────┼────────────────────────────┐
      ▼                            ▼                            ▼
[ Target Ports ≥ 8 ]        [ SYNs ≥ 35 ]               [ Unique IPs ≥ 3 ]
   Window: 10.0s                Window: 3.0s                Window: 4.0s
      │                            │                            │
      ▼                            ▼                            ▼
Rule: `port_scan`           Rule: `port_flood`          Rule: `multi_ip_spoof`
Action: L3 Drop             Action: Port Quarantine     Action: Dual-Layer Drop
(Priority 10)               (Priority 200 + 100)        (Priority 200 + 100)
```

### Detection Logic & Mitigations

1. **Horizontal Port Scan (`rule=port_scan`)**
   * **Trigger:** `≥ 8` distinct destination TCP ports (`tp_dst`) targeted from the same sender IP (`nw_src`) within a **10.0s** sliding window.
   * **Mitigation:** Pushes OpenFlow `priority=10, ip, nw_src=10.0.0.1, actions=drop`.
   * **Performance:** Detection latency `~372 ms` | Controller response `4.87 ms` | Total mitigation `~377 ms`.

2. **TCP SYN Connection Flood (`rule=port_flood`)**
   * **Trigger:** `≥ 35` TCP connection requests (`SYN=1, ACK=0`) entering via a single switch port within a **3.0s** sliding window.
   * **Mitigation:** Enforces immediate physical port and MAC suppression:
     * `priority=200, in_port=1, actions=drop`
     * `priority=100, dl_src=00:00:00:00:00:01, actions=drop`
   * **Performance:** Detection latency `~137 ms` | Controller response `4.47 ms` | Total mitigation `~141 ms`. Halts `Packet-In` generation to prevent controller CPU starvation.

3. **Multi-IP Spoofing Flood (`rule=multi_ip_spoof`)**
   * **Trigger:** Packets originating from the same physical switch port (`in_port=1`) or source MAC (`dl_src`) claim `≥ 3` distinct source IP addresses (`nw_src`) within a **4.0s** sliding window.
   * **Defense Advantage:** Traditional firewalls suffer state-table exhaustion trying to blacklist thousands of rotating spoofed IPs. This architecture binds detection to Layer 1/2 hardware properties, shutting down the ingress port regardless of forged Layer 3 headers.
   * **Mitigation:** Deploys dual-layer hardware isolation (`Priority 200 in_port=1` + `Priority 100 dl_src`).
   * **Performance:** Detection latency `~203 ms` | Controller response `5.27 ms` | Total mitigation `~209 ms`.

4. **Self-Healing & Auto-Recovery (`idle_timeout`)**
   * All mitigation drop rules are programmed with an ephemeral `idle_timeout` (`10–15s`).
   * Once the attacker stops sending malicious traffic, OVS flow counters register zero matches for the timeout duration and automatically evict the drop rule.
   * Ryu receives the `OFPFlowRemoved` event, clears the penalty state, logs `[IDS RECOVERY] UNBLOCKED`, and restores normal L2 connectivity without manual intervention.

---

## 4. Repository Structure

```text
sdn-ids/
├── apps/
│   ├── attack_conn_flood.py       # High-rate TCP SYN connection flood generator
│   ├── attack_port_scan.py        # Controlled port scanner (Connect, SYN, FIN, NULL, XMAS)
│   ├── attack_spoof_flood.py      # Scapy raw multi-IP spoofing flood script
│   ├── tcp_client.py              # Legitimate client traffic generator (RTT & loss tracker)
│   └── tcp_server.py              # Multi-port victim TCP server (ports 22, 80, 443, 5000)
├── controller/
│   ├── ids_controller.py          # Ryu OpenFlow 1.3 app: L2 switch, stats poller, FlowMod governor
│   ├── ids_engine.py              # Pure-Python sliding-window detection engine
│   ├── ids_rules.json             # Hot-reloaded detection thresholds and timeouts
│   └── ids_rules_team.json        # Alternative threshold profile
├── tools/
│   ├── telemetry_panel.py         # Real-time web telemetry dashboard ([http://127.0.0.1:8080](http://127.0.0.1:8080))
│   ├── panel.py                   # CLI status monitor
│   ├── report.py                  # Latency & mitigation benchmark report generator
│   ├── mininet_host_exec.sh       # Namespace command execution helper
│   ├── preflight.sh               # Environment & port readiness verifier
│   └── install_ubuntu.sh          # Automated package & virtualenv installer
├── topology/
│   ├── topo.py                    # Mininet 3-host (h1, h2, h3) + OVS switch (s1) topology
│   └── attacker_node.sh           # Attacker namespace configuration utility
├── tests/
│   ├── test_engine.py             # Unit tests for sliding-window rules
│   ├── test_controller_mock.py    # Mock tests for OpenFlow controller reactions
│   └── test_telemetry_panel.py    # Telemetry dashboard unit tests
├── CONTROLLER_LOGGING_AUDIT.patch # Controller telemetry logging patch
├── TELEMETRY_RUNBOOK.md           # Detailed operational runbook for live demonstrations
├── run_controller.sh              # Activates ryu-venv and launches Ryu controller
├── run_switch.sh                  # Boots Mininet topology and connects OVS to 127.0.0.1
├── run_attacker.sh                # Executes scan, flood, and spoof attacks inside h1 namespace
├── upgrade_sdn.sh                 # Environment upgrade utility
└── README.md                      # Project documentation
```

---

## 5. Quick Start & 4-Terminal Execution Guide

The entire system is designed to run smoothly on **one Ubuntu 22.04 LTS laptop** using 4 terminal windows.

### Initial Installation (Run Once)
```bash
cd ~/Desktop/sdn-ids
./tools/install_ubuntu.sh all
```

### Terminal 1: Data Plane (Mininet & Open vSwitch)
Launch the 3-host virtual network connected to local controller `127.0.0.1`:
```bash
cd ~/Desktop/sdn-ids
sudo ./run_switch.sh 127.0.0.1
```
Verify initial connectivity inside the `mininet>` prompt:
```text
mininet> pingall
*** Results: 0% dropped (6/6 received)
```

### Terminal 2: Control Plane (Ryu SDN Controller)
Activate the Python 3.10 virtual environment and start the IDS controller:
```bash
cd ~/Desktop/sdn-ids
source ~/ryu-venv/bin/activate
./run_controller.sh
```
Wait for `[SWITCH] s1 connected` to appear in the console.

### Terminal 3: Live Telemetry Web Dashboard
Start the real-time web UI server:
```bash
cd ~/Desktop/sdn-ids
sudo -E python3 tools/telemetry_panel.py
```
Open **`http://127.0.0.1:8080`** in your browser to monitor live packet rates, active OpenFlow rules, alert timelines, and quarantined hosts.

### Terminal 4: Attacker Console (`h1` Namespace)
Run controlled cyber-attacks from host `h1` (`10.0.0.1`) against the server `h2` (`10.0.0.2`):

* **1. Horizontal Port Scan:**
  ```bash
  sudo ./run_attacker.sh scan
  ```
  *Result:* Controller triggers `rule=port_scan` in `~372 ms` and installs a `Priority 10` L3 drop rule.

* **2. TCP SYN / Port Flood:**
  ```bash
  sudo ./run_attacker.sh flood
  ```
  *Result:* Controller triggers `rule=port_flood` in `~137 ms` and quarantines physical Switch Port 1 (`Priority 200`).

* **3. Multi-IP Spoofing Flood:**
  ```bash
  sudo ./run_attacker.sh spoof
  ```
  *Result:* Controller detects rotating fake IPs from the same MAC/Port in `~203 ms` and locks down Port 1 (`Priority 200` + `Priority 100`).

### Verify Zero Collateral Damage & Self-Healing
1. **During an active block:** Run `pingall` in **Terminal 1**. Host `h1` is completely blocked, while benign hosts `h2 <-> h3` communicate with **0% packet loss**.
2. **After stopping the attack:** Wait `10–15 seconds` for the `idle_timeout` to expire. Terminal 2 logs `[IDS RECOVERY] UNBLOCKED`, and `pingall` returns to `0% dropped (6/6 received)`.

---

## 6. Performance Benchmarks

Measured via OpenFlow barrier-verified timestamps (`python3 tools/report.py`):

| Attack Vector | Rule Triggered | Sliding Window | Detection Latency | Controller Reaction | Total Mitigation Time | Benign Traffic Loss |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Port Scan** | `port_scan` | `≥ 8 ports / 10.0s` | `372.4 ms` | `4.87 ms` | **`377.3 ms`** | `0.0%` |
| **TCP SYN Flood** | `port_flood` | `≥ 35 SYNs / 3.0s` | `136.8 ms` | `4.47 ms` | **`141.3 ms`** | `0.0%` |
| **Multi-IP Spoofing** | `multi_ip_spoof` | `≥ 3 IPs / 4.0s` | `203.1 ms` | `5.27 ms` | **`208.4 ms`** | `0.0%` |

---

## 7. Troubleshooting

| Issue / Symptom | Quick Fix |
| :--- | :--- |
| `Switch NOT connected` in Mininet | Ensure Terminal 2 (`./run_controller.sh`) is running and listening on port `6653` (`ss -ltn \| grep 6653`). |
| `RTNETLINK answers: File exists` | Clean up stale Mininet namespaces and virtual interfaces with `sudo mn -c`, then re-run `sudo ./run_switch.sh 127.0.0.1`. |
| `ryu-manager: command not found` | Activate the virtual environment first: `source ~/ryu-venv/bin/activate`. |
| `ImportError: ALREADY_HANDLED` | Ensure `eventlet==0.30.2` is installed inside `~/ryu-venv` on Python 3.10 (Ubuntu 22.04). |
| Attacker still blocked before next test | Wait `15s` for the `idle_timeout` to auto-expire, or restart `./run_controller.sh` to flush switch flow tables. |
