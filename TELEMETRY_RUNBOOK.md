# SDN-IDS live telemetry dashboard

This runbook accompanies `tools/telemetry_panel.py`. The dashboard uses only Python's standard library; no Flask/FastAPI install or external CDN is required. Charts are drawn locally with Canvas, and the browser requests fresh JSON telemetry every 2.5 seconds.

## What it reads

| Source | Read/display behavior |
|---|---|
| `logs/ids_events.jsonl` | Reads recent JSONL records newest-first: alert, mitigation-confirmed, and recovery events |
| `logs/flow_stats.csv` | Reads the existing CSV columns `timestamp,src_ip,active_flows,packets_per_sec,bytes_in_interval`; aggregates per-source rows into one sample per controller poll |
| `logs/status.json` | Reads switch IDs, blocked source records, blocked ports, stats interval, and latest rules-load timestamp |
| Open vSwitch | Runs `ovs-ofctl -O OpenFlow13 dump-flows s1` and `ovs-ofctl -O OpenFlow13 show s1`; the flow table is used to verify currently installed DROP rules |
| `controller/ids_rules.json` | Displays live thresholds and lets a local user save rule enable/threshold/window settings or request a controller reload |

The dashboard defaults to `127.0.0.1:8080`. Keep that default for the presentation. Binding to `0.0.0.0` exposes an unauthenticated local control panel to other machines on the reachable network, so only do that on a trusted isolated lab network.

## One-time setup (recommended all-in-one demo)

Use the Ubuntu/Linux environment in which the existing project, Mininet, Open vSwitch, and Ryu are installed. The repository's existing README recommends Ubuntu 22.04 for its current Ryu dependency combination. Run these commands from the extracted project directory:

```bash
cd ~/sdn-ids
chmod +x run_controller.sh run_switch.sh run_attacker.sh tools/*.sh
./tools/install_ubuntu.sh all
sudo apt install -y python3-scapy
```

`python3-scapy` is only needed for `apps/attack_spoof_flood.py`; ordinary port-scan/connection-flood scripts do not need Scapy. Install packages before the presentation, not while presenting.

Optional clean start — run this **before launching the controller**, because it removes the event log and statistics CSV so the controller will recreate the CSV header:

```bash
python3 tools/report.py --clear
```

## Four-terminal presentation sequence (single laptop)

Keep the same extracted project directory available to all four terminals.

### Terminal 1 — Ryu controller

```bash
cd ~/sdn-ids
./run_controller.sh
```

Wait for `IDS controller started` and leave the controller console visible. After the Mininet switch connects, the console should show a switch-connected message and periodic `[FLOW-STATS]` records.

### Terminal 2 — Mininet/Open vSwitch

```bash
cd ~/sdn-ids
sudo ./run_switch.sh 127.0.0.1
```

This runs the repository's **single** topology mode: h1 is the attacker (`10.0.0.1`), h2 is the server (`10.0.0.2`), and h3 is the legitimate client (`10.0.0.3`). Wait for the `mininet>` prompt.

At the `mininet>` prompt, start harmless legitimate traffic and leave it running:

```text
h3 python3 apps/tcp_client.py --server 10.0.0.2 --port 5000 --duration 300 > logs/legit.out 2>&1 &
```

The server is started by the topology on h2. The client output is captured in `logs/legit.out` so it does not clutter the CLI.

### Terminal 3 — Live telemetry dashboard

```bash
cd ~/sdn-ids
sudo -E python3 tools/telemetry_panel.py
```

Open **http://127.0.0.1:8080** in the browser. The dashboard runs as root here to make local OVS read queries reliable; the threshold-save handler preserves the existing owner and permissions of `ids_rules.json`. The server remains bound to loopback by default.

If your user can already run both `ovs-ofctl -O OpenFlow13 show s1` and `ovs-ofctl -O OpenFlow13 dump-flows s1` without `sudo`, you can instead launch it as `python3 tools/telemetry_panel.py`.

### Terminal 4 — Trigger the spoof-cycling demo

This repository's multi-IP spoof demo is the most direct way to show the **priority-200 ingress-port quarantine** path. It uses Scapy and emits lab traffic only within the Mininet test network:

```bash
cd ~/sdn-ids
sudo ./tools/mininet_host_exec.sh h1 python3 apps/attack_spoof_flood.py --target 10.0.0.2 --count 20
```

Expected visual sequence:

1. The alert feed adds `ALERT` with rule `multi_ip_spoof`, the changing source IP, MAC `00:00:00:00:00:01`, and the reported ingress port.
2. The topology marks the attacker/ingress path as quarantined after the corresponding status/flow data arrives.
3. The feed adds `BLOCK_INSTALLED` after the OpenFlow barrier reply, with response timing and mitigation action.
4. The OpenFlow table shows a priority-200 `in_port=... actions=drop` rule. The source-MAC fallback is a separate priority-100 drop rule in the current controller implementation.
5. h3's normal client connection to h2 should continue, because the quarantine is applied to the attacker's ingress port.

`tools/mininet_host_exec.sh` finds the existing Mininet shell for h1 so the attack can be launched from a fourth terminal. If that lookup fails on a customized Mininet installation, run the attack directly at Terminal 2's `mininet>` prompt instead:

```text
h1 python3 apps/attack_spoof_flood.py --target 10.0.0.2 --count 20
```

An ingress drop flow uses the configured idle timeout (30 seconds by default). After stopping attack traffic, allow the configured timeout to expire before expecting automatic recovery. You can also stop and restart the topology to reset the switch flow table for another rehearsal.

### Alternate attacks

From Terminal 4, use a controlled port scan:

```bash
sudo ./tools/mininet_host_exec.sh h1 python3 apps/attack_port_scan.py --target 10.0.0.2 --ports 1-1024 --delay 0.05
```

Or a controlled connection burst:

```bash
sudo ./tools/mininet_host_exec.sh h1 python3 apps/attack_conn_flood.py --target 10.0.0.2 --rate 60 --duration 20
```

These usually exercise the controller's IP-block path (priority 100), rather than the priority-200 port quarantine path. Use the spoof-cycling command for the port-isolation part of the presentation.

## Three-laptop / distributed mode

The repository's distributed topology puts the controller/logs on Laptop A and the OVS bridge `s1` on Laptop B. Start the controller and switch using the existing README instructions. On Laptop C, create the attacker namespace with `sudo ./topology/attacker_node.sh up <LAPTOP_B_IP>`.

To display controller-local logs and query the **remote** switch in one dashboard, run the dashboard on Laptop A with SSH access to Laptop B:

```bash
# Laptop A (controller/logs)
cd ~/sdn-ids
sudo -E python3 tools/telemetry_panel.py --ovs-ssh <SWITCH_USER>@<LAPTOP_B_IP>
```

The SSH account on Laptop B must use key authentication (no interactive password prompts), and it must be able to run `sudo -n ovs-ofctl -O OpenFlow13 show s1` and `sudo -n ovs-ofctl -O OpenFlow13 dump-flows s1`. Test these manually from Laptop A before the demo. If needed, add a narrowly-scoped sudoers entry using `sudo visudo -f /etc/sudoers.d/sdn-ids-telemetry` on Laptop B, replacing `<SWITCH_USER>` and the `ovs-ofctl` path with the actual account/path on that machine. Do not enable passwordless remote root login.

Run attacks from Laptop C:

```bash
sudo ./run_attacker.sh spoof --count 20
# Alternatives:
sudo ./run_attacker.sh scan --ports 1-1024 --delay 0.05
sudo ./run_attacker.sh flood --rate 60 --duration 20
```

The browser still opens on Laptop A at `http://127.0.0.1:8080`. The dashboard reads `logs/` and `controller/ids_rules.json` from Laptop A and reads the switch flow table remotely over SSH. Keep the project copies' rules in sync if you edit them separately on multiple machines.

## Threshold controls

1. Click **Show thresholds**.
2. Tick/untick a rule or edit its threshold/window.
3. Click **Save thresholds**. The JSON is validated and atomically replaced, then the controller detects the changed mtime on its next monitor iteration.
4. Alternatively, click **Reload from JSON / notify controller** after editing the file externally. This re-reads the JSON in the panel and touches the file timestamp to trigger the controller's polling reload.
5. Confirm reload from the controller console and the `rules_loaded_at` timestamp surfaced in `logs/status.json`.

Only the detection-rule enabled/threshold/window fields are editable in the panel. Root options such as `protected_hosts`, `block_idle_timeout`, and `stats_interval` remain in the JSON and are displayed indirectly by system status; edit those manually if your demo requires different values.

## Controller logging audit / resulting telemetry schema

The controller patch in this package makes these writes explicit and immediate:

- **JSONL events:** each event is serialized as one compact JSON record, followed by `\n`, then `file.flush()`. Records include alert metadata (`mac`, `in_port`, `action_target`, `mitigation_action`), a `BLOCK_INSTALLED` event after the barrier reply, and `UNBLOCKED` recovery events on flow removal.
- **CSV stats:** each statistics-reply batch calculates packet- and byte-counter deltas per TCP flow; `bytes_in_interval` now means byte delta in that sample rather than cumulative OpenFlow `byte_count`. CSV rows are written together per polling interval and explicitly flushed.
- **Status JSON:** the controller writes a temporary file, calls `flush()` and `os.fsync()`, then atomically replaces `logs/status.json`. It includes switch IDs, blocked-source metadata, `blocked_ports`, and `rules_loaded_at`.

The existing flow-stat CSV header is retained for compatibility:

```text
timestamp,src_ip,active_flows,packets_per_sec,bytes_in_interval
```

`packets_per_sec` is the packet-counter delta divided by the interval; the dashboard estimates bytes/sec by dividing the summed `bytes_in_interval` by the time between samples. Old CSV rows created before this patch were written with cumulative bytes despite the historical column name; the graph becomes semantically correct for new samples after the patched controller starts. For best-looking presentation graphs, clear logs before starting the new controller.

## Quick verification / troubleshooting

Run parser unit tests from the project root (these need no Mininet or Ryu install):

```bash
python3 -m unittest tests/test_telemetry_panel.py -v
python3 -m py_compile tools/telemetry_panel.py controller/ids_controller.py
```

Verify HTTP/API endpoints from another terminal:

```bash
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/api/rules
curl -fsS http://127.0.0.1:8080/api/telemetry | python3 -m json.tool | head -80
```

Verify flows directly on the switch host:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
sudo ovs-ofctl -O OpenFlow13 show s1
```

If the dashboard says controller offline, inspect `logs/status.json` and the Terminal 1 console. If flows are unavailable locally, try the dashboard command with `sudo -E`; in distributed mode, test the SSH commands above. If the dashboard has no charts yet, wait for at least one statistics poll after the switch connects. The panel deliberately displays missing/stale data as unavailable rather than fabricating live values.
