# SDN-IDS Deliverable 2 — Global CLI Suite and Live Demo Runbook

This runbook documents the shortcut installer and the final 3-laptop flow. The shortcuts are installed into `/usr/local/bin`, so they can be called from any terminal tab without entering the `mininet>` prompt. Every host-side command runs through `tools/mininet_host_exec.sh`/`mnexec` or the distributed `attacker` network namespace.

## 1. Install the global shortcuts on each laptop

Extract the **entire** `sdn-ids-deliverable2-complete.zip` archive, preserving the `sdn-ids/` root folder, in the same location on each laptop if possible (the suggested path is `~/sdn-ids`). Run on Laptop A, Laptop B, and Laptop C:

```bash
cd ~/sdn-ids
sudo ./tools/install_cli_shortcuts.sh
sdn-help
```

The installer creates `/usr/local/bin` symlinks for all 16 commands and initializes `/etc/sdn-ids-cli.conf` if the file does not already exist. Re-run the installer after updating the project. It refuses to overwrite an unrelated existing command or symlink.

## 2. Configure each laptop

Edit the config on each laptop with `sudoedit /etc/sdn-ids-cli.conf`. Use actual usernames and LAN IP addresses; do not copy the documentation IPs below verbatim.

### Laptop A — Ryu controller and dashboard

```ini
SDN_ROLE=controller
SDN_SWITCH_SSH=linux_user@LAPTOP_B_IP
SDN_CONTROLLER_SSH=
SDN_ATTACKER_SSH=
SDN_ATTACKER_IP=
SDN_REMOTE_SUDO=interactive
SDN_DASHBOARD_HOST=0.0.0.0
SDN_DASHBOARD_PORT=8080
SDN_SWITCH_NAME=s1
```

### Laptop B — Mininet and Open vSwitch

```ini
SDN_ROLE=switch
SDN_SWITCH_SSH=
SDN_CONTROLLER_SSH=linux_user@LAPTOP_A_IP
SDN_ATTACKER_SSH=linux_user@LAPTOP_C_IP
SDN_ATTACKER_IP=LAPTOP_C_IP
SDN_REMOTE_SUDO=interactive
SDN_DASHBOARD_HOST=0.0.0.0
SDN_DASHBOARD_PORT=8080
SDN_SWITCH_NAME=s1
```

### Laptop C — remote attacker namespace and SOC browser

```ini
SDN_ROLE=attacker
SDN_SWITCH_SSH=linux_user@LAPTOP_B_IP
SDN_CONTROLLER_SSH=linux_user@LAPTOP_A_IP
SDN_ATTACKER_SSH=
SDN_ATTACKER_IP=
SDN_REMOTE_SUDO=interactive
SDN_DASHBOARD_HOST=0.0.0.0
SDN_DASHBOARD_PORT=8080
SDN_SWITCH_NAME=s1
```

`SDN_REMOTE_SUDO=interactive` lets an SSH-operated shortcut request sudo in the remote terminal. This is the safer default for a lab because the dispatcher itself is not run as root remotely. Remote operations can prompt for the remote user's sudo password. The dashboard cannot prompt during background polling, so its **read-only** OVS queries on Laptop B must support `sudo -n` (see section 3).

Set up SSH key authentication for the connections you use:

```bash
ssh-copy-id linux_user@LAPTOP_B_IP   # from A and C
ssh-copy-id linux_user@LAPTOP_A_IP   # from C (and B if you use remote report)
ssh-copy-id linux_user@LAPTOP_C_IP   # from B only if you want to launch attacks remotely from B
```

Log in once with `ssh linux_user@LAPTOP_B_IP` etc. to accept host keys and verify connectivity. Do this before the presentation; the commands will not be able to answer first-time host-key prompts reliably in a timed showcase.

### Allow dashboard-only read access to the OVS flow table

On Laptop B, check the binary path with `command -v ovs-ofctl`. Usually it is `/usr/bin/ovs-ofctl`. If using a separate operator account for Laptop A, add a narrow read-only sudoers entry on Laptop B with `sudo visudo -f /etc/sudoers.d/sdn-ids-telemetry`, replacing `linux_user` and the binary path:

```sudoers
linux_user ALL=(root) NOPASSWD: /usr/bin/ovs-ofctl -O OpenFlow13 dump-flows s1, /usr/bin/ovs-ofctl -O OpenFlow13 show s1
```

Validate the entry with `sudo visudo -c`, then from Laptop A run:

```bash
ssh linux_user@LAPTOP_B_IP 'sudo -n ovs-ofctl -O OpenFlow13 dump-flows s1'
ssh linux_user@LAPTOP_B_IP 'sudo -n ovs-ofctl -O OpenFlow13 show s1'
```

This sudoers entry is only for the dashboard's two read-only OVS queries. Do **not** add a broad `NOPASSWD: ALL` rule for this demo.

## 3. Start the three-laptop demo

### Terminal A1 — Controller (Laptop A)

```bash
cd ~/sdn-ids
sdn-brain
```

Wait for the controller-started log line. On first start, verify that the OpenFlow 1.3 server listens on TCP port 6653 and that Laptop B can reach Laptop A over the LAN.

### Terminal A2 — Dashboard (Laptop A)

```bash
sdn-ui
```

The dashboard binds to `0.0.0.0:8080` by default so Laptop C can open it. Browse to `http://LAPTOP_A_IP:8080` on Laptop C. If UFW is enabled, allow TCP port 8080 from the trusted demo LAN only. Do not expose this unauthenticated local-lab dashboard to an untrusted network.

### Terminal B1 — Switch/Mininet (Laptop B)

Because `SDN_ATTACKER_IP` is configured in `/etc/sdn-ids-cli.conf`, this starts the distributed topology with one command:

```bash
cd ~/sdn-ids
sdn-net LAPTOP_A_IP
```

The shortcut runs `sudo mn -c` then starts `run_switch.sh` with the controller and configured attacker IP. It enters Mininet's CLI for the topology lifetime. **Leave this terminal open at `mininet>`**; shortcut commands in other tabs operate the hosts externally via `mnexec`.

If you want to override the configured attacker address, use `sdn-net LAPTOP_A_IP LAPTOP_C_IP`.

### Terminal C1 — Attacker namespace (Laptop C)

After Laptop B starts the topology:

```bash
cd ~/sdn-ids
sudo ./topology/attacker_node.sh up LAPTOP_B_IP
sudo ./topology/attacker_node.sh status
sdn-help
```

Verify the `attacker` namespace shows `10.0.0.1/24`, and verify baseline connectivity with `test-h1`. On Laptop B, the VXLAN interface is `vxlan0` (normally OpenFlow ingress port 10); this is the edge the controller can quarantine.

### Clear old sample/demo records (recommended once before a fresh evaluation)

From Laptop C or Laptop A, run `sdn-report --clear`. When run from Laptop C it routes to the controller laptop; on Laptop A it clears the controller's JSONL event log and recreates the CSV header. This preserves all project files but resets the telemetry data for a clean, presentation-ready report. Do not run it during an active attack.

### Start legitimate traffic

From Laptop C (routes to Laptop B when SSH config is set), or from a terminal on Laptop B:

```bash
legit-start
test-h3
```

The command checks h2:5000 before starting the TCP server and only starts the h3 client when it is not already running. It writes output to `logs/server.log` and `logs/legit.out` on the switch laptop.

## 4. Shortcut reference

| Command | Behaviour |
|---|---|
| `sdn-brain` | `cd` to the project root and launch `./run_controller.sh`. |
| `sdn-ui` | Run `sudo python3 tools/telemetry_panel.py` with a remote OVS target when configured, bound for the presentation LAN. |
| `sdn-net [A_IP] [C_IP]` | Run `sudo mn -c`, then `sudo ./run_switch.sh A_IP`. If `SDN_ATTACKER_IP` is configured and an A_IP argument is given, the topology uses distributed mode. With no arguments, it uses `127.0.0.1` and the single-laptop topology. |
| `sdn-sync A_IP` | Bounce the controller endpoint and set `s1` to OpenFlow 1.3 with `tcp:A_IP:6653`. |
| `sdn-flows` | Query the live OVS table and show priority, match, actions, and `n_packets` counters. Labels: red `[QUARANTINE DROP]`, green `[ACTIVE FORWARD]`, yellow `[TABLE-MISS -> CTRL]`. |
| `sdn-unblock` | Deletes IDS priority-200 and priority-100 DROP rules; the controller resets engine state when OpenFlow `FLOW_REMOVED` events arrive. |
| `test-h1` | Run `ping -c 2 -W 1 10.0.0.2` from h1/the attacker namespace and print an explicit reachability banner. |
| `test-h3` | Run the same 2-packet ping from h3 and print the legitimate-SLA banner. |
| `legit-start` | Ensure h2 server and h3 long-running client are up; logs are redirected to files. |
| `atk-spoof` | Send 25 spoof-cycling probes and exercise `multi_ip_spoof`/port isolation. Requires Scapy. |
| `atk-flood` | Start a 60-connection/s TCP burst at 10.0.0.2:5000; this crosses the default `conn_flood` threshold (20 in 3 seconds). |
| `atk-scan` | Scan 20 TCP ports at 120 ms intervals; it crosses the default `port_scan` threshold (8 distinct ports in 10 seconds) without reaching the separate 35-packet `port_flood` trigger first. |
| `atk-flags` | Send SYN+FIN, NULL, and XMAS TCP flag combinations; it sends 6 packets by default and crosses the `invalid_flags` threshold of 3. Requires Scapy/raw-socket privileges. |
| `sdn-report [--clear] [--csv FILE]` | Print alert counts per vector, mitigation response times, active DROP-flow counters, h3 telemetry and a live h3 reachability test; optional clear/export. |
| `sdn-autopilot` | Narrate baseline checks, unblock, spoof burst, flow inspection, post-attack h1/h3 checks, and quantitative report. |
| `sdn-help` | Print this cheat sheet. |

### Recovery semantics are deliberate

The current controller uses two quarantine priorities:

* `multi_ip_spoof` and `port_flood` install a priority-200 `in_port` DROP and a priority-100 source-MAC fallback.
* `conn_flood`, `port_scan`, `invalid_flags`, `packet_rate`, and `concurrent_flows` normally install a priority-100 IPv4-source DROP.

For that reason `sdn-unblock` clears both priority 200 and priority 100, not only priority 200. In this repository priority 100 is reserved for IDS quarantine rules. If you add your own unrelated priority-100 flows, inspect them before using `sdn-unblock` because they will also be deleted.

`sdn-unblock` does not directly edit controller memory. The DROP FlowMods that request `SEND_FLOW_REM` cause OpenFlow flow-removed events; `ids_controller.py` uses those events to clear the blocked source, MAC/IP history, and ingress-port history. `ids_engine.py` now resets these trackers during `unblock`, so a fresh `atk-scan` or `atk-flood` can trigger a new alert. This is an event-driven reset, not a silent dashboard-side state change.

## 5. Recommended live 60-second narration

Run on Laptop C after all three laptops are ready and baseline connectivity works:

```bash
sdn-autopilot
```

Suggested narration:

1. **Baseline:** `test-h1` and `test-h3` demonstrate both paths before an attack.
2. **Detection:** `atk-spoof` rotates source IPs from one Ethernet source MAC.
3. **Mitigation:** `sdn-flows` shows the priority-200 ingress-port DROP rule and its `n_packets` counter.
4. **Isolation:** `test-h1` should show 100% packet loss while the rule is installed.
5. **SLA:** `test-h3` should still show 0% packet loss because its ingress port is not quarantined.
6. **Evidence:** `sdn-report` reports JSONL alert counts, confirmed block events, switch DROP counters, and the latest h3 throughput samples.

The script continues after a failed stage so you still see the remaining diagnostics. Read each warning rather than interpreting the final “showcase complete” line as a pass. Use `sdn-unblock` before demonstrating another attack vector.

## 6. Individual attack commands and reset sequence

Use these in a presentation where you want to demonstrate a single rule:

```bash
sdn-unblock && atk-scan
sdn-flows
sdn-unblock && atk-flood
sdn-flows
sdn-unblock && atk-flags
sdn-flows
```

Allow a second for the alert and barrier response to be logged after each attack. Verify the event feed on Laptop A and compare the actual flow table on Laptop B; avoid claiming a rule installed until a `BLOCK_INSTALLED` event/barrier response is recorded.

## 7. Quantitative report interpretation

`sdn-report` separates:

* **Total alert events** (`ALERT`) from **confirmed mitigations** (`BLOCK_INSTALLED` after barrier reply).
* **Current OVS DROP counters**: the sum of `n_packets` from currently active priority-100/200 DROP flows. On a removed flow, its final counter is included in the controller's `UNBLOCKED` event only when the controller receives that flow-removed notification.
* **h3 telemetry**: latest recorded `active_flows`, `packets_per_sec`, and estimated bytes/sec for source `10.0.0.3`, plus a live ping when switch access is available.

Precision note for the presentation: an OVS `actions=drop` rule proves the Open vSwitch datapath enforces the drop before a packet is sent to the controller. It does **not** prove the flow is offloaded to a physical TCAM, and this project does not measure whole-controller CPU utilization. The report therefore describes controller per-packet handling of packets matched by the installed DROP rule as absent and labels system-wide CPU % as “not measured”; do not present that as a measured 0% CPU utilization result.

## 8. Troubleshooting

* **`sdn-net` cannot connect:** confirm `sdn-brain` is running on A, TCP 6653 is reachable from B, and the IP supplied is the controller's LAN address (not `127.0.0.1` on B in distributed mode).
* **`sdn-flows` says s1 is missing:** confirm Terminal B still runs Mininet and is at the `mininet>` prompt.
* **`test-h1` cannot find namespace h1:** for a single-laptop topology use a running Mininet host named h1. For the three-laptop setup, bring up the `attacker` namespace on C with `topology/attacker_node.sh up B_IP`.
* **`mnexec` cannot find a host:** leave Terminal B's Mininet instance running; do not close the `mininet>` terminal. Run `sudo mn -c` only when you intend to reset the topology.
* **Dashboard has live logs but no flow table:** confirm `SDN_SWITCH_SSH` on A, SSH key connectivity, and the two read-only `sudo -n ovs-ofctl` tests in section 2.
* **Remote command fails on sudo:** leave `SDN_REMOTE_SUDO=interactive` to permit an explicit password prompt, or configure narrowly scoped command permissions that your team has reviewed. Do not grant `NOPASSWD: ALL`.
* **Scapy import fails:** on Laptop C run `sudo apt install -y python3-scapy`. On a single-laptop Mininet setup, install Scapy on the host so `h1` can import it.
* **No fresh alert after a previous vector:** run `sdn-unblock`, wait for it to return, verify no priority-100/200 DROP remains in `sdn-flows`, then send the next vector. A persistent p100/p200 DROP means the flow removal or remote switch cleanup needs investigation.

## 9. Run tests before the evaluation

From the project root:

```bash
python3 -m compileall -q controller apps tools tests
python3 tests/test_engine.py
python3 tests/test_telemetry_panel.py
python3 tests/test_cli_suite.py
python3 tests/test_controller_mock.py
```

`test_controller_mock.py` requires Ryu installed in the Python environment that runs it. Run it from the project's controller virtual environment on Laptop A if the test machine lacks Ryu. These tests do not replace an end-to-end rehearsal with the actual three laptops, OVS, and Mininet.
