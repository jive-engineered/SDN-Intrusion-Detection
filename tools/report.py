#!/usr/bin/env python3
"""SDN-IDS Deliverable 2 quantitative audit report.

Reads controller JSONL/CSV logs, inspects active OVS DROP counters, and (when
configured) probes the legitimate Mininet h3 -> h2 path. Example:
    sdn-report
    python3 tools/report.py --csv results.csv
    python3 tools/report.py --clear

Important: OVS's `n_packets` proves packets matched installed DROP flows. On a
software OVS datapath this is dataplane enforcement, not proof of a physical
hardware TCAM offload or a measurement of total controller CPU utilization.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = ROOT / "logs"
EVENT_LOG = LOG_DIR / "ids_events.jsonl"
STATS_CSV = LOG_DIR / "flow_stats.csv"
STATUS_JSON = LOG_DIR / "status.json"
RULES_JSON = ROOT / "controller" / "ids_rules.json"
RULE_NAMES = ("multi_ip_spoof", "conn_flood", "port_scan", "invalid_flags", "packet_rate",
              "concurrent_flows", "port_flood")
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
END = "\033[0m"


def load_config() -> dict[str, str]:
    cfg: dict[str, str] = {}
    for path in (ROOT / "tools" / "sdn-cli.conf", Path.home() / ".config/sdn-ids/cli.conf", Path("/etc/sdn-ids-cli.conf")):
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                cfg[key.strip()] = value.strip().strip("'\"")
        except OSError:
            continue
    cfg.update({k: v for k, v in os.environ.items() if k.startswith("SDN_")})
    return cfg


def read_events() -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    try:
        with EVENT_LOG.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                    if isinstance(item, dict):
                        events.append(item)
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    return events


def read_status() -> dict[str, Any]:
    try:
        value = json.loads(STATUS_JSON.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def parse_flow_counters(raw: str) -> list[dict[str, Any]]:
    flows: list[dict[str, Any]] = []
    for line in raw.splitlines():
        if "actions=" not in line:
            continue
        left, actions = line.split("actions=", 1)
        pri = re.search(r"(?:^|[,\s])priority=(\d+)", left)
        packets = re.search(r"(?:^|[,\s])n_packets=(\d+)", left)
        if not pri:
            continue
        priority = int(pri.group(1))
        if "drop" not in actions.lower() or priority < 100:
            continue
        flows.append({"priority": priority, "packets": int(packets.group(1)) if packets else 0,
                      "match": left.strip(), "actions": actions.strip()})
    return flows


def _local_flow_dump(bridge: str, interactive: bool = False) -> tuple[str | None, str | None]:
    command = ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", bridge]
    try:
        p = subprocess.run(command, cwd=str(ROOT), text=True, capture_output=True, timeout=6)
        if p.returncode == 0:
            return p.stdout, None
        first_error = (p.stderr or p.stdout or f"exit code {p.returncode}").strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        first_error = str(exc)
    if os.geteuid() == 0:
        return None, first_error
    sudo_command = ["sudo", *command] if interactive else ["sudo", "-n", *command]
    try:
        if interactive:
            # Keep stderr/stdin attached to the terminal so sudo can prompt; capture only table output.
            p = subprocess.run(sudo_command, cwd=str(ROOT), text=True, stdout=subprocess.PIPE,
                               stderr=None, timeout=8)
        else:
            p = subprocess.run(sudo_command, cwd=str(ROOT), text=True, capture_output=True, timeout=8)
        if p.returncode == 0:
            return p.stdout, None
        second_error = (getattr(p, "stderr", None) or p.stdout or f"sudo exit code {p.returncode}").strip()
        return None, f"{first_error}; sudo: {second_error}"
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"{first_error}; sudo: {exc}"


def get_flow_dump(cfg: dict[str, str]) -> tuple[str | None, str | None]:
    bridge = cfg.get("SDN_SWITCH_NAME", "s1") or "s1"
    target = cfg.get("SDN_SWITCH_SSH", "").strip()
    role = cfg.get("SDN_ROLE", "auto").lower()
    local_only = cfg.get("SDN_LOCAL_ONLY", "0") == "1"
    interactive = cfg.get("SDN_REMOTE_SUDO", "interactive").lower() == "interactive"
    if target and not local_only and role != "switch":
        remote_cmd = f"sudo ovs-ofctl -O OpenFlow13 dump-flows {bridge}" if interactive else f"sudo -n ovs-ofctl -O OpenFlow13 dump-flows {bridge}"
        ssh_args = (["ssh", "-tt", "-o", "ConnectTimeout=5", target, remote_cmd] if interactive else
                    ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", target, remote_cmd])
        try:
            p = subprocess.run(ssh_args, text=True, stdout=subprocess.PIPE,
                               stderr=None if interactive else subprocess.PIPE, timeout=10)
            if p.returncode == 0:
                return p.stdout, None
            if interactive:
                return None, f"remote ovs-ofctl exited {p.returncode}"
            return None, (p.stderr or f"remote ovs-ofctl exited {p.returncode}").strip()
        except (OSError, subprocess.TimeoutExpired) as exc:
            return None, str(exc)
    return _local_flow_dump(bridge, interactive=interactive)


def latest_h3_telemetry(default_interval: float) -> dict[str, float] | None:
    rows = []
    try:
        with STATS_CSV.open("r", encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                if row.get("src_ip") == "10.0.0.3":
                    try:
                        rows.append({"ts": float(row.get("timestamp", 0)),
                                     "pps": float(row.get("packets_per_sec", 0)),
                                     "bytes": float(row.get("bytes_in_interval", 0)),
                                     "flows": float(row.get("active_flows", 0))})
                    except (TypeError, ValueError):
                        pass
    except OSError:
        return None
    if not rows:
        return None
    last = rows[-1]
    dt = default_interval
    if len(rows) > 1 and last["ts"] > rows[-2]["ts"]:
        dt = last["ts"] - rows[-2]["ts"]
    return {"pps": last["pps"], "bytes_per_sec": last["bytes"] / max(dt, 0.05), "flows": last["flows"], "timestamp": last["ts"]}


def live_h3_probe(cfg: dict[str, str]) -> tuple[str, int | None]:
    """Return a concise live SLA result; None means unavailable rather than a failure."""
    target = cfg.get("SDN_SWITCH_SSH", "").strip()
    role = cfg.get("SDN_ROLE", "auto").lower()
    interactive = cfg.get("SDN_REMOTE_SUDO", "interactive").lower() == "interactive"
    if target and role != "switch" and cfg.get("SDN_LOCAL_ONLY", "0") != "1":
        ssh_args = (["ssh", "-tt", "-o", "ConnectTimeout=5", target, "/usr/local/bin/test-h3"] if interactive else
                    ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", target, "/usr/local/bin/test-h3"])
        cmd = ssh_args
    else:
        helper = ROOT / "tools" / "mininet_host_exec.sh"
        cmd = ["bash", str(helper), "h3", "ping", "-c", "2", "-W", "1", "10.0.0.2"]
        if os.geteuid() != 0:
            cmd.insert(0, "sudo")
    try:
        p = subprocess.run(cmd, cwd=str(ROOT), text=True, stdout=subprocess.PIPE,
                           stderr=None if interactive else subprocess.PIPE, timeout=10)
        output = p.stdout or ""
        if not interactive and p.stderr:
            output += p.stderr
        loss = re.search(r"([0-9]+(?:\.[0-9]+)?)%\s*packet loss", output, re.IGNORECASE)
        if loss:
            pct = float(loss.group(1))
            return (f"PASS · h3 → h2 ping packet loss {pct:.1f}%" if pct == 0 else f"WARN · h3 → h2 ping packet loss {pct:.1f}%", p.returncode)
        if p.returncode == 0:
            return "PASS · h3 → h2 probe completed", p.returncode
        return "UNAVAILABLE · live h3 probe failed (check Mininet/SSH/sudo); see telemetry logs", None
    except (OSError, subprocess.TimeoutExpired):
        return "UNAVAILABLE · live h3 probe could not run", None


def color(text: str, tone: str) -> str:
    return f"{tone}{text}{END}" if sys.stdout.isatty() else text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", help="export the event response table to CSV")
    parser.add_argument("--clear", action="store_true", help="clear event/stat logs before a fresh demo (controller should be running after clear to recreate CSV header)")
    args = parser.parse_args()
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    if args.clear:
        EVENT_LOG.write_text("", encoding="utf-8")
        STATS_CSV.write_text("timestamp,src_ip,active_flows,packets_per_sec,bytes_in_interval\n", encoding="utf-8")
        print(color("[OK] Cleared ids_events.jsonl and reset flow_stats.csv with its header", GREEN))
        print("     The running controller will append fresh telemetry on its next stats poll.")
        return 0

    events = read_events()
    alerts = [e for e in events if e.get("event") == "ALERT"]
    blocks = [e for e in events if e.get("event") == "BLOCK_INSTALLED"]
    recoveries = [e for e in events if e.get("event") == "UNBLOCKED"]
    by_rule: Counter[str] = Counter()
    for event in alerts:
        rules = event.get("rules", [])
        if isinstance(rules, str):
            rules = [x.strip() for x in rules.split(",") if x.strip()]
        if isinstance(rules, list):
            for rule in set(str(r) for r in rules):
                by_rule[rule] += 1

    print("\n" + color("DELIVERABLE 2 · QUANTITATIVE SDN-IDS AUDIT", BOLD + CYAN))
    print("=" * 96)
    print(f"Total alert events triggered: {len(alerts)}")
    print(f"Mitigation confirmations (OpenFlow barrier reply): {len(blocks)}")
    print(f"Recovery / unblock events recorded: {len(recoveries)}")
    print("\nATTACK VECTOR BREAKDOWN")
    print("-" * 46)
    for rule in RULE_NAMES:
        print(f"{rule:<22} {by_rule.get(rule, 0):>6} alert(s)")
    for rule in sorted(set(by_rule) - set(RULE_NAMES)):
        print(f"{rule:<22} {by_rule[rule]:>6} alert(s)")

    cfg = load_config()
    status = read_status()
    block_items = status.get("blocked", {}) if isinstance(status.get("blocked", {}), dict) else {}
    blocked_ports = status.get("blocked_ports", [])
    print("\nCONTROLLER / QUARANTINE STATE")
    print("-" * 46)
    print("Connected switch IDs: " + (", ".join(str(x) for x in status.get("switches", [])) or "not reported"))
    print(f"Currently blocked sources: {len(block_items)}")
    print(f"Currently quarantined ingress ports: {', '.join(map(str, blocked_ports)) if blocked_ports else 'none reported'}")

    raw, flow_error = get_flow_dump(cfg)
    drops = parse_flow_counters(raw or "") if raw else []
    live_drop_packets = sum(f["packets"] for f in drops)
    print("\nOVS DATAPLANE / HARDWARE-OFFLOAD EVIDENCE")
    print("-" * 46)
    if raw is not None:
        print(f"Active priority-100/200 DROP flows: {len(drops)}")
        print(f"Packets matched by currently active DROP flows (sum of OVS n_packets): {live_drop_packets}")
        for f in drops:
            match = f["match"].strip()
            print(f"  p={f['priority']:<3} n_packets={f['packets']:<8} {match}")
        historical = sum(int(e.get("dropped_packets", 0) or 0) for e in recoveries)
        print(f"Packets counted when expired/deleted DROP flows were removed: {historical}")
        print("Controller per-packet handling for packets matching an installed DROP: none (switch drops them before Packet-In).")
        print("Controller system CPU percentage: NOT MEASURED by this project; no 0% whole-process CPU claim is inferred.")
        print("Note: OVS n_packets is a switch datapath counter; hardware TCAM offload is not proven unless configured on the actual switch.")
    else:
        print("Live OVS counters unavailable: " + (flow_error or "unknown error"))
        print("Run with OVS access locally or configure SSH keys + remote sudo for SDN_SWITCH_SSH.")

    rules = {}
    try:
        rules = json.loads(RULES_JSON.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        pass
    interval = float(rules.get("stats_interval", 3) or 3)
    h3 = latest_h3_telemetry(interval)
    sla_text, _ = live_h3_probe(cfg)
    print("\nLEGITIMATE HOST h3 · SLA / THROUGHPUT")
    print("-" * 46)
    if h3:
        age = max(0.0, time.time() - h3["timestamp"])
        print(f"Latest telemetry age: {age:.1f}s | active flows: {h3['flows']:.0f} | packets/sec: {h3['pps']:.1f} | estimated bytes/sec: {h3['bytes_per_sec']:.1f}")
    else:
        print("No h3 (10.0.0.3) flow_stats.csv samples found yet.")
    print("Live reachability: " + sla_text)

    print("\nDETECTION / RESPONSE DETAILS")
    print("-" * 96)
    print(f"{'TIME':<10} {'SOURCE':<15} {'RULE':<25} {'DETECT ms':>10} {'RESP ms':>10} {'TOTAL ms':>10}")
    print("-" * 96)
    rows: list[list[Any]] = []
    for e in blocks:
        rules_text = ",".join(e.get("rules", [])) if isinstance(e.get("rules", []), list) else str(e.get("rules", ""))
        row = [e.get("time", "?"), e.get("ip", "?"), rules_text,
               float(e.get("detection_ms", 0) or 0), float(e.get("response_ms", 0) or 0), float(e.get("total_ms", 0) or 0), e.get("detail", "")]
        rows.append(row)
        print(f"{row[0]:<10} {row[1]:<15} {row[2][:25]:<25} {row[3]:>10.1f} {row[4]:>10.2f} {row[5]:>10.1f}")
    if not rows:
        print("No BLOCK_INSTALLED events logged yet. Run an attack vector to populate this report.")
    else:
        n = len(rows)
        print("-" * 96)
        print(f"Average detection: {sum(r[3] for r in rows) / n:.1f} ms | average alert-to-barrier response: {sum(r[4] for r in rows) / n:.2f} ms | average total: {sum(r[5] for r in rows) / n:.1f} ms")
    print("\nDetection = first packet -> alert; response = alert -> OpenFlow barrier reply confirming queued FlowMods were processed.")

    if args.csv:
        try:
            with open(args.csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["time", "source", "rule", "detection_ms", "response_ms", "total_ms", "detail"])
                writer.writerows(rows)
            print(f"\nCSV response table written to {args.csv}")
        except OSError as exc:
            print(f"Could not write CSV: {exc}", file=sys.stderr)
            return 1
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
