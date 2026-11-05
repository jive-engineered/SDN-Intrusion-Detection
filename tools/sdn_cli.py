#!/usr/bin/env python3
"""Global command dispatcher for the SDN-IDS demo shortcut suite.

Install symlinks with tools/install_cli_shortcuts.sh. The script deliberately
uses argv lists (not shell=True) for all local commands. In distributed mode,
SDN_SWITCH_SSH / SDN_CONTROLLER_SSH / SDN_ATTACKER_SSH may route operations to
other laptops using SSH keys and interactive sudo over SSH by default; switch to
noninteractive mode only when narrow remote sudo permissions are configured.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
HOST_EXEC = TOOLS / "mininet_host_exec.sh"
DASHBOARD = TOOLS / "telemetry_panel.py"
REPORT = TOOLS / "report.py"
STATUS_JSON = ROOT / "logs" / "status.json"
SWITCH_NAME_DEFAULT = "s1"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BLUE = "\033[94m"
BOLD = "\033[1m"
DIM = "\033[2m"
END = "\033[0m"

COMMANDS = [
    "sdn-brain", "sdn-ui", "sdn-net", "sdn-sync", "sdn-flows", "sdn-unblock",
    "test-h1", "test-h3", "legit-start", "atk-spoof", "atk-flood", "atk-scan",
    "atk-flags", "atk-rate", "atk-concurrent", "sdn-report", "sdn-autopilot", "sdn-help",
]


def _read_kv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for line in lines:
        text = line.strip()
        if not text or text.startswith("#") or "=" not in text:
            continue
        key, value = text.split("=", 1)
        key, value = key.strip(), value.strip()
        if value and value[0:1] in ("'", '"') and value[-1:] == value[0:1]:
            value = value[1:-1]
        values[key] = value
    return values


def load_config() -> dict[str, str]:
    cfg = {
        "SDN_ROLE": "auto",
        "SDN_SWITCH_SSH": "",
        "SDN_CONTROLLER_SSH": "",
        "SDN_ATTACKER_SSH": "",
        "SDN_ATTACKER_IP": "",
        "SDN_REMOTE_SUDO": "interactive",
        "SDN_DASHBOARD_HOST": "0.0.0.0",
        "SDN_DASHBOARD_PORT": "8080",
        "SDN_SWITCH_NAME": SWITCH_NAME_DEFAULT,
    }
    paths = [TOOLS / "sdn-cli.conf", Path.home() / ".config/sdn-ids/cli.conf", Path("/etc/sdn-ids-cli.conf")]
    for path in paths:
        cfg.update(_read_kv(path))
    for key in list(cfg):
        if key in os.environ:
            cfg[key] = os.environ[key]
    cfg["SDN_LOCAL_ONLY"] = os.environ.get("SDN_LOCAL_ONLY", "0")
    return cfg


def color(text: str, value: str) -> str:
    if sys.stdout.isatty() or os.environ.get("FORCE_COLOR") == "1":
        return f"{value}{text}{END}"
    return text


def info(message: str) -> None:
    print(color("[INFO] ", CYAN) + message, flush=True)


def success(message: str) -> None:
    print(color("[ OK ] ", GREEN) + message, flush=True)


def warning(message: str) -> None:
    print(color("[WARN] ", YELLOW) + message, flush=True)


def error(message: str) -> None:
    print(color("[FAIL] ", RED) + message, file=sys.stderr, flush=True)


def sudo_argv(argv: list[str]) -> list[str]:
    return argv if os.geteuid() == 0 else ["sudo", *argv]


def run(argv: list[str], *, cwd: Path | None = ROOT, capture: bool = False,
        check: bool = False, timeout: float | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, cwd=str(cwd) if cwd else None, text=True,
                              stdout=subprocess.PIPE if capture else None,
                              stderr=subprocess.PIPE if capture else None,
                              check=check, timeout=timeout, env=env)
    except FileNotFoundError as exc:
        error(f"Command not found: {argv[0]} ({exc})")
        return subprocess.CompletedProcess(argv, 127, "" if capture else None, str(exc) if capture else None)
    except subprocess.TimeoutExpired:
        error(f"Command timed out: {' '.join(argv)}")
        return subprocess.CompletedProcess(argv, 124, "" if capture else None, "timed out" if capture else None)


def config_target(cfg: dict[str, str], key: str) -> str:
    target = cfg.get(key, "").strip()
    if target and ("\n" in target or "\r" in target or " " in target):
        error(f"{key} must be a single SSH destination such as user@192.0.2.10")
        return ""
    return target


def remote_command(cfg: dict[str, str], key: str, command: str, args: list[str] | None = None,
                   *, sudo: bool = True, capture: bool = False, local_only: bool = True) -> subprocess.CompletedProcess | None:
    target = config_target(cfg, key)
    if not target:
        return None
    args = args or []
    remote_tokens = ["/usr/local/bin/" + command, *args]
    quoted_command = " ".join(shlex.quote(token) for token in remote_tokens)
    if local_only:
        quoted_command = "env SDN_LOCAL_ONLY=1 " + quoted_command
    # Run the shortcut as the SSH user, not as root. Each shortcut invokes sudo
    # only for the specific network operation it needs. This avoids executing a
    # user-writable project dispatcher with blanket root privileges remotely.
    if cfg.get("SDN_REMOTE_SUDO", "interactive").lower() == "interactive":
        ssh_args = ["ssh", "-tt", "-o", "ConnectTimeout=5", target, quoted_command]
    else:
        ssh_args = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", target, quoted_command]
    result = run(ssh_args, cwd=None, capture=capture)
    if result.returncode != 0:
        error(f"Remote {command} on {target} failed (exit {result.returncode}). Check SSH keys, shortcut installation, and remote sudo configuration.")
    return result


def remote_is_configured(cfg: dict[str, str], key: str) -> bool:
    return bool(config_target(cfg, key)) and cfg.get("SDN_LOCAL_ONLY", "0") != "1"


def local_switch_role(cfg: dict[str, str]) -> bool:
    return cfg.get("SDN_ROLE", "auto").lower() == "switch"


def local_controller_role(cfg: dict[str, str]) -> bool:
    return cfg.get("SDN_ROLE", "auto").lower() == "controller"


def has_netns(name: str = "attacker") -> bool:
    result = run(["ip", "netns", "list"], cwd=None, capture=True, timeout=2)
    return result.returncode == 0 and any(line.split() and line.split()[0] == name for line in (result.stdout or "").splitlines())


def has_mininet_host(name: str) -> bool:
    result = run(["ps", "-eo", "args="], cwd=None, capture=True, timeout=2)
    return result.returncode == 0 and any(f"mininet:{name}" in line for line in (result.stdout or "").splitlines())


def local_attacker_mode() -> str | None:
    if has_netns("attacker"):
        return "namespace"
    if has_mininet_host("h1"):
        return "mininet"
    return None


def invoke_switch(name: str, args: list[str] | None = None, cfg: dict[str, str] | None = None,
                  *, capture: bool = False) -> int:
    cfg = cfg or load_config()
    if remote_is_configured(cfg, "SDN_SWITCH_SSH") and not local_switch_role(cfg):
        result = remote_command(cfg, "SDN_SWITCH_SSH", name, args, capture=capture)
        return result.returncode if result else 2
    return dispatch_local(name, args or [], cfg)


def invoke_controller_report(cfg: dict[str, str], args: list[str] | None = None) -> int:
    args = args or []
    if remote_is_configured(cfg, "SDN_CONTROLLER_SSH") and not local_controller_role(cfg):
        result = remote_command(cfg, "SDN_CONTROLLER_SSH", "sdn-report", args, capture=False, local_only=False)
        return result.returncode if result else 2
    return run(["python3", str(REPORT), *args], cwd=ROOT).returncode


def invoke_attacker(name: str, args: list[str], cfg: dict[str, str]) -> int:
    mode = local_attacker_mode()
    role = cfg.get("SDN_ROLE", "auto").lower()
    if mode:
        return attack_local(name, args, mode)
    if role != "attacker" and remote_is_configured(cfg, "SDN_ATTACKER_SSH"):
        result = remote_command(cfg, "SDN_ATTACKER_SSH", name, args, capture=False)
        return result.returncode if result else 2
    error("No local attacker namespace or Mininet h1 was found. On Laptop C run 'sudo ./topology/attacker_node.sh up <SWITCH_IP>', or configure SDN_ATTACKER_SSH.")
    return 2


def read_status() -> dict[str, Any]:
    try:
        data = json.loads(STATUS_JSON.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def parse_flow_dump(raw: str) -> list[dict[str, Any]]:
    """Parse OVS `dump-flows` lines into displayable records."""
    parsed = []
    for line in raw.splitlines():
        if "actions=" not in line:
            continue
        before, actions = line.split("actions=", 1)
        priority_match = re.search(r"(?:^|[,\s])priority=(\d+)", before)
        if not priority_match:
            continue
        priority = int(priority_match.group(1))
        n_packets = re.search(r"(?:^|[,\s])n_packets=(\d+)", before)
        match_text = before
        for pattern in (r"^.*?priority=\d+\s*,?", r"cookie=[^,]+,?", r"duration=[^,]+,?", r"table=\d+,?", r"n_packets=\d+,?", r"n_bytes=\d+,?"):
            match_text = re.sub(pattern, "", match_text)
        match_text = re.sub(r"\s*,\s*", ",", match_text).strip(" ,") or "(any)"
        action_lower = actions.strip().lower()
        if "drop" in action_lower:
            kind = "DROP"
        elif "controller" in action_lower and priority in (0, 5):
            kind = "TABLE-MISS -> CTRL"
        elif "controller" in action_lower:
            kind = "CONTROLLER"
        elif "output:" in action_lower or "resubmit" in action_lower:
            kind = "FORWARD"
        else:
            kind = "OTHER"
        parsed.append({"priority": priority, "packets": int(n_packets.group(1)) if n_packets else 0,
                       "match": match_text, "actions": actions.strip(), "kind": kind})
    return sorted(parsed, key=lambda row: (-row["priority"], row["match"]))


def print_flow_table(raw: str) -> int:
    flows = parse_flow_dump(raw)
    if not flows:
        print("No parseable flow entries were returned.")
        if raw.strip():
            print(raw.rstrip())
        return 1 if not raw.strip() else 0
    print("\n" + color("OPENFLOW 1.3 · LIVE SWITCH FLOW TABLE", BOLD + CYAN))
    print("=" * 112)
    print(f"{'CLASSIFICATION':<22} {'PRIO':>5} {'N_PACKETS':>12}  {'MATCH':<45} ACTIONS")
    print("-" * 112)
    for flow in flows:
        if flow["kind"] == "DROP":
            label, tone = "[QUARANTINE DROP]", RED
        elif flow["kind"] == "TABLE-MISS -> CTRL":
            label, tone = "[TABLE-MISS -> CTRL]", YELLOW
        elif flow["kind"] == "FORWARD":
            label, tone = "[ACTIVE FORWARD]", GREEN
        else:
            label, tone = "[CONTROLLER/OTHER]", CYAN
        match = flow["match"]
        if len(match) > 45:
            match = match[:42] + "..."
        line = f"{label:<22} {flow['priority']:>5} {flow['packets']:>12}  {match:<45} {flow['actions']}"
        print(color(line, tone))
    print("=" * 112)
    total_drops = sum(flow["packets"] for flow in flows if flow["kind"] == "DROP")
    print(f"Active DROP-flow packet counters: {total_drops}  |  Rules shown: {len(flows)}\n")
    return 0


def command_sdn_brain(_: list[str], cfg: dict[str, str]) -> int:
    info(f"Launching Ryu controller from {ROOT}")
    return run([str(ROOT / "run_controller.sh")], cwd=ROOT).returncode


def command_sdn_ui(_: list[str], cfg: dict[str, str]) -> int:
    host = cfg.get("SDN_DASHBOARD_HOST", "0.0.0.0") or "0.0.0.0"
    port = cfg.get("SDN_DASHBOARD_PORT", "8080") or "8080"
    argv = ["python3", str(DASHBOARD), "--host", host, "--port", port]
    switch_ssh = config_target(cfg, "SDN_SWITCH_SSH")
    if switch_ssh:
        argv.extend(["--ovs-ssh", switch_ssh])
    info(f"Starting telemetry dashboard on {host}:{port}; on Laptop C open http://<CONTROLLER_IP>:{port}")
    return run(sudo_argv(argv), cwd=ROOT).returncode


def command_sdn_net(args: list[str], cfg: dict[str, str]) -> int:
    if len(args) > 2:
        error("Usage: sdn-net [CONTROLLER_IP] [ATTACKER_IP]")
        return 2
    controller_ip = args[0] if args else "127.0.0.1"
    attacker_ip = args[1] if len(args) > 1 else (cfg.get("SDN_ATTACKER_IP", "") if args else "")
    if attacker_ip:
        info(f"Cleaning Mininet, then starting distributed topology (controller={controller_ip}, attacker={attacker_ip})")
    else:
        info(f"Cleaning Mininet, then starting single-laptop topology (controller={controller_ip})")
    cleanup = run(sudo_argv(["mn", "-c"]), cwd=ROOT)
    if cleanup.returncode != 0:
        warning("'mn -c' returned a non-zero exit code; attempting topology startup anyway.")
    argv = [str(ROOT / "run_switch.sh"), controller_ip]
    if attacker_ip:
        argv.append(attacker_ip)
    return run(sudo_argv(argv), cwd=ROOT).returncode


def command_sdn_sync(args: list[str], cfg: dict[str, str]) -> int:
    if len(args) != 1:
        error("Usage: sdn-sync CONTROLLER_IP")
        return 2
    controller_ip = args[0]
    if remote_is_configured(cfg, "SDN_SWITCH_SSH") and not local_switch_role(cfg):
        result = remote_command(cfg, "SDN_SWITCH_SSH", "sdn-sync", [controller_ip])
        return result.returncode if result else 2
    bridge = cfg.get("SDN_SWITCH_NAME", SWITCH_NAME_DEFAULT) or SWITCH_NAME_DEFAULT
    info(f"Reconnecting {bridge} to tcp:{controller_ip}:6653 using OpenFlow 1.3")
    # Del + set forces a connection reconfiguration even if the endpoint is unchanged.
    for argv in (["ovs-vsctl", "del-controller", bridge],
                 ["ovs-vsctl", "set", "Bridge", bridge, "protocols=OpenFlow13"],
                 ["ovs-vsctl", "set-controller", bridge, f"tcp:{controller_ip}:6653"]):
        result = run(sudo_argv(list(argv)), cwd=ROOT)
        if result.returncode != 0:
            error("Reconnect step failed; confirm s1 exists and Open vSwitch is running.")
            return result.returncode
    success("Controller endpoint reset. Check the Ryu console for a fresh switch connect event.")
    return 0


def command_sdn_flows(_: list[str], cfg: dict[str, str]) -> int:
    if remote_is_configured(cfg, "SDN_SWITCH_SSH") and not local_switch_role(cfg):
        result = remote_command(cfg, "SDN_SWITCH_SSH", "sdn-flows", [], capture=False)
        return result.returncode if result else 2
    bridge = cfg.get("SDN_SWITCH_NAME", SWITCH_NAME_DEFAULT) or SWITCH_NAME_DEFAULT
    result = run(sudo_argv(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", bridge]), cwd=ROOT, capture=True, timeout=8)
    if result.returncode != 0:
        error("Could not read OpenFlow table. Is OVS bridge s1 running?")
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="")
        return result.returncode
    return print_flow_table(result.stdout or "")


def _active_quarantine_diagnostics(raw: str) -> tuple[int, int]:
    flows = parse_flow_dump(raw)
    return (sum(1 for f in flows if f["priority"] == 200 and f["kind"] == "DROP"),
            sum(1 for f in flows if f["priority"] == 100 and f["kind"] == "DROP"))


def command_sdn_unblock(_: list[str], cfg: dict[str, str]) -> int:
    if remote_is_configured(cfg, "SDN_SWITCH_SSH") and not local_switch_role(cfg):
        result = remote_command(cfg, "SDN_SWITCH_SSH", "sdn-unblock", [])
        return result.returncode if result else 2
    bridge = cfg.get("SDN_SWITCH_NAME", SWITCH_NAME_DEFAULT) or SWITCH_NAME_DEFAULT
    result = run(sudo_argv(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", bridge]), cwd=ROOT, capture=True, timeout=8)
    if result.returncode != 0:
        error("Could not inspect s1. Start the Mininet topology first.")
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="")
        return result.returncode
    result_dump_text = result.stdout or ""
    p200, p100 = _active_quarantine_diagnostics(result_dump_text)
    if p200 == 0 and p100 == 0:
        success("No priority-200/100 DROP quarantine rules are active; controller state should already be clear.")
        return 0
    info(f"Removing dynamic quarantine flows (priority 200: {p200}, priority 100: {p100})")
    # In this project priorities 100 and 200 are reserved for IDS quarantine only.
    # Priority 100 covers both source-IP drops and the source-MAC fallback for port drops.
    # Priority 200 has SEND_FLOW_REM; its FLOW_REMOVED message synchronizes engine state.
    # NOTE: plain `del-flows <br> priority=N` is REJECTED by ovs-ofctl ("unknown keyword priority"):
    # priority is only legal together with --strict. So each DROP rule is deleted individually with
    # --strict, using the exact priority + match text read back from the switch's own flow dump.
    drops = [f for f in parse_flow_dump(result_dump_text) if f["priority"] in (100, 200) and f["kind"] == "DROP"]
    failures = 0
    for flow in drops:
        spec = f"priority={flow['priority']}" + ("" if flow["match"] == "(any)" else f",{flow['match']}")
        result = run(sudo_argv(["ovs-ofctl", "-O", "OpenFlow13", "--strict", "del-flows", bridge, spec]), cwd=ROOT, capture=True, timeout=8)
        if result.returncode != 0:
            failures += 1
            error(f"Could not delete flow [{spec}].")
            if result.stderr:
                print(result.stderr, file=sys.stderr, end="")
    if failures:
        return 1
    time.sleep(0.4)  # Give OpenFlow FLOW_REMOVED messages time to reach Ryu.
    success("Switch DROP rules deleted. Ryu resets source/port suppression on FLOW_REMOVED; fresh attacks can be detected again.")
    warning("Priority 100 is reserved for IDS blocks in this repository; custom non-IDS priority-100 flows would also be deleted.")
    return 0


def _run_host(host: str, command: list[str], *, capture: bool = False, timeout: float | None = None) -> subprocess.CompletedProcess:
    return run(sudo_argv(["bash", str(HOST_EXEC), host, *command]), cwd=ROOT, capture=capture, timeout=timeout)


def _ping_banner(host_label: str, argv: list[str], *, timeout: float = 5.5) -> int:
    result = run(argv, cwd=ROOT, capture=True, timeout=timeout)
    output = (result.stdout or "") + (result.stderr or "")
    if output.strip():
        print(output.rstrip())
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)%\s*packet loss", output, re.IGNORECASE)
    loss = float(match.group(1)) if match else (0.0 if result.returncode == 0 else 100.0)
    if host_label == "h1":
        if loss == 0:
            print(color("🟢 h1 UNBLOCKED (0% Packet Loss)", GREEN + BOLD))
        elif loss >= 99.9:
            print(color("🛑 h1 QUARANTINED AT SWITCH EDGE (100% Packet Loss)", RED + BOLD))
        else:
            print(color(f"🟡 h1 PARTIALLY REACHABLE ({loss:.1f}% Packet Loss)", YELLOW + BOLD))
    else:
        if loss == 0:
            print(color("✅ LEGITIMATE TRAFFIC SLA INTACT (0% Packet Loss)", GREEN + BOLD))
        else:
            print(color(f"⚠️ LEGITIMATE TRAFFIC SLA DEGRADED ({loss:.1f}% Packet Loss)", RED + BOLD))
    return 0 if loss == 0 else 1


def command_test_h1(_: list[str], cfg: dict[str, str]) -> int:
    mode = local_attacker_mode()
    if mode:
        if mode == "namespace":
            return _ping_banner("h1", sudo_argv(["ip", "netns", "exec", "attacker", "ping", "-c", "2", "-W", "1", "10.0.0.2"]))
        return _ping_banner("h1", sudo_argv(["bash", str(HOST_EXEC), "h1", "ping", "-c", "2", "-W", "1", "10.0.0.2"]))
    if cfg.get("SDN_ROLE", "auto").lower() != "attacker" and remote_is_configured(cfg, "SDN_ATTACKER_SSH"):
        result = remote_command(cfg, "SDN_ATTACKER_SSH", "test-h1", [])
        return result.returncode if result else 2
    error("No local h1/attacker namespace found and SDN_ATTACKER_SSH is not configured.")
    return 2


def command_test_h3(_: list[str], cfg: dict[str, str]) -> int:
    if remote_is_configured(cfg, "SDN_SWITCH_SSH") and not local_switch_role(cfg):
        result = remote_command(cfg, "SDN_SWITCH_SSH", "test-h3", [])
        return result.returncode if result else 2
    return _ping_banner("h3", sudo_argv(["bash", str(HOST_EXEC), "h3", "ping", "-c", "2", "-W", "1", "10.0.0.2"]))


def _check_tcp_port(host: str, port: int) -> bool:
    py = "import socket,sys; s=socket.socket(); s.settimeout(.4); r=s.connect_ex(('127.0.0.1',%d)); s.close(); sys.exit(0 if r==0 else 1)" % port
    result = _run_host(host, ["python3", "-c", py], capture=True, timeout=2)
    return result.returncode == 0


def _host_background(host: str, shell_command: str) -> int:
    result = _run_host(host, ["bash", "-lc", shell_command], capture=True, timeout=5)
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")
    return result.returncode


# 12-host "office LAN" layout - matches topology/topo.py
_LEGIT_CLIENTS = ("h3", "h4", "h5", "h6", "h7", "h8", "h9")
_SERVER_IPS    = ("10.0.0.2", "10.0.0.10", "10.0.0.11", "10.0.0.12")


def command_legit_start(_: list[str], cfg: dict[str, str]) -> int:
    if remote_is_configured(cfg, "SDN_SWITCH_SSH") and not local_switch_role(cfg):
        result = remote_command(cfg, "SDN_SWITCH_SSH", "legit-start", [])
        return result.returncode if result else 2
    # Primary server on h2 is the one we check for readiness (always port 5000).
    if _check_tcp_port("h2", 5000):
        success("Protected TCP server already listening on h2:5000")
    else:
        info("Starting protected TCP server on h2")
        server_cmd = f"cd {shlex.quote(str(ROOT))} && nohup python3 {shlex.quote(str(ROOT / 'apps/tcp_server.py'))} --ports 22 80 443 5000 > {shlex.quote(str(ROOT / 'logs/server.log'))} 2>&1 < /dev/null &"
        rc = _host_background("h2", server_cmd)
        if rc != 0:
            return rc
        time.sleep(1)
        if not _check_tcp_port("h2", 5000):
            error("TCP server did not become ready on h2:5000. Check logs/server.log.")
            return 1

    # Keep the h3 heartbeat client (original single-flow tcp_client.py) running too.
    check_client = _run_host("h3", ["bash", "-lc", "pgrep -af '[a]pps/tcp_client.py' >/dev/null"], capture=True, timeout=2)
    if check_client.returncode == 0:
        success("Heartbeat TCP client already running on h3")
    else:
        info("Starting heartbeat TCP client on h3 (steady 2 req/s to h2:5000)")
        client_cmd = f"cd {shlex.quote(str(ROOT))} && nohup python3 {shlex.quote(str(ROOT / 'apps/tcp_client.py'))} --server 10.0.0.2 --port 5000 --interval 0.5 > {shlex.quote(str(ROOT / 'logs/legit.out'))} 2>&1 < /dev/null &"
        _host_background("h3", client_cmd)

    # Fan out the background office chatter across EVERY legit client (h3-h9).
    servers = ",".join(_SERVER_IPS)
    started = 0
    for h in _LEGIT_CLIENTS:
        if not has_mininet_host(h):
            continue
        pg = _run_host(h, ["bash", "-lc", "pgrep -af '[a]pps/background_traffic.py' >/dev/null"], capture=True, timeout=2)
        if pg.returncode == 0:
            continue   # already chattering
        bg_cmd = (
            f"cd {shlex.quote(str(ROOT))} && nohup python3 "
            f"{shlex.quote(str(ROOT / 'apps/background_traffic.py'))} "
            f"--servers {servers} --client-tag {h} "
            f"> {shlex.quote(str(ROOT / 'logs' / f'bg_{h}.log'))} 2>&1 < /dev/null &"
        )
        if _host_background(h, bg_cmd) == 0:
            started += 1
    if started:
        success(f"Started background office chatter on {started} client(s); 7 source IPs hit 4 servers continuously.")
    else:
        info("Background chatter was already running on all available clients.")
    return 0


def attack_local(command: str, args: list[str], mode: str | None = None) -> int:
    mode = mode or local_attacker_mode()
    scripts = {
        "atk-spoof": ["attack_spoof_flood.py", "--target", "10.0.0.2", "--count", "25"],
        "atk-flood": ["attack_conn_flood.py", "--target", "10.0.0.2", "--port", "5000", "--rate", "60", "--duration", "12"],
        "atk-scan": ["attack_port_scan.py", "--target", "10.0.0.2", "--ports", "1-20", "--delay", "0.12", "--timeout", "0.2"],
        "atk-flags": ["attack_invalid_flags.py", "--target", "10.0.0.2", "--port", "5000", "--count", "6"],
        # Heavy-traffic volumetric: few flows, very high PPS -> packet_rate rule via flow-counter polling.
        "atk-rate": ["attack_packet_rate.py", "--target", "10.0.0.2", "--port", "5000", "--flows", "4", "--duration", "15"],
        # Slow-and-low state exhaustion: many HELD simultaneous flows -> concurrent_flows rule.
        "atk-concurrent": ["attack_conn_flood.py", "--target", "10.0.0.2", "--port", "5000", "--hold", "--rate", "5", "--duration", "30"],
    }
    if command not in scripts:
        error(f"Unknown attack command: {command}")
        return 2
    base = ["python3", str(ROOT / "apps" / scripts[command][0]), *scripts[command][1:], *args]
    if mode == "namespace":
        return run(sudo_argv(["ip", "netns", "exec", "attacker", *base]), cwd=ROOT).returncode
    if mode == "mininet":
        return run(sudo_argv(["bash", str(HOST_EXEC), "h1", *base]), cwd=ROOT).returncode
    error("No local attacker execution environment was found.")
    return 2


def command_attack(name: str, args: list[str], cfg: dict[str, str]) -> int:
    mode = local_attacker_mode()
    if mode:
        return attack_local(name, args, mode)
    if cfg.get("SDN_ROLE", "auto").lower() != "attacker" and remote_is_configured(cfg, "SDN_ATTACKER_SSH"):
        result = remote_command(cfg, "SDN_ATTACKER_SSH", name, args)
        return result.returncode if result else 2
    error("No local h1/attacker namespace found. Configure SDN_ATTACKER_SSH for distributed use.")
    return 2


def command_sdn_report(args: list[str], cfg: dict[str, str]) -> int:
    return invoke_controller_report(cfg, args)


def command_sdn_autopilot(_: list[str], cfg: dict[str, str]) -> int:
    print(color("\n╔══════════════════════════════════════════════════════════════╗", BOLD + CYAN))
    print(color("║       SDN-IDS · NARRATED LIVE MITIGATION SHOWCASE            ║", BOLD + CYAN))
    print(color("╚══════════════════════════════════════════════════════════════╝", BOLD + CYAN))
    stages = [
        ("1/7 · Reset existing quarantine rules", lambda: invoke_switch("sdn-unblock", [], cfg)),
        ("2/7 · Verify attacker and legitimate baseline", lambda: (command_test_h1([], cfg), command_test_h3([], cfg))[1]),
        ("3/7 · Send the multi-IP spoofing burst", lambda: command_attack("atk-spoof", [], cfg)),
    ]
    for label, action in stages:
        print("\n" + color("▶ " + label, BOLD + BLUE), flush=True)
        rc = action()
        if rc != 0 and not (label.startswith("2/7") and rc == 1):
            warning(f"Stage returned {rc}; continuing so the remaining evidence can still be collected.")
        if label.startswith("3/7"):
            time.sleep(1.2)
    later = [
        ("4/7 · Inspect live OpenFlow DROP counters", lambda: invoke_switch("sdn-flows", [], cfg)),
        ("5/7 · Prove the attacker is blocked", lambda: command_test_h1([], cfg)),
        ("6/7 · Prove legitimate h3 traffic remains available", lambda: command_test_h3([], cfg)),
        ("7/7 · Print the Deliverable 2 quantitative audit", lambda: command_sdn_report([], cfg)),
    ]
    for label, action in later:
        print("\n" + color("▶ " + label, BOLD + BLUE), flush=True)
        rc = action()
        if rc != 0:
            warning(f"Stage returned {rc}; see its output above.")
    print("\n" + color("Showcase complete. Use sdn-unblock before the next attack vector.", GREEN + BOLD))
    return 0


def command_sdn_help(_: list[str], cfg: dict[str, str]) -> int:
    rows = [
        ("sdn-brain", "Start the Ryu controller (Laptop A)."),
        ("sdn-ui", "Start dashboard on all interfaces; browse http://A_IP:8080."),
        ("sdn-net [A_IP] [C_IP]", "Clean up and start Mininet; C_IP selects 3-laptop mode."),
        ("sdn-sync A_IP", "Force s1 to reconnect to controller A over OpenFlow 1.3."),
        ("sdn-flows", "Color-coded live OpenFlow table and DROP packet counters."),
        ("sdn-unblock", "Remove IDS priority-200/100 drops; Ryu resets state on FLOW_REMOVED."),
        ("test-h1", "Ping h2 from attacker h1 and classify packet loss."),
        ("test-h3", "Ping h2 from legitimate client h3 and show SLA status."),
        ("legit-start", "Ensure h2 server and h3 continuous TCP client are running."),
        ("atk-spoof", "25-packet multi-IP spoofing burst from h1."),
        ("atk-flood", "60 new TCP connections/s; crosses conn_flood threshold."),
        ("atk-scan", "Measured scan of 20 ports; targets port_scan without hitting port_flood first."),
        ("atk-flags", "Scapy SYN+FIN/NULL/XMAS packets; crosses invalid_flags threshold."),
        ("atk-rate", "Volumetric high-PPS flood on a few flows; crosses packet_rate via flow-counter polling."),
        ("atk-concurrent", "Slow-and-low: >=40 held simultaneous flows; crosses concurrent_flows."),
        ("sdn-report [--clear] [--csv FILE]", "Attack-vector counts, DROP counters, SLA and throughput; optional log reset/export."),
        ("sdn-autopilot", "Run the narrated spoof → quarantine → SLA → report showcase."),
        ("sdn-help", "Print this cheat sheet."),
    ]
    print(color("\nSDN-IDS SHORT COMMANDS", BOLD + CYAN))
    print("-" * 104)
    for cmd, desc in rows:
        print(f"{color(cmd, GREEN):<28} {desc}")
    print("\nThree-laptop config: edit /etc/sdn-ids-cli.conf (or tools/sdn-cli.conf) on each laptop.")
    print("Laptop A: SDN_ROLE=controller, SDN_SWITCH_SSH=user@B_IP")
    print("Laptop B: SDN_ROLE=switch, SDN_CONTROLLER_SSH=user@A_IP, SDN_ATTACKER_SSH=user@C_IP, SDN_ATTACKER_IP=C_IP")
    print("Laptop C: SDN_ROLE=attacker, SDN_SWITCH_SSH=user@B_IP, SDN_CONTROLLER_SSH=user@A_IP")
    print("For autopilot across laptops, configure SSH keys and remote sudo as documented in TELEMETRY_RUNBOOK.md.\n")
    return 0


def dispatch_local(name: str, args: list[str], cfg: dict[str, str]) -> int:
    handlers = {
        "sdn-brain": command_sdn_brain,
        "sdn-ui": command_sdn_ui,
        "sdn-net": command_sdn_net,
        "sdn-sync": command_sdn_sync,
        "sdn-flows": command_sdn_flows,
        "sdn-unblock": command_sdn_unblock,
        "test-h1": command_test_h1,
        "test-h3": command_test_h3,
        "legit-start": command_legit_start,
        "atk-spoof": command_attack,
        "atk-flood": command_attack,
        "atk-scan": command_attack,
        "atk-flags": command_attack,
        "atk-rate": command_attack,
        "atk-concurrent": command_attack,
        "sdn-report": command_sdn_report,
        "sdn-autopilot": command_sdn_autopilot,
        "sdn-help": command_sdn_help,
    }
    handler = handlers.get(name)
    if handler is None:
        error(f"Unknown command '{name}'. Run sdn-help.")
        return 2
    if name.startswith("atk-"):
        return handler(name, args, cfg)
    return handler(args, cfg)


def main() -> int:
    invoked = Path(sys.argv[0]).name
    if invoked in COMMANDS:
        name, args = invoked, sys.argv[1:]
    elif len(sys.argv) >= 2 and sys.argv[1] in COMMANDS:
        name, args = sys.argv[1], sys.argv[2:]
    else:
        name, args = "sdn-help", []
    cfg = load_config()
    # Commands that operate on the switch route remotely when running from A/C.
    if name in ("sdn-flows", "sdn-unblock", "test-h3", "legit-start"):
        return invoke_switch(name, args, cfg)
    if name == "sdn-sync":
        return command_sdn_sync(args, cfg)
    if name.startswith("atk-"):
        return command_attack(name, args, cfg)
    if name == "test-h1":
        return command_test_h1(args, cfg)
    if name == "sdn-report":
        return command_sdn_report(args, cfg)
    if name == "sdn-autopilot":
        return command_sdn_autopilot(args, cfg)
    return dispatch_local(name, args, cfg)


if __name__ == "__main__":
    raise SystemExit(main())
