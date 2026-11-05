#!/usr/bin/env bash
# =============================================================================
#  run_attacker.sh  -  launch controlled lab attack-simulation traffic to
#                      exercise the SDN IDS detection + IPS mitigation.
#
#  Works in BOTH deployment modes automatically, with NO namespace errors:
#    * SINGLE-LAPTOP Mininet  -> runs inside host h1 via tools/mininet_host_exec.sh
#    * 3-LAPTOP distributed   -> runs inside the standalone `attacker` ip-netns
#
#  The script auto-detects which environment is live. On one laptop you simply
#  start Mininet in single mode (sudo ./run_switch.sh 127.0.0.1) and every
#  command below "just works" against host h1 - no `attacker` namespace needed.
#
#    sudo ./run_attacker.sh scan          [args]   # port_scan     (recon)
#    sudo ./run_attacker.sh flood         [args]   # conn_flood    (high SYN rate)
#    sudo ./run_attacker.sh concurrent    [args]   # concurrent_flows (slow-and-low)
#    sudo ./run_attacker.sh packet_rate   [args]   # packet_rate   (volumetric high-PPS)
#    sudo ./run_attacker.sh spoof         [args]   # multi_ip_spoof
#    sudo ./run_attacker.sh invalid_flags [args]   # invalid_flags (NULL/XMAS/SYN+FIN)
#    sudo ./run_attacker.sh ping
#    sudo ./run_attacker.sh shell
#
#  Override the victim with:  SDN_TARGET=10.0.0.2 sudo ./run_attacker.sh ...
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

TARGET="${SDN_TARGET:-10.0.0.2}"
NS="${SDN_ATTACKER_NS:-attacker}"
# Which attacker host runs the traffic. Two attackers exist: h1 and h10.
#   SDN_ATTACKER=h10 sudo ./run_attacker.sh flood     # launch from the 2nd attacker
HOST="${SDN_ATTACKER:-${SDN_MININET_HOST:-h1}}"

die() { echo "[run_attacker] $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run with sudo (entering a network namespace / mnexec needs root)."

cmd="${1:-}"
[[ -n "$cmd" ]] || die "usage: sudo $0 {scan|flood|concurrent|packet_rate|spoof|invalid_flags|ping|shell} [args]"
shift || true

# ---------------------------------------------------------------------------
#  Pick the execution environment ONCE, then exec the requested program in it.
#    1) distributed:  standalone `attacker` ip-netns  (3-laptop VXLAN setup)
#    2) single-laptop: Mininet host h1 PID namespace via mnexec wrapper
# ---------------------------------------------------------------------------
has_netns() { ip netns list 2>/dev/null | awk '{print $1}' | grep -qx "$NS"; }
# Match the exact host, so "h1" does not also match "h10" (pgrep never self-matches).
has_host()  { pgrep -f "mininet:${HOST}([^0-9]|\$)" >/dev/null 2>&1; }

run_in_env() {
  if has_netns; then
    echo "[run_attacker] environment: distributed netns '$NS'" >&2
    exec ip netns exec "$NS" "$@"
  elif has_host; then
    echo "[run_attacker] environment: single-laptop Mininet host '$HOST'" >&2
    exec bash tools/mininet_host_exec.sh "$HOST" "$@"
  else
    die "No attacker environment found.
  * Single laptop: start Mininet so host '$HOST' exists ->  sudo ./run_switch.sh 127.0.0.1
  * 3 laptops    : bring up the attacker node          ->  sudo ./topology/attacker_node.sh up <SWITCH_IP>"
  fi
}

case "$cmd" in
  scan)          run_in_env python3 apps/attack_port_scan.py    --target "$TARGET" "$@" ;;
  flood)         run_in_env python3 apps/attack_conn_flood.py   --target "$TARGET" "$@" ;;
  # slow-and-low state exhaustion: many simultaneous HELD flows, low new-conn rate
  concurrent)    run_in_env python3 apps/attack_conn_flood.py   --target "$TARGET" --hold --rate 5 --duration 30 "$@" ;;
  # volumetric: few established flows, very high packets/sec (caught by flow-counter polling)
  packet_rate)   run_in_env python3 apps/attack_packet_rate.py  --target "$TARGET" "$@" ;;
  spoof)         run_in_env python3 apps/attack_spoof_flood.py  --target "$TARGET" "$@" ;;
  invalid_flags) run_in_env python3 apps/attack_invalid_flags.py --target "$TARGET" "$@" ;;
  ping)          run_in_env ping -c 4 "$TARGET" ;;
  shell)         run_in_env bash ;;
  *) die "usage: sudo $0 {scan|flood|concurrent|packet_rate|spoof|invalid_flags|ping|shell} [args]" ;;
esac
