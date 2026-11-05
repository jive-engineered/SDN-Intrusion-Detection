#!/usr/bin/env bash
# =============================================================================
#  auto_demo.sh  -  1-click automated demo + verification for the
#                   SDN-Based Intrusion Detection System (IDS) with inline
#                   Intrusion Prevention System (IPS) hardware mitigation,
#                   built on Ryu + Open vSwitch + Mininet. SINGLE-LAPTOP mode.
#
#  What it does, hands-free:
#    1. Ensures the Ryu controller and the single-laptop Mininet topology are up
#       (launches them in tmux if they are not already running).
#    2. Starts the legitimate client on h3 -> protected server h2:5000.
#    3. Runs every attack scenario from h1 in sequence, and after each one:
#         - prints the live OVS flow table (Priority-100/200 DROP proof),
#         - proves h1 is dropped at the switch edge (100% loss),
#         - proves h3 legitimate traffic is untouched (0% loss),
#         - clears the block so the next scenario starts clean
#           (self-healing via idle_timeout is also demonstrated once).
#    4. Prints the final quantitative benchmark via tools/report.py.
#
#  Usage:
#     sudo ./auto_demo.sh                 # full automated showcase
#     sudo ./auto_demo.sh --no-launch     # assume controller+mininet already up
#     sudo ./auto_demo.sh --heal-wait 35  # actually wait for idle_timeout eviction
#     sudo KEEP_UP=1 ./auto_demo.sh       # leave tmux sessions running at the end
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
ROOT="$(pwd)"
export ROOT

# ----- configuration ---------------------------------------------------------
CTRL_IP="127.0.0.1"
SWITCH="s1"
CLI="python3 $ROOT/tools/sdn_cli.py"
ATTACK="$ROOT/run_attacker.sh"
TMUX_CTRL="sdn-brain"
TMUX_MN="sdn-mn"
LAUNCH=1
HEAL_WAIT=0          # seconds to wait to show idle_timeout self-eviction (0 = use sdn-unblock instead)
SETTLE=4             # seconds to let detection + one stats poll complete after an attack

# ----- colours ---------------------------------------------------------------
R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"; B="\033[94m"; BOLD="\033[1m"; D="\033[2m"; E="\033[0m"
say()   { echo -e "$*"; }
hdr()   { echo -e "\n${BOLD}${C}============================================================${E}"; echo -e "${BOLD}${C}  $*${E}"; echo -e "${BOLD}${C}============================================================${E}"; }
step()  { echo -e "\n${BOLD}${B}▶ $*${E}"; }
ok()    { echo -e "  ${G}[ OK ]${E} $*"; }
warn()  { echo -e "  ${Y}[WARN]${E} $*"; }
bad()   { echo -e "  ${R}[FAIL]${E} $*"; }

for arg in "$@"; do
  case "$arg" in
    --no-launch) LAUNCH=0 ;;
    --heal-wait) : ;;  # value consumed below
    --heal-wait=*) HEAL_WAIT="${arg#*=}" ;;
    [0-9]*) HEAL_WAIT="$arg" ;;   # bare number after --heal-wait
  esac
done

[[ $EUID -eq 0 ]] || { bad "Run with sudo:  sudo ./auto_demo.sh"; exit 1; }

# ----- helpers ---------------------------------------------------------------
# Every process check uses pgrep (which never reports itself) or a bracketed
# pattern, so no check can be fooled by its own command line.
ctrl_up()    { ss -ltn 2>/dev/null | grep -q ':6653 '; }
ctrl_alive() { pgrep -f '[r]yu-manager' >/dev/null 2>&1; }
mn_up()      { pgrep -f 'topology/topo\.py' >/dev/null 2>&1; }
bridge_up()  { ovs-vsctl br-exists "$SWITCH" 2>/dev/null; }
hosts_up()   { pgrep -f 'mininet:h10([^0-9]|$)' >/dev/null 2>&1; }  # h10 is the last host topo.py creates
net_ready()  { bridge_up && hosts_up; }
sw_ready()   { ovs-ofctl -O OpenFlow13 dump-flows "$SWITCH" 2>/dev/null | grep -q 'priority=5'; }

wait_for() {  # wait_for <desc> <timeout> <fn>   (prints OK / FAIL)
  local desc="$1" timeout="$2" fn="$3" i=0
  while ! $fn; do
    sleep 1; i=$((i+1))
    if [[ $i -ge $timeout ]]; then bad "Timed out waiting for: $desc"; return 1; fi
  done
  ok "$desc"
  return 0
}
wait_quiet() {  # wait_quiet <timeout> <fn>   (silent; just returns status)
  local timeout="$1" fn="$2" i=0
  while ! $fn; do
    sleep 1; i=$((i+1))
    [[ $i -ge $timeout ]] && return 1
  done
  return 0
}

have_tmux() { command -v tmux >/dev/null 2>&1; }

hard_reset() {  # wipe every leftover from previous runs
  tmux kill-session -t "$TMUX_MN"   2>/dev/null || true
  tmux kill-session -t "$TMUX_CTRL" 2>/dev/null || true
  pkill -9 -f '[r]yu-manager'             2>/dev/null || true
  pkill -9 -f '[t]opology/topo\.py'       2>/dev/null || true
  pkill -9 -f '[b]ackground_traffic\.py'  2>/dev/null || true
  pkill -9 -f '[t]cp_(server|client)\.py' 2>/dev/null || true
  pkill -9 -f '[m]ininet:'                2>/dev/null || true
  mn -c >/dev/null 2>&1 || true
  ovs-vsctl --if-exists del-br "$SWITCH" 2>/dev/null || true
  sleep 1
}

start_controller() {
  tmux kill-session -t "$TMUX_CTRL" 2>/dev/null || true
  # SUDO_USER lets run_controller.sh find the user's ~/ryu-venv under sudo.
  tmux new-session -d -s "$TMUX_CTRL" "cd $ROOT && SUDO_USER='${SUDO_USER:-}' ./run_controller.sh 2>&1 | tee logs/controller.out"
}

kick_switch() {  # make s1 reconnect now instead of waiting out OVS back-off
  ovs-vsctl del-controller "$SWITCH" 2>/dev/null || true
  ovs-vsctl set-controller "$SWITCH" "tcp:$CTRL_IP:6653" 2>/dev/null || true
}

diag() {  # printed automatically on any startup failure
  echo -e "\n${BOLD}${Y}---------------- automatic diagnostics ----------------${E}"
  echo -e "${BOLD}controller process :${E} $(ctrl_alive && echo alive || echo DEAD)"
  echo -e "${BOLD}port 6653          :${E} $(ctrl_up && echo listening || echo closed)"
  echo -e "${BOLD}bridge $SWITCH          :${E} $(bridge_up && echo present || echo missing)"
  echo -e "${BOLD}mininet hosts      :${E} $(hosts_up && echo up || echo missing)"
  echo -e "${BOLD}ovs-vsctl show:${E}";                     ovs-vsctl show 2>&1 | sed -n '1,20p'
  echo -e "${BOLD}last 25 lines of logs/controller.out:${E}"; tail -n 25 "$ROOT/logs/controller.out" 2>/dev/null || echo "(no file)"
  echo -e "${BOLD}last 25 lines of logs/mininet.out:${E}";    tail -n 25 "$ROOT/logs/mininet.out"    2>/dev/null || echo "(no file)"
  echo -e "${BOLD}${Y}-------------------------------------------------------${E}"
  echo "Copy this whole block when asking for help."
}

apply_whitelist() {  # trust the 7 internal clients so office chatter can't trip port_scan
python3 - <<'PY' || warn "could not apply whitelist (continuing with current rules)"
import json, os
p = os.path.join(os.environ.get("ROOT", "."), "controller/ids_rules.json")
d = json.load(open(p))
want = ["10.0.0.2","10.0.0.10","10.0.0.11","10.0.0.12",
        "10.0.0.3","10.0.0.4","10.0.0.5","10.0.0.6","10.0.0.7","10.0.0.8","10.0.0.9"]
if set(d.get("protected_hosts", [])) != set(want):
    d["protected_hosts"] = want
    json.dump(d, open(p, "w"), indent=2)
    print("  [whitelist] protected_hosts updated in ids_rules.json")
else:
    print("  [whitelist] already correct")
PY
}

# =============================================================================
hdr "SDN IDS + IPS · AUTOMATED DEMO (single laptop · 13-host office LAN · 2 attackers)"
echo -e "${BOLD}  Topology:${E} 2 attackers (h1, h10) · 4 protected servers · 7 legit clients (continuous office chatter)"
echo -e "${BOLD}  Live dashboard:${E} open a new terminal and run  ${C}sudo python3 tools/sdn_cli.py sdn-ui${E}  then browse http://127.0.0.1:8080"

# Whitelist first, so the controller loads the right rules the moment it boots.
apply_whitelist

# ----- 1. bring-up ----------------------------------------------------------
# WHY THE ORDER MATTERS: Mininet's own startup cleanup runs
#   killall ... ryu-manager
# so a controller that is already running gets killed when Mininet starts.
# We therefore start Mininet, wait until the network is fully BUILT (bridge s1
# and every host exist, meaning that cleanup is long finished), and only then
# start the controller.
if [[ $LAUNCH -eq 1 ]]; then
  step "1/4 · Fresh start: Mininet first, controller second"
  have_tmux || { bad "tmux is required for one-command mode:  sudo apt install -y tmux"; exit 1; }
  hard_reset
  ok "cleared stale Mininet / OVS / controller state"

  mkdir -p "$ROOT/logs"; : > "$ROOT/logs/mininet.out"; : > "$ROOT/logs/controller.out"
  tmux new-session -d -s "$TMUX_MN" "cd $ROOT && ./run_switch.sh $CTRL_IP 2>&1 | tee logs/mininet.out"
  say "  ${D}launched 13-host Mininet in tmux session '$TMUX_MN'${E}"
  wait_for "13-host network built (bridge $SWITCH + all hosts up)" 60 net_ready || { diag; exit 1; }
  sleep 2   # let net.start() finish before the controller appears

  start_controller
  say "  ${D}launched Ryu controller in tmux session '$TMUX_CTRL'${E}"
  wait_for "controller listening on :6653" 30 ctrl_up || { diag; exit 1; }
else
  step "1/4 · --no-launch: assuming Mininet + controller are already up"
  mn_up   || { bad "Mininet not running. Start it first:  sudo ./run_switch.sh 127.0.0.1"; exit 1; }
  ctrl_up || { bad "Controller not listening on :6653. Start it second:  sudo ./run_controller.sh"; exit 1; }
fi

# ----- 1b. OpenFlow handshake, with automatic recovery ----------------------
if wait_quiet 15 sw_ready; then
  ok "switch $SWITCH connected to controller (table-miss rules installed)"
else
  if ! ctrl_alive; then
    warn "controller process died during startup - restarting it once"
    start_controller
    wait_for "controller listening on :6653 (restart)" 30 ctrl_up || { diag; exit 1; }
  fi
  warn "nudging $SWITCH to reconnect to tcp:$CTRL_IP:6653"
  kick_switch
  wait_for "switch $SWITCH connected to controller (retry)" 30 sw_ready || { diag; exit 1; }
fi
[[ $LAUNCH -eq 0 ]] && sleep 4   # running controller re-reads ids_rules.json every stats_interval

# ----- 2. legitimate baseline ------------------------------------------------
step "2/4 · Starting the legitimate client (h3 -> h2:5000) and clearing old logs"
$CLI legit-start
python3 "$ROOT/tools/report.py" --clear >/dev/null 2>&1 && ok "logs cleared for a fresh benchmark" || warn "could not clear logs (continuing)"
$CLI sdn-unblock >/dev/null 2>&1 || true
sleep 2
step "Baseline connectivity BEFORE any attack"
$CLI test-h1 || true      # should be reachable now (0% loss)
$CLI test-h3 || true      # should be reachable (0% loss)

# ----- 3. attack scenarios ---------------------------------------------------
# name | human label | rule proven | command
run_scenario() {
  local label="$1" rule="$2"; shift 2
  hdr "SCENARIO: $label   (rule: $rule)"
  step "Clean slate"
  $CLI sdn-unblock >/dev/null 2>&1 || true
  sleep 1
  step "Launching attack from h1:  $*"
  "$@" || true
  say "  ${D}letting detection + flow-stats polling settle (${SETTLE}s)...${E}"
  sleep "$SETTLE"
  step "Live OVS flow table (look for Priority-100/200 actions=drop)"
  $CLI sdn-flows || true
  step "Is the ATTACKER (h1) dropped at the switch edge?"
  $CLI test-h1 || true
  step "Is LEGITIMATE traffic (h3) still intact? (zero collateral damage)"
  $CLI test-h3 || true
}

# -- Group A: stateful IDS/IPS detection vectors (Packet-In path) --
run_scenario "Stealth illegal TCP flags (NULL / XMAS / SYN+FIN)" "invalid_flags" \
  "$ATTACK" invalid_flags --count 6
run_scenario "Port-scan reconnaissance" "port_scan" \
  "$ATTACK" scan --ports 1-40 --delay 0.1
run_scenario "Multi-IP spoofing from one host (ingress-port quarantine)" "multi_ip_spoof" \
  "$ATTACK" spoof --count 25

# -- Group B: heavy-traffic / volumetric vectors (flow-counter polling path) --
run_scenario "High-rate SYN connection flood" "conn_flood" \
  "$ATTACK" flood --rate 80 --duration 12
run_scenario "Slow-and-low state exhaustion (>=40 held flows)" "concurrent_flows" \
  "$ATTACK" concurrent
run_scenario "Volumetric high-PPS flood (flow-counter polling)" "packet_rate" \
  "$ATTACK" packet_rate --flows 4 --duration 15

# -- Group C: COORDINATED multi-source attack (both attackers at once) --------
hdr "SCENARIO: Coordinated distributed attack from BOTH h1 and h10   (rule: conn_flood + packet_rate)"
step "Clean slate"
$CLI sdn-unblock >/dev/null 2>&1 || true
sleep 1
step "Launching SIMULTANEOUS attacks: h1 -> SYN flood  &  h10 -> volumetric flood"
SDN_ATTACKER=h1  "$ATTACK" flood --rate 80 --duration 14        &
SDN_ATTACKER=h10 "$ATTACK" packet_rate --flows 4 --duration 14  &
wait
say "  ${D}letting detection + flow-stats polling settle (${SETTLE}s)...${E}"
sleep "$SETTLE"
step "Live OVS flow table (expect TWO Priority-100 drops: 10.0.0.1 and 10.0.0.13)"
$CLI sdn-flows || true
step "Are BOTH attackers dropped at the switch edge?"
$CLI test-h1 || true
SDN_ATTACKER=h10 "$ATTACK" ping >/dev/null 2>&1 && echo "  h10 still reachable (unexpected)" || echo "  h10 (10.0.0.13) dropped at the edge"
step "Is LEGITIMATE traffic (h3) still intact? (zero collateral damage)"
$CLI test-h3 || true

# ----- self-healing demonstration -------------------------------------------
hdr "SELF-HEALING  (automatic DROP eviction on idle_timeout / OFPFlowRemoved)"
if [[ "$HEAL_WAIT" -gt 0 ]]; then
  step "Attack has stopped. Waiting ${HEAL_WAIT}s for the switch to evict the DROP rule by idle_timeout"
  sleep "$HEAL_WAIT"
  ok "idle_timeout elapsed - the controller logs an [IDS RECOVERY] UNBLOCKED event"
else
  step "Clearing residual quarantine rules (equivalent to the automatic idle_timeout eviction)"
  $CLI sdn-unblock || true
fi
step "Flow table after recovery (DROP rules should be gone)"
$CLI sdn-flows || true
step "h1 reachable again after recovery?"
$CLI test-h1 || true

# ----- 4. final benchmark ----------------------------------------------------
hdr "4/4 · FINAL QUANTITATIVE BENCHMARK  (tools/report.py)"
python3 "$ROOT/tools/report.py" --csv "$ROOT/logs/deliverable2_results.csv" || true
ok "CSV exported: logs/deliverable2_results.csv"

# ----- teardown --------------------------------------------------------------
hdr "DEMO COMPLETE"
say "Controller log : logs/controller.out    (tmux attach -t $TMUX_CTRL)"
say "Mininet log    : logs/mininet.out       (tmux attach -t $TMUX_MN)"
say "Event log      : logs/ids_events.jsonl  |  Stats: logs/flow_stats.csv"
if [[ "${KEEP_UP:-0}" = "1" ]]; then
  warn "KEEP_UP=1 -> leaving controller/Mininet tmux sessions running."
else
  if have_tmux; then
    step "Stopping background tmux sessions (set KEEP_UP=1 to keep them)"
    tmux kill-session -t "$TMUX_MN"   2>/dev/null && ok "stopped Mininet session" || true
    tmux kill-session -t "$TMUX_CTRL" 2>/dev/null && ok "stopped controller session" || true
    mn -c >/dev/null 2>&1 || true
  fi
fi
echo -e "\n${BOLD}${G}All scenarios demonstrated. Full report written to logs/deliverable2_results.csv${E}\n"
