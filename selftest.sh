#!/usr/bin/env bash
# =============================================================================
#  selftest.sh  -  readiness check for the SDN IDS + IPS single-laptop demo.
#
#  Runs WITHOUT sudo and WITHOUT starting the controller/Mininet. It verifies
#  the code is intact and that every tool the live demo needs is installed, then
#  prints a clear READY / NOT-READY verdict. Run this tonight before the demo.
#
#     ./selftest.sh
# =============================================================================
cd "$(dirname "$0")"
ROOT="$(pwd)"

R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"; BOLD="\033[1m"; E="\033[0m"
pass() { echo -e "  ${G}[PASS]${E} $*"; }
warn() { echo -e "  ${Y}[WARN]${E} $*"; WARNS=$((WARNS+1)); }
fail() { echo -e "  ${R}[FAIL]${E} $*"; FAILS=$((FAILS+1)); }
hdr()  { echo -e "\n${BOLD}${C}== $* ==${E}"; }
WARNS=0; FAILS=0

have() { command -v "$1" >/dev/null 2>&1; }

# venv python if present, else system python3
PY="python3"
VENV="$HOME/ryu-venv"
[ -x "$VENV/bin/python3" ] && PY="$VENV/bin/python3"

echo -e "${BOLD}${C}SDN IDS + IPS single-laptop readiness self-test${E}"
echo    "Project: $ROOT"

# ---- 1. code files present --------------------------------------------------
hdr "1. Project files"
FILES=(run_controller.sh run_switch.sh run_attacker.sh auto_demo.sh
       tools/sdn_cli.py tools/mininet_host_exec.sh tools/report.py tools/telemetry_panel.py
       apps/attack_packet_rate.py apps/attack_conn_flood.py apps/attack_port_scan.py
       apps/attack_spoof_flood.py apps/attack_invalid_flags.py apps/tcp_server.py apps/tcp_client.py
       apps/background_traffic.py
       controller/ids_controller.py controller/ids_engine.py controller/ids_rules.json
       topology/topo.py)
for f in "${FILES[@]}"; do
  [ -f "$f" ] && pass "$f" || fail "missing: $f"
done

# ---- 2. executable bits -----------------------------------------------------
hdr "2. Executable bits"
for f in run_controller.sh run_switch.sh run_attacker.sh auto_demo.sh selftest.sh \
         tools/mininet_host_exec.sh tools/sdn_cli.py tools/install_cli_shortcuts.sh; do
  if [ -x "$f" ]; then pass "$f is +x"
  else warn "$f not executable -> run: chmod +x $f"; fi
done

# ---- 3. python compiles -----------------------------------------------------
hdr "3. Python syntax"
if $PY -m py_compile tools/sdn_cli.py apps/*.py controller/ids_engine.py 2>/tmp/stc.$$; then
  pass "all Python files compile"
else
  fail "syntax error:"; sed 's/^/        /' /tmp/stc.$$
fi
rm -f /tmp/stc.$$

# ---- 4. unit tests (no ryu / no root needed) --------------------------------
hdr "4. Unit tests"
if $PY tests/test_engine.py >/tmp/te.$$ 2>&1; then pass "engine tests ($(grep -o 'Ran [0-9]* test' /tmp/te.$$))"
else fail "engine tests failed:"; tail -5 /tmp/te.$$ | sed 's/^/        /'; fi
if $PY tests/test_cli_suite.py >/tmp/tc.$$ 2>&1; then pass "CLI tests ($(grep -o 'Ran [0-9]* test' /tmp/tc.$$))"
else fail "CLI tests failed:"; tail -5 /tmp/tc.$$ | sed 's/^/        /'; fi
rm -f /tmp/te.$$ /tmp/tc.$$

# ---- 5. required tools ------------------------------------------------------
hdr "5. System tools"
have python3  && pass "python3 $(python3 -V 2>&1 | awk '{print $2}')" || fail "python3 missing"
have mn       && pass "mininet (mn)"            || fail "mininet missing -> sudo apt install mininet"
have mnexec   && pass "mnexec (host entry)"     || fail "mnexec missing (part of mininet)"
have ovs-vsctl&& pass "open vswitch"            || fail "ovs missing -> sudo apt install openvswitch-switch"
have ovs-ofctl&& pass "ovs-ofctl"               || fail "ovs-ofctl missing"
have tmux     && pass "tmux (auto_demo launcher)" || warn "tmux missing -> sudo apt install tmux (or use: sudo ./auto_demo.sh --no-launch)"

# ---- 6. python deps ---------------------------------------------------------
hdr "6. Python environment"
if [ -f "$VENV/bin/activate" ]; then pass "virtualenv found: $VENV"; else warn "no venv at $VENV (ryu-manager must be on PATH some other way)"; fi
if $PY -c "import ryu" 2>/dev/null; then pass "ryu importable ($PY)"; else fail "ryu not importable by $PY -> activate venv / reinstall ryu"; fi
if have ryu-manager || [ -x "$VENV/bin/ryu-manager" ]; then pass "ryu-manager present"; else fail "ryu-manager not found -> source ~/ryu-venv/bin/activate"; fi
if $PY -c "import scapy" 2>/dev/null; then pass "scapy present (spoof / invalid_flags)"; else warn "scapy missing -> $VENV/bin/pip install scapy  (only spoof & invalid_flags need it)"; fi

# ---- verdict ----------------------------------------------------------------
echo -e "\n${BOLD}${C}===========================================================${E}"
if [ "$FAILS" -eq 0 ] && [ "$WARNS" -eq 0 ]; then
  echo -e "${BOLD}${G}READY ✅  — everything checks out. Run: sudo ./auto_demo.sh${E}"
elif [ "$FAILS" -eq 0 ]; then
  echo -e "${BOLD}${Y}READY (with $WARNS warning[s]) — demo will run; see WARN lines above.${E}"
else
  echo -e "${BOLD}${R}NOT READY ❌  — $FAILS failure[s], $WARNS warning[s]. Fix the FAIL lines first.${E}"
fi
echo -e "${BOLD}${C}===========================================================${E}"
[ "$FAILS" -eq 0 ]
