#!/usr/bin/env bash
# =============================================================================
#  TERMINAL 2 · CONTROL PLANE
#  The Ryu IDS/IPS controller (the "brain").
#
#  RUN THIS SECOND, after Terminal 1 shows the mininet> prompt.
#  It waits for the switch to exist (so Mininet's startup cleanup is finished
#  and cannot kill us), applies the internal-client whitelist, then starts the
#  controller. Watch this terminal during the demo: every [IDS ALERT],
#  [IDS RESPONSE ... MITIGATED] and [IDS RECOVERY] line prints here live.
#
#     sudo -E ./t2_controlplane.sh
# =============================================================================
cd "$(dirname "$0")"
C="\033[96m"; G="\033[92m"; Y="\033[93m"; R="\033[91m"; B="\033[1m"; D="\033[2m"; E="\033[0m"
SWITCH=s1

[[ $EUID -eq 0 ]] || { echo -e "${R}Run with sudo -E:${E}  sudo -E ./t2_controlplane.sh"; exit 1; }

echo -e "${B}${C}============================================================${E}"
echo -e "${B}${C}  TERMINAL 2 · CONTROL PLANE  (Ryu IDS/IPS controller)${E}"
echo -e "${B}${C}============================================================${E}"

# The data plane must be up first. If not, wait for it (and tell the user why).
if ! ovs-vsctl br-exists "$SWITCH" 2>/dev/null; then
  echo -e "${Y}Switch $SWITCH not found yet - waiting for Terminal 1 (data plane)...${E}"
  echo -e "${D}If you have not started it, open Terminal 1 and run:  sudo ./t1_dataplane.sh${E}"
  for i in $(seq 1 60); do
    ovs-vsctl br-exists "$SWITCH" 2>/dev/null && break
    sleep 1
  done
  if ! ovs-vsctl br-exists "$SWITCH" 2>/dev/null; then
    echo -e "${R}Still no switch after 60s. Start Terminal 1 first, then rerun this.${E}"
    exit 1
  fi
fi
echo -e "${G}[ OK ] data plane is up (switch $SWITCH exists)${E}"

# Whitelist the 7 internal clients so the realistic office chatter does not trip
# the sensitive port_scan rule. Only the untrusted host (h1) stays detectable.
python3 - <<'PY' 2>/dev/null && echo -e "${G}[ OK ] internal clients h3-h9 whitelisted in ids_rules.json${E}" || true
import json
p = "controller/ids_rules.json"
d = json.load(open(p))
d["protected_hosts"] = ["10.0.0.2","10.0.0.10","10.0.0.11","10.0.0.12",
                        "10.0.0.3","10.0.0.4","10.0.0.5","10.0.0.6","10.0.0.7","10.0.0.8","10.0.0.9"]
json.dump(d, open(p, "w"), indent=2)
PY

echo
echo -e "${B}${Y}NEXT:${E} once you see ${B}[SWITCH] s1 connected${E} below, start ${B}Terminal 3${E}:  ${C}sudo ./t3_telemetry.sh${E}"
echo -e "${G}Starting the controller now (Ctrl-C here stops it)...${E}"
echo

# run_controller.sh resolves ~/ryu-venv even under sudo (uses SUDO_USER).
exec ./run_controller.sh
