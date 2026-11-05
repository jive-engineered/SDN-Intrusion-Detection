#!/usr/bin/env bash
# =============================================================================
#  TERMINAL 3 · TELEMETRY PANEL
#  The live web dashboard (per-host status, packet-rate chart, event feed,
#  active quarantine).
#
#  RUN THIS THIRD, after Terminal 2 shows "[SWITCH] s1 connected".
#  It serves the dashboard on port 8080; open it in your browser.
#
#     sudo ./t3_telemetry.sh
#     then open:  http://127.0.0.1:8080
# =============================================================================
cd "$(dirname "$0")"
C="\033[96m"; G="\033[92m"; Y="\033[93m"; R="\033[91m"; B="\033[1m"; D="\033[2m"; E="\033[0m"

[[ $EUID -eq 0 ]] || { echo -e "${R}Run with sudo:${E}  sudo ./t3_telemetry.sh"; exit 1; }

echo -e "${B}${C}============================================================${E}"
echo -e "${B}${C}  TERMINAL 3 · LIVE TELEMETRY PANEL${E}"
echo -e "${B}${C}============================================================${E}"

# Gentle nudge if the controller is not writing status yet (panel still works,
# it will just show "controller offline" until the controller is up).
if ! ss -ltn 2>/dev/null | grep -q ':6653 '; then
  echo -e "${Y}Note: the controller (:6653) is not up yet. The panel will show 'offline'${E}"
  echo -e "${Y}until Terminal 2 is running. Start it, then refresh the page.${E}"
fi

echo
echo -e "${B}${G}>>> OPEN THIS IN YOUR BROWSER:  http://127.0.0.1:8080  <<<${E}"
echo -e "${D}Best moment to open it: right after Terminal 2 shows '[SWITCH] s1 connected',${E}"
echo -e "${D}and BEFORE you launch attacks in Terminal 4 - so the professor watches it react live.${E}"
echo -e "${D}Leave this terminal running. Ctrl-C stops the dashboard.${E}"
echo

exec python3 tools/sdn_cli.py sdn-ui
