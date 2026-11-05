#!/usr/bin/env bash
# =============================================================================
#  TERMINAL 1 · DATA PLANE
#  Open vSwitch (s1) + the 12-host office LAN (Mininet).
#
#  RUN THIS FIRST. It clears any stale state, builds the network, auto-starts
#  the four servers and the background office chatter, then drops you at the
#  mininet> prompt. Leave this terminal open for the whole demo.
#
#     sudo ./t1_dataplane.sh
# =============================================================================
cd "$(dirname "$0")"
C="\033[96m"; G="\033[92m"; Y="\033[93m"; R="\033[91m"; B="\033[1m"; D="\033[2m"; E="\033[0m"

[[ $EUID -eq 0 ]] || { echo -e "${R}Run with sudo:${E}  sudo ./t1_dataplane.sh"; exit 1; }

echo -e "${B}${C}============================================================${E}"
echo -e "${B}${C}  TERMINAL 1 · DATA PLANE  (switch s1 + 12-host office LAN)${E}"
echo -e "${B}${C}============================================================${E}"

echo -e "${Y}Clearing any stale Mininet / OVS state from a previous run...${E}"
pkill -9 -f '[t]opology/topo\.py'      2>/dev/null || true
pkill -9 -f '[b]ackground_traffic\.py' 2>/dev/null || true
pkill -9 -f '[t]cp_server\.py'         2>/dev/null || true
pkill -9 -f '[t]cp_client\.py'         2>/dev/null || true
pkill -9 -f '[m]ininet:'               2>/dev/null || true
mn -c >/dev/null 2>&1 || true
ovs-vsctl --if-exists del-br s1 2>/dev/null || true

echo -e "${G}Building network: attacker h1 · servers h2/srv2/srv3/srv4 · clients h3-h9${E}"
echo -e "${D}(servers + background chatter start automatically)${E}"
echo
echo -e "${B}${Y}NEXT:${E} when you see the ${B}mininet>${E} prompt below, go to ${B}Terminal 2${E} and run  ${C}sudo -E ./t2_controlplane.sh${E}"
echo -e "${D}Useful commands at the mininet> prompt:${E}"
echo -e "${D}   nodes                                   # list all 12 hosts${E}"
echo -e "${D}   pingall                                 # reachability matrix${E}"
echo -e "${D}   sh ovs-ofctl -O OpenFlow13 dump-flows s1   # live flow table${E}"
echo

# run_switch.sh -> topology/topo.py (single mode). topo.py runs Mininet's own
# cleanup at startup (which kills any ryu-manager), so the controller must be
# started AFTER this - that is exactly what Terminal 2 does.
exec ./run_switch.sh 127.0.0.1
