#!/usr/bin/env bash
# =============================================================================
#  TERMINAL 4 · ATTACK CONSOLE (lab IDS/IPS validation)
#  Fires controlled, cooperating-lab attack simulations against the protected
#  servers from one of TWO attacker hosts (h1 / h10), so you can demonstrate
#  detection + mitigation live - including a coordinated multi-source attack.
#  Every option is a bounded test-traffic generator inside Mininet.
#
#  RUN THIS LAST, after Terminals 1-3 are up.
#     sudo ./t4_attacker.sh
# =============================================================================
cd "$(dirname "$0")"
C="\033[96m"; G="\033[92m"; Y="\033[93m"; R="\033[91m"; B="\033[1m"; D="\033[2m"; E="\033[0m"
CLI="python3 tools/sdn_cli.py"
ATK="h1"                       # currently selected attacker (toggle with 'a')
declare -A AIP=( [h1]="10.0.0.1" [h10]="10.0.0.13" )

[[ $EUID -eq 0 ]] || { echo -e "${R}Run with sudo:${E}  sudo ./t4_attacker.sh"; exit 1; }

pause() { echo; read -rp "$(echo -e "${D}press Enter to return to the menu...${E}")" _; }

# ping a given attacker host -> 100% loss means it is blocked at the edge
attacker_blocked_check() {
  local h="$1"
  echo -e "\n${B}${C}-- attacker $h (${AIP[$h]}) — expect 100% loss when blocked --${E}"
  SDN_ATTACKER="$h" ./run_attacker.sh ping 2>/dev/null | sed -n '/statistics/,$p' | grep -E 'packet loss' \
    || echo "  (no reply — blocked / unreachable)"
}

prove() {   # after an attack: flows + active-attacker check + legit SLA
  echo -e "\n${B}${C}-- live OVS flow table (look for Priority-100/200 actions=drop) --${E}"
  $CLI sdn-flows || true
  attacker_blocked_check "$ATK"
  echo -e "\n${B}${C}-- legit client h3 (expect 0% loss = zero collateral) --${E}"
  $CLI test-h3 || true
}

attack() {  # attack <label> <run_attacker-args...>   (uses the selected $ATK)
  local label="$1"; shift
  echo -e "\n${B}${Y}>>> [$ATK] $label${E}"
  echo -e "${D}clearing any previous block first...${E}"
  $CLI sdn-unblock >/dev/null 2>&1 || true
  echo -e "${D}launching from $ATK (${AIP[$ATK]}):  ./run_attacker.sh $*${E}\n"
  SDN_ATTACKER="$ATK" ./run_attacker.sh "$@" || true
  echo -e "\n${D}letting detection + flow-stats polling settle...${E}"
  sleep 4
  prove
}

coordinated() {   # both attackers at once, two different vectors / detection paths
  echo -e "\n${B}${R}>>> COORDINATED DISTRIBUTED ATTACK  (h1 + h10 simultaneously)${E}"
  echo -e "${D}h1 -> SYN connection flood   |   h10 -> volumetric packet-rate flood${E}"
  $CLI sdn-unblock >/dev/null 2>&1 || true
  sleep 1
  SDN_ATTACKER=h1  ./run_attacker.sh flood --rate 80 --duration 14        &
  SDN_ATTACKER=h10 ./run_attacker.sh packet_rate --flows 4 --duration 14  &
  echo -e "${D}both attacks running in parallel... (watch Terminal 2 + the dashboard)${E}"
  wait
  echo -e "\n${D}letting detection + polling settle...${E}"
  sleep 4
  echo -e "\n${B}${C}-- flow table: expect TWO drops (10.0.0.1 AND 10.0.0.13) --${E}"
  $CLI sdn-flows || true
  attacker_blocked_check h1
  attacker_blocked_check h10
  echo -e "\n${B}${C}-- legit client h3 (expect 0% loss) --${E}"
  $CLI test-h3 || true
}

menu() {
  clear 2>/dev/null || true
  echo -e "${B}${C}============================================================${E}"
  echo -e "${B}${C}  TERMINAL 4 · ATTACK CONSOLE  (IDS/IPS validation)${E}"
  echo -e "${B}${C}============================================================${E}"
  echo -e "  selected attacker: ${B}${Y}$ATK${E} ${D}(${AIP[$ATK]})  — toggle with 'a'${E}"
  echo
  echo -e "  ${B}Stateful detection (real-time, Packet-In path):${E}"
  echo -e "    ${G}1${E})  Illegal TCP flags   ${D}(invalid_flags)${E}"
  echo -e "    ${G}2${E})  Port scan           ${D}(port_scan)${E}"
  echo -e "    ${G}3${E})  Multi-IP spoof      ${D}(multi_ip_spoof -> port quarantine)${E}"
  echo -e "  ${B}Heavy-traffic detection (flow-counter polling path):${E}"
  echo -e "    ${G}4${E})  SYN connection flood${D} (conn_flood)${E}"
  echo -e "    ${G}5${E})  Slow-and-low flows  ${D}(concurrent_flows)${E}"
  echo -e "    ${G}6${E})  Volumetric flood    ${D}(packet_rate, high PPS)${E}"
  echo -e "  ${B}Multi-source:${E}"
  echo -e "    ${R}c${E})  COORDINATED attack from BOTH h1 + h10 at once"
  echo -e "    ${G}7${E})  Run all six from the selected attacker"
  echo -e "  ${B}Tools:${E}"
  echo -e "    ${G}a${E})  Toggle attacker (h1 <-> h10)"
  echo -e "    ${G}8${E})  Clear blocks (sdn-unblock)   ${G}9${E}) Show flows   ${G}0${E}) Verify SLA"
  echo -e "    ${G}s${E})  Ensure legit traffic (legit-start)   ${G}r${E}) Final report   ${G}q${E}) Quit"
  echo
}

echo -e "${D}Ensuring servers + background office chatter are running...${E}"
$CLI legit-start || true
sleep 1

while true; do
  menu
  read -rp "$(echo -e "${B}select>${E} ")" choice
  case "$choice" in
    1) attack "Illegal TCP flags (invalid_flags)"   invalid_flags --count 6 ; pause ;;
    2) attack "Port scan (port_scan)"               scan --ports 1-40 --delay 0.1 ; pause ;;
    3) attack "Multi-IP spoof (multi_ip_spoof)"      spoof --count 25 ; pause ;;
    4) attack "SYN connection flood (conn_flood)"    flood --rate 80 --duration 12 ; pause ;;
    5) attack "Slow-and-low concurrent flows"        concurrent ; pause ;;
    6) attack "Volumetric packet-rate flood"         packet_rate --flows 4 --duration 15 ; pause ;;
    c|C) coordinated ; pause ;;
    7)
       attack "1/6 Illegal TCP flags"   invalid_flags --count 6
       attack "2/6 Port scan"           scan --ports 1-40 --delay 0.1
       attack "3/6 Multi-IP spoof"      spoof --count 25
       attack "4/6 SYN conn flood"      flood --rate 80 --duration 12
       attack "5/6 Slow-and-low"        concurrent
       attack "6/6 Volumetric flood"    packet_rate --flows 4 --duration 15
       echo -e "\n${B}${G}All six complete from $ATK.${E}"; pause ;;
    a|A) [[ "$ATK" == "h1" ]] && ATK=h10 || ATK=h1 ;;
    8) echo; $CLI sdn-unblock || true; pause ;;
    9) echo; $CLI sdn-flows   || true; pause ;;
    0) echo; $CLI test-h1 || true; attacker_blocked_check h10; $CLI test-h3 || true; pause ;;
    s) echo; $CLI legit-start || true; pause ;;
    r) echo; $CLI sdn-report --csv logs/deliverable2_results.csv || true; pause ;;
    q|Q) echo -e "${D}leaving the attack console (servers/controller keep running).${E}"; exit 0 ;;
    *) ;;
  esac
done
