#!/usr/bin/env bash
# LAPTOP C - run an attack script inside the attacker namespace
#   sudo ./run_attacker.sh scan  [args]      e.g.  sudo ./run_attacker.sh scan --ports 1-1024 --delay 0.05
#   sudo ./run_attacker.sh flood [args]      e.g.  sudo ./run_attacker.sh flood --rate 60
#   sudo ./run_attacker.sh spoof [args]      e.g.  sudo ./run_attacker.sh spoof --count 20
#   sudo ./run_attacker.sh ping
#   sudo ./run_attacker.sh shell
cd "$(dirname "$0")"
cmd="$1"; shift
case "$cmd" in
  scan)  exec ip netns exec attacker python3 apps/attack_port_scan.py --target 10.0.0.2 "$@" ;;
  flood) exec ip netns exec attacker python3 apps/attack_conn_flood.py --target 10.0.0.2 "$@" ;;
  spoof) exec ip netns exec attacker python3 apps/attack_spoof_flood.py --target 10.0.0.2 "$@" ;;
  ping)  exec ip netns exec attacker ping -c 4 10.0.0.2 ;;
  shell) exec ip netns exec attacker bash ;;
  *) echo "usage: sudo $0 {scan|flood|spoof|ping|shell} [args]"; exit 1 ;;
esac
