#!/usr/bin/env bash
# LAPTOP B - start Mininet (switch s1 + server h2 + legit client h3)
#   sudo ./run_switch.sh <LAPTOP_A_IP> <LAPTOP_C_IP>      3-laptop demo
#   sudo ./run_switch.sh <LAPTOP_A_IP>                    single-laptop backup (h1 = attacker inside Mininet)
cd "$(dirname "$0")"
[ -n "$1" ] || { echo "usage: sudo $0 <LAPTOP_A_IP> [<LAPTOP_C_IP>]"; exit 1; }
(systemctl start openvswitch-switch 2>/dev/null || service openvswitch-switch start 2>/dev/null) || true
if [ -n "$2" ]; then
  exec python3 topology/topo.py --mode distributed --controller-ip "$1" --attacker-ip "$2"
else
  exec python3 topology/topo.py --mode single --controller-ip "$1"
fi
