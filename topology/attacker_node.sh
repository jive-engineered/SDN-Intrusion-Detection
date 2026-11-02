#!/usr/bin/env bash
# =============================================================================
#  attacker_node.sh  -  run on LAPTOP C (the attacker)
#
#  Builds a tiny Open vSwitch bridge and an isolated "attacker" network namespace
#  (IP 10.0.0.1/24, MAC 00:00:00:00:00:01) that is connected through a VXLAN tunnel
#  to the Open vSwitch s1 running on LAPTOP B. To the SDN controller the attacker
#  looks like a normal host plugged into a switch port.
#
#     sudo ./topology/attacker_node.sh up <LAPTOP_B_IP>
#     sudo ./topology/attacker_node.sh status
#     sudo ./topology/attacker_node.sh down
#
#  Run attacks inside the namespace:
#     sudo ip netns exec attacker python3 apps/attack_port_scan.py --target 10.0.0.2
# =============================================================================
set -e
BR=br-att; NS=attacker; KEY=100; ATT_IP=10.0.0.1/24; ATT_MAC=00:00:00:00:00:01

need_root() { [ "$(id -u)" = 0 ] || { echo "Run with sudo"; exit 1; }; }

case "$1" in
  up)
    need_root
    B_IP="$2"; [ -n "$B_IP" ] || { echo "usage: sudo $0 up <LAPTOP_B_IP>"; exit 1; }
    "$0" down >/dev/null 2>&1 || true
    (systemctl start openvswitch-switch 2>/dev/null || service openvswitch-switch start 2>/dev/null) || true
    sleep 1
    ovs-vsctl --may-exist add-br $BR
    ovs-vsctl set-fail-mode $BR standalone                     # plain learning switch, no controller
    ovs-vsctl --may-exist add-port $BR vx0 -- set interface vx0 type=vxlan \
              options:remote_ip="$B_IP" options:key=$KEY
    ip netns add $NS
    ovs-vsctl --may-exist add-port $BR att0 -- set interface att0 type=internal
    ip link set att0 netns $NS
    ip netns exec $NS ip link set lo up
    ip netns exec $NS ip link set dev att0 address $ATT_MAC
    ip netns exec $NS ip addr add $ATT_IP dev att0
    ip netns exec $NS ip link set att0 mtu 1400 up            # VXLAN adds 50 bytes of overhead
    echo "[OK] attacker namespace '$NS' ready: $ATT_IP  <==VXLAN==>  $B_IP"
    echo "     test:  sudo ip netns exec $NS ping -c 3 10.0.0.2     (Laptop B must already be running topo.py)"
    ;;
  down)
    need_root
    ovs-vsctl --if-exists del-br $BR
    ip netns del $NS 2>/dev/null || true
    echo "[OK] attacker node removed"
    ;;
  status)
    ovs-vsctl show | sed -n '1,25p'
    ip netns exec $NS ip -br addr 2>/dev/null || echo "namespace '$NS' not present"
    ;;
  *)
    echo "usage: sudo $0 {up <LAPTOP_B_IP>|down|status}"; exit 1 ;;
esac
