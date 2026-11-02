#!/usr/bin/env bash
# Quick self-check before the presentation.   ./tools/preflight.sh {controller|switch|attacker} [peer_ip ...]
ROLE="$1"; shift
ok()   { echo -e "  \033[92m[ OK ]\033[0m $*"; }
bad()  { echo -e "  \033[91m[FAIL]\033[0m $*"; FAILED=1; }
have() { command -v "$1" >/dev/null 2>&1; }
cd "$(dirname "$0")/.."
echo "Pre-flight check for role: $ROLE"
have python3 && ok "python3 $(python3 --version 2>&1 | cut -d' ' -f2)" || bad "python3 missing"
python3 tests/test_engine.py >/dev/null 2>&1 && ok "IDS engine unit tests pass" || bad "engine unit tests fail"
case "$ROLE" in
  controller)
    [ -f "$HOME/ryu-venv/bin/activate" ] && source "$HOME/ryu-venv/bin/activate"
    have ryu-manager && ok "ryu-manager found" || bad "ryu-manager missing (run tools/install_ubuntu.sh controller)"
    python3 -c "import ryu.base.app_manager" 2>/dev/null && ok "ryu imports" || bad "ryu import error (see README troubleshooting)"
    python3 tests/test_controller_mock.py >/dev/null 2>&1 && ok "controller mock-switch test passes" || bad "controller mock test fails"
    ss -ltn 2>/dev/null | grep -q ':6653 ' && ok "port 6653 already listening (controller running)" || echo "  [info] controller not running yet"
    if have ufw && sudo -n ufw status 2>/dev/null | grep -q "Status: active"; then echo "  [warn] ufw active -> run: sudo ufw allow 6653/tcp"; fi ;;
  switch)
    have mn && ok "mininet (mn) found" || bad "mininet missing"
    have ovs-vsctl && ok "ovs-vsctl found" || bad "open vSwitch missing"
    sudo ovs-vsctl show >/dev/null 2>&1 && ok "ovs-vswitchd running" || bad "ovs not running: sudo systemctl start openvswitch-switch"
    sudo modprobe openvswitch 2>/dev/null; lsmod | grep -q openvswitch && ok "openvswitch kernel module loaded" || bad "kernel module openvswitch missing"
    have ethtool && ok "ethtool found" || bad "ethtool missing"
    if have ufw && sudo -n ufw status 2>/dev/null | grep -q "Status: active"; then echo "  [warn] ufw active -> run: sudo ufw allow 4789/udp"; fi ;;
  attacker)
    have ovs-vsctl && ok "ovs-vsctl found" || bad "open vSwitch missing"
    sudo ovs-vsctl show >/dev/null 2>&1 && ok "ovs-vswitchd running" || bad "ovs not running: sudo systemctl start openvswitch-switch"
    sudo modprobe openvswitch 2>/dev/null; lsmod | grep -q openvswitch && ok "openvswitch kernel module loaded" || bad "kernel module openvswitch missing"
    python3 -c "import scapy" 2>/dev/null && ok "scapy present (optional raw scans)" || echo "  [info] scapy not installed (only needed for --mode xmas/null/fin/syn)"
    if have ufw && sudo -n ufw status 2>/dev/null | grep -q "Status: active"; then echo "  [warn] ufw active -> run: sudo ufw allow 4789/udp"; fi ;;
  *) echo "usage: $0 {controller|switch|attacker} [peer_ip ...]"; exit 1 ;;
esac
for ip in "$@"; do
  ping -c 2 -W 1 "$ip" >/dev/null 2>&1 && ok "can ping $ip" || bad "cannot ping $ip (same Wi-Fi/hotspot? AP client-isolation? firewall?)"
done
[ -z "$FAILED" ] && echo -e "\nAll checks passed." || { echo -e "\nFix the FAIL lines above."; exit 1; }
