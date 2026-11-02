#!/usr/bin/env bash
# Installs everything for ONE role on Ubuntu 22.04 (recommended). Run as a normal user (it uses sudo itself).
#   ./tools/install_ubuntu.sh controller     # Laptop A : Ryu
#   ./tools/install_ubuntu.sh switch         # Laptop B : Mininet + Open vSwitch
#   ./tools/install_ubuntu.sh attacker       # Laptop C : Open vSwitch + scapy
#   ./tools/install_ubuntu.sh all            # single-laptop backup : everything
set -e
ROLE="${1:-all}"
sudo apt update
sudo apt install -y python3 python3-pip python3-venv iproute2 net-tools ethtool curl

if [[ "$ROLE" == "controller" || "$ROLE" == "all" ]]; then
  python3 -m venv "$HOME/ryu-venv"
  source "$HOME/ryu-venv/bin/activate"
  pip install --upgrade pip wheel
  pip install "setuptools==67.6.1"
  pip install "eventlet==0.30.2"
  pip install ryu
  deactivate
  echo "[OK] Ryu installed in ~/ryu-venv   (run_controller.sh activates it automatically)"
fi
if [[ "$ROLE" == "switch" || "$ROLE" == "all" ]]; then
  sudo apt install -y mininet openvswitch-switch openvswitch-common
  sudo systemctl enable --now openvswitch-switch
  echo "[OK] Mininet + Open vSwitch installed"
fi
if [[ "$ROLE" == "attacker" ]]; then
  sudo apt install -y openvswitch-switch openvswitch-common
  sudo systemctl enable --now openvswitch-switch
  sudo apt install -y python3-scapy || true      # only needed for the optional --mode xmas/null/fin/syn scans
  echo "[OK] attacker tools installed"
fi
echo "Done. Next: tools/preflight.sh $ROLE"
