#!/usr/bin/env bash
# LAPTOP A - start the Ryu IDS controller (listens for the switch on TCP 6653)
cd "$(dirname "$0")"
[ -f "$HOME/ryu-venv/bin/activate" ] && source "$HOME/ryu-venv/bin/activate"
echo "Controller IP addresses of this laptop (give one of them to Laptop B):"
hostname -I
echo
exec ryu-manager --ofp-tcp-listen-port 6653 controller/ids_controller.py
