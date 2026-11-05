#!/usr/bin/env bash
# Install the project-wide 1-2 word SDN-IDS commands into /usr/local/bin.
# Run from anywhere: sudo /path/to/sdn-ids/tools/install_cli_shortcuts.sh
set -euo pipefail

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
PROJECT_ROOT="$(cd "$(dirname "$SCRIPT_PATH")/.." && pwd)"
CLI="$PROJECT_ROOT/tools/sdn_cli.py"
CONFIG="/etc/sdn-ids-cli.conf"
COMMANDS=(
  sdn-brain sdn-ui sdn-net sdn-sync sdn-flows sdn-unblock
  test-h1 test-h3 legit-start atk-spoof atk-flood atk-scan atk-flags
  atk-rate atk-concurrent sdn-report sdn-autopilot sdn-help
)

if [[ ${EUID} -ne 0 ]]; then
  exec sudo -E bash "$SCRIPT_PATH" "$@"
fi

if [[ ! -f "$CLI" ]]; then
  echo "[FAIL] CLI dispatcher not found: $CLI" >&2
  exit 1
fi
chmod 755 "$CLI" "$PROJECT_ROOT/tools/mininet_host_exec.sh" "$PROJECT_ROOT/tools/telemetry_panel.py" \
  "$PROJECT_ROOT/tools/report.py" "$PROJECT_ROOT/run_switch.sh" "$PROJECT_ROOT/run_controller.sh" \
  "$PROJECT_ROOT/run_attacker.sh" "$PROJECT_ROOT/apps/attack_invalid_flags.py" \
  "$PROJECT_ROOT/apps/attack_packet_rate.py" "$PROJECT_ROOT/auto_demo.sh"
install -d -m 0755 /usr/local/bin

if [[ ! -e "$CONFIG" ]]; then
  cat > "$CONFIG" <<'EOF'
# SDN-IDS global shortcut configuration. Edit with: sudoedit /etc/sdn-ids-cli.conf
# Set SDN_ROLE separately on each laptop: controller | switch | attacker | auto
SDN_ROLE=auto
# SSH destinations use user@host and require SSH key authentication for automation.
SDN_SWITCH_SSH=
SDN_CONTROLLER_SSH=
SDN_ATTACKER_SSH=
# Optional Laptop C IP; used by `sdn-net <A_IP>` to select distributed mode.
SDN_ATTACKER_IP=
# interactive lets remote commands ask sudo on a remote TTY; use noninteractive only after configuring suitable sudo permissions.
SDN_REMOTE_SUDO=interactive
SDN_DASHBOARD_HOST=0.0.0.0
SDN_DASHBOARD_PORT=8080
SDN_SWITCH_NAME=s1
EOF
  chmod 0644 "$CONFIG"
  chown root:root "$CONFIG"
  echo "[OK] Wrote initial configuration: $CONFIG"
fi

for command in "${COMMANDS[@]}"; do
  link="/usr/local/bin/$command"
  if [[ -e "$link" && ! -L "$link" ]]; then
    echo "[FAIL] Refusing to overwrite existing non-symlink: $link" >&2
    echo "       Move it aside manually, then rerun this installer." >&2
    exit 1
  fi
  if [[ -L "$link" ]]; then
    old_target="$(readlink -f "$link" || true)"
    if [[ "$old_target" != "$CLI" ]]; then
      echo "[FAIL] Refusing to replace unrelated symlink: $link -> $(readlink "$link")" >&2
      exit 1
    fi
  fi
  ln -sfn "$CLI" "$link"
done

echo ""
echo "[OK] Installed ${#COMMANDS[@]} global commands into /usr/local/bin."
echo "[OK] Project root: $PROJECT_ROOT"
echo "[NEXT] Edit per-laptop endpoints: sudoedit $CONFIG"
echo "[NEXT] Run: sdn-help"
echo ""
echo "Distributed mode tips:"
echo "  Laptop A: SDN_ROLE=controller; set SDN_SWITCH_SSH=user@B_IP"
echo "  Laptop B: SDN_ROLE=switch; set SDN_ATTACKER_IP=C_IP and SDN_ATTACKER_SSH=user@C_IP"
echo "  Laptop C: SDN_ROLE=attacker; set SDN_SWITCH_SSH=user@B_IP and SDN_CONTROLLER_SSH=user@A_IP"
