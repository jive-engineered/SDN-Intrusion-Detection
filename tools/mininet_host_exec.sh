#!/usr/bin/env bash
# Run a command in an existing Mininet host namespace from a separate terminal.
# Example: sudo ./tools/mininet_host_exec.sh h1 python3 apps/attack_spoof_flood.py --count 20
set -euo pipefail
if [[ $# -lt 2 ]]; then
  echo "Usage: sudo $0 <h1-h9 | srv2-srv4> <command> [args...]" >&2
  exit 2
fi
host="$1"; shift
# 13-host office LAN: attackers h1/h10, clients h3-h9, servers h2/srv2/srv3/srv4.
case "$host" in h[1-9]|h10|srv[2-4]) ;; *) echo "Unsupported host '$host' (expected h1-h10 or srv2-srv4)" >&2; exit 2 ;; esac
if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo so mnexec can enter the host network namespace." >&2
  exit 1
fi
if ! command -v mnexec >/dev/null 2>&1; then
  echo "mnexec not found. Install Mininet or run the command at the mininet> prompt." >&2
  exit 1
fi
# EXACT host match: "mininet:h1" must not also match "mininet:h10" (a plain substring match did,
# which made every h1 command fail with "multiple Mininet shells").
mapfile -t pids < <(ps -eo pid=,args= | awk -v re="mininet:${host}([^0-9a-zA-Z_]|$)" '$0 ~ re && $0 !~ /awk/ {print $1}')
if [[ ${#pids[@]} -eq 0 ]]; then
  echo "Could not find a running Mininet shell for $host." >&2
  echo "Confirm Terminal 2 is still at the mininet> prompt. As a fallback, run this command there:" >&2
  printf '  %s ' "$host"; printf '%q ' "$@"; printf '\n' >&2
  exit 1
fi
if [[ ${#pids[@]} -gt 1 ]]; then
  echo "Found multiple Mininet shells for $host (${pids[*]}). Stop the extra topology and retry." >&2
  exit 1
fi
exec mnexec -a "${pids[0]}" "$@"
