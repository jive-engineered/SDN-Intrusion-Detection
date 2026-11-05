#!/usr/bin/env python3
"""
plot_results.py - generate a report-ready figure from demo logs.

Reads:
  logs/flow_stats.csv        - per-source-IP pps/flows time series (append-only)
  logs/ids_events.jsonl      - every ALERT / BLOCK / UNBLOCK with timestamp
Writes:
  logs/results.png (or wherever --output points)

Two stacked panels:
  TOP    - packets/sec per source IP, with ALERT and BLOCK markers overlaid
  BOTTOM - active flow count per source IP, with the concurrent_flows threshold

Attacker lines render in red (gradient when there are several blocked IPs),
legit lines in cool colours. Zero collateral damage is the visual: during an
attack one line spikes and gets cut, while the others keep humming along.

Usage:
  python3 tools/plot_results.py                        # read logs/, write logs/results.png
  python3 tools/plot_results.py --output report.png    # custom output
  python3 tools/plot_results.py --demo                 # synthesize a sample figure
                                                       # (useful before the first real run)
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from pathlib import Path

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    print("matplotlib is required: pip install matplotlib", file=sys.stderr)
    sys.exit(2)

ROOT = Path(__file__).resolve().parents[1]
STATS_CSV = ROOT / "logs" / "flow_stats.csv"
EVENT_LOG = ROOT / "logs" / "ids_events.jsonl"
DEFAULT_OUT = ROOT / "logs" / "results.png"

# Colour palette - attacker tones are warm, legit tones are cool
ATTACKER_COLORS = ["#ff5a7a", "#f08a4a", "#e04858"]
LEGIT_COLORS = ["#4bdc9f", "#58dafe", "#6ea8fe", "#b084f0", "#7ae0d6", "#a3e4a3", "#ffc966"]
BLOCKED_HINT_IPS = {"10.0.0.1"}   # the default attacker; auto-updated from events too


def _load_events(path: Path):
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def _load_series(path: Path):
    """Return {ip: [(t, pps, flows)]}, time-ordered."""
    series: dict[str, list[tuple[float, float, int]]] = {}
    if not path.exists():
        return series
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                t = float(row["timestamp"])
                ip = row["src_ip"]
                pps = float(row.get("packets_per_sec", 0) or 0)
                flows = int(float(row.get("active_flows", 0) or 0))
            except (KeyError, ValueError, TypeError):
                continue
            series.setdefault(ip, []).append((t, pps, flows))
    for ip in series:
        series[ip].sort(key=lambda x: x[0])
    return series


def _synth():
    """Build a believable demo dataset so the script produces a figure even with no logs."""
    import math, random, time
    now = time.time()
    series = {}
    events = []
    for ip, color_kind in [("10.0.0.1","attacker"), ("10.0.0.3","legit"), ("10.0.0.4","legit"),
                           ("10.0.0.5","legit"), ("10.0.0.6","legit"), ("10.0.0.7","legit")]:
        pts = []
        for i in range(60):
            t = now - (60 - i) * 3
            if color_kind == "attacker":
                # ramp from 0 -> ~4800 pps between t=20 and t=35, then cut to 0
                if i < 20: pps, flows = random.uniform(0, 10), 0
                elif i < 35: pps, flows = (i - 20) * 330 + random.uniform(-50, 80), 4
                else: pps, flows = 0, 0
            else:
                pps = max(0, random.gauss(12, 5))
                flows = random.randint(1, 3)
            pts.append((t, pps, flows))
        series[ip] = pts
    # events roughly aligned with the ramp
    events = [
        {"ts": now - 60 + 34*3, "event":"ALERT", "ip":"10.0.0.1", "rules":["packet_rate"], "detail":"4320 pps"},
        {"ts": now - 60 + 34*3 + 0.002, "event":"BLOCK_INSTALLED", "ip":"10.0.0.1", "rules":["packet_rate"], "response_ms":2.4},
        {"ts": now - 60 + 55*3, "event":"UNBLOCKED", "ip":"10.0.0.1", "reason":"idle timeout"},
    ]
    return series, events


def plot(series, events, output: Path, title: str):
    if not series:
        print("[plot_results] no data in logs/flow_stats.csv and --demo not set; nothing to draw.", file=sys.stderr)
        return 1

    # Shift time origin to zero for readability
    all_t = [t for pts in series.values() for (t, _, _) in pts]
    t0 = min(all_t)

    # Figure
    plt.rcParams.update({
        "figure.facecolor": "#0a1324", "axes.facecolor": "#0f1626",
        "axes.edgecolor": "#2a3850", "axes.labelcolor": "#cdd8e8",
        "xtick.color": "#8697b4", "ytick.color": "#8697b4",
        "axes.titlecolor": "#e8eef8", "text.color": "#e8eef8",
        "font.family": "DejaVu Sans", "font.size": 10,
        "grid.color": "#1f2b43", "grid.linewidth": 0.6,
        "legend.facecolor": "#0f1626", "legend.edgecolor": "#2a3850",
    })
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(13, 8), sharex=True,
                                   gridspec_kw={"height_ratios":[2.4, 1]})
    fig.suptitle(title, fontsize=16, fontweight="bold", color="#e8eef8", y=0.98)

    # Pick colour per IP (attacker-ish IPs get warm colours)
    hint = set(BLOCKED_HINT_IPS)
    for e in events:
        if e.get("event") in ("ALERT", "BLOCK_INSTALLED") and e.get("ip"):
            hint.add(e["ip"])

    attacker_i = legit_i = 0
    colors = {}
    for ip in sorted(series.keys()):
        if ip in hint:
            colors[ip] = ATTACKER_COLORS[attacker_i % len(ATTACKER_COLORS)]
            attacker_i += 1
        else:
            colors[ip] = LEGIT_COLORS[legit_i % len(LEGIT_COLORS)]
            legit_i += 1

    # Top panel: PPS
    for ip, pts in sorted(series.items()):
        xs = [p[0] - t0 for p in pts]
        ys = [p[1] for p in pts]
        lw = 2.4 if ip in hint else 1.6
        ax1.plot(xs, ys, label=f"{ip} ({'attacker' if ip in hint else 'legit'})",
                 color=colors[ip], linewidth=lw)
    ax1.axhline(3000, color="#ffc966", linestyle="--", linewidth=1, alpha=0.6,
                label="packet_rate threshold (3000 pps)")
    ax1.set_ylabel("Packets / sec", fontweight="bold")
    ax1.set_title("Live packet rate per source IP", loc="left", fontsize=12, pad=8)
    ax1.grid(True, alpha=0.4)
    ax1.legend(loc="upper right", fontsize=9, ncol=2, framealpha=0.9)

    # Overlay event markers on top panel
    for e in events:
        ts = e.get("ts")
        if ts is None: continue
        x = ts - t0
        if e.get("event") == "ALERT":
            ax1.axvline(x, color="#ff5a7a", linestyle=":", linewidth=1.2, alpha=0.7)
            rules = ",".join(e.get("rules") or [e.get("rule","")])
            ax1.annotate(f"[ALERT]\n{rules}", xy=(x, ax1.get_ylim()[1]*0.9),
                         xytext=(5, 0), textcoords="offset points",
                         fontsize=8, color="#ff5a7a", fontweight="bold",
                         bbox=dict(boxstyle="round,pad=0.3", fc="#2a0f1a", ec="#7a2742", alpha=0.9))
        elif e.get("event") == "BLOCK_INSTALLED":
            ax1.axvline(x, color="#ffc966", linestyle="--", linewidth=1.4, alpha=0.8)
            lat = e.get("response_ms", e.get("total_ms", "?"))
            ax1.annotate(f"[IPS BLOCK]\n{lat} ms", xy=(x, ax1.get_ylim()[1]*0.6),
                         xytext=(5, 0), textcoords="offset points",
                         fontsize=8, color="#ffc966", fontweight="bold",
                         bbox=dict(boxstyle="round,pad=0.3", fc="#2a1f0a", ec="#7a5a1a", alpha=0.9))
        elif e.get("event") == "UNBLOCKED":
            ax1.axvline(x, color="#4bdc9f", linestyle=":", linewidth=1.2, alpha=0.7)
            ax1.annotate("[RECOVER]", xy=(x, ax1.get_ylim()[1]*0.75),
                         xytext=(5, 0), textcoords="offset points",
                         fontsize=8, color="#4bdc9f", fontweight="bold",
                         bbox=dict(boxstyle="round,pad=0.3", fc="#0f2a1f", ec="#1d6a4a", alpha=0.9))

    # Bottom panel: active flow count
    for ip, pts in sorted(series.items()):
        xs = [p[0] - t0 for p in pts]
        ys = [p[2] for p in pts]
        lw = 2.2 if ip in hint else 1.4
        ax2.plot(xs, ys, color=colors[ip], linewidth=lw)
    ax2.axhline(40, color="#ffc966", linestyle="--", linewidth=1, alpha=0.6,
                label="concurrent_flows threshold (40)")
    ax2.set_ylabel("Active flows", fontweight="bold")
    ax2.set_xlabel("Time (s) from first telemetry sample", fontweight="bold")
    ax2.set_title("Active flow count per source IP", loc="left", fontsize=12, pad=8)
    ax2.grid(True, alpha=0.4)
    ax2.legend(loc="upper right", fontsize=9, framealpha=0.9)

    fig.text(0.99, 0.01, "SDN IDS + IPS · generated by tools/plot_results.py",
             ha="right", va="bottom", fontsize=8, color="#5a6a85")
    plt.tight_layout(rect=(0, 0.02, 1, 0.96))
    output.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output, dpi=140, facecolor=fig.get_facecolor())
    print(f"[plot_results] wrote {output}  ({len(series)} source IP(s), {len(events)} event(s))")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", default=str(DEFAULT_OUT), help="output image path (PNG)")
    ap.add_argument("--demo", action="store_true", help="synthesize a sample figure (no logs needed)")
    ap.add_argument("--title", default="SDN IDS + IPS — attack timeline & zero-collateral proof")
    args = ap.parse_args()

    if args.demo:
        series, events = _synth()
    else:
        series = _load_series(STATS_CSV)
        events = _load_events(EVENT_LOG)
    return plot(series, events, Path(args.output), args.title)


if __name__ == "__main__":
    sys.exit(main())
