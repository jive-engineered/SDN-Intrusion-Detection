#!/usr/bin/env python3
"""Send a controlled burst of malformed TCP flags to exercise `invalid_flags`.

Lab-only IDS validation tool. Requires Scapy and raw-socket privileges. The default
sends six packets (above the default threshold of three) using SYN+FIN, NULL, and
XMAS flag combinations. Run inside Mininet h1 or the distributed `attacker` netns.
"""
import argparse
import random
import time

from scapy.all import IP, TCP, send, conf

conf.verb = 0
PATTERNS = {
    "synfin": ("SYN+FIN", "SF"),
    "null": ("NULL", ""),
    "xmas": ("XMAS", "FPU"),
    "synrst": ("SYN+RST", "SR"),
    "fin": ("FIN-only", "F"),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="10.0.0.2")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--count", type=int, default=6, help="number of malformed TCP packets (default: 6)")
    parser.add_argument("--patterns", default="synfin,null,xmas",
                        help="comma-separated list: synfin,null,xmas,synrst,fin")
    parser.add_argument("--delay", type=float, default=0.08)
    args = parser.parse_args()
    if args.count < 1:
        parser.error("--count must be at least 1")
    if args.port < 1 or args.port > 65535:
        parser.error("--port must be in the range 1..65535")
    if args.delay < 0:
        parser.error("--delay must be >= 0")

    selected = [part.strip().lower() for part in args.patterns.split(",") if part.strip()]
    unknown = sorted(set(selected) - PATTERNS.keys())
    if not selected or unknown:
        parser.error("invalid --patterns value; valid names: " + ",".join(PATTERNS))

    print(f"[invalid-flags] target={args.target}:{args.port}, packets={args.count}, patterns={','.join(selected)}", flush=True)
    for i in range(args.count):
        name = selected[i % len(selected)]
        label, flags = PATTERNS[name]
        sport = random.randint(40000, 60000)
        packet = IP(dst=args.target) / TCP(sport=sport, dport=args.port, flags=flags)
        send(packet, verbose=False)
        print(f"  [{i + 1:02d}/{args.count:02d}] sent {label} (TCP flags={flags or 'NONE'})", flush=True)
        if args.delay:
            time.sleep(args.delay)
    print("[invalid-flags] complete. Verify an invalid_flags alert and the resulting DROP flow in sdn-flows.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
