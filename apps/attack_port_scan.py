#!/usr/bin/env python3
"""
attack_port_scan.py - CONTROLLED reconnaissance test traffic (lab use only, runs on the attacker host).

Modes
  connect (default)  classic TCP connect() scan - needs no extra libraries
  syn | fin | null | xmas   raw-flag scans - need scapy (pip install scapy) and root

The scan stops by itself when the SDN controller blocks us (10 consecutive timeouts) and reports
how long it took - this is the attacker-side view of "time to block".
"""
import argparse
import socket
import sys
import time


def parse_ports(spec):
    out = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return out


def connect_probe(target, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        rc = s.connect_ex((target, port))
    except OSError:
        rc = -1
    finally:
        s.close()
    if rc == 0:
        return "open"
    if rc in (111, 104):                  # ECONNREFUSED / ECONNRESET
        return "closed"
    return "timeout"


def raw_probe(target, port, mode):
    from scapy.all import IP, TCP, sr1, conf  # imported lazily
    conf.verb = 0
    flags = {"syn": "S", "fin": "F", "null": "", "xmas": "FPU"}[mode]
    r = sr1(IP(dst=target) / TCP(sport=40000 + port % 20000, dport=port, flags=flags), timeout=0.5)
    if r is None:
        return "timeout"
    if r.haslayer(TCP) and (r[TCP].flags & 0x12) == 0x12:
        return "open"
    return "closed"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="10.0.0.2")
    ap.add_argument("--ports", default="1-1024", help="e.g. 1-1024 or 20-90,443,5000")
    ap.add_argument("--delay", type=float, default=0.05, help="seconds between probes (0.2 = slow/stealthy scan)")
    ap.add_argument("--timeout", type=float, default=0.5)
    ap.add_argument("--mode", choices=["connect", "syn", "fin", "null", "xmas"], default="connect")
    ap.add_argument("--keep-going", action="store_true", help="do not stop when blocked")
    a = ap.parse_args()

    ports = parse_ports(a.ports)
    print("[scan] %s scan of %s, %d ports, delay %.2fs" % (a.mode, a.target, len(ports), a.delay), flush=True)
    start = time.time()
    open_ports, consecutive_timeouts, first_timeout = [], 0, None
    scanned = 0
    for p in ports:
        res = connect_probe(a.target, p, a.timeout) if a.mode == "connect" else raw_probe(a.target, p, a.mode)
        scanned += 1
        if res == "open":
            open_ports.append(p)
            print("[scan] t=%5.2fs  port %-5d OPEN" % (time.time() - start, p), flush=True)
        if res == "timeout":
            consecutive_timeouts += 1
            if first_timeout is None:
                first_timeout = time.time() - start
        else:
            consecutive_timeouts = 0
        if consecutive_timeouts >= 10 and not a.keep_going:
            print("\n[scan] *** BLOCKED *** 10 consecutive probes dropped.")
            print("[scan] first dropped probe at t=%.2fs (after %d ports) -> the SDN switch stopped us" % (first_timeout, scanned - 10))
            break
        time.sleep(a.delay)
    print("[scan] finished after %.2fs, %d ports probed, open ports found: %s" % (time.time() - start, scanned, open_ports))


if __name__ == "__main__":
    main()
