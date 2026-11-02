#!/usr/bin/env python3
"""
tcp_client.py - the LEGITIMATE user (runs on h3, 10.0.0.3).

Every --interval seconds it opens a NEW TCP connection, sends "PING n", waits for "PONG n" and
records the round-trip time. It proves that normal users keep working while the attacker is blocked.
At the end (or Ctrl+C) it prints the success rate / packet-loss summary.
"""
import argparse
import socket
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default="10.0.0.2")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--interval", type=float, default=0.5, help="seconds between requests")
    ap.add_argument("--duration", type=float, default=0, help="stop after N seconds (0 = until Ctrl+C)")
    ap.add_argument("--timeout", type=float, default=2.0)
    a = ap.parse_args()

    ok = fail = 0
    rtts = []
    start = time.time()
    n = 0
    print("[client] legitimate user -> %s:%d every %.2fs" % (a.server, a.port, a.interval), flush=True)
    try:
        while a.duration == 0 or time.time() - start < a.duration:
            n += 1
            t0 = time.time()
            try:
                s = socket.create_connection((a.server, a.port), timeout=a.timeout)
                s.sendall(("PING %d\n" % n).encode())
                reply = s.recv(100).decode().strip()
                s.close()
                rtt = (time.time() - t0) * 1000
                if reply.startswith("PONG %d" % n):
                    ok += 1
                    rtts.append(rtt)
                    print("[client] t=%5.1fs  #%-4d OK    rtt=%6.1f ms   (%s)" % (time.time() - start, n, rtt, reply), flush=True)
                else:
                    fail += 1
                    print("[client] t=%5.1fs  #%-4d BAD REPLY %r" % (time.time() - start, n, reply), flush=True)
            except (OSError, socket.timeout) as e:
                fail += 1
                print("[client] t=%5.1fs  #%-4d FAIL  (%s)" % (time.time() - start, n, e), flush=True)
            time.sleep(max(0, a.interval - (time.time() - t0)))
    except KeyboardInterrupt:
        pass
    total = ok + fail
    print("\n========== LEGITIMATE CLIENT SUMMARY ==========")
    print("requests: %d   success: %d   failed: %d   loss: %.1f%%" % (total, ok, fail, 100.0 * fail / total if total else 0))
    if rtts:
        print("rtt  min/avg/max = %.1f / %.1f / %.1f ms" % (min(rtts), sum(rtts) / len(rtts), max(rtts)))
    print("===============================================")


if __name__ == "__main__":
    main()
