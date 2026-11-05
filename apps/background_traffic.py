#!/usr/bin/env python3
"""
background_traffic.py - realistic office-LAN chatter from a legit client.

Runs on h3/h4/h5/.../h9 under Mininet. Every 0.3-2.5s this host picks a RANDOM
server (from --servers), opens a TCP connection to a random one of a few
candidate ports on it, exchanges a PING/PONG line, and closes. Timing is
jittered, request sizes vary a little, and occasional short bursts simulate a
user "clicking a link" (3-5 rapid requests in a row).

The point is to make the switch busy with ~50-100 legit TCP flows per second,
distributed across many source IPs and many destination ports, so that:

  * the dashboard shows seven green source-IP lines humming along a baseline,
  * when h1 attacks, only one line (red) spikes and gets cut while the other
    seven keep flowing - "zero collateral damage" becomes a visual, not a claim.

Not an attack generator. No raw sockets. Entirely normal application traffic.
"""
import argparse
import random
import socket
import sys
import threading
import time

# Candidate destination ports we may hit on any server. The server will accept
# whichever of these it actually opened; others just error quickly and we move on.
CANDIDATE_PORTS = (22, 80, 443, 5000, 21, 445, 8080, 3306, 5432, 25, 53, 143)

_stats = {"ok": 0, "fail": 0, "last_server": "-"}
_stats_lock = threading.Lock()


def _one_request(server, port, timeout, payload_size, tag):
    try:
        s = socket.create_connection((server, port), timeout=timeout)
    except OSError:
        with _stats_lock:
            _stats["fail"] += 1
        return False
    try:
        s.settimeout(timeout)
        # Slightly varied line, so it looks like real-ish payload, not a fixed byte sequence.
        req = ("PING %s %d %s\n" % (tag, random.randint(1, 10 ** 9), "x" * max(0, payload_size))).encode()
        s.sendall(req)
        try:
            s.recv(1024)   # may be empty for ports the server doesn't PONG
        except (socket.timeout, OSError):
            pass
    finally:
        try:
            s.close()
        except OSError:
            pass
    with _stats_lock:
        _stats["ok"] += 1
        _stats["last_server"] = "%s:%d" % (server, port)
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--servers", required=True, help="comma-separated list of server IPs")
    ap.add_argument("--client-tag", default="h?", help="label for this client in logs")
    ap.add_argument("--min-interval", type=float, default=0.3)
    ap.add_argument("--max-interval", type=float, default=2.5)
    ap.add_argument("--timeout", type=float, default=1.0)
    ap.add_argument("--duration", type=float, default=0, help="stop after N seconds (0 = run forever)")
    ap.add_argument("--burst-chance", type=float, default=0.07, help="probability of a 3-5 request burst instead of a single request")
    ap.add_argument("--max-payload", type=int, default=64, help="upper bound on 'x' padding bytes")
    args = ap.parse_args()

    servers = [s.strip() for s in args.servers.split(",") if s.strip()]
    if not servers:
        print("[%s] no servers specified; exiting" % args.client_tag, file=sys.stderr)
        return 2

    print("[bg %s] chattering against %d server(s): %s" % (args.client_tag, len(servers), ", ".join(servers)), flush=True)
    start = time.time()
    next_report = start + 10

    try:
        while args.duration == 0 or time.time() - start < args.duration:
            server = random.choice(servers)
            port = random.choice(CANDIDATE_PORTS)
            payload = random.randint(0, args.max_payload)
            if random.random() < args.burst_chance:
                # a "page load" burst: a few rapid requests to the same server
                burst_n = random.randint(3, 5)
                for _ in range(burst_n):
                    _one_request(server, random.choice(CANDIDATE_PORTS), args.timeout, payload, args.client_tag)
                    time.sleep(random.uniform(0.02, 0.15))
            else:
                _one_request(server, port, args.timeout, payload, args.client_tag)

            # One-line periodic heartbeat so you can tail -f the log and see life.
            if time.time() >= next_report:
                with _stats_lock:
                    ok, fail, last = _stats["ok"], _stats["fail"], _stats["last_server"]
                print("[bg %s] t=%4.0fs ok=%d fail=%d last=%s" % (args.client_tag, time.time() - start, ok, fail, last), flush=True)
                next_report = time.time() + 10

            time.sleep(random.uniform(args.min_interval, args.max_interval))
    except KeyboardInterrupt:
        pass

    with _stats_lock:
        print("[bg %s] stopping. total ok=%d fail=%d" % (args.client_tag, _stats["ok"], _stats["fail"]), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
