#!/usr/bin/env python3
"""
attack_packet_rate.py - CONTROLLED volumetric high-PPS test traffic (lab use only).

Purpose in this project
------------------------
Exercises the `packet_rate` rule, which is the heavy-traffic / volumetric defence.
It opens only a FEW long-lived TCP connections to the protected server and then
sends many tiny application-layer messages per second over them.

Why this specifically triggers `packet_rate` and nothing else:
  * Each connection is a single, normal SYN handshake, so this does NOT raise
    `conn_flood` (that rule counts NEW connections/sec).
  * Only a handful of flows are opened, so this does NOT raise `concurrent_flows`
    (that rule counts simultaneous flows, threshold 40).
  * Once established, each flow is offloaded to the OVS kernel fast-path
    (Priority-20 exact 5-tuple rule), so the packets never reach the controller
    as Packet-In events - the control plane stays idle.
  * The controller instead notices the surge through its asynchronous
    OFPFlowStatsRequest polling (_monitor / _process_stats): the per-flow
    packet-counter delta divided by the poll interval yields packets/sec, and
    crossing the threshold (default 3000 pps) installs the DROP rule.

This is the clean way to demonstrate that a volumetric flood is mitigated by
hardware-counter polling rather than by flooding the Ryu CPU with Packet-Ins.

TCP_NODELAY is set so each small write becomes its own segment, maximising the
packet rate on the veth link without needing raw sockets or root.
"""
import argparse
import socket
import threading
import time

_stop = threading.Event()
_lock = threading.Lock()
_counter = {"pkts": 0, "errs": 0, "flows_up": 0}


def _blaster(target, port, timeout):
    try:
        s = socket.create_connection((target, port), timeout=timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        with _lock:
            _counter["errs"] += 1
        return
    with _lock:
        _counter["flows_up"] += 1
    msg = b"PING 0\n"
    local = 0
    try:
        while not _stop.is_set():
            try:
                s.sendall(msg)
                local += 1
                if local % 512 == 0:          # flush to the shared counter periodically
                    with _lock:
                        _counter["pkts"] += 512
            except OSError:
                with _lock:
                    _counter["errs"] += 1
                break
    finally:
        with _lock:
            _counter["pkts"] += local % 512
        try:
            s.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser(description="Volumetric high-PPS lab test traffic (packet_rate rule).")
    ap.add_argument("--target", default="10.0.0.2")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--flows", type=int, default=4, help="parallel established connections (keep well under concurrent_flows threshold)")
    ap.add_argument("--duration", type=float, default=15, help="seconds to sustain the flood")
    ap.add_argument("--timeout", type=float, default=2.0)
    a = ap.parse_args()

    if a.flows < 1:
        ap.error("--flows must be at least 1")

    print("[packet-rate] %d flow(s) -> %s:%d, sustaining high PPS for %.0fs (volumetric test)"
          % (a.flows, a.target, a.port, a.duration), flush=True)

    threads = [threading.Thread(target=_blaster, args=(a.target, a.port, a.timeout), daemon=True)
               for _ in range(a.flows)]
    for t in threads:
        t.start()

    start = time.time()
    last = 0
    blocked_seconds = 0
    try:
        while time.time() - start < a.duration:
            time.sleep(1.0)
            with _lock:
                total = _counter["pkts"]
                up = _counter["flows_up"]
            rate = total - last
            last = total
            print("[packet-rate] t=%2ds  flows_up=%d  ~%d pkts/s  (total %d)"
                  % (int(time.time() - start), up, rate, total), flush=True)
            # If sends have stalled, the switch is dropping us - stop early.
            if up > 0 and rate == 0:
                blocked_seconds += 1
                if blocked_seconds >= 2:
                    print("\n[packet-rate] *** BLOCKED *** traffic stopped flowing - the SDN switch "
                          "dropped the attacker at the edge.", flush=True)
                    break
            else:
                blocked_seconds = 0
    except KeyboardInterrupt:
        pass

    _stop.set()
    time.sleep(0.3)
    with _lock:
        print("[packet-rate] done. packets sent ~%d, errors %d." % (_counter["pkts"], _counter["errs"]), flush=True)
    print("[packet-rate] Verify a `packet_rate` alert in the Ryu console and a Priority-100 DROP in sdn-flows.", flush=True)


if __name__ == "__main__":
    main()
