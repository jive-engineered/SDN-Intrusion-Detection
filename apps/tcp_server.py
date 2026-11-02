#!/usr/bin/env python3
"""
tcp_server.py - the protected service (runs on h2, 10.0.0.2).

Opens several TCP "services" at once (default 22 80 443 5000). Every connection is handled in its own
thread. Protocol (line based):   client sends  "PING <n>\n"   server answers  "PONG <n> port=<p>\n".
Prints a one-line summary every 2 seconds (connections/s, active connections).
"""
import argparse
import socket
import threading
import time

lock = threading.Lock()
stats = {"accepted": 0, "active": 0}


def handle(conn, addr, port):
    with lock:
        stats["accepted"] += 1
        stats["active"] += 1
    try:
        conn.settimeout(60)
        buf = b""
        while True:
            data = conn.recv(1024)
            if not data:
                break
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                parts = line.decode(errors="replace").split()
                if len(parts) >= 2 and parts[0] == "PING":
                    conn.sendall(("PONG %s port=%d\n" % (parts[1], port)).encode())
    except (OSError, socket.timeout):
        pass
    finally:
        conn.close()
        with lock:
            stats["active"] -= 1


def listener(port, bind):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind, port))
    s.listen(1024)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr, port), daemon=True).start()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ports", type=int, nargs="+", default=[22, 80, 443, 5000])
    ap.add_argument("--bind", default="0.0.0.0")
    a = ap.parse_args()
    for p in a.ports:
        try:
            threading.Thread(target=listener, args=(p, a.bind), daemon=True).start()
        except OSError as e:
            print("cannot open port %d: %s" % (p, e))
    print("[server] listening on %s ports %s" % (a.bind, a.ports), flush=True)
    last = 0
    while True:
        time.sleep(2)
        with lock:
            acc, act = stats["accepted"], stats["active"]
        print("[server] %s accepted=%d (+%d in 2s) active=%d" % (time.strftime("%H:%M:%S"), acc, acc - last, act), flush=True)
        last = acc


if __name__ == "__main__":
    main()
