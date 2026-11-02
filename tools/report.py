#!/usr/bin/env python3
"""
report.py - turns logs/ids_events.jsonl into the detection / response-time table for your presentation.

   python3 tools/report.py                 # pretty table + averages
   python3 tools/report.py --csv out.csv   # also export CSV (for Excel graphs)
   python3 tools/report.py --clear         # empty the event log before a fresh demo run
"""
import argparse
import csv
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(ROOT, "logs", "ids_events.jsonl")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv")
    ap.add_argument("--clear", action="store_true")
    a = ap.parse_args()
    if a.clear:
        for f in ("ids_events.jsonl", "flow_stats.csv"):
            p = os.path.join(ROOT, "logs", f)
            if os.path.exists(p):
                os.remove(p)
        print("logs cleared")
        return
    if not os.path.exists(LOG):
        sys.exit("no events yet: %s" % LOG)

    events = [json.loads(l) for l in open(LOG) if l.strip()]
    rows = []
    unblock = {}
    for e in events:
        if e["event"] == "UNBLOCKED":
            unblock.setdefault(e["ip"], []).append(e)
    for e in events:
        if e["event"] == "BLOCK_INSTALLED":
            rows.append([e["time"], e["ip"], ",".join(e["rules"]), e["detection_ms"], e["response_ms"], e["total_ms"], e["detail"]])

    print("\n  DETECTION & RESPONSE TIME REPORT")
    print("  " + "=" * 118)
    print("  %-9s %-10s %-18s %14s %16s %12s   %s" % ("time", "source", "rule", "detection(ms)", "response(ms)", "total(ms)", "detail"))
    print("  " + "-" * 118)
    for r in rows:
        print("  %-9s %-10s %-18s %14.1f %16.2f %12.1f   %s" % tuple(r))
    print("  " + "=" * 118)
    if rows:
        n = float(len(rows))
        print("  attacks blocked: %d | avg detection %.1f ms | avg response (detect -> DROP rule active in switch) %.2f ms | avg total %.1f ms"
              % (len(rows), sum(r[3] for r in rows) / n, sum(r[4] for r in rows) / n, sum(r[5] for r in rows) / n))
    print("\n  detection = first packet seen from the source -> alert raised")
    print("  response  = alert raised -> switch confirmed the DROP rule (OpenFlow barrier reply)")
    print("  total     = detection + response\n")
    for ip, lst in unblock.items():
        for u in lst:
            print("  recovery: %s unblocked (%s) after dropping %s packets" % (ip, u["reason"], u["dropped_packets"]))
    if a.csv:
        with open(a.csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["time", "source", "rule", "detection_ms", "response_ms", "total_ms", "detail"])
            w.writerows(rows)
        print("\n  CSV written to", a.csv)


if __name__ == "__main__":
    main()
