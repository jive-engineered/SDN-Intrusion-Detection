"""
ids_engine.py - Detection engine with Multi-IP Spoof & Ingress Port Isolation.
Pure Python (no Ryu dependencies) for standalone unit testing.
"""
import time
from collections import deque, defaultdict

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20

DEFAULT_RULES = {
    "protected_hosts": ["10.0.0.2"],
    "block_idle_timeout": 30,
    "stats_interval": 3,
    "conn_flood":       {"enabled": True, "threshold": 20, "window": 3.0},
    "port_scan":        {"enabled": True, "threshold": 8,  "window": 10.0},
    "invalid_flags":    {"enabled": True, "threshold": 3,  "window": 10.0},
    "concurrent_flows": {"enabled": True, "threshold": 40},
    "packet_rate":      {"enabled": True, "threshold": 3000},
    "multi_ip_spoof":   {"enabled": True, "threshold": 2,  "window": 4.0},
    "port_flood":       {"enabled": True, "threshold": 35, "window": 3.0}
}

def classify_flags(flags):
    if flags == 0:
        return "NULL-scan"
    if (flags & (FIN | PSH | URG)) == (FIN | PSH | URG):
        return "XMAS-scan"
    if (flags & (SYN | FIN)) == (SYN | FIN):
        return "SYN+FIN"
    if (flags & (SYN | RST)) == (SYN | RST):
        return "SYN+RST"
    if (flags & FIN) and not (flags & ACK):
        return "FIN-scan"
    return None

def is_new_connection(flags):
    return bool(flags & SYN) and not (flags & ACK)

class Alert:
    def __init__(self, ip, rule, detail, t_detect, first_seen, action_target="ip", in_port=None, mac=None):
        self.ip = ip
        self.rule = rule
        self.detail = detail
        self.t_detect = t_detect
        self.first_seen = first_seen
        self.action_target = action_target  # "ip" or "port"
        self.in_port = in_port
        self.mac = mac

    @property
    def detect_latency_ms(self):
        if self.first_seen is None:
            return 0.0
        return round((self.t_detect - self.first_seen) * 1000.0, 1)

    def __repr__(self):
        return f"Alert({self.ip}, {self.rule}, {self.detail})"

class _SrcState:
    def __init__(self):
        self.first_seen = None
        self.last_seen = None
        self.syns = deque()
        self.port_events = deque()
        self.port_counts = {}
        self.invalid = deque()
        self.total_syns = 0

class IDSEngine:
    def __init__(self, rules=None):
        self.rules = {}
        self.protected = set()
        self.update_rules(rules or DEFAULT_RULES)
        self._state = defaultdict(_SrcState)
        self.blocked = {}
        self.blocked_ports = set()
        self.last_stats = {}

        # Edge-case trackers
        self._mac_ip_events = defaultdict(deque)  # mac -> deque([(timestamp, ip)])
        self._port_events = defaultdict(deque)    # in_port -> deque([timestamp])

    def update_rules(self, rules):
        merged = {}
        for k, v in DEFAULT_RULES.items():
            if isinstance(v, dict):
                d = dict(v)
                d.update(rules.get(k, {}))
                merged[k] = d
            else:
                merged[k] = rules.get(k, v)
        self.rules = merged
        self.protected = set(merged.get("protected_hosts", ["10.0.0.2"]))

    def _on(self, name):
        return self.rules.get(name, {}).get("enabled", True)

    def is_blocked(self, ip):
        return ip in self.blocked

    def is_port_blocked(self, in_port):
        return in_port in self.blocked_ports

    def block(self, ip, alert):
        self.blocked[ip] = {"since": alert.t_detect, "rule": alert.rule}
        if alert.action_target == "port" and alert.in_port is not None:
            self.blocked_ports.add(alert.in_port)

    def unblock(self, ip, mac=None, in_port=None, release_port=True):
        """Forget a quarantine and reset its detection history for a clean next run.

        The optional MAC and ingress port are important for port-isolation alerts:
        multiple spoofed source IPs share one source MAC, and ingress-port counters
        otherwise survive an administrative override and can cause stale detections.
        For an IP-only flow removal, callers may clear the port's history without
        releasing a distinct active port quarantine (`release_port=False`).
        """
        info = self.blocked.pop(ip, None)
        self._state.pop(ip, None)
        if mac:
            self._mac_ip_events.pop(mac, None)
        if in_port is not None:
            self._port_events.pop(in_port, None)
            if release_port:
                self.blocked_ports.discard(in_port)
        return info

    def unblock_port(self, in_port):
        self.blocked_ports.discard(in_port)
        # A manual delete or idle timeout is a new detection epoch for this port.
        self._port_events.pop(in_port, None)

    def observe_tcp(self, src, dst, sport, dport, flags, in_port=None, mac=None, now=None):
        now = time.time() if now is None else now
        if src in self.protected or src in self.blocked:
            return []
        if in_port is not None and in_port in self.blocked_ports:
            return []

        alerts = []

        # EDGE CASE 1: Multi-IP Spoofing Detection (Same MAC using multiple IPs)
        if mac and self._on("multi_ip_spoof"):
            r = self.rules["multi_ip_spoof"]
            q = self._mac_ip_events[mac]
            q.append((now, src))
            while q and now - q[0][0] > r["window"]:
                q.popleft()
            unique_ips = set(item[1] for item in q)
            if len(unique_ips) > r["threshold"]:
                return [Alert(src, "multi_ip_spoof",
                              f"MAC {mac} rotated {len(unique_ips)} source IPs in {r['window']}s (Spoofing Attack)",
                              now, q[0][0], action_target="port", in_port=in_port, mac=mac)]

        # EDGE CASE 2: Ingress Port Flooding (DDoS / Random IP flood from single port)
        if in_port and self._on("port_flood"):
            r = self.rules["port_flood"]
            pq = self._port_events[in_port]
            pq.append(now)
            while pq and now - pq[0] > r["window"]:
                pq.popleft()
            if len(pq) >= r["threshold"]:
                return [Alert(src, "port_flood",
                              f"Ingress port {in_port} emitted {len(pq)} SYNs in {r['window']}s -> Quarantining Port",
                              now, pq[0], action_target="port", in_port=in_port, mac=mac)]

        # Standard L4 State Inspection
        st = self._state[src]
        if st.first_seen is None:
            st.first_seen = now
        st.last_seen = now

        bad = classify_flags(flags)
        if bad and self._on("invalid_flags"):
            r = self.rules["invalid_flags"]
            st.invalid.append(now)
            while st.invalid and now - st.invalid[0] > r["window"]:
                st.invalid.popleft()
            if len(st.invalid) >= r["threshold"]:
                alerts.append(Alert(src, "invalid_flags",
                                    f"{len(st.invalid)} illegal-flag packets ({bad}) in {r['window']:.0f}s",
                                    now, st.invalid[0]))

        if is_new_connection(flags):
            st.total_syns += 1
            if self._on("conn_flood"):
                r = self.rules["conn_flood"]
                st.syns.append(now)
                while st.syns and now - st.syns[0] > r["window"]:
                    st.syns.popleft()
                if len(st.syns) >= r["threshold"]:
                    alerts.append(Alert(src, "conn_flood",
                                        f"{len(st.syns)} new TCP connections in {r['window']:.1f}s (limit {r['threshold']})",
                                        now, st.syns[0], in_port=in_port, mac=mac))

            if self._on("port_scan"):
                r = self.rules["port_scan"]
                st.port_events.append((now, dport))
                st.port_counts[dport] = st.port_counts.get(dport, 0) + 1
                while st.port_events and now - st.port_events[0][0] > r["window"]:
                    _, p = st.port_events.popleft()
                    st.port_counts[p] -= 1
                    if st.port_counts[p] <= 0:
                        del st.port_counts[p]
                if len(st.port_counts) >= r["threshold"]:
                    alerts.append(Alert(src, "port_scan",
                                        f"{len(st.port_counts)} distinct destination ports in {r['window']:.0f}s (limit {r['threshold']})",
                                        now, st.port_events[0][0], in_port=in_port, mac=mac))
        return alerts

    def evaluate_stats(self, per_src, interval, now=None):
        now = time.time() if now is None else now
        self.last_stats = {}
        alerts = []
        for ip, s in per_src.items():
            pps = s["pkts"] / float(interval) if interval else 0.0
            self.last_stats[ip] = {"flows": s["flows"], "pps": pps, "bytes": s["bytes"]}
            if ip in self.protected or ip in self.blocked:
                continue
            first = self._state[ip].first_seen if ip in self._state else None
            if self._on("concurrent_flows") and s["flows"] >= self.rules["concurrent_flows"]["threshold"]:
                alerts.append(Alert(ip, "concurrent_flows",
                                    f"{s['flows']} active flows (limit {self.rules['concurrent_flows']['threshold']})",
                                    now, first))
            elif self._on("packet_rate") and pps >= self.rules["packet_rate"]["threshold"]:
                alerts.append(Alert(ip, "packet_rate",
                                    f"{pps:.0f} packets/s (limit {self.rules['packet_rate']['threshold']})",
                                    now, first))
        return alerts

    def stats_snapshot(self):
        return dict(self.last_stats)
