#!/usr/bin/env python3
"""
ids_controller.py - Ryu SDN IDS Controller with Port & MAC Quarantine (OpenFlow 1.3).
"""
import json
import os
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, ether_types
from ryu.lib import hub

try:
    from ids_engine import IDSEngine, classify_flags, is_new_connection
except ImportError:
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from ids_engine import IDSEngine, classify_flags, is_new_connection

PRIO_MISS, PRIO_L2, PRIO_TCP_CATCH, PRIO_CONN, PRIO_BLOCK, PRIO_PORT_QUARANTINE = 0, 1, 5, 20, 100, 200
CONN_IDLE_TIMEOUT = 10
L2_IDLE_TIMEOUT = 30

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RULES_FILE = os.environ.get("IDS_RULES", os.path.join(HERE, "ids_rules.json"))
LOG_DIR = os.environ.get("IDS_LOG_DIR", os.path.join(ROOT, "logs"))
EVENT_LOG = os.path.join(LOG_DIR, "ids_events.jsonl")
STATS_CSV = os.path.join(LOG_DIR, "flow_stats.csv")
STATUS_JSON = os.path.join(LOG_DIR, "status.json")

RED, GREEN, YELLOW, CYAN, BOLD, END = "\033[91m", "\033[92m", "\033[93m", "\033[96m", "\033[1m", "\033[0m"

class IDSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(IDSController, self).__init__(*args, **kwargs)
        os.makedirs(LOG_DIR, exist_ok=True)
        self.rules_mtime = 0
        self.rules_loaded_at = None
        self.engine = IDSEngine()
        self._load_rules(force=True)

        self.mac_to_port = {}
        self.datapaths = {}
        self._stats_buf = {}
        self._prev_pkts = {}
        self._prev_bytes = {}
        self._pending_barrier = {}
        self._block_records = {}
        self._last_stats_ts = None

        with open(STATS_CSV, "a") as f:
            if f.tell() == 0:
                f.write("timestamp,src_ip,active_flows,packets_per_sec,bytes_in_interval\n")
                f.flush()

        self.monitor_thread = hub.spawn(self._monitor)
        self.logger.info("%sIDS controller started. Advanced Edge-Defense Active.%s", BOLD, END)

    def _load_rules(self, force=False):
        try:
            mt = os.path.getmtime(RULES_FILE)
            if force or mt != self.rules_mtime:
                with open(RULES_FILE) as f:
                    self.engine.update_rules(json.load(f))
                self.rules_mtime = mt
                self.rules_loaded_at = time.time()
                self.logger.info("%s[CONFIG] IDS rules reloaded from %s%s", CYAN, RULES_FILE, END)
        except (OSError, ValueError) as e:
            self.logger.warning("Could not load rules: %s", e)

    def _log_event(self, event, **fields):
        rec = {"ts": round(time.time(), 6), "time": time.strftime("%H:%M:%S"), "event": event}
        rec.update(fields)
        try:
            with open(EVENT_LOG, "a") as f:
                f.write(json.dumps(rec, separators=(",", ":")) + "\n")
                f.flush()
        except OSError as e:
            self.logger.warning("Could not append IDS event to %s: %s", EVENT_LOG, e)

    def _write_status(self):
        try:
            blocked = {}
            for ip, item in self.engine.blocked.items():
                rec = self._block_records.get(ip, {})
                blocked[ip] = {
                    "since": item.get("since"),
                    "rule": item.get("rule"),
                    "rules": rec.get("rules", [item.get("rule")]),
                    "action_target": rec.get("action_target", "ip"),
                    "in_port": rec.get("in_port"),
                    "mac": rec.get("mac"),
                    "detail": rec.get("detail", "")
                }
            st = {
                "ts": time.time(),
                "switches": sorted(self.datapaths),
                "blocked": blocked,
                "blocked_ports": sorted(self.engine.blocked_ports),
                "stats": dict((ip, {"flows": v["flows"], "pps": round(v["pps"], 1),
                                     "bytes": v.get("bytes", 0)})
                               for ip, v in self.engine.stats_snapshot().items()),
                "block_idle_timeout": self.engine.rules["block_idle_timeout"],
                "stats_interval": self.engine.rules["stats_interval"],
                "rules_loaded_at": self.rules_loaded_at
            }
            tmp = STATUS_JSON + ".tmp"
            with open(tmp, "w") as f:
                json.dump(st, f, separators=(",", ":"))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, STATUS_JSON)
        except OSError as e:
            self.logger.warning("Could not write IDS status file %s: %s", STATUS_JSON, e)

    def add_flow(self, dp, priority, match, actions, idle_timeout=0, hard_timeout=0, flags=0):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] if actions else []
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=inst,
                                      idle_timeout=idle_timeout, hard_timeout=hard_timeout, flags=flags))

    def _packet_out(self, dp, msg, in_port, out_port):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
                                        actions=[parser.OFPActionOutput(out_port)], data=data))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        dp.send_msg(parser.OFPFlowMod(datapath=dp, table_id=ofp.OFPTT_ALL, command=ofp.OFPFC_DELETE,
                                      out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                                      match=parser.OFPMatch()))
        to_ctrl = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, PRIO_MISS, parser.OFPMatch(), to_ctrl)
        self.add_flow(dp, PRIO_TCP_CATCH, parser.OFPMatch(eth_type=0x0800, ip_proto=6), to_ctrl)
        self.logger.info("%s[SWITCH] s%s connected - Flow tables initialized%s", GREEN, dp.id, END)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)
            self.mac_to_port.pop(dp.id, None)
        self._write_status()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Check if physical switch port is already quarantined
        if self.engine.is_port_blocked(in_port):
            return

        table = self.mac_to_port.setdefault(dp.id, {})
        table[eth.src] = in_port
        out_port = table.get(eth.dst, ofp.OFPP_FLOOD)

        ip4 = pkt.get_protocol(ipv4.ipv4)
        t = pkt.get_protocol(tcp.tcp)
        if ip4 is not None and t is not None:
            self._handle_tcp(dp, msg, in_port, out_port, ip4, t, eth.src)
            return

        if ip4 is not None and self.engine.is_blocked(ip4.src):
            return
        parser = dp.ofproto_parser
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
            self.add_flow(dp, PRIO_L2, match, [parser.OFPActionOutput(out_port)], idle_timeout=L2_IDLE_TIMEOUT)
        self._packet_out(dp, msg, in_port, out_port)

    def _handle_tcp(self, dp, msg, in_port, out_port, ip4, t, eth_src):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        src, dst = ip4.src, ip4.dst
        flags = t.bits

        if self.engine.is_blocked(src) or self.engine.is_port_blocked(in_port):
            return

        alerts = self.engine.observe_tcp(src, dst, t.src_port, t.dst_port, flags, in_port=in_port, mac=eth_src)
        if alerts:
            self._react(dp, alerts)
            return

        if classify_flags(flags):
            return

        if out_port == ofp.OFPP_FLOOD:
            self._packet_out(dp, msg, in_port, out_port)
            return

        fwd = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=src, ipv4_dst=dst,
                              tcp_src=t.src_port, tcp_dst=t.dst_port)
        rev = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=dst, ipv4_dst=src,
                              tcp_src=t.dst_port, tcp_dst=t.src_port)
        self.add_flow(dp, PRIO_CONN, fwd, [parser.OFPActionOutput(out_port)], idle_timeout=CONN_IDLE_TIMEOUT)
        self.add_flow(dp, PRIO_CONN, rev, [parser.OFPActionOutput(in_port)], idle_timeout=CONN_IDLE_TIMEOUT)
        self._packet_out(dp, msg, in_port, out_port)

    def _react(self, dp, alerts):
        first = alerts[0]
        ip = first.ip
        if self.engine.is_blocked(ip) or (first.in_port and self.engine.is_port_blocked(first.in_port)):
            return

        rules = sorted(set(a.rule for a in alerts))
        self.engine.block(ip, first)

        self.logger.warning("%s%s[IDS ALERT] %s | rule=%s | %s | detected %.0f ms after first packet%s",
                            RED, BOLD, ip, ",".join(rules), first.detail, first.detect_latency_ms, END)
        mitigation_action = ("DROP ingress port %s and source MAC %s" % (first.in_port, first.mac)
                             if first.action_target == "port"
                             else "DROP source IP %s" % ip)
        self._log_event("ALERT", ip=ip, rules=rules, detail=first.detail,
                        detect_latency_ms=first.detect_latency_ms, mac=first.mac,
                        in_port=first.in_port, action_target=first.action_target,
                        mitigation_action=mitigation_action)

        idle = self.engine.rules["block_idle_timeout"]
        rec = {"ip": ip, "rules": rules, "detail": first.detail, "first_seen": first.first_seen,
               "t_detect": first.t_detect, "detect_latency_ms": first.detect_latency_ms,
               "action_target": first.action_target, "in_port": first.in_port, "mac": first.mac,
               "mitigation_action": mitigation_action}
        self._block_records[ip] = rec

        for d in list(self.datapaths.values()) or [dp]:
            if first.action_target == "port" and first.in_port is not None:
                self._install_port_block(d, first.in_port, first.mac, idle)
            else:
                self._install_ip_block(d, ip, idle)

        parser = dp.ofproto_parser
        barrier = parser.OFPBarrierRequest(dp)
        dp.send_msg(barrier)
        self._pending_barrier[(dp.id, barrier.xid)] = rec
        self._write_status()

    def _install_ip_block(self, dp, ip, idle):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
        self.add_flow(dp, PRIO_BLOCK, match, [], idle_timeout=idle, flags=ofp.OFPFF_SEND_FLOW_REM)

    def _install_port_block(self, dp, in_port, mac, idle):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        match_port = parser.OFPMatch(in_port=in_port)
        self.add_flow(dp, PRIO_PORT_QUARANTINE, match_port, [], idle_timeout=idle, flags=ofp.OFPFF_SEND_FLOW_REM)
        if mac:
            match_mac = parser.OFPMatch(eth_src=mac)
            self.add_flow(dp, PRIO_BLOCK, match_mac, [], idle_timeout=idle)
        self.logger.warning("%s[HARDWARE DEFENSE] Ingress Port %s quarantined (Priority 200 DROP); MAC fallback %s (Priority 100 DROP)%s",
                            RED, in_port, mac, END)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def _barrier_reply(self, ev):
        rec = self._pending_barrier.pop((ev.msg.datapath.id, ev.msg.xid), None)
        if rec is None:
            return
        t_done = time.time()
        response_ms = round((t_done - rec["t_detect"]) * 1000.0, 2)
        total_ms = round((t_done - rec["first_seen"]) * 1000.0, 1) if rec["first_seen"] else response_ms
        self.logger.warning("%s[IDS RESPONSE] %s MITIGATED | detection=%.0f ms | response=%.2f ms | total=%.0f ms%s",
                            YELLOW, rec["ip"], rec["detect_latency_ms"], response_ms, total_ms, END)
        self._log_event("BLOCK_INSTALLED", ip=rec["ip"], rules=rec["rules"], detail=rec["detail"],
                        detection_ms=rec["detect_latency_ms"], response_ms=response_ms, total_ms=total_ms,
                        mac=rec.get("mac"), in_port=rec.get("in_port"),
                        action_target=rec.get("action_target", "ip"),
                        mitigation_action=rec.get("mitigation_action", "DROP source IP %s" % rec["ip"]))
        self._write_status()

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed(self, ev):
        msg = ev.msg
        why = {0: "idle timeout", 1: "hard timeout", 2: "deleted"}.get(msg.reason, str(msg.reason))

        # Priority-200 ingress-port quarantine sends a flow-removed notification on timeout.
        if msg.priority == PRIO_PORT_QUARANTINE and "in_port" in msg.match:
            in_port = msg.match["in_port"]
            self.engine.unblock_port(in_port)
            for ip, rec in list(self._block_records.items()):
                if rec.get("action_target") == "port" and rec.get("in_port") == in_port:
                    self.engine.unblock(ip)
                    self._block_records.pop(ip, None)
                    self._log_event("UNBLOCKED", ip=ip, rules=rec.get("rules", []),
                                    detail=rec.get("detail", ""), reason=why,
                                    mac=rec.get("mac"), in_port=in_port,
                                    dropped_packets=getattr(msg, "packet_count", 0),
                                    action_target="port", mitigation_action="Ingress port restored")
            self.logger.info("%s[IDS RECOVERY] Physical Port %s RESTORED (%s)%s", GREEN, in_port, why, END)
            self._write_status()
            return

        if msg.priority != PRIO_BLOCK or "ipv4_src" not in msg.match:
            return
        ip = msg.match["ipv4_src"]
        self.engine.unblock(ip)
        rec = self._block_records.pop(ip, {})
        self.logger.info("%s[IDS RECOVERY] %s UNBLOCKED (%s)%s", GREEN, ip, why, END)
        self._log_event("UNBLOCKED", ip=ip, rules=rec.get("rules", [rec.get("rule")]),
                        detail=rec.get("detail", ""), reason=why, mac=rec.get("mac"),
                        in_port=rec.get("in_port"), dropped_packets=getattr(msg, "packet_count", 0),
                        action_target=rec.get("action_target", "ip"),
                        mitigation_action="DROP rule removed")
        self._write_status()

    def _monitor(self):
        while True:
            self._load_rules()
            interval = self.engine.rules["stats_interval"]
            hub.sleep(interval)
            self._write_status()
            for dp in list(self.datapaths.values()):
                self._stats_buf[dp.id] = []
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply(self, ev):
        msg = ev.msg
        dp = msg.datapath
        buf = self._stats_buf.setdefault(dp.id, [])
        buf.extend(msg.body)
        if msg.flags & dp.ofproto.OFPMPF_REPLY_MORE:
            return
        self._stats_buf[dp.id] = []
        self._process_stats(dp, buf)

    def _process_stats(self, dp, flow_stats):
        now = time.time()
        interval = (now - self._last_stats_ts) if self._last_stats_ts else self.engine.rules["stats_interval"]
        self._last_stats_ts = now

        per_src, seen = {}, set()
        for st in flow_stats:
            if st.priority != PRIO_CONN:
                continue
            m = st.match
            try:
                key = (m["ipv4_src"], m["ipv4_dst"], m["tcp_src"], m["tcp_dst"])
            except KeyError:
                continue
            seen.add(key)
            delta_packets = st.packet_count - self._prev_pkts.get(key, 0)
            delta_bytes = st.byte_count - self._prev_bytes.get(key, 0)
            self._prev_pkts[key] = st.packet_count
            self._prev_bytes[key] = st.byte_count
            s = per_src.setdefault(key[0], {"flows": 0, "pkts": 0, "bytes": 0})
            s["flows"] += 1
            s["pkts"] += max(delta_packets, 0)
            # CSV field bytes_in_interval is a counter delta, not a cumulative total.
            s["bytes"] += max(delta_bytes, 0)
        for k in [k for k in self._prev_pkts if k not in seen]:
            del self._prev_pkts[k]
            self._prev_bytes.pop(k, None)

        alerts = self.engine.evaluate_stats(per_src, interval, now)
        try:
            with open(STATS_CSV, "a") as f:
                for ip, s in self.engine.stats_snapshot().items():
                    f.write("%.3f,%s,%d,%.1f,%d\n" %
                            (now, ip, s["flows"], s["pps"], s.get("bytes", 0)))
                f.flush()
        except OSError as e:
            self.logger.warning("Could not append flow statistics to %s: %s", STATS_CSV, e)

        line = " | ".join("%s flows=%d pps=%.1f" % (ip, s["flows"], s["pps"])
                          for ip, s in sorted(self.engine.stats_snapshot().items()))
        blocked = ",".join(sorted(self.engine.blocked)) or "-"
        self.logger.info("%s[FLOW-STATS] %s | blocked: %s%s", CYAN, line or "no active TCP flows", blocked, END)

        by_ip = {}
        for a in alerts:
            by_ip.setdefault(a.ip, []).append(a)
        for ip, al in by_ip.items():
            self._react(dp, al)
        self._write_status()
