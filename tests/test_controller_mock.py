"""
Integration test of ids_controller.py WITHOUT a network: a fake OpenFlow switch receives every
message the controller sends and SERIALIZES it (so malformed OpenFlow messages would crash here).
Needs ryu installed.   Run:  python3 tests/test_controller_mock.py
"""
import os, sys, json, tempfile, time, unittest
LOGDIR = tempfile.mkdtemp()
os.environ["IDS_LOG_DIR"] = LOGDIR
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "controller"))

from ryu.ofproto import ofproto_v1_3 as ofp, ofproto_v1_3_parser as parser
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.lib.packet import packet, ethernet, ipv4, tcp, ether_types
import ids_controller as ic


class FakeDP:
    ofproto, ofproto_parser = ofp, parser
    def __init__(self, dpid=1):
        self.id, self.sent, self._xid = dpid, [], 0
    def send_msg(self, msg):
        self._xid += 1
        msg.set_xid(self._xid)
        msg.serialize()                    # raises if the message is malformed
        self.sent.append(msg)


class Ev:
    def __init__(self, **kw): self.__dict__.update(kw)


MACS = {"10.0.0.1": "00:00:00:00:00:01", "10.0.0.2": "00:00:00:00:00:02", "10.0.0.3": "00:00:00:00:00:03"}
PORTS = {"10.0.0.1": 1, "10.0.0.2": 2, "10.0.0.3": 3}


def tcp_packet_in(dp, src, dst, sport, dport, bits):
    p = packet.Packet()
    p.add_protocol(ethernet.ethernet(dst=MACS[dst], src=MACS[src], ethertype=ether_types.ETH_TYPE_IP))
    p.add_protocol(ipv4.ipv4(src=src, dst=dst, proto=6))
    p.add_protocol(tcp.tcp(src_port=sport, dst_port=dport, bits=bits))
    p.serialize()
    return Ev(msg=parser.OFPPacketIn(dp, buffer_id=ofp.OFP_NO_BUFFER, total_len=len(p.data), reason=0,
                                     table_id=0, cookie=0, match=parser.OFPMatch(in_port=PORTS[src]), data=bytes(p.data)))


class ControllerTest(unittest.TestCase):
    def setUp(self):
        self.app = ic.IDSController()
        self.dp = FakeDP()
        self.app._switch_features(Ev(msg=Ev(datapath=self.dp)))
        self.app._state_change(Ev(datapath=self.dp, state=MAIN_DISPATCHER))

    def prios(self, cls=parser.OFPFlowMod):
        return [(m.priority, len(m.instructions)) for m in self.dp.sent if isinstance(m, cls) and m.command == ofp.OFPFC_ADD]

    def test_handshake_rules(self):
        self.assertIn((0, 1), self.prios())     # table-miss -> controller
        self.assertIn((5, 1), self.prios())     # TCP inspection rule
        self.assertEqual(self.dp.sent[0].command, ofp.OFPFC_DELETE)   # clean start

    def test_legit_traffic_forwarded_with_connection_flows(self):
        self.app._packet_in(tcp_packet_in(self.dp, "10.0.0.2", "10.0.0.3", 5000, 40000, tcp.TCP_SYN | tcp.TCP_ACK))  # learn h2
        self.dp.sent.clear()
        self.app._packet_in(tcp_packet_in(self.dp, "10.0.0.3", "10.0.0.2", 40001, 5000, tcp.TCP_SYN))
        self.assertEqual(sum(1 for p, _ in self.prios() if p == 20), 2)       # forward + reverse flow
        outs = [m for m in self.dp.sent if isinstance(m, parser.OFPPacketOut)]
        self.assertEqual(len(outs), 1)
        self.assertEqual(outs[0].actions[0].port, 2)
        self.assertFalse(self.app.engine.is_blocked("10.0.0.3"))

    def test_flood_blocked_barrier_unblock(self):
        self.app._packet_in(tcp_packet_in(self.dp, "10.0.0.2", "10.0.0.1", 5000, 40000, tcp.TCP_SYN | tcp.TCP_ACK))
        self.dp.sent.clear()
        for i in range(40):
            self.app._packet_in(tcp_packet_in(self.dp, "10.0.0.1", "10.0.0.2", 41000 + i, 5000, tcp.TCP_SYN))
            time.sleep(0.002)
            if self.app.engine.is_blocked("10.0.0.1"):
                break
        self.assertTrue(self.app.engine.is_blocked("10.0.0.1"))
        self.assertEqual(i + 1, 20)
        drops = [m for m in self.dp.sent if isinstance(m, parser.OFPFlowMod) and m.priority == 100]
        self.assertEqual(len(drops), 1)
        self.assertEqual(len(drops[0].instructions), 0)                      # DROP = no actions
        self.assertEqual(drops[0].idle_timeout, 30)
        self.assertTrue(drops[0].flags & ofp.OFPFF_SEND_FLOW_REM)
        bar = [m for m in self.dp.sent if isinstance(m, parser.OFPBarrierRequest)][0]
        # further packets from the attacker are ignored
        n = len(self.dp.sent)
        self.app._packet_in(tcp_packet_in(self.dp, "10.0.0.1", "10.0.0.2", 49999, 5000, tcp.TCP_SYN))
        self.assertEqual(len(self.dp.sent), n)
        # the switch confirms the rule -> metrics are logged
        self.app._barrier_reply(Ev(msg=Ev(datapath=self.dp, xid=bar.xid)))
        # idle timeout -> controller forgets the block
        fr = parser.OFPFlowRemoved(self.dp, cookie=0, priority=100, reason=ofp.OFPRR_IDLE_TIMEOUT, table_id=0,
                                   duration_sec=31, duration_nsec=0, idle_timeout=30, hard_timeout=0,
                                   packet_count=77, byte_count=1, match=parser.OFPMatch(eth_type=0x0800, ipv4_src="10.0.0.1"))
        self.app._flow_removed(Ev(msg=fr))
        self.assertFalse(self.app.engine.is_blocked("10.0.0.1"))
        events = [json.loads(l)["event"] for l in open(ic.EVENT_LOG)]
        self.assertEqual(events, ["ALERT", "BLOCK_INSTALLED", "UNBLOCKED"])

    def test_source_ip_unblock_then_fresh_flood_is_detected_again(self):
        self.app.engine.update_rules({
            "multi_ip_spoof": {"enabled": False},
            "conn_flood": {"enabled": True, "threshold": 3, "window": 3.0},
            "port_scan": {"enabled": False},
            "port_flood": {"enabled": False},
        })
        self.app._packet_in(tcp_packet_in(self.dp, "10.0.0.2", "10.0.0.1", 5000, 40000, tcp.TCP_SYN | tcp.TCP_ACK))
        for offset in range(10):
            self.app._packet_in(tcp_packet_in(self.dp, "10.0.0.1", "10.0.0.2", 42000 + offset, 5000, tcp.TCP_SYN))
            if self.app.engine.is_blocked("10.0.0.1"):
                break
        self.assertTrue(self.app.engine.is_blocked("10.0.0.1"))
        self.assertTrue(any(isinstance(m, parser.OFPFlowMod) and m.priority == 100 and
                            m.command == ofp.OFPFC_ADD and not m.instructions for m in self.dp.sent))

        removed = parser.OFPFlowRemoved(self.dp, cookie=0, priority=100, reason=ofp.OFPRR_DELETE,
                                        table_id=0, duration_sec=1, duration_nsec=0, idle_timeout=30,
                                        hard_timeout=0, packet_count=9, byte_count=540,
                                        match=parser.OFPMatch(eth_type=0x0800, ipv4_src="10.0.0.1"))
        self.app._flow_removed(Ev(msg=removed))
        self.assertFalse(self.app.engine.is_blocked("10.0.0.1"))

        start = len(self.dp.sent)
        for offset in range(10):
            self.app._packet_in(tcp_packet_in(self.dp, "10.0.0.1", "10.0.0.2", 43000 + offset, 5000, tcp.TCP_SYN))
            if self.app.engine.is_blocked("10.0.0.1"):
                break
        self.assertTrue(self.app.engine.is_blocked("10.0.0.1"), "new attack after unblock must re-quarantine")
        fresh_drops = [m for m in self.dp.sent[start:] if isinstance(m, parser.OFPFlowMod) and
                       m.priority == 100 and m.command == ofp.OFPFC_ADD and not m.instructions]
        self.assertEqual(len(fresh_drops), 1)

    def test_port_quarantine_delete_resets_state_and_allows_requarantine(self):
        self.app.engine.update_rules({
            "multi_ip_spoof": {"enabled": False},
            "conn_flood": {"enabled": False},
            "port_scan": {"enabled": False},
            "port_flood": {"enabled": True, "threshold": 3, "window": 3.0},
        })
        self.app._packet_in(tcp_packet_in(self.dp, "10.0.0.2", "10.0.0.1", 5000, 40000, tcp.TCP_SYN | tcp.TCP_ACK))

        def send_port_burst(base):
            for offset in range(5):
                self.app._packet_in(tcp_packet_in(self.dp, "10.0.0.1", "10.0.0.2", base + offset, 5000, tcp.TCP_SYN))
                if self.app.engine.is_port_blocked(1):
                    break

        send_port_burst(44000)
        self.assertTrue(self.app.engine.is_port_blocked(1))
        self.assertTrue(any(isinstance(m, parser.OFPFlowMod) and m.priority == 200 and
                            m.command == ofp.OFPFC_ADD and not m.instructions for m in self.dp.sent))
        removed = parser.OFPFlowRemoved(self.dp, cookie=0, priority=200, reason=ofp.OFPRR_DELETE,
                                        table_id=0, duration_sec=1, duration_nsec=0, idle_timeout=30,
                                        hard_timeout=0, packet_count=8, byte_count=512,
                                        match=parser.OFPMatch(in_port=1))
        self.app._flow_removed(Ev(msg=removed))
        self.assertFalse(self.app.engine.is_port_blocked(1))
        self.assertFalse(self.app.engine.is_blocked("10.0.0.1"))
        start = len(self.dp.sent)
        send_port_burst(45000)
        self.assertTrue(self.app.engine.is_port_blocked(1), "fresh post-unblock attack must quarantine the ingress port again")
        self.assertTrue(any(isinstance(m, parser.OFPFlowMod) and m.priority == 200 and
                            m.command == ofp.OFPFC_ADD and not m.instructions for m in self.dp.sent[start:]))

    def test_port_scan_blocked(self):
        self.app._packet_in(tcp_packet_in(self.dp, "10.0.0.2", "10.0.0.1", 22, 40000, tcp.TCP_RST | tcp.TCP_ACK))
        for port in range(1, 30):
            self.app._packet_in(tcp_packet_in(self.dp, "10.0.0.1", "10.0.0.2", 50000 + port, port, tcp.TCP_SYN))
            if self.app.engine.is_blocked("10.0.0.1"):
                break
        self.assertEqual(port, 8)

    def test_xmas_scan_dropped_not_forwarded(self):
        self.app._packet_in(tcp_packet_in(self.dp, "10.0.0.2", "10.0.0.1", 22, 40000, tcp.TCP_SYN | tcp.TCP_ACK))
        self.dp.sent.clear()
        self.app._packet_in(tcp_packet_in(self.dp, "10.0.0.1", "10.0.0.2", 50000, 80, tcp.TCP_FIN | tcp.TCP_PSH | tcp.TCP_URG))
        self.assertEqual(self.dp.sent, [])

    def test_flow_stats_concurrent_flows_rule(self):
        body = []
        for i in range(60):
            fs = parser.OFPFlowStats(table_id=0, duration_sec=1, duration_nsec=0, priority=20, idle_timeout=10, hard_timeout=0,
                                     flags=0, cookie=0, packet_count=3, byte_count=180, instructions=[],
                                     match=parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src="10.0.0.1", ipv4_dst="10.0.0.2",
                                                           tcp_src=42000 + i, tcp_dst=5000))
            body.append(fs)
        rep = parser.OFPFlowStatsReply(self.dp, flags=0, body=body)
        self.app._flow_stats_reply(Ev(msg=rep))
        self.assertTrue(self.app.engine.is_blocked("10.0.0.1"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
