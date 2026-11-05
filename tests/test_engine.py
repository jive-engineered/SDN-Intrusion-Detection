"""Unit tests for the detection engine.  Run:  python3 tests/test_engine.py"""
import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "controller"))
from ids_engine import IDSEngine, classify_flags, SYN, ACK, FIN, PSH, URG, RST

ATT, LEGIT, SRV = "10.0.0.1", "10.0.0.3", "10.0.0.2"


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.e = IDSEngine()

    def test_flag_classifier(self):
        self.assertEqual(classify_flags(0), "NULL-scan")
        self.assertEqual(classify_flags(FIN | PSH | URG), "XMAS-scan")
        self.assertEqual(classify_flags(SYN | FIN), "SYN+FIN")
        self.assertEqual(classify_flags(SYN | RST), "SYN+RST")
        self.assertEqual(classify_flags(FIN), "FIN-scan")
        self.assertIsNone(classify_flags(SYN))
        self.assertIsNone(classify_flags(SYN | ACK))
        self.assertIsNone(classify_flags(ACK))
        self.assertIsNone(classify_flags(FIN | ACK))

    def test_legit_client_never_flagged(self):
        t = 100.0
        for i in range(120):                       # 1 connection per second for 2 minutes
            self.assertEqual(self.e.observe_tcp(LEGIT, SRV, 40000 + i, 5000, SYN, now=t + i), [])

    def test_connection_flood_detected_quickly(self):
        alerts, t = [], 100.0
        for i in range(100):                       # 50 conn/s
            alerts = self.e.observe_tcp(ATT, SRV, 40000 + i, 5000, SYN, now=t + i * 0.02)
            if alerts:
                break
        self.assertTrue(alerts)
        self.assertEqual(alerts[0].rule, "conn_flood")
        self.assertEqual(i + 1, 20)                # 20th SYN triggers it
        self.assertLess(alerts[0].detect_latency_ms, 500)

    def test_port_scan_detected(self):
        t, hit = 100.0, None
        for p in range(1, 200):                    # slow scan: 5 ports/second (below flood limit)
            a = self.e.observe_tcp(ATT, SRV, 50000 + p, p, SYN, now=t + p * 0.2)
            if a:
                hit = (p, a)
                break
        self.assertIsNotNone(hit)
        self.assertEqual(hit[1][0].rule, "port_scan")
        self.assertEqual(hit[0], 8)

    def test_same_port_many_times_is_not_scan(self):
        for i in range(15):
            a = self.e.observe_tcp(LEGIT, SRV, 40000 + i, 5000, SYN, now=100 + i * 0.5)
            self.assertEqual(a, [])

    def test_invalid_flags(self):
        hit = None
        for i in range(5):
            a = self.e.observe_tcp(ATT, SRV, 50000, 80 + i, FIN | PSH | URG, now=100 + i)
            if a:
                hit = a
                break
        self.assertIsNotNone(hit)
        self.assertEqual(hit[0].rule, "invalid_flags")

    def test_protected_and_blocked_hosts_ignored(self):
        for i in range(100):
            self.assertEqual(self.e.observe_tcp(SRV, ATT, 5000, 40000 + i, SYN, now=100 + i * 0.01), [])
        a = None
        for i in range(30):
            a = self.e.observe_tcp(ATT, SRV, 40000 + i, 5000, SYN, now=200 + i * 0.01) or a
        self.e.block(ATT, a[0])
        self.assertTrue(self.e.is_blocked(ATT))
        self.assertEqual(self.e.observe_tcp(ATT, SRV, 1, 5000, SYN, now=201), [])

    def test_unblock_resets_history(self):
        a = None
        for i in range(25):
            a = self.e.observe_tcp(ATT, SRV, 40000 + i, 5000, SYN, now=100 + i * 0.01) or a
        self.e.block(ATT, a[0])
        self.e.unblock(ATT)
        self.assertFalse(self.e.is_blocked(ATT))
        self.assertEqual(self.e.observe_tcp(ATT, SRV, 1, 5000, SYN, now=300), [])

    def test_stats_rules(self):
        al = self.e.evaluate_stats({ATT: {"flows": 60, "pkts": 30, "bytes": 1}, LEGIT: {"flows": 9, "pkts": 20, "bytes": 1},
                                    SRV: {"flows": 500, "pkts": 99999, "bytes": 1}}, 3.0, now=100)
        self.assertEqual([(a.ip, a.rule) for a in al], [(ATT, "concurrent_flows")])
        al = self.e.evaluate_stats({ATT: {"flows": 3, "pkts": 30000, "bytes": 1}}, 3.0, now=100)
        self.assertEqual(al[0].rule, "packet_rate")

    def test_rules_can_be_disabled(self):
        self.e.update_rules({"conn_flood": {"enabled": False}})
        for i in range(50):
            self.assertEqual(self.e.observe_tcp(ATT, SRV, 40000 + i, 5000, SYN, now=100 + i * 0.01), [])

    def test_unblock_clears_mac_and_ingress_port_windows_for_requarantine(self):
        engine = IDSEngine({
            "multi_ip_spoof": {"enabled": True, "threshold": 2, "window": 4.0},
            "conn_flood": {"enabled": False},
            "port_scan": {"enabled": False},
        })
        mac, port = "00:00:00:00:00:99", 7
        alert = None
        for i in range(3):
            result = engine.observe_tcp("10.0.0.%d" % (20 + i), SRV, 40000 + i, 5000,
                                        SYN, in_port=port, mac=mac, now=100 + i * 0.1)
            if result:
                alert = result[0]
        self.assertIsNotNone(alert)
        self.assertEqual(alert.rule, "multi_ip_spoof")
        engine.block(alert.ip, alert)
        self.assertTrue(engine.is_port_blocked(port))
        engine.unblock(alert.ip, mac=mac, in_port=port)
        self.assertFalse(engine.is_blocked(alert.ip))
        self.assertFalse(engine.is_port_blocked(port))
        self.assertNotIn(mac, engine._mac_ip_events)
        self.assertNotIn(port, engine._port_events)

        fresh = None
        for i in range(3):
            result = engine.observe_tcp("10.0.1.%d" % (20 + i), SRV, 41000 + i, 5000,
                                        SYN, in_port=port, mac=mac, now=200 + i * 0.1)
            if result:
                fresh = result[0]
        self.assertIsNotNone(fresh, "a fresh attack after unblock must be detected again")
        self.assertEqual(fresh.rule, "multi_ip_spoof")


if __name__ == "__main__":
    unittest.main(verbosity=2)
