"""Pure-Python unit tests for telemetry parsing (no Mininet/OVS needed)."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "tools" / "telemetry_panel.py"
SPEC = importlib.util.spec_from_file_location("telemetry_panel", MODULE)
panel = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(panel)


class TelemetryPanelTest(unittest.TestCase):
    def test_parse_flow_rules_and_drop_kind(self):
        raw = """OFPST_FLOW reply (OF1.3) (xid=0x2):
 cookie=0x0, duration=1.2s, table=0, n_packets=17, n_bytes=1428, priority=200,in_port=10 actions=drop
 cookie=0x0, duration=4.0s, table=0, n_packets=21, n_bytes=800, priority=0 actions=CONTROLLER:65535
 cookie=0x0, duration=5.0s, table=0, n_packets=22, n_bytes=1800, priority=20,ip,nw_src=10.0.0.3 actions=output:2
"""
        flows = panel.parse_flows(raw)
        self.assertEqual(len(flows), 3)
        port_drop = next(flow for flow in flows if flow["priority"] == 200)
        self.assertEqual(port_drop["action_kind"], "DROP")
        self.assertIn("in_port=10", port_drop["match"])
        self.assertEqual(port_drop["packets"], 17)
        self.assertEqual(next(f for f in flows if f["priority"] == 0)["action_kind"], "CONTROLLER")
        self.assertEqual(next(f for f in flows if f["priority"] == 20)["action_kind"], "OUTPUT")

    def test_topology_port_mapping_single_and_distributed(self):
        self.assertEqual(panel.map_host_ports({"s1-eth1": 1, "s1-eth2": 2, "s1-eth3": 3}),
                         {"h1": 1, "h2": 2, "h3": 3})
        self.assertEqual(panel.map_host_ports({"s1-eth1": 1, "s1-eth2": 2, "vxlan0": 10}),
                         {"h1": 10, "h2": 1, "h3": 2})

    def test_load_series_aggregates_sources_and_estimates_byte_rate(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "flow_stats.csv"
            path.write_text(
                "timestamp,src_ip,active_flows,packets_per_sec,bytes_in_interval\n"
                "100.000,10.0.0.1,2,10,300\n"
                "100.000,10.0.0.2,3,5,600\n"
                "103.000,10.0.0.1,4,20,900\n", encoding="utf-8"
            )
            series = panel.load_series(path, default_interval=3)
            self.assertEqual(len(series), 2)
            self.assertEqual(series[0]["packets_per_sec"], 15)
            self.assertEqual(series[0]["active_flows"], 5)
            self.assertEqual(series[0]["bytes_per_sec"], 300)
            self.assertEqual(series[1]["packets_per_sec"], 20)
            self.assertEqual(series[1]["bytes_per_sec"], 300)


    def test_rule_config_write_validates_and_preserves_root_settings(self):
        original_path = panel.RULES_JSON
        try:
            with tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "ids_rules.json"
                original = json.loads((MODULE.parents[1] / "controller" / "ids_rules.json").read_text(encoding="utf-8"))
                path.write_text(json.dumps(original), encoding="utf-8")
                panel.RULES_JSON = path
                candidate = json.loads(json.dumps(original))
                candidate["multi_ip_spoof"]["enabled"] = False
                candidate["multi_ip_spoof"]["threshold"] = 3
                saved = panel._validate_and_write_rules(candidate)
                self.assertFalse(saved["multi_ip_spoof"]["enabled"])
                self.assertEqual(saved["multi_ip_spoof"]["threshold"], 3)
                self.assertEqual(saved["protected_hosts"], original["protected_hosts"])
                bad = json.loads(json.dumps(saved))
                bad["multi_ip_spoof"]["threshold"] = 0
                with self.assertRaises(ValueError):
                    panel._validate_and_write_rules(bad)
        finally:
            panel.RULES_JSON = original_path

    def test_explicit_drop_action_is_detected(self):
        # Real OVS normally prints actions=drop explicitly.
        flow = panel.parse_flows("cookie=0x0, duration=1.0s, table=0, n_packets=2, n_bytes=64, priority=100,ip,nw_src=10.0.0.1 actions=drop")
        self.assertEqual(flow[0]["action_kind"], "DROP")


if __name__ == "__main__":
    unittest.main(verbosity=2)
