"""Pure-Python tests for CLI flow parsing and recovery-tier classification."""
import importlib.util
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "tools" / "sdn_cli.py"
SPEC = importlib.util.spec_from_file_location("sdn_cli", MODULE)
cli = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cli)


class CliSuiteTest(unittest.TestCase):
    def test_openflow_flow_dump_classifies_quarantine_forward_and_controller(self):
        raw = """OFPST_FLOW reply (OF1.3) (xid=0x2):
 cookie=0x0, duration=1.2s, table=0, n_packets=17, n_bytes=1428, priority=200,in_port=10 actions=drop
 cookie=0x0, duration=4.0s, table=0, n_packets=21, n_bytes=800, priority=0 actions=CONTROLLER:65535
 cookie=0x0, duration=5.0s, table=0, n_packets=22, n_bytes=1800, priority=20,ip,nw_src=10.0.0.3 actions=output:2
 cookie=0x0, duration=6.0s, table=0, n_packets=9, n_bytes=700, priority=100,ip,nw_src=10.0.0.1 actions=drop
"""
        flows = cli.parse_flow_dump(raw)
        self.assertEqual(len(flows), 4)
        port_drop = next(f for f in flows if f["priority"] == 200)
        self.assertEqual(port_drop["kind"], "DROP")
        self.assertEqual(port_drop["packets"], 17)
        self.assertIn("in_port=10", port_drop["match"])
        self.assertEqual(next(f for f in flows if f["priority"] == 0)["kind"], "TABLE-MISS -> CTRL")
        self.assertEqual(next(f for f in flows if f["priority"] == 20)["kind"], "FORWARD")
        self.assertEqual(cli._active_quarantine_diagnostics(raw), (1, 1))

    def test_drop_rules_are_sorted_highest_priority_first(self):
        raw = """cookie=0x0, n_packets=1, n_bytes=60, priority=100,ip,nw_src=10.0.0.1 actions=drop
 cookie=0x0, n_packets=2, n_bytes=60, priority=200,in_port=10 actions=drop
"""
        flows = cli.parse_flow_dump(raw)
        self.assertEqual([f["priority"] for f in flows], [200, 100])


    def test_report_arguments_are_forwarded_for_clean_baseline_and_csv_export(self):
        from unittest.mock import patch
        with patch.object(cli, "invoke_controller_report", return_value=0) as invoke:
            self.assertEqual(cli.command_sdn_report(["--clear"], {}), 0)
            invoke.assert_called_once_with({}, ["--clear"])

    def test_shortcut_list_contains_required_commands(self):
        expected = {
            "sdn-brain", "sdn-ui", "sdn-net", "sdn-sync", "sdn-flows", "sdn-unblock",
            "test-h1", "test-h3", "legit-start", "atk-spoof", "atk-flood", "atk-scan",
            "atk-flags", "atk-rate", "atk-concurrent", "sdn-report", "sdn-autopilot", "sdn-help",
        }
        self.assertEqual(set(cli.COMMANDS), expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
