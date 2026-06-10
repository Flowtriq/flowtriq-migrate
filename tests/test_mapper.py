"""Tests for FastNetMon -> Flowtriq config mapper."""

import os
import unittest

from flowtriq_migrate.mapper import FLOWTRIQ_DEFAULTS, map_to_flowtriq
from flowtriq_migrate.parser import parse_config

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


class TestBasicMapping(unittest.TestCase):
    def setUp(self):
        parsed = parse_config(
            os.path.join(FIXTURES, "community_basic.conf"),
            networks_file=os.path.join(FIXTURES, "networks_list.txt"),
        )
        self.config, self.notes = map_to_flowtriq(parsed)

    def test_interface_mapped(self):
        self.assertEqual(self.config["interface"], "eth0")

    def test_credentials_placeholder(self):
        self.assertEqual(self.config["api_key"], "YOUR_API_KEY_HERE")
        self.assertEqual(self.config["node_uuid"], "YOUR_NODE_UUID_HERE")

    def test_dynamic_threshold_enabled(self):
        self.assertTrue(self.config["dynamic_threshold"])

    def test_pcap_enabled(self):
        self.assertTrue(self.config["pcap_enabled"])

    def test_all_default_keys_present(self):
        for key in FLOWTRIQ_DEFAULTS:
            self.assertIn(key, self.config, f"Missing key: {key}")

    def test_has_mapped_notes(self):
        mapped = [n for n in self.notes if n["type"] == "mapped"]
        self.assertGreater(len(mapped), 0)

    def test_has_manual_notes(self):
        manual = [n for n in self.notes if n["type"] == "manual"]
        self.assertGreater(len(manual), 0)


class TestMirrorModeMapping(unittest.TestCase):
    def setUp(self):
        parsed = parse_config(
            os.path.join(FIXTURES, "community_full.conf"),
            networks_file=os.path.join(FIXTURES, "networks_list.txt"),
        )
        self.config, self.notes = map_to_flowtriq(parsed)

    def test_mirror_mode_enabled(self):
        self.assertTrue(self.config["mirror_mode"])

    def test_mirror_interface(self):
        self.assertEqual(self.config["mirror_interface"], "eth0")

    def test_mirror_subnets(self):
        self.assertEqual(
            self.config["mirror_subnets"],
            ["10.0.0.0/24", "192.168.1.0/24", "172.16.0.0/16"],
        )

    def test_mirror_capture_mode(self):
        self.assertEqual(self.config["mirror_capture_mode"], "af_packet")

    def test_exabgp_note(self):
        manual = [n for n in self.notes if n["type"] == "manual"]
        bgp_notes = [n for n in manual if "ExaBGP" in n["message"]]
        self.assertEqual(len(bgp_notes), 1)
        self.assertIn("65001:666", bgp_notes[0]["message"])

    def test_graphite_note(self):
        info = [n for n in self.notes if n["type"] == "info"]
        graphite_notes = [n for n in info if "Graphite" in n["message"]]
        self.assertEqual(len(graphite_notes), 1)


class TestSFlowMapping(unittest.TestCase):
    def test_sflow_config(self):
        parsed = {
            "edition": "community",
            "interfaces": ["ens3"],
            "thresholds": {"pps": 10000, "mbps": 500, "flows": 0},
            "ban": {"enabled": False, "time": 1900},
            "collection": {
                "mirror": False, "mirror_afpacket": False, "mirror_netmap": False,
                "netflow": False, "sflow": True,
                "sflow_port": 6343, "netflow_port": 2055,
                "sflow_host": "0.0.0.0", "netflow_host": "0.0.0.0",
            },
            "networks": [],
            "networks_list_path": "",
            "notify_script": "",
            "exabgp": {"enabled": False},
            "gobgp": {"enabled": False},
            "graphite": {"enabled": False},
        }
        config, notes = map_to_flowtriq(parsed)
        self.assertTrue(config["flow_enabled"])
        self.assertEqual(config["flow_protocol"], "sflow")
        self.assertEqual(config["flow_port"], 6343)
        self.assertFalse(config["mirror_mode"])


class TestNetFlowMapping(unittest.TestCase):
    def test_netflow_config(self):
        parsed = {
            "edition": "community",
            "interfaces": ["eth1"],
            "thresholds": {"pps": 0, "mbps": 0, "flows": 0},
            "ban": {"enabled": False, "time": 1900},
            "collection": {
                "mirror": False, "mirror_afpacket": False, "mirror_netmap": False,
                "netflow": True, "sflow": False,
                "sflow_port": 6343, "netflow_port": 9995,
                "sflow_host": "0.0.0.0", "netflow_host": "0.0.0.0",
            },
            "networks": [],
            "networks_list_path": "",
            "notify_script": "",
            "exabgp": {"enabled": False},
            "gobgp": {"enabled": False},
            "graphite": {"enabled": False},
        }
        config, notes = map_to_flowtriq(parsed)
        self.assertTrue(config["flow_enabled"])
        self.assertEqual(config["flow_protocol"], "netflow_v5")
        self.assertEqual(config["flow_port"], 9995)


class TestCredentialOverride(unittest.TestCase):
    def test_api_key_override(self):
        parsed = {
            "edition": "community",
            "interfaces": [],
            "thresholds": {"pps": 0, "mbps": 0, "flows": 0},
            "ban": {"enabled": False, "time": 0},
            "collection": {
                "mirror": False, "mirror_afpacket": False, "mirror_netmap": False,
                "netflow": False, "sflow": False,
                "sflow_port": 6343, "netflow_port": 2055,
                "sflow_host": "0.0.0.0", "netflow_host": "0.0.0.0",
            },
            "networks": [],
            "networks_list_path": "",
            "notify_script": "",
            "exabgp": {"enabled": False},
            "gobgp": {"enabled": False},
            "graphite": {"enabled": False},
        }
        config, _ = map_to_flowtriq(parsed, api_key="my-key", node_uuid="my-uuid")
        self.assertEqual(config["api_key"], "my-key")
        self.assertEqual(config["node_uuid"], "my-uuid")


class TestWanguardMapping(unittest.TestCase):
    def setUp(self):
        parsed = parse_config(os.path.join(FIXTURES, "wanguard_basic.json"))
        self.config, self.notes = map_to_flowtriq(parsed)

    def test_interface_mapped(self):
        self.assertEqual(self.config["interface"], "eth0")

    def test_flow_enabled(self):
        self.assertTrue(self.config["flow_enabled"])
        self.assertEqual(self.config["flow_protocol"], "netflow_v5")
        self.assertEqual(self.config["flow_port"], 2055)

    def test_dynamic_threshold(self):
        self.assertTrue(self.config["dynamic_threshold"])

    def test_all_keys_present(self):
        for key in FLOWTRIQ_DEFAULTS:
            self.assertIn(key, self.config)

    def test_has_wanguard_notes(self):
        all_msgs = " ".join(n["message"] for n in self.notes)
        self.assertIn("Wanguard", all_msgs)

    def test_snmp_note(self):
        manual = [n for n in self.notes if n["type"] == "manual"]
        snmp_notes = [n for n in manual if "SNMP" in n["message"]]
        self.assertGreater(len(snmp_notes), 0)


class TestCoreroMapping(unittest.TestCase):
    def setUp(self):
        parsed = parse_config(os.path.join(FIXTURES, "corero_basic.json"))
        self.config, self.notes = map_to_flowtriq(parsed)

    def test_interface_mapped(self):
        self.assertEqual(self.config["interface"], "eth0")

    def test_agent_mode(self):
        # Corero is inline, so no flow/mirror -- defaults to agent mode
        self.assertFalse(self.config["flow_enabled"])
        self.assertFalse(self.config["mirror_mode"])

    def test_networks_from_managed_objects(self):
        # Networks should be noted but not in mirror_subnets (not mirror mode)
        info = [n for n in self.notes if n["type"] == "info"]
        net_notes = [n for n in info if "managed object" in n["message"].lower()]
        self.assertGreater(len(net_notes), 0)

    def test_has_corero_notes(self):
        all_msgs = " ".join(n["message"] for n in self.notes)
        self.assertIn("Corero", all_msgs)
        self.assertIn("inline", all_msgs.lower())

    def test_bgp_flowspec_note(self):
        manual = [n for n in self.notes if n["type"] == "manual"]
        bgp_notes = [n for n in manual if "FlowSpec" in n["message"]]
        self.assertGreater(len(bgp_notes), 0)

    def test_syslog_note(self):
        manual = [n for n in self.notes if n["type"] == "manual"]
        syslog_notes = [n for n in manual if "Syslog" in n["message"]]
        self.assertGreater(len(syslog_notes), 0)

    def test_webhook_note(self):
        manual = [n for n in self.notes if n["type"] == "manual"]
        webhook_notes = [n for n in manual if "webhook" in n["message"].lower() or "Webhook" in n["message"]]
        self.assertGreater(len(webhook_notes), 0)


if __name__ == "__main__":
    unittest.main()
