"""Tests for FastNetMon config parser."""

import json
import os
import tempfile
import unittest

from flowtriq_migrate.parser import parse_config

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


class TestCommunityBasic(unittest.TestCase):
    def setUp(self):
        self.parsed = parse_config(
            os.path.join(FIXTURES, "community_basic.conf"),
            networks_file=os.path.join(FIXTURES, "networks_list.txt"),
        )

    def test_edition(self):
        self.assertEqual(self.parsed["edition"], "community")

    def test_interfaces(self):
        self.assertEqual(self.parsed["interfaces"], ["eth0"])

    def test_thresholds(self):
        self.assertEqual(self.parsed["thresholds"]["pps"], 20000)
        self.assertEqual(self.parsed["thresholds"]["mbps"], 1024)
        self.assertEqual(self.parsed["thresholds"]["flows"], 3500)

    def test_ban(self):
        self.assertTrue(self.parsed["ban"]["enabled"])
        self.assertEqual(self.parsed["ban"]["time"], 1900)

    def test_notify_script(self):
        self.assertEqual(
            self.parsed["notify_script"],
            "/usr/local/bin/notify_about_attack.sh",
        )

    def test_networks(self):
        self.assertEqual(
            self.parsed["networks"],
            ["10.0.0.0/24", "192.168.1.0/24", "172.16.0.0/16"],
        )


class TestCommunityFull(unittest.TestCase):
    def setUp(self):
        self.parsed = parse_config(
            os.path.join(FIXTURES, "community_full.conf"),
            networks_file=os.path.join(FIXTURES, "networks_list.txt"),
        )

    def test_mirror_enabled(self):
        self.assertTrue(self.parsed["collection"]["mirror"])
        self.assertTrue(self.parsed["collection"]["mirror_afpacket"])
        self.assertFalse(self.parsed["collection"]["mirror_netmap"])

    def test_thresholds(self):
        self.assertEqual(self.parsed["thresholds"]["pps"], 50000)

    def test_exabgp(self):
        self.assertTrue(self.parsed["exabgp"]["enabled"])
        self.assertEqual(self.parsed["exabgp"]["community"], "65001:666")
        self.assertEqual(self.parsed["exabgp"]["next_hop"], "192.0.2.1")

    def test_graphite(self):
        self.assertTrue(self.parsed["graphite"]["enabled"])
        self.assertEqual(self.parsed["graphite"]["host"], "10.0.0.50")

    def test_ban_time(self):
        self.assertEqual(self.parsed["ban"]["time"], 3600)


class TestAdvancedJSON(unittest.TestCase):
    def setUp(self):
        self.config = {
            "interfaces": ["ens3", "ens4"],
            "ban_for_pps": 100000,
            "ban_for_bandwidth": 5000,
            "ban_for_flows": 10000,
            "enable_ban": True,
            "ban_time": 7200,
            "sflow": True,
            "sflow_port": 6343,
            "networks_list": "/etc/networks_list",
            "exabgp": {
                "enabled": True,
                "community": "65001:999",
                "next_hop": "10.0.0.1",
            },
            "hostgroups": {
                "web_servers": {"threshold_pps": 50000},
                "dns_servers": {"threshold_pps": 200000},
            },
            "email": {
                "enabled": True,
                "from_address": "noc@example.com",
                "to_address": "alerts@example.com",
                "smtp_host": "smtp.example.com",
            },
        }
        self.tmpfile = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        )
        json.dump(self.config, self.tmpfile)
        self.tmpfile.close()
        self.parsed = parse_config(self.tmpfile.name)

    def tearDown(self):
        os.unlink(self.tmpfile.name)

    def test_edition(self):
        self.assertEqual(self.parsed["edition"], "advanced")

    def test_interfaces(self):
        self.assertEqual(self.parsed["interfaces"], ["ens3", "ens4"])

    def test_thresholds(self):
        self.assertEqual(self.parsed["thresholds"]["pps"], 100000)

    def test_sflow(self):
        self.assertTrue(self.parsed["collection"]["sflow"])

    def test_exabgp(self):
        self.assertTrue(self.parsed["exabgp"]["enabled"])
        self.assertEqual(self.parsed["exabgp"]["community"], "65001:999")

    def test_hostgroups(self):
        self.assertIn("hostgroups", self.parsed)
        self.assertEqual(len(self.parsed["hostgroups"]), 2)

    def test_email(self):
        self.assertTrue(self.parsed["email"]["enabled"])
        self.assertEqual(self.parsed["email"]["smtp_host"], "smtp.example.com")


class TestEmptyConfig(unittest.TestCase):
    def test_empty_ini(self):
        tmpfile = tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False
        )
        tmpfile.write("# empty config\n")
        tmpfile.close()
        parsed = parse_config(tmpfile.name)
        os.unlink(tmpfile.name)
        self.assertEqual(parsed["edition"], "community")
        self.assertEqual(parsed["interfaces"], [])

    def test_comments_only(self):
        tmpfile = tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False
        )
        tmpfile.write("# comment 1\n# comment 2\n; another comment\n")
        tmpfile.close()
        parsed = parse_config(tmpfile.name)
        os.unlink(tmpfile.name)
        self.assertEqual(parsed["thresholds"]["pps"], 0)


class TestBooleanParsing(unittest.TestCase):
    def test_various_booleans(self):
        content = (
            "enable_ban = yes\n"
            "mirror = true\n"
            "sflow = 1\n"
            "netflow = no\n"
            "redis_enabled = disabled\n"
        )
        tmpfile = tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False
        )
        tmpfile.write(content)
        tmpfile.close()
        parsed = parse_config(tmpfile.name)
        os.unlink(tmpfile.name)
        self.assertTrue(parsed["ban"]["enabled"])
        self.assertTrue(parsed["collection"]["mirror"])
        self.assertTrue(parsed["collection"]["sflow"])
        self.assertFalse(parsed["collection"]["netflow"])


if __name__ == "__main__":
    unittest.main()
