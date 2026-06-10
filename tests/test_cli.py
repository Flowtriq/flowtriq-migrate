"""Integration tests for the CLI entry point."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


class TestCLIDryRun(unittest.TestCase):
    def test_dry_run_outputs_valid_json(self):
        result = subprocess.run(
            [
                sys.executable, "-m", "flowtriq_migrate",
                os.path.join(FIXTURES, "community_basic.conf"),
                "--networks-file", os.path.join(FIXTURES, "networks_list.txt"),
                "--dry-run", "--quiet",
            ],
            capture_output=True,
            text=True,
            cwd=os.path.join(os.path.dirname(__file__), ".."),
        )
        self.assertEqual(result.returncode, 0)
        config = json.loads(result.stdout)
        self.assertIn("api_key", config)
        self.assertIn("interface", config)
        self.assertEqual(config["interface"], "eth0")

    def test_dry_run_with_credentials(self):
        result = subprocess.run(
            [
                sys.executable, "-m", "flowtriq_migrate",
                os.path.join(FIXTURES, "community_basic.conf"),
                "--networks-file", os.path.join(FIXTURES, "networks_list.txt"),
                "--dry-run", "--quiet",
                "--api-key", "test-key-123",
                "--node-uuid", "test-uuid-456",
            ],
            capture_output=True,
            text=True,
            cwd=os.path.join(os.path.dirname(__file__), ".."),
        )
        self.assertEqual(result.returncode, 0)
        config = json.loads(result.stdout)
        self.assertEqual(config["api_key"], "test-key-123")
        self.assertEqual(config["node_uuid"], "test-uuid-456")


class TestCLIFileOutput(unittest.TestCase):
    def test_writes_config_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "config.json")
            result = subprocess.run(
                [
                    sys.executable, "-m", "flowtriq_migrate",
                    os.path.join(FIXTURES, "community_basic.conf"),
                    "--networks-file", os.path.join(FIXTURES, "networks_list.txt"),
                    "-o", output_path,
                    "--quiet",
                ],
                capture_output=True,
                text=True,
                cwd=os.path.join(os.path.dirname(__file__), ".."),
            )
            self.assertEqual(result.returncode, 0)
            self.assertTrue(os.path.exists(output_path))
            with open(output_path) as f:
                config = json.load(f)
            self.assertEqual(config["interface"], "eth0")


class TestCLIErrors(unittest.TestCase):
    def test_missing_config_file(self):
        result = subprocess.run(
            [
                sys.executable, "-m", "flowtriq_migrate",
                "/nonexistent/path/config.conf",
                "--dry-run",
            ],
            capture_output=True,
            text=True,
            cwd=os.path.join(os.path.dirname(__file__), ".."),
        )
        self.assertNotEqual(result.returncode, 0)

    def test_version_flag(self):
        result = subprocess.run(
            [sys.executable, "-m", "flowtriq_migrate", "--version"],
            capture_output=True,
            text=True,
            cwd=os.path.join(os.path.dirname(__file__), ".."),
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("1.0.0", result.stdout)


class TestCLIReport(unittest.TestCase):
    def test_report_includes_key_sections(self):
        result = subprocess.run(
            [
                sys.executable, "-m", "flowtriq_migrate",
                os.path.join(FIXTURES, "community_full.conf"),
                "--networks-file", os.path.join(FIXTURES, "networks_list.txt"),
                "--dry-run",
            ],
            capture_output=True,
            text=True,
            cwd=os.path.join(os.path.dirname(__file__), ".."),
        )
        self.assertEqual(result.returncode, 0)
        # Report goes to stderr in dry-run mode
        report = result.stderr
        self.assertIn("Migration Report", report)
        self.assertIn("MAPPED SETTINGS", report)
        self.assertIn("NEW IN FLOWTRIQ", report)


if __name__ == "__main__":
    unittest.main()
