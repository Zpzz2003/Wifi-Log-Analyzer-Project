
import tempfile
import unittest
from pathlib import Path

from wifi_analyzer import (
    analyze_log,
    categorize_error,
    extract_valid_ips,
)


class TestErrorCategorization(unittest.TestCase):
    def test_categorize_dhcp_error(self):
        self.assertEqual(
            categorize_error("DHCP lease request failed"),
            "DHCP",
        )

    def test_categorize_authentication_error(self):
        self.assertEqual(
            categorize_error("Authentication failed"),
            "Authentication",
        )

    def test_categorize_dns_error(self):
        self.assertEqual(
            categorize_error("DNS resolution failed"),
            "DNS",
        )

    def test_categorize_other_error(self):
        self.assertEqual(
            categorize_error("Unknown network failure"),
            "Other",
        )


class TestIPExtraction(unittest.TestCase):
    def test_extract_valid_ipv4_addresses(self):
        result = extract_valid_ips(
            "Client 192.168.1.10 connected"
        )

        self.assertEqual(result, ["192.168.1.10"])

    def test_ignore_invalid_ip_addresses(self):
        result = extract_valid_ips(
            "Client 999.999.1.10 connected"
        )

        self.assertEqual(result, [])

    def test_extract_multiple_addresses(self):
        result = extract_valid_ips(
            "Connection between 192.168.1.10 and 10.0.0.5"
        )

        self.assertEqual(
            result,
            ["192.168.1.10", "10.0.0.5"],
        )


class TestLogAnalysis(unittest.TestCase):
    def analyze_test_log(self, log_contents):
        """Create a temporary log and analyze it."""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "test.log"
            log_path.write_text(
                log_contents,
                encoding="utf-8",
            )

            return analyze_log(
                log_path,
                spike_threshold=1.5,
                auth_threshold=3,
            )

    def test_count_events_errors_and_warnings(self):
        log = (
            "2026-10-06 08:01:22 INFO "
            "Client 192.168.1.10 connected\n"
            "2026-10-06 08:02:15 WARNING "
            "High latency detected\n"
            "2026-10-06 08:03:40 ERROR "
            "DNS resolution failed\n"
        )

        result = self.analyze_test_log(log)

        self.assertEqual(result["total_events"], 3)
        self.assertEqual(result["errors"], 1)
        self.assertEqual(result["warnings"], 1)
        self.assertAlmostEqual(
            result["error_rate"],
            100 / 3,
        )

    def test_detect_client_ip(self):
        log = (
            "2026-10-06 08:01:22 INFO "
            "Client 192.168.1.10 connected\n"
        )

        result = self.analyze_test_log(log)

        self.assertIn("192.168.1.10", result["clients"])
        self.assertEqual(
            result["client_activity"]["192.168.1.10"][
                "connections"
            ],
            1,
        )

    def test_authentication_alert_threshold(self):
        log = (
            "2026-10-06 08:01:22 ERROR "
            "Authentication failed for 192.168.1.15\n"
            "2026-10-06 08:02:22 ERROR "
            "Authentication failed for 192.168.1.15\n"
            "2026-10-06 08:03:22 ERROR "
            "Authentication failed for 192.168.1.15\n"
        )

        result = self.analyze_test_log(log)

        self.assertEqual(
            result["authentication_failures"]["192.168.1.15"],
            3,
        )
        self.assertIn(
            "192.168.1.15",
            result["security_alerts"],
        )

    def test_empty_log(self):
        result = self.analyze_test_log("")

        self.assertEqual(result["total_events"], 0)
        self.assertEqual(result["errors"], 0)
        self.assertEqual(result["warnings"], 0)
        self.assertEqual(result["error_rate"], 0)
        self.assertEqual(result["clients"], [])
        self.assertEqual(result["baseline"], 0)

    def test_malformed_entry_and_invalid_timestamp(self):
        result = self.analyze_test_log(
            "This is a malformed log entry\n"
        )

        self.assertEqual(result["total_events"], 1)
        self.assertEqual(result["malformed_entries"], 1)
        self.assertEqual(result["invalid_timestamps"], 1)

    def test_no_errors(self):
        log = (
            "2026-10-06 08:01:22 INFO "
            "Client 192.168.1.10 connected\n"
            "2026-10-06 08:02:22 WARNING "
            "Signal strength is weak\n"
        )

        result = self.analyze_test_log(log)

        self.assertEqual(result["errors"], 0)
        self.assertEqual(len(result["error_details"]), 0)
        self.assertEqual(len(result["error_types"]), 0)


if __name__ == "__main__":
    unittest.main()
