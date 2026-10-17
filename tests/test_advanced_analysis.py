
import unittest
from datetime import datetime

from wifi_analyzer import (
    analyze_activity_trend,
    detect_traffic_spikes,
)


class TestAdvancedAnalysis(unittest.TestCase):
    def test_detect_unusually_busy_hour(self):
        hourly_traffic = {
            datetime(2026, 10, 6, 8): 2,
            datetime(2026, 10, 6, 9): 3,
            datetime(2026, 10, 6, 10): 2,
            datetime(2026, 10, 6, 11): 12,
            datetime(2026, 10, 6, 12): 3,
            datetime(2026, 10, 6, 13): 2,
        }

        spikes = detect_traffic_spikes(
            hourly_traffic,
            spike_threshold=1.5,
            min_events=5,
        )

        busy_hour = datetime(2026, 10, 6, 11)

        self.assertIn(busy_hour, spikes)
        self.assertEqual(spikes[busy_hour]["count"], 12)

    def test_minimum_event_threshold(self):
        hourly_traffic = {
            datetime(2026, 10, 6, 8): 1,
            datetime(2026, 10, 6, 9): 2,
            datetime(2026, 10, 6, 10): 1,
            datetime(2026, 10, 6, 11): 4,
        }

        spikes = detect_traffic_spikes(
            hourly_traffic,
            spike_threshold=1.5,
            min_events=5,
        )

        self.assertEqual(spikes, {})

    def test_single_hour_has_no_comparison(self):
        hourly_traffic = {
            datetime(2026, 10, 6, 8): 10,
        }

        spikes = detect_traffic_spikes(
            hourly_traffic,
            spike_threshold=1.5,
            min_events=5,
        )

        self.assertEqual(spikes, {})

    def test_increasing_activity_trend(self):
        hourly_traffic = {
            datetime(2026, 10, 6, 8): 2,
            datetime(2026, 10, 6, 9): 2,
            datetime(2026, 10, 6, 10): 8,
            datetime(2026, 10, 6, 11): 10,
        }

        trend = analyze_activity_trend(hourly_traffic)

        self.assertEqual(trend["direction"], "Increasing")
        self.assertGreater(trend["change_percent"], 10)

    def test_insufficient_trend_data(self):
        hourly_traffic = {
            datetime(2026, 10, 6, 8): 3,
        }

        trend = analyze_activity_trend(hourly_traffic)

        self.assertEqual(
            trend["direction"],
            "Insufficient data",
        )
        self.assertIsNone(trend["change_percent"])


if __name__ == "__main__":
    unittest.main()
