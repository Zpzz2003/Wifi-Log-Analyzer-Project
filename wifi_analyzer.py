
import argparse
import csv
import ipaddress
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import matplotlib.pyplot as plt


DEFAULT_LOG_FILE = Path("logs/wifi.log")
DEFAULT_REPORT_FILE = Path("reports/network_report.txt")

DEFAULT_SPIKE_THRESHOLD = 1.5
DEFAULT_AUTH_FAILURE_THRESHOLD = 3
DEFAULT_MIN_SPIKE_EVENTS = 5

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def categorize_error(message):
    """Categorize an error based on its log message."""
    message_lower = message.lower()

    if "dhcp" in message_lower:
        return "DHCP"
    elif "authentication" in message_lower:
        return "Authentication"
    elif "dns" in message_lower:
        return "DNS"

    return "Other"


def get_recommendation(error_type):
    """Return a suggested troubleshooting step for an error."""
    recommendations = {
        "DHCP": (
            "Check DHCP service status, address pool availability, "
            "and client lease configuration."
        ),
        "Authentication": (
            "Review authentication logs, credentials, and wireless "
            "security settings."
        ),
        "DNS": (
            "Check DNS server settings, name resolution, "
            "and network connectivity."
        ),
        "Other": (
            "Review the original log message and related events."
        ),
    }

    return recommendations[error_type]


def extract_valid_ips(message):
    """Return valid IPv4 addresses found in a log message."""
    valid_ips = []

    for candidate in IP_PATTERN.findall(message):
        try:
            address = ipaddress.ip_address(candidate)

            if address.version == 4:
                valid_ips.append(str(address))

        except ValueError:
            continue

    return valid_ips


def detect_traffic_spikes(
    hourly_traffic,
    spike_threshold,
    min_events,
):
    """Detect busy hours using the median of other recorded hours."""
    spikes = {}

    for hour, count in hourly_traffic.items():
        comparison_counts = [
            other_count
            for other_hour, other_count in hourly_traffic.items()
            if other_hour != hour
        ]

        # A comparison requires at least one other hour.
        if not comparison_counts:
            continue

        comparison_counts.sort()
        middle = len(comparison_counts) // 2

        if len(comparison_counts) % 2:
            baseline = comparison_counts[middle]
        else:
            baseline = (
                comparison_counts[middle - 1]
                + comparison_counts[middle]
            ) / 2

        if (
            count >= min_events
            and count > baseline * spike_threshold
        ):
            spikes[hour] = {
                "count": count,
                "baseline": baseline,
            }

    return spikes


def analyze_activity_trend(hourly_traffic):
    """Compare average hourly activity across two periods."""
    counts = [
        count
        for hour, count in sorted(hourly_traffic.items())
    ]

    if len(counts) < 2:
        return {
            "direction": "Insufficient data",
            "first_average": None,
            "second_average": None,
            "change_percent": None,
        }

    midpoint = len(counts) // 2
    first_half = counts[:midpoint]
    second_half = counts[midpoint:]

    first_average = sum(first_half) / len(first_half)
    second_average = sum(second_half) / len(second_half)

    if first_average == 0:
        if second_average > 0:
            change_percent = None
            direction = "Increasing"
        else:
            change_percent = 0
            direction = "Stable"
    else:
        change_percent = (
            (second_average - first_average)
            / first_average
            * 100
        )

        if change_percent > 10:
            direction = "Increasing"
        elif change_percent < -10:
            direction = "Decreasing"
        else:
            direction = "Stable"

    return {
        "direction": direction,
        "first_average": first_average,
        "second_average": second_average,
        "change_percent": change_percent,
    }


def analyze_log(
    log_file,
    spike_threshold,
    auth_threshold,
    min_spike_events=DEFAULT_MIN_SPIKE_EVENTS,
):
    """Analyze log events, errors, clients, and hourly activity."""
    total_events = 0
    errors = 0
    warnings = 0
    malformed_entries = 0
    invalid_timestamps = 0

    clients = set()
    error_types = Counter()
    error_details = []
    client_activity = defaultdict(Counter)
    authentication_failures = Counter()
    hourly_traffic = defaultdict(int)
    timestamps = []

    with log_file.open("r", encoding="utf-8") as file:
        for line_number, raw_line in enumerate(file, start=1):
            line = raw_line.strip()

            if not line:
                continue

            total_events += 1
            parts = line.split()

            # Parse the timestamp and count hourly events.
            timestamp = None

            if len(parts) >= 2:
                try:
                    timestamp = datetime.strptime(
                        " ".join(parts[:2]),
                        TIMESTAMP_FORMAT,
                    )

                    timestamps.append(timestamp)

                    hour = timestamp.replace(
                        minute=0,
                        second=0,
                        microsecond=0,
                    )

                    hourly_traffic[hour] += 1

                except ValueError:
                    invalid_timestamps += 1
            else:
                invalid_timestamps += 1

            # Check basic log structure.
            if (
                len(parts) < 4
                or parts[2] not in {"INFO", "WARNING", "ERROR"}
            ):
                malformed_entries += 1

            # Count errors and retain their details.
            if len(parts) >= 3 and parts[2] == "ERROR":
                errors += 1

                error_type = categorize_error(line)
                error_types[error_type] += 1

                error_details.append({
                    "line_number": line_number,
                    "timestamp": timestamp,
                    "type": error_type,
                    "message": line,
                })

            elif len(parts) >= 3 and parts[2] == "WARNING":
                warnings += 1

            # Extract valid IPv4 addresses.
            ips = extract_valid_ips(line)

            if "Client" in line and ips:
                ip_address = ips[0]
                clients.add(ip_address)

                message_lower = line.lower()

                if "connected" in message_lower:
                    client_activity[ip_address]["connections"] += 1

                elif "disconnected" in message_lower:
                    client_activity[ip_address]["disconnections"] += 1

            # Count failed authentication attempts by IP.
            if (
                "authentication" in line.lower()
                and "failed" in line.lower()
            ):
                for ip_address in ips:
                    authentication_failures[ip_address] += 1

    # Calculate the overall error rate.
    error_rate = (
        errors / total_events * 100
        if total_events
        else 0
    )

    # Fill missing hours between the first and last valid timestamps.
    if timestamps:
        first_hour = min(timestamps).replace(
            minute=0,
            second=0,
            microsecond=0,
        )

        last_hour = max(timestamps).replace(
            minute=0,
            second=0,
            microsecond=0,
        )

        current_hour = first_hour

        while current_hour <= last_hour:
            hourly_traffic.setdefault(current_hour, 0)
            current_hour += timedelta(hours=1)

    hourly_traffic = dict(sorted(hourly_traffic.items()))

    # Calculate overall hourly average for the report.
    baseline = (
        sum(hourly_traffic.values()) / len(hourly_traffic)
        if hourly_traffic
        else 0
    )

    # Detect spikes using a comparison baseline that excludes
    # the hour being evaluated.
    spikes = detect_traffic_spikes(
        hourly_traffic,
        spike_threshold,
        min_spike_events,
    )

    # Analyze the direction of activity over time.
    trend = analyze_activity_trend(hourly_traffic)

    # Flag IP addresses reaching the authentication threshold.
    security_alerts = {
        ip_address: count
        for ip_address, count in authentication_failures.items()
        if count >= auth_threshold
    }

    return {
        "total_events": total_events,
        "errors": errors,
        "warnings": warnings,
        "error_rate": error_rate,
        "clients": sorted(clients),
        "error_types": error_types,
        "error_details": error_details,
        "client_activity": dict(sorted(client_activity.items())),
        "hourly_traffic": hourly_traffic,
        "baseline": baseline,
        "spikes": spikes,
        "trend": trend,
        "timestamps": timestamps,
        "malformed_entries": malformed_entries,
        "invalid_timestamps": invalid_timestamps,
        "authentication_failures": authentication_failures,
        "security_alerts": security_alerts,
    }


def create_report(
    results,
    report_file,
    spike_threshold,
    auth_threshold,
    min_spike_events=DEFAULT_MIN_SPIKE_EVENTS,
):
    """Generate and save the text network report."""
    report = [
        "=" * 44,
        "          HOME WIFI NETWORK REPORT",
        "=" * 44,
        "",
        "ANALYSIS SUMMARY",
        "-" * 44,
        f"Total Events: {results['total_events']}",
        f"Network Errors: {results['errors']}",
        f"Warnings: {results['warnings']}",
        f"Error Rate: {results['error_rate']:.2f}%",
        "",
        "LOG VALIDATION",
        "-" * 44,
        f"Malformed Entries: {results['malformed_entries']}",
        f"Invalid Timestamps: {results['invalid_timestamps']}",
        "",
        "CLIENTS DETECTED",
        "-" * 44,
    ]

    report.extend(
        results["clients"] or ["No client IP addresses detected."]
    )

    report.extend(["", "CLIENT ACTIVITY", "-" * 44])

    if results["client_activity"]:
        for ip, activity in results["client_activity"].items():
            report.append(
                f"{ip}: {activity['connections']} connection event(s), "
                f"{activity['disconnections']} disconnection event(s)"
            )
    else:
        report.append("No client connection events detected.")

    report.extend(["", "ERROR BREAKDOWN", "-" * 44])

    if results["error_types"]:
        for error_type, count in results["error_types"].items():
            report.append(f"{error_type}: {count}")
    else:
        report.append("No errors detected.")

    report.extend(["", "ERROR DETAILS", "-" * 44])

    if results["error_details"]:
        for error in results["error_details"]:
            time_text = (
                error["timestamp"].strftime(TIMESTAMP_FORMAT)
                if error["timestamp"]
                else "Unknown timestamp"
            )

            report.extend([
                f"Log line: {error['line_number']}",
                f"Time: {time_text}",
                f"Category: {error['type']}",
                f"Message: {error['message']}",
                f"Suggested next step: "
                f"{get_recommendation(error['type'])}",
                "",
            ])
    else:
        report.append("No errors require investigation.")

    report.extend([
        "AUTHENTICATION AUDIT",
        "-" * 44,
        f"Alert threshold: {auth_threshold} failed attempts per IP",
    ])

    if results["authentication_failures"]:
        for ip, count in sorted(
            results["authentication_failures"].items()
        ):
            report.append(
                f"{ip}: {count} failed authentication event(s)"
            )
    else:
        report.append(
            "No identifiable authentication failures detected."
        )

    report.append("")

    if results["security_alerts"]:
        for ip, count in sorted(results["security_alerts"].items()):
            report.append(
                f"SECURITY ALERT: {ip} recorded {count} failed "
                f"authentication events. Review the source and context."
            )
    else:
        report.append("No IP addresses reached the alert threshold.")

    report.extend([
        "",
        "HOURLY TRAFFIC ANALYSIS",
        "-" * 44,
        f"Average Events Per Hour: {results['baseline']:.2f}",
        f"Spike Threshold: {spike_threshold}x comparison median",
        f"Minimum Events for Spike Alert: {min_spike_events}",
    ])

    for hour, count in results["hourly_traffic"].items():
        report.append(
            f"{hour:%Y-%m-%d %H:00}: {count} events"
        )

    report.extend(["", "TRAFFIC SPIKE ALERTS", "-" * 44])

    if results["spikes"]:
        for hour, details in results["spikes"].items():
            report.append(
                f"ALERT: {hour:%Y-%m-%d %H:00} - "
                f"{details['count']} events "
                f"(comparison median: {details['baseline']:.2f})"
            )
    else:
        report.append(
            "No traffic spikes detected, or insufficient "
            "comparison data was available."
        )

    trend = results["trend"]

    report.extend([
        "",
        "ACTIVITY TREND ANALYSIS",
        "-" * 44,
        f"Trend: {trend['direction']}",
    ])

    if trend["first_average"] is not None:
        report.append(
            f"First-period average: "
            f"{trend['first_average']:.2f} events per hour"
        )
        report.append(
            f"Second-period average: "
            f"{trend['second_average']:.2f} events per hour"
        )

        if trend["change_percent"] is not None:
            report.append(
                f"Activity change: {trend['change_percent']:.2f}%"
            )
        else:
            report.append(
                "Activity change: not calculated because "
                "the first-period average was zero."
            )

    if results["timestamps"]:
        report.extend([
            "",
            f"Analysis Start: "
            f"{min(results['timestamps']):%Y-%m-%d %H:%M:%S}",
            f"Analysis End: "
            f"{max(results['timestamps']):%Y-%m-%d %H:%M:%S}",
        ])

    report.extend(["", "=" * 44, ""])

    report_text = "\n".join(report)

    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text(report_text, encoding="utf-8")

    print(report_text)


def export_csv(results, report_file):
    """Export error details and hourly activity to CSV files."""
    output_dir = report_file.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    error_csv = output_dir / "error_details.csv"

    with error_csv.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        fields = ["line_number", "timestamp", "type", "message"]
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()

        for error in results["error_details"]:
            writer.writerow({
                "line_number": error["line_number"],
                "timestamp": (
                    error["timestamp"].strftime(TIMESTAMP_FORMAT)
                    if error["timestamp"]
                    else "Unknown"
                ),
                "type": error["type"],
                "message": error["message"],
            })

    hourly_csv = output_dir / "hourly_activity.csv"

    with hourly_csv.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.writer(file)
        writer.writerow(["hour", "event_count"])

        for hour, count in results["hourly_traffic"].items():
            writer.writerow([
                hour.strftime("%Y-%m-%d %H:%M:%S"),
                count,
            ])

    print(f"\nCSV exports saved to: {output_dir}")
    print(f"- {error_csv.name}")
    print(f"- {hourly_csv.name}")


def create_charts(results, report_file):
    """Generate PNG charts for error categories and hourly activity."""
    chart_dir = report_file.parent / "charts"
    chart_dir.mkdir(parents=True, exist_ok=True)

    # Chart 1: Error categories.
    error_types = results["error_types"]

    plt.figure(figsize=(8, 5))

    if error_types:
        labels = list(error_types.keys())
        counts = list(error_types.values())

        plt.bar(labels, counts)
        plt.ylabel("Number of Errors")
        plt.title("Wi-Fi Log Errors by Category")
    else:
        plt.text(
            0.5,
            0.5,
            "No errors detected",
            ha="center",
            va="center",
        )
        plt.title("Wi-Fi Log Errors by Category")
        plt.axis("off")

    plt.tight_layout()

    error_chart = chart_dir / "error_categories.png"
    plt.savefig(error_chart, dpi=150)
    plt.close()

    # Chart 2: Hourly log activity.
    hourly = results["hourly_traffic"]

    plt.figure(figsize=(10, 5))

    if hourly:
        labels = [
            hour.strftime("%m-%d %H:%M")
            for hour in hourly.keys()
        ]

        counts = list(hourly.values())

        plt.plot(labels, counts, marker="o")
        plt.xlabel("Hour")
        plt.ylabel("Number of Log Events")
        plt.title("Wi-Fi Log Activity Over Time")
        plt.xticks(rotation=45, ha="right")
        plt.grid(True, alpha=0.3)
    else:
        plt.text(
            0.5,
            0.5,
            "No valid timestamps available",
            ha="center",
            va="center",
        )
        plt.title("Wi-Fi Log Activity Over Time")
        plt.axis("off")

    plt.tight_layout()

    activity_chart = chart_dir / "hourly_activity.png"
    plt.savefig(activity_chart, dpi=150)
    plt.close()

    print(f"\nCharts saved to: {chart_dir}")
    print(f"- {error_chart.name}")
    print(f"- {activity_chart.name}")


def main():
    """Parse command-line arguments and run the analyzer."""
    parser = argparse.ArgumentParser(
        description="Analyze Wi-Fi network log events."
    )

    parser.add_argument(
        "--log-file",
        type=Path,
        default=DEFAULT_LOG_FILE,
        help="Path to the input log file.",
    )

    parser.add_argument(
        "--report-file",
        type=Path,
        default=DEFAULT_REPORT_FILE,
        help="Path for the generated text report and output files.",
    )

    parser.add_argument(
        "--spike-threshold",
        type=float,
        default=DEFAULT_SPIKE_THRESHOLD,
        help="Hourly spike multiplier; must be greater than zero.",
    )

    parser.add_argument(
        "--auth-threshold",
        type=int,
        default=DEFAULT_AUTH_FAILURE_THRESHOLD,
        help="Failed authentication count per IP required for an alert.",
    )

    parser.add_argument(
        "--min-spike-events",
        type=int,
        default=DEFAULT_MIN_SPIKE_EVENTS,
        help="Minimum hourly event count required for a spike alert.",
    )

    args = parser.parse_args()

    if args.spike_threshold <= 0:
        parser.error("--spike-threshold must be greater than zero.")

    if args.auth_threshold < 1:
        parser.error("--auth-threshold must be at least 1.")

    if args.min_spike_events < 1:
        parser.error("--min-spike-events must be at least 1.")

    if not args.log_file.is_file():
        parser.error(f"Log file not found: {args.log_file}")

    try:
        results = analyze_log(
            args.log_file,
            args.spike_threshold,
            args.auth_threshold,
            args.min_spike_events,
        )

        create_report(
            results,
            args.report_file,
            args.spike_threshold,
            args.auth_threshold,
            args.min_spike_events,
        )

        export_csv(results, args.report_file)
        create_charts(results, args.report_file)

    except (OSError, UnicodeError) as error:
        parser.error(f"Could not process files: {error}")


if __name__ == "__main__":
    main()
