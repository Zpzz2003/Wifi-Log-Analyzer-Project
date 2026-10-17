
# Wi-Fi Log Analyzer

A Python-based network log analysis tool that identifies errors,
tracks client activity, audits repeated authentication failures,
detects unusual hourly activity, and generates reports and charts.

This project was built as a hands-on home lab project to develop
Python programming, log analysis, troubleshooting, and data
visualization skills.

## Features

- Parses timestamped network log entries.
- Counts errors, warnings, and total events.
- Categorizes DHCP, DNS, authentication, and other errors.
- Extracts and validates IPv4 addresses.
- Tracks client connection and disconnection events.
- Counts failed authentication attempts by IP address.
- Generates alerts when authentication failures reach a threshold.
- Analyzes hourly log activity and detects unusually busy hours.
- Summarizes activity trends over time.
- Exports error details and hourly activity to CSV.
- Generates charts using Matplotlib.
- Provides command-line options for input files and alert thresholds.
- Includes automated tests using Python's unittest framework.

## Technologies

- Python 3
- Linux / Ubuntu on WSL
- Matplotlib
- Python standard library: argparse, csv, datetime, ipaddress,
  pathlib, re, collections, tempfile, and unittest

## Project Structure

```text
wifi-log-analyzer/
├── logs/
│   └── wifi.log
├── reports/
│   ├── network_report.txt
│   ├── error_details.csv
│   ├── hourly_activity.csv
│   └── charts/
│       ├── error_categories.png
│       └── hourly_activity.png
├── tests/
│   └── test_wifi_analyzer.py
├── wifi_analyzer.py
├── requirements.txt
├── .gitignore
└── README.md
```

Generated report files appear after running the analyzer.

## Requirements

- Python 3.10 or newer
- pip
- Matplotlib

## Installation

Clone the repository and enter the project directory:

```bash
git clone YOUR_REPOSITORY_URL
cd wifi-log-analyzer
```

Install the required Python package:

```bash
python3 -m pip install -r requirements.txt
```

If your Linux environment restricts system-wide pip installations,
create and activate a virtual environment first:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Running the Analyzer

Run the default log file:

```bash
python3 wifi_analyzer.py
```

Specify another log file:

```bash
python3 wifi_analyzer.py --log-file logs/wifi.log
```

Choose a different report location:

```bash
python3 wifi_analyzer.py \
  --report-file reports/custom_report.txt
```

Adjust the traffic spike multiplier:

```bash
python3 wifi_analyzer.py --spike-threshold 2.0
```

Adjust the minimum event count for a spike alert:

```bash
python3 wifi_analyzer.py --min-spike-events 3
```

Adjust the authentication failure alert threshold:

```bash
python3 wifi_analyzer.py --auth-threshold 2
```

View all available options:

```bash
python3 wifi_analyzer.py --help
```

## Output Files

The analyzer generates the following files relative to the selected
report location:

- `network_report.txt` — Human-readable analysis summary.
- `error_details.csv` — Individual error records.
- `hourly_activity.csv` — Event counts organized by hour.
- `charts/error_categories.png` — Errors grouped by category.
- `charts/hourly_activity.png` — Logged event activity over time.

## Running Tests

Run the automated test suite:

```bash
python3 -m unittest discover -s tests -v
```

Check Python syntax:

```bash
python3 -m py_compile wifi_analyzer.py
```

## How the Analysis Works

The analyzer parses timestamps and severity levels, validates IPv4
addresses, categorizes errors, and counts activity by hour.

Traffic spike detection compares an hour's event count with the
median of other recorded hours. Activity trend analysis compares
average event counts across two periods.

These methods identify patterns that may deserve further investigation.
They do not independently confirm a cyberattack or measure actual
network bandwidth.

## Limitations

- Results depend on the format and completeness of the input logs.
- The tool analyzes recorded events, not actual network throughput.
- An unusual event pattern is not proof of malicious activity.
- The included sample logs are simulated test data.
- The tool does not directly monitor a router or capture live traffic.

## Future Improvements

Potential improvements include support for additional log formats,
more advanced anomaly detection, configurable alert rules, and
integration with real network logging sources.

## Author

Isaiah Williams

Computing graduate interested in IT support, Linux administration,
networking, and cybersecurity.
