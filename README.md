# Masscan Webscanner

High-speed parallelized port scanner with automated HTML fetching and screenshotting for discovered web services.

## 🧭 What it does

This tool scans large IP ranges for open HTTP/HTTPS services using [masscan], and automatically fetches and screenshots the web interfaces using [MechanicalSoup] and [Selenium].

It's designed to give you quick visual and HTML-based insights into exposed web services across many hosts.

## ⚙️ Features

- ⚡ **Fast Scanning** – Parallel execution of `masscan` for multiple ranges.
- 🕵️ **Web Visibility** – Captures full HTML and screenshots of discovered HTTP/HTTPS ports.
- 🗂 **Organized Output** – Results are sorted into timestamped directories:
  ```
  Masscan_Webscanner_YYYYMMDD_HHMMSS/
    ├── logs/
    │   ├── masscan.log
    │   └── errors.log
    ├── output/
    │   ├── *.lst
    │   └── *_summary.txt
    └── html/
        └── <IP>/
            ├── <IP>_html_<port>_<timestamp>.html
            └── <IP>_screenshot_<port>_<timestamp>.png
  ```

## 🚀 How to use

```bash
python3 masscan_webscanner.py --ranges ranges.txt --ports 80,443
```

**Optional:**
Use `--dry-run` to simulate the scan without executing `masscan`.

## 📦 Requirements

- Python ≥ 3.8
- System tools:
  - `masscan`
  - `chromium` or `google-chrome`
  - `chromedriver` (matching the installed browser version)
- Python packages:
  - `mechanicalsoup`
  - `selenium`
  - `beautifulsoup4`
  - `urllib3`

You can install the required Python libraries via:

```bash
pip install mechanicalsoup selenium beautifulsoup4 urllib3
```

Install required system packages (example for Debian/Ubuntu):

```bash
sudo apt install masscan chromium chromium-driver
```

## 📋 Software Bill of Materials (SBOM)

- `masscan` v1.3.2+
- `chromium` or `google-chrome` system package
- `chromedriver` system package
- `mechanicalsoup >= 0.12.0`
- `selenium >= 4.0.0`
- `beautifulsoup4 >= 4.9.0`
- `urllib3 >= 1.26.0`

---

Made for security analysts and automation lovers who want more than just open ports — get content, screenshots, and context.
