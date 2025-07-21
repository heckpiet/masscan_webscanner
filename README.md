# Masscan Web Scanner

High-speed, parallelized port scanning with automated HTML fetching and screenshotting for discovered web services.

This tool is built for security analysts and automation enthusiasts who want not just open ports, but also visual and HTML-based insights into exposed web services across many hosts.

# Info 
This Code is written a glued with AI
Use on your own risk!

---

## 🧭 What it does

1. **Parallel Masscan scans** multiple IP ranges simultaneously.
2. **Parses** Masscan output to identify open HTTP/HTTPS ports.
3. **Fetches HTML** and **screenshots** of discovered services via MechanicalSoup and Selenium.
4. **Organizes** all output into a timestamped root directory:
   ```
   Masscan_WebScanner_YYYYMMDD_HHMMSS/
   ├── logs/
   │   ├── masscan.log       # masscan stdout logs
   │   └── errors.log        # fetch errors and warnings
   ├── output/
   │   ├── *.lst             # raw masscan output files
   │   └── *_summary.txt     # parsed summaries of open ports
   └── html/
       └── <IP>/             # directory per scanned IP
           ├── <IP>_page_<port>_<timestamp>.html
           └── <IP>_screenshot_<port>_<timestamp>.png
   ```

---

## 🚀 Usage

```bash
python3 masscan_webscanner.py \
  --ranges ranges.txt \
  --ports 80,443 \
  [--timeout 3] \
  [--rate 5000] \
  [--dry-run]
```

- **--ranges** / **-r**: File containing IP ranges (CIDR), one per line.
- **--ports** / **-p**: Comma-separated list of ports to scan (e.g., `80,443`).
- **--timeout** / **-t**: Timeout (seconds) for page fetch and screenshot (default: 2).
- **--rate** / **-R**: Rate limit for Masscan packets per second (default: 1000).
- **--dry-run**: Simulate scans without executing Masscan.

---

## 📦 Requirements

- **Python** ≥ 3.8
- **System tools**:
  - `masscan` (tested v1.3.2)
  - `chromium` or `google-chrome`
  - `chromedriver` matching the installed browser version
- **Python libraries**:
  - `mechanicalsoup` ≥ 0.12.0
  - `selenium` ≥ 4.0.0
  - `beautifulsoup4` ≥ 4.9.0
  - `urllib3` ≥ 1.26.0

Install Python dependencies:

```bash
pip install mechanicalsoup selenium beautifulsoup4 urllib3
```

Install system packages on Debian/Ubuntu:

```bash
sudo apt update && sudo apt install masscan chromium chromium-driver
```

---

## 📝 Software Bill of Materials (SBOM)

- **masscan** v1.3.2
- **chromium** / **google-chrome** system package
- **chromedriver** system package
- **mechanicalsoup** ≥ 0.12.0
- **selenium** ≥ 4.0.0
- **beautifulsoup4** ≥ 4.9.0
- **urllib3** ≥ 1.26.0

