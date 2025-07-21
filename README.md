# Masscan Web Scanner

High-speed, modularized port scanning with automated HTML fetching and screenshotting for exposed web services.  
Now supports **IPv6**, **range splitting**, and **parallel execution** across IP spaces.

This tool is built for security analysts and automation enthusiasts who want not just open ports, but also **visual** and **HTML-based insights** into exposed services — for both IPv4 and IPv6.

> ⚠️ This code was assembled and partially generated with AI assistance. Use at your own risk!

---

## 🧭 What it does

1. **Parallel Masscan scans** across multiple IPv4 and IPv6 ranges.
2. **Automatic IPv6 range splitting** to bypass Masscan limitations.
3. **Parses** Masscan output to identify open ports.
4. **Fetches HTML** and **screenshots** from web services via MechanicalSoup + Selenium.
5. **Organizes output** into a timestamped directory structure:
   ```
   Masscan_WebScanner_YYYYMMDD_HHMMSS/
   ├── logs/
   │   ├── masscan.log        # raw scan logs
   │   └── errors.log         # errors and timeouts
   ├── output/
   │   ├── *.lst              # raw scan output
   │   └── *_summary.txt      # parsed summaries
   └── html/
       └── <IP>/              # one directory per IP
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
  [--max-ipv6-bits 32] \
  [--dry-run]
```

### Parameters

- `--ranges` / `-r`: Path to a file with IP ranges (one per line, supports IPv4 and IPv6)
- `--ports` / `-p`: Comma-separated list of ports to scan (e.g. `80,443`)
- `--timeout` / `-t`: Timeout in seconds for page fetch and screenshot (default: `2`)
- `--rate` / `-R`: Packet rate limit for Masscan (default: `1000`)
- `--max-ipv6-bits`: Max number of host bits for IPv6 before auto-splitting (default: `32`)
- `--dry-run`: Simulate scans without executing Masscan

---

## 📦 Requirements

- **Python** ≥ 3.8
- **System tools**:
  - `masscan` (tested v1.3.2)
  - `chromium` or `google-chrome`
  - `chromedriver` matching your browser version
- **Python packages**:
  - `mechanicalsoup` ≥ 0.12.0
  - `selenium` ≥ 4.0.0
  - `beautifulsoup4` ≥ 4.9.0
  - `urllib3` ≥ 1.26.0

### Install dependencies

```bash
pip install mechanicalsoup selenium beautifulsoup4 urllib3
```

```bash
sudo apt update && sudo apt install masscan chromium chromium-driver
```

---

## 📝 Software Bill of Materials (SBOM)

| Component         | Version      |
|------------------|--------------|
| masscan           | v1.3.2       |
| chromium/chrome   | system pkg   |
| chromedriver      | system pkg   |
| mechanicalsoup    | ≥ 0.12.0     |
| selenium          | ≥ 4.0.0      |
| beautifulsoup4    | ≥ 4.9.0      |
| urllib3           | ≥ 1.26.0     |

---

## 💡 Notes

- IPv6 support requires appropriate system and network configuration.
- Screenshots are taken with a headless browser; ensure `chromedriver` version matches your browser.
- Temporary `.lst` files for split ranges are auto-deleted after merging.
