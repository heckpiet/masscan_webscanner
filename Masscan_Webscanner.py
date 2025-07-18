#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Masscan Webscanner – Parallelized Scanning and Fetching
------------------------------------------------------

This tool performs:
1. Parallel Masscan scanning for multiple IP ranges.
2. Parsing of Masscan output to identify open ports.
3. Parallel fetching of HTML and screenshots via Selenium.
4. Organized output in a timestamped root directory:
   - logs/
     - masscan.log      # raw scan logs
     - errors.log       # fetch errors
   - output/
     - *.lst            # individual scan results
     - *_summary.txt    # parsed summaries
   - html/
     - <IP>/            # per-IP directories
       - <IP>_html_<port>_<timestamp>.html
       - <IP>_screenshot_<port>_<timestamp>.png

Prerequisites:
- Python 3.8+
- masscan
- Chromium or Google Chrome
- chromedriver matching browser version
- Python packages: mechanicalsoup, selenium, beautifulsoup4, urllib3

Software Bill of Materials (SBOM):
- masscan v1.3.2
- chromium/chrome system package
- chromedriver system package
- mechanicalsoup >= 0.12.0
- selenium >= 4.0.0
- beautifulsoup4 >= 4.9.0
- urllib3 >= 1.26.0
"""

import os
import sys
import shutil
import subprocess
import argparse
import logging
import warnings
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed

import mechanicalsoup
import urllib3
from bs4 import XMLParsedAsHTMLWarning
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service as ChromeService

# Suppress XMLParsedAsHTMLWarning from BeautifulSoup
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
# Disable warnings for insecure HTTPS certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Browser and driver executable candidates
BROWSER_CANDIDATES = ["chromium", "chromium-browser", "google-chrome", "chrome"]
DRIVER_PATHS = ["/usr/bin/chromedriver", "/usr/local/bin/chromedriver"]

# Parse command-line arguments
parser = argparse.ArgumentParser(description='Masscan Webscanner')
parser.add_argument('--ranges', required=True, help='File containing IP ranges, one per line')
parser.add_argument('--ports', required=True, help='Ports to scan, e.g. 80,443')
parser.add_argument('--dry-run', action='store_true', help='Perform a dry-run without executing Masscan')
args = parser.parse_args()

# Create root directory for this scan run
scan_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
ROOT_DIR = f"Masscan_Webscanner_{scan_timestamp}"
LOG_DIR = os.path.join(ROOT_DIR, 'logs')
OUTPUT_DIR = os.path.join(ROOT_DIR, 'output')
HTML_DIR = os.path.join(ROOT_DIR, 'html')

# Create directory structure
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(HTML_DIR, exist_ok=True)

# Configure logging to file and stdout
log_file = os.path.join(LOG_DIR, 'masscan.log')
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def find_executable(names):
    """Return the first available executable from a list of names."""
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    return None

def check_dependencies():
    """Ensure required external tools are available."""
    logger.info("Checking external dependencies...")
    if not shutil.which("masscan"):
        logger.error("masscan not found. Install it via: sudo apt install masscan")
        sys.exit(1)
    browser_exec = find_executable(BROWSER_CANDIDATES)
    if not browser_exec:
        logger.error("Chromium/Chrome browser not found. Install chromium or google-chrome.")
        sys.exit(1)
    driver_exec = next((p for p in DRIVER_PATHS if os.path.isfile(p) and os.access(p, os.X_OK)), None)
    if not driver_exec:
        logger.error("chromedriver not found. Install the chromium-driver package.")
        sys.exit(1)
    logger.info(f"Using browser: {browser_exec}, driver: {driver_exec}")
    return browser_exec, driver_exec

def run_masscan(ip_range: str, ports: str, prefix: str) -> str:
    """Run masscan on the specified range and return the .lst filepath."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    lst_path = os.path.join(OUTPUT_DIR, f"{prefix}_{timestamp}.lst")
    cmd = ["sudo", "masscan", ip_range, "-p", ports, "--rate", "1000", "-oL", lst_path]
    logger.info(f"Executing masscan for {ip_range}: output -> {lst_path}")
    if args.dry_run:
        logger.info(f"[Dry-run] Would generate: {lst_path}")
        return lst_path
    try:
        subprocess.run(cmd, check=True)
        logger.info(f"Masscan completed: {lst_path}")
    except subprocess.CalledProcessError as exc:
        logger.error(f"Masscan failed with error: {exc}")
        sys.exit(1)
    return lst_path

def parse_masscan_output(lst_file: str) -> list[tuple[str,int]]:
    """Parse the Masscan .lst file, write a summary, and return a list of (IP, port)."""
    hosts = defaultdict(list)
    with open(lst_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if parts[0] == 'open' and len(parts) >= 4:
                ip = parts[3]
                port = parts[2].split('/')[0]
                hosts[ip].append(port)
    # Write summary
    summary_base = os.path.basename(lst_file).replace('.lst', '')
    summary_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    summary_path = os.path.join(
        OUTPUT_DIR,
        f"{summary_base}_{summary_ts}_summary.txt"
    )
    with open(summary_path, 'w') as sf:
        sf.write(f"Scan Time: {datetime.now()}\nSource File: {lst_file}\n\n")
        for ip, ports in hosts.items():
            sf.write(f"{ip}: open ports -> {', '.join(sorted(ports, key=int))}\n")
    logger.info(f"Parsed summary saved: {summary_path}")
    return [(ip, int(port)) for ip, ports in hosts.items() for port in ports]

def fetch_target(target, browser_exec, driver_exec):
    """Fetch HTML and screenshot for a single (ip, port) target."""
    ip, port = target
    proto = 'https' if port == 443 else 'http'
    url = f"{proto}://{ip}:{port}"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ip_folder = os.path.join(HTML_DIR, ip.replace('.', '_'))
    os.makedirs(ip_folder, exist_ok=True)
    html_path = os.path.join(ip_folder, f"{ip.replace('.', '_')}_html_{port}_{ts}.html")
    png_path = os.path.join(ip_folder, f"{ip.replace('.', '_')}_screenshot_{port}_{ts}.png")
    error_log = os.path.join(LOG_DIR, 'errors.log')
    try:
        logger.info(f"Fetching URL: {url}")
        browser = mechanicalsoup.StatefulBrowser()
        browser.session.verify = False
        browser.open(url)
        with open(html_path, 'w', encoding='utf-8') as hf:
            hf.write(browser.get_current_page().prettify())
        chrome_opts = Options()
        chrome_opts.binary_location = browser_exec
        for opt in ['--headless','--disable-gpu','--no-sandbox','--ignore-certificate-errors','--window-size=1920,1080']:
            chrome_opts.add_argument(opt)
        service = ChromeService(executable_path=driver_exec)
        driver = webdriver.Chrome(service=service, options=chrome_opts)
        driver.get(url)
        driver.save_screenshot(png_path)
        driver.quit()
    except Exception as e:
        msg = f"Error fetching {url}: {e}"
        logger.warning(msg)
        with open(error_log, 'a') as elog:
            elog.write(msg + '\n')

def main():
    browser_exec, driver_exec = check_dependencies()

    # Parallel Masscan scans
    with ProcessPoolExecutor() as proc_pool:
        ranges = [r.strip() for r in open(args.ranges) if r.strip() and not r.startswith('#')]
        tasks = [(r, args.ports, f"scan_{i}") for i, r in enumerate(ranges)]
        futures = [proc_pool.submit(run_masscan, *t) for t in tasks]
        all_targets = []
        for fut in as_completed(futures):
            lst_file = fut.result()
            all_targets.extend(parse_masscan_output(lst_file))

    # Parallel web fetching
    with ThreadPoolExecutor(max_workers=8) as thread_pool:
        for _ in thread_pool.map(lambda tgt: fetch_target(tgt, browser_exec, driver_exec), all_targets):
            pass

    duration = datetime.now() - datetime.strptime(scan_timestamp, "%Y%m%d_%H%M%S")
    msg = f"Scan completed: {len(all_targets)} services in {duration}"
    logger.info(msg)
    print(msg)

if __name__ == '__main__':
    main()
