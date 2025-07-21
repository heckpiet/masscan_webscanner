#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Masscan Web Scanner – Parallelized Scanning and Fetching
--------------------------------------------------------

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
       - <IP>_page_<port>_<timestamp>.html
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
import sys
import shutil
import subprocess
import argparse
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Optional, Dict
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed

import mechanicalsoup
import urllib3
from bs4 import XMLParsedAsHTMLWarning
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.common.exceptions import TimeoutException

# Suppress XML parsing and certificate warnings
import warnings
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Default possible browser and driver executables
DEFAULT_BROWSERS = ["chromium", "chromium-browser", "google-chrome", "chrome"]
DEFAULT_DRIVERS = ["/usr/bin/chromedriver", "/usr/local/bin/chromedriver"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Modular Masscan-based web scanner'
    )
    parser.add_argument(
        '--ranges', '-r', required=True,
        help='File with IP ranges, one per line'
    )
    parser.add_argument(
        '--ports', '-p', required=True,
        help='Ports to scan, e.g. "80,443"'
    )
    parser.add_argument(
        '--timeout', '-t', type=int, default=2,
        help='Page fetch and screenshot timeout in seconds'
    )
    parser.add_argument(
        '--rate', '-R', type=int, default=1000,
        help='Rate limit for masscan'
    )
    parser.add_argument(
        '--dry-run', action='store_true',
        help='Perform a dry run without executing masscan'
    )
    return parser.parse_args()


def setup_directories(base_name: str) -> Dict[str, Path]:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    root = Path(f"{base_name}_{timestamp}")
    dirs = {key: root / key for key in ['logs', 'output', 'html']}
    dirs['root'] = root
    for path in dirs.values():
        path.mkdir(parents=True, exist_ok=True)
    return dirs


def setup_logging(log_dir: Path) -> None:
    log_format = "%(asctime)s | %(name)-12s | %(levelname)-8s | %(message)s"
    logging.basicConfig(level=logging.INFO, format=log_format)
    info_handler = RotatingFileHandler(
        log_dir / 'masscan.log', maxBytes=5_000_000, backupCount=3
    )
    info_handler.setFormatter(logging.Formatter(log_format))
    logging.getLogger().addHandler(info_handler)
    error_handler = RotatingFileHandler(
        log_dir / 'errors.log', maxBytes=1_000_000, backupCount=2
    )
    error_handler.setLevel(logging.WARNING)
    error_handler.setFormatter(logging.Formatter(log_format))
    logging.getLogger().addHandler(error_handler)


class DependencyChecker:
    """Check for required executables: masscan, browser, driver"""

    @staticmethod
    def find_executable(names: List[str]) -> Optional[str]:
        for name in names:
            path = shutil.which(name)
            if path:
                return path
        return None

    @classmethod
    def check(cls, rate: int) -> Tuple[str, str, int]:
        logging.info("Checking external dependencies...")
        if not shutil.which("masscan"):
            logging.error("masscan not found. Please install masscan.")
            sys.exit(1)
        browser = cls.find_executable(DEFAULT_BROWSERS)
        if not browser:
            logging.error("No Chrome/Chromium browser found.")
            sys.exit(1)
        driver = next((p for p in DEFAULT_DRIVERS if Path(p).is_file()), None)
        if not driver:
            logging.error("Chromedriver not found.")
            sys.exit(1)
        logging.info(f"Browser: {browser}, Driver: {driver}, Rate: {rate}")
        return browser, driver, rate


class MasscanRunner:
    """Run masscan scans and write output to list files"""

    def __init__(
        self, output_dir: Path, dry_run: bool = False, rate: int = 1000
    ):
        self.output_dir = output_dir
        self.dry_run = dry_run
        self.rate = rate

    def run(self, ip_range: str, ports: str, prefix: str) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"{prefix}_{timestamp}.lst"
        cmd = [
            "sudo", "masscan", ip_range,
            "-p", ports,
            "--rate", str(self.rate),
            "-oL", str(output_file)
        ]
        logging.info(f"[{prefix}] Starting scan: {ip_range} on ports {ports} at {datetime.now()}")
        if self.dry_run:
            logging.info(f"[{prefix}] Dry run mode, would output to: {output_file}")
            return output_file
        try:
            result = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True
            )
            # Optionally log discovered entries
            for line in result.stdout.splitlines():
                if line.startswith('open'):
                    logging.info(f"[{prefix}] {line}")
            logging.info(f"[{prefix}] Scan completed, results saved to {output_file}")
        except subprocess.CalledProcessError as e:
            err = e.stderr.strip() if e.stderr else str(e)
            logging.error(f"[{prefix}] Masscan error: {err}")
        return output_file
        try:
            subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            logging.info(f"Scan completed: {output_file}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Masscan error: {e}")
            sys.exit(1)
        return output_file


class MasscanParser:
    """Parse masscan list output and summarize open ports per host"""

    @staticmethod
    def parse(list_file: Path, summary_dir: Path) -> List[Tuple[str, int]]:
        hosts: Dict[str, List[int]] = {}
        with list_file.open() as f:
            for line in f:
                if line.startswith('open'):
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    port_proto = parts[2]
                    ip = parts[3]
                    try:
                        port = int(port_proto.split('/')[0])
                    except ValueError:
                        continue
                    hosts.setdefault(ip, []).append(port)
        summary_file = summary_dir / f"{list_file.stem}_summary.txt"
        with summary_file.open('w') as out:
            out.write(f"Scan time: {datetime.now()}\nSource: {list_file}\n\n")
            for ip, ports in hosts.items():
                ports_str = ','.join(map(str, sorted(ports)))
                out.write(f"{ip}: open ports -> {ports_str}\n")
        logging.info(f"Summary saved: {summary_file}")
        return [(ip, port) for ip, ports in hosts.items() for port in ports]


class HTMLFetcher:
    """Fetch HTML and screenshots from web services on discovered ports"""

    def __init__(self, html_dir: Path, browser_exec: str, driver_exec: str, timeout: int = 2):
        self.html_dir = html_dir
        self.browser_exec = browser_exec
        self.driver_exec = driver_exec
        self.timeout = timeout

    def fetch(self, target: Tuple[str, int]) -> None:
        ip, port = target
        protocol = 'https' if port == 443 else 'http'
        url = f"{protocol}://{ip}:{port}"
        host_dir = self.html_dir / ip.replace('.', '_')
        host_dir.mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_file = host_dir / f"{ip}_page_{port}_{ts}.html"
        screenshot_file = host_dir / f"{ip}_screenshot_{port}_{ts}.png"
        logging.info(f"Fetching URL: {url}")
        try:
            browser = mechanicalsoup.StatefulBrowser()
            browser.session.verify = False
            browser.open(url)
            html_file.write_text(browser.get_current_page().prettify(), encoding='utf-8')

            options = Options()
            options.binary_location = self.browser_exec
            opts = [
                '--headless',
                '--disable-gpu',
                '--no-sandbox',
                '--ignore-certificate-errors',
                '--window-size=1920,1080'
            ]
            for opt in opts:
                options.add_argument(opt)
            service = ChromeService(executable_path=self.driver_exec)
            driver = webdriver.Chrome(service=service, options=options)
            driver.set_page_load_timeout(self.timeout)
            try:
                driver.get(url)
                driver.save_screenshot(str(screenshot_file))
            except TimeoutException:
                logging.warning(f"Screenshot timeout for URL: {url}")
            finally:
                driver.quit()
        except Exception as e:
            logging.warning(f"Error fetching {url}: {e}")


def main() -> None:
    args = parse_args()
    dirs = setup_directories('Masscan_WebScanner')
    setup_logging(dirs['logs'])
    browser, driver, rate = DependencyChecker.check(args.rate)

    with open(args.ranges) as f:
        ranges = [line.strip() for line in f if line.strip()]

    scanner = MasscanRunner(dirs['output'], dry_run=args.dry_run, rate=rate)
    parser = MasscanParser()
    fetcher = HTMLFetcher(dirs['html'], browser, driver, timeout=args.timeout)

    # Run scans in parallel
    with ProcessPoolExecutor() as proc_exec:
        scan_futures = {proc_exec.submit(scanner.run, r, args.ports, f'range_{i}'): r for i, r in enumerate(ranges, 1)}
        for future in as_completed(scan_futures):
            prefix = list(scan_futures.keys())[list(scan_futures.values()).index(scan_futures[future])] if False else future  # placeholder
            list_file = future.result()
            targets = parser.parse(list_file, dirs['output'])
            # Log summary per range
            hosts = set(ip for ip, _ in targets)
            logging.info(f"Range scan {list_file.stem}: found {len(hosts)} hosts, {len(targets)} open ports")
            # Fetch HTML and screenshots in parallel
            with ThreadPoolExecutor() as thread_exec:
                fetch_futures = [thread_exec.submit(fetcher.fetch, t) for t in targets]
                for _ in as_completed(fetch_futures):
                    pass

if __name__ == '__main__':
    main()
