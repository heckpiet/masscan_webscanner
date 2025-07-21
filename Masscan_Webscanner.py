#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Masscan Web Scanner – Parallelized Scanning and Fetching with IPv6 Support
--------------------------------------------------------------------------
 
This tool performs:
1. Parallel Masscan scanning for multiple IP ranges (IPv4 and IPv6).
2. Automatic IPv6 range splitting when ranges exceed masscan limitations.
3. Parsing of Masscan output to identify open ports.
4. Parallel fetching of HTML and screenshots via Selenium.
5. Organized output in a timestamped root directory:
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
import ipaddress
 
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
        description='Modular Masscan-based web scanner with IPv6 support'
    )
    parser.add_argument(
        '--ranges', '-r', required=True,
        help='File with IP ranges, one per line (supports IPv4 and IPv6)'
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
    parser.add_argument(
        '--max-ipv6-bits', type=int, default=32,
        help='Maximum host bits for IPv6 ranges before splitting (default: 32)'
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
 
 
class IPv6RangeSplitter:
    """Handle IPv6 range splitting when ranges are too large for masscan"""
    
    def __init__(self, max_range_bits: int = 63, max_ipv6_bits: int = 32):
        self.max_range_bits = max_range_bits  # Masscan limitation
        self.max_ipv6_bits = max_ipv6_bits    # User-configurable limit
    
    def calculate_address_bits(self, network: str) -> int:
        """Calculate the number of address bits in a network"""
        try:
            net = ipaddress.ip_network(network, strict=False)
            if net.version == 6:
                return 128 - net.prefixlen
            else:
                return 32 - net.prefixlen
        except ValueError:
            return 0
    
    def is_range_too_large(self, network: str) -> bool:
        """Check if a range is too large for masscan"""
        address_bits = self.calculate_address_bits(network)
        return address_bits > self.max_range_bits
    
    def should_split_ipv6(self, network: str) -> bool:
        """Check if IPv6 range should be split based on user-defined limit"""
        try:
            net = ipaddress.ip_network(network, strict=False)
            if net.version != 6:
                return False
            address_bits = 128 - net.prefixlen
            return address_bits > self.max_ipv6_bits
        except ValueError:
            return False
    
    def split_ipv6_range(self, network: str) -> List[str]:
        """Split IPv6 ranges into smaller subnets"""
        try:
            net = ipaddress.ip_network(network, strict=False)
            if net.version != 6:
                return [network]
            
            address_bits = 128 - net.prefixlen
            
            if address_bits <= self.max_ipv6_bits:
                return [network]
            
            # Calculate new prefix length
            new_prefixlen = 128 - self.max_ipv6_bits
            subnets = list(net.subnets(new_prefix=new_prefixlen))
            
            logging.info(f"Splitting {network} into {len(subnets)} subnets")
            return [str(subnet) for subnet in subnets]
            
        except ValueError as e:
            logging.error(f"Error splitting range {network}: {e}")
            return [network]
    
    def process_range(self, network: str) -> List[str]:
        """Process a single range, splitting if necessary"""
        # Check if it's too large for masscan (hard limit)
        if self.is_range_too_large(network):
            logging.warning(f"Range {network} exceeds masscan limit, splitting...")
            return self.split_ipv6_range(network)
        
        # Check if it's IPv6 and should be split (user preference)
        if self.should_split_ipv6(network):
            logging.info(f"Splitting large IPv6 range {network}...")
            return self.split_ipv6_range(network)
        
        return [network]
 
 
class MasscanRunner:
    """Run masscan scans and write output to list files"""
 
    def __init__(
        self, output_dir: Path, dry_run: bool = False, rate: int = 1000, max_ipv6_bits: int = 32
    ):
        self.output_dir = output_dir
        self.dry_run = dry_run
        self.rate = rate
        self.splitter = IPv6RangeSplitter(max_ipv6_bits=max_ipv6_bits)
 
    def run_single_range(self, ip_range: str, ports: str, output_file: Path) -> None:
        """Run masscan on a single range"""
        cmd = [
            "sudo", "masscan", ip_range,
            "-p", ports,
            "--rate", str(self.rate),
            "-oL", str(output_file)
        ]
        
        if self.dry_run:
            logging.info(f"Dry run mode, would scan {ip_range}")
            return
            
        try:
            result = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True
            )
            # Log discovered entries
            open_count = 0
            for line in result.stdout.splitlines():
                if line.startswith('open'):
                    open_count += 1
            if open_count > 0:
                logging.info(f"Found {open_count} open ports in {ip_range}")
                
        except subprocess.CalledProcessError as e:
            err = e.stderr.strip() if e.stderr else str(e)
            logging.error(f"Masscan error for {ip_range}: {err}")
 
    def run(self, ip_range: str, ports: str, prefix: str) -> Path:
        """Run masscan scan with automatic IPv6 range splitting"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        main_output_file = self.output_dir / f"{prefix}_{timestamp}.lst"
        
        logging.info(f"[{prefix}] Starting scan: {ip_range} on ports {ports} at {datetime.now()}")
        
        # Process the range (split if necessary)
        ranges_to_scan = self.splitter.process_range(ip_range)
        
        if len(ranges_to_scan) > 1:
            logging.info(f"[{prefix}] Scanning {len(ranges_to_scan)} sub-ranges")
            
            # Create temporary files for each sub-range
            temp_files = []
            for i, sub_range in enumerate(ranges_to_scan):
                temp_file = self.output_dir / f"{prefix}_{timestamp}_part_{i+1}.lst"
                temp_files.append(temp_file)
                logging.info(f"[{prefix}] Scanning sub-range {i+1}/{len(ranges_to_scan)}: {sub_range}")
                self.run_single_range(sub_range, ports, temp_file)
            
            # Combine results into main output file
            if not self.dry_run:
                with main_output_file.open('w') as main_file:
                    main_file.write(f"# Combined results from {len(ranges_to_scan)} sub-ranges of {ip_range}\n")
                    main_file.write(f"# Scan completed at {datetime.now()}\n")
                    
                    for temp_file in temp_files:
                        if temp_file.exists():
                            with temp_file.open() as tf:
                                for line in tf:
                                    if not line.startswith('#'):
                                        main_file.write(line)
                            # Remove temporary file
                            temp_file.unlink()
        else:
            # Single range, scan directly
            self.run_single_range(ip_range, ports, main_output_file)
        
        logging.info(f"[{prefix}] Scan completed, results saved to {main_output_file}")
        return main_output_file
 
 
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
        
        # Handle IPv6 addresses in URLs
        if ':' in ip and not ip.startswith('['):
            url = f"{protocol}://[{ip}]:{port}"
        else:
            url = f"{protocol}://{ip}:{port}"
        
        # Create safe directory name for IPv6
        safe_ip = ip.replace('.', '_').replace(':', '_')
        host_dir = self.html_dir / safe_ip
        host_dir.mkdir(exist_ok=True)
        
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_file = host_dir / f"{safe_ip}_page_{port}_{ts}.html"
        screenshot_file = host_dir / f"{safe_ip}_screenshot_{port}_{ts}.png"
        
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
 
    logging.info(f"Starting scan with {len(ranges)} ranges, IPv6 max bits: {args.max_ipv6_bits}")
 
    scanner = MasscanRunner(
        dirs['output'], 
        dry_run=args.dry_run, 
        rate=rate,
        max_ipv6_bits=args.max_ipv6_bits
    )
    parser = MasscanParser()
    fetcher = HTMLFetcher(dirs['html'], browser, driver, timeout=args.timeout)
 
    # Run scans in parallel
    with ProcessPoolExecutor() as proc_exec:
        scan_futures = {
            proc_exec.submit(scanner.run, r, args.ports, f'range_{i}'): (r, i) 
            for i, r in enumerate(ranges, 1)
        }
        
        for future in as_completed(scan_futures):
            range_str, range_num = scan_futures[future]
            try:
                list_file = future.result()
                targets = parser.parse(list_file, dirs['output'])
                
                # Log summary per range
                hosts = set(ip for ip, _ in targets)
                logging.info(f"Range {range_num} ({range_str}): found {len(hosts)} hosts, {len(targets)} open ports")
                
                # Fetch HTML and screenshots in parallel
                if targets:
                    with ThreadPoolExecutor() as thread_exec:
                        fetch_futures = [thread_exec.submit(fetcher.fetch, t) for t in targets]
                        for _ in as_completed(fetch_futures):
                            pass
            except Exception as e:
                logging.error(f"Error processing range {range_str}: {e}")
 
    logging.info("Scan completed successfully")
 
 
if __name__ == '__main__':
    main()
