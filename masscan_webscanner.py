#!/usr/bin/env python3
"""Discover web services with masscan and archive their HTML and screenshots."""

from __future__ import annotations

import argparse
import ipaddress
import itertools
import json
import logging
import shutil
import subprocess
import sys
from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOGGER = logging.getLogger("masscan_webscanner")
DEFAULT_BROWSERS = ("chromium", "chromium-browser", "google-chrome", "chrome")
HTTPS_PORTS = frozenset({443, 8443, 9443})


@dataclass(frozen=True)
class AppConfig:
    ranges_file: Path
    ports: str
    output_dir: Path
    timeout: float = 5.0
    rate: int = 1_000
    scan_workers: int = 4
    fetch_workers: int = 8
    max_ipv6_host_bits: int = 32
    dry_run: bool = False
    skip_fetch: bool = False
    screenshots: bool = False
    verify_tls: bool = False
    max_html_bytes: int = 5_000_000
    masscan: str = "masscan"
    browser: str | None = None


def parse_args(argv: Sequence[str] | None = None) -> AppConfig:
    parser = argparse.ArgumentParser(description="Scan authorized IP ranges and archive discovered web services.")
    parser.add_argument("--ranges", "-r", required=True, type=Path)
    parser.add_argument("--ports", "-p", required=True, help="masscan port expression, e.g. 80,443,8000-8100")
    parser.add_argument("--output-dir", "-o", type=Path, help="output root (default: timestamped directory)")
    parser.add_argument("--timeout", "-t", type=float, default=5.0)
    parser.add_argument("--rate", "-R", type=int, default=1_000, help="global packet rate shared by scan workers")
    parser.add_argument("--scan-workers", type=int, default=4)
    parser.add_argument("--fetch-workers", type=int, default=8)
    parser.add_argument("--max-ipv6-host-bits", "--max-ipv6-bits", dest="max_ipv6_host_bits", type=int, default=32)
    parser.add_argument("--masscan", default="masscan", help="masscan executable path")
    parser.add_argument("--browser", help="Chrome/Chromium executable path")
    parser.add_argument("--skip-fetch", action="store_true", help="only scan and create summaries")
    parser.add_argument(
        "--screenshots", action="store_true", help="opt in to browser screenshots (may load external resources)"
    )
    parser.add_argument("--verify-tls", action="store_true", help="verify HTTPS certificates while fetching HTML")
    parser.add_argument("--max-html-bytes", type=int, default=5_000_000, help="maximum HTML bytes stored per endpoint")
    parser.add_argument("--dry-run", action="store_true", help="validate and print planned scans only")
    ns = parser.parse_args(argv)

    for name in ("timeout", "rate", "scan_workers", "fetch_workers", "max_html_bytes"):
        if getattr(ns, name) <= 0:
            parser.error(f"--{name.replace('_', '-')} must be greater than zero")
    if not 1 <= ns.max_ipv6_host_bits <= 63:
        parser.error("--max-ipv6-host-bits must be between 1 and 63")
    if "U:" in ns.ports.upper():
        parser.error("UDP port expressions are not supported; web retrieval requires TCP")

    if ns.skip_fetch and ns.screenshots:
        parser.error("--screenshots cannot be combined with --skip-fetch")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    return AppConfig(
        ranges_file=ns.ranges,
        ports=ns.ports,
        output_dir=ns.output_dir or Path(f"Masscan_WebScanner_{timestamp}"),
        timeout=ns.timeout,
        rate=ns.rate,
        scan_workers=ns.scan_workers,
        fetch_workers=ns.fetch_workers,
        max_ipv6_host_bits=ns.max_ipv6_host_bits,
        dry_run=ns.dry_run,
        skip_fetch=ns.skip_fetch,
        screenshots=ns.screenshots,
        verify_tls=ns.verify_tls,
        max_html_bytes=ns.max_html_bytes,
        masscan=ns.masscan,
        browser=ns.browser,
    )


def load_ranges(path: Path) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Read, validate and de-duplicate CIDRs; comments and blank lines are ignored."""
    if not path.is_file():
        raise ValueError(f"ranges file does not exist: {path}")
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    seen: set[str] = set()
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        value = raw_line.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError(f"{path}:{line_number}: invalid network {value!r}: {exc}") from exc
        canonical = str(network)
        if canonical not in seen:
            networks.append(network)
            seen.add(canonical)
    if not networks:
        raise ValueError(f"ranges file contains no networks: {path}")
    return networks


def expand_network(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network, max_ipv6_host_bits: int
) -> Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Lazily split large IPv6 networks so their host part stays bounded."""
    if network.version == 6 and (128 - network.prefixlen) > max_ipv6_host_bits:
        yield from network.subnets(new_prefix=128 - max_ipv6_host_bits)
    else:
        yield network


def setup_output(root: Path) -> dict[str, Path]:
    directories = {name: root / name for name in ("logs", "output", "html")}
    for directory in directories.values():
        directory.mkdir(parents=True, exist_ok=True)
    return directories


def setup_logging(log_dir: Path) -> None:
    log_format = "%(asctime)s | %(levelname)-8s | %(message)s"
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    info_handler = RotatingFileHandler(log_dir / "scanner.log", maxBytes=5_000_000, backupCount=3)
    error_handler = RotatingFileHandler(log_dir / "errors.log", maxBytes=1_000_000, backupCount=2)
    error_handler.setLevel(logging.WARNING)
    handlers.extend((info_handler, error_handler))
    logging.basicConfig(level=logging.INFO, format=log_format, handlers=handlers, force=True)


def find_browser(explicit: str | None = None) -> str | None:
    if explicit:
        path = shutil.which(explicit) or (explicit if Path(explicit).is_file() else None)
        return str(path) if path else None
    return next((path for name in DEFAULT_BROWSERS if (path := shutil.which(name))), None)


def require_dependencies(config: AppConfig) -> str | None:
    """Check only dependencies needed for the selected execution mode."""
    if config.dry_run:
        return None
    if not (shutil.which(config.masscan) or Path(config.masscan).is_file()):
        raise RuntimeError(f"masscan executable not found: {config.masscan}")
    if config.skip_fetch or not config.screenshots:
        return None
    browser = find_browser(config.browser)
    if not browser:
        raise RuntimeError("Chrome/Chromium not found; install it or use --browser/--skip-fetch")
    return browser


def safe_name(value: str) -> str:
    return value.replace(".", "_").replace(":", "_").replace("/", "_")


def run_scan(network: str, index: int, config: AppConfig, output_dir: Path, worker_rate: int) -> Path | None:
    output_file = output_dir / f"range_{index:04d}_{safe_name(network)}.lst"
    command = [config.masscan, network, "-p", config.ports, "--rate", str(worker_rate), "-oL", str(output_file)]
    if config.dry_run:
        LOGGER.info("DRY RUN: %s", " ".join(command))
        return None
    LOGGER.info("Scanning %s", network)
    subprocess.run(command, check=True, capture_output=True, text=True)
    return output_file


def parse_masscan(list_file: Path, summary_dir: Path) -> list[tuple[str, int]]:
    targets: set[tuple[str, int]] = set()
    for line in list_file.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "open":
            if parts[1].lower() != "tcp":
                LOGGER.warning("Ignoring non-TCP masscan line: %s", line)
                continue
            try:
                targets.add((str(ipaddress.ip_address(parts[3])), int(parts[2].split("/", 1)[0])))
            except ValueError:
                LOGGER.warning("Ignoring malformed masscan line: %s", line)
    ordered = sorted(
        targets,
        key=lambda item: (
            ipaddress.ip_address(item[0]).version,
            int(ipaddress.ip_address(item[0])),
            item[1],
        ),
    )
    summary = summary_dir / f"{list_file.stem}_summary.txt"
    summary.write_text("".join(f"{ip}: open port {port}\n" for ip, port in ordered), encoding="utf-8")
    return ordered


def target_url(ip: str, port: int) -> str:
    host = f"[{ip}]" if ipaddress.ip_address(ip).version == 6 else ip
    scheme = "https" if port in HTTPS_PORTS else "http"
    return f"{scheme}://{host}:{port}"


def fetch_target(
    target: tuple[str, int], html_dir: Path, config: AppConfig, browser_exec: str | None
) -> tuple[tuple[str, int], bool, str | None]:
    import requests

    ip, port = target
    url = target_url(ip, port)
    host_dir = html_dir / safe_name(ip)
    host_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{safe_name(ip)}_{port}"
    try:
        with requests.Session() as session:
            session.trust_env = False
            with session.get(
                url,
                timeout=config.timeout,
                verify=config.verify_tls,
                allow_redirects=False,
                stream=True,
                headers={"User-Agent": "masscan-webscanner/2"},
            ) as response:
                response.raise_for_status()
                html_file = host_dir / f"{stem}.html"
                written = 0
                with html_file.open("wb") as handle:
                    for chunk in response.iter_content(chunk_size=65_536):
                        written += len(chunk)
                        if written > config.max_html_bytes:
                            raise ValueError(f"response exceeds --max-html-bytes={config.max_html_bytes}")
                        handle.write(chunk)

        if config.screenshots and browser_exec:
            capture_screenshot(url, host_dir / f"{stem}.png", browser_exec, config)
        return target, True, None
    except Exception as exc:  # Network/browser failures are isolated per target.
        LOGGER.warning("Could not archive %s: %s", url, exc)
        (host_dir / f"{stem}.html").unlink(missing_ok=True)
        return target, False, str(exc)


def capture_screenshot(url: str, destination: Path, browser_exec: str, config: AppConfig) -> None:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options

    options = Options()
    options.binary_location = browser_exec
    chrome_arguments = ["--headless=new", "--disable-gpu", "--window-size=1920,1080"]
    if not config.verify_tls:
        chrome_arguments.append("--ignore-certificate-errors")
    for option in chrome_arguments:
        options.add_argument(option)
    driver = webdriver.Chrome(options=options)
    try:
        driver.set_page_load_timeout(config.timeout)
        driver.get(url)
        driver.save_screenshot(str(destination))
    finally:
        driver.quit()


def write_run_summary(
    root: Path,
    *,
    scan_succeeded: int,
    scan_failed: int,
    targets: set[tuple[str, int]],
    fetch_attempted: int,
    fetch_failed: list[tuple[tuple[str, int], str]],
) -> None:
    payload = {
        "scan_jobs": {"succeeded": scan_succeeded, "failed": scan_failed},
        "endpoints_discovered": len(targets),
        "fetches": {
            "attempted": fetch_attempted,
            "succeeded": fetch_attempted - len(fetch_failed),
            "failed": len(fetch_failed),
            "skipped": len(targets) - fetch_attempted,
        },
        "fetch_failures": [{"ip": target[0], "port": target[1], "error": error} for target, error in fetch_failed],
    }
    (root / "run-summary.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def run(config: AppConfig) -> int:
    networks = load_ranges(config.ranges_file)
    directories = setup_output(config.output_dir)
    setup_logging(directories["logs"])
    browser = require_dependencies(config)
    expanded = (str(subnet) for network in networks for subnet in expand_network(network, config.max_ipv6_host_bits))
    targets: set[tuple[str, int]] = set()
    scan_succeeded = 0
    scan_failed = 0
    fetch_failed: list[tuple[tuple[str, int], str]] = []
    indexed_networks = enumerate(expanded, 1)
    # Bound each submission batch so broad IPv6 scopes do not create an in-memory
    # future for every subnet. The generator itself remains lazy between batches.
    while batch := list(itertools.islice(indexed_networks, config.scan_workers * 4)):
        active_workers = min(config.scan_workers, len(batch), config.rate)
        worker_rate = max(1, config.rate // active_workers)
        LOGGER.info(
            "Scan batch: %d workers at %d packets/s each (global limit %d)", active_workers, worker_rate, config.rate
        )
        with ThreadPoolExecutor(max_workers=active_workers) as executor:
            futures = {
                executor.submit(run_scan, network, index, config, directories["output"], worker_rate): network
                for index, network in batch
            }
            for future in as_completed(futures):
                try:
                    output_file = future.result()
                    if output_file:
                        targets.update(parse_masscan(output_file, directories["output"]))
                        scan_succeeded += 1
                except subprocess.CalledProcessError as exc:
                    scan_failed += 1
                    LOGGER.error("Scan failed for %s: %s", futures[future], exc.stderr or exc)
    if not config.skip_fetch and targets:
        with ThreadPoolExecutor(max_workers=config.fetch_workers) as executor:
            results = executor.map(lambda target: fetch_target(target, directories["html"], config, browser), targets)
            fetch_failed = [(target, error or "unknown error") for target, ok, error in results if not ok]
    write_run_summary(
        config.output_dir,
        scan_succeeded=scan_succeeded,
        scan_failed=scan_failed,
        targets=targets,
        fetch_attempted=0 if config.skip_fetch else len(targets),
        fetch_failed=fetch_failed,
    )
    LOGGER.info(
        "Completed: %d endpoints, %d scan failures, %d fetch failures",
        len(targets),
        scan_failed,
        len(fetch_failed),
    )
    return 1 if scan_failed or fetch_failed else 0


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return run(parse_args(argv))
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
