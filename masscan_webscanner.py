#!/usr/bin/env python3
"""Discover web services with masscan and archive their HTML and screenshots."""

from __future__ import annotations

import argparse
import importlib.util
import ipaddress
import itertools
import json
import logging
import os
import shutil
import subprocess
import sys
from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import NamedTuple

LOGGER = logging.getLogger("masscan_webscanner")
__version__ = "2.1.0"
DEFAULT_BROWSERS = ("chromium", "chromium-browser", "google-chrome", "chrome")
DEFAULT_CHROMEDRIVERS = ("chromedriver", "chromium-driver")
HTTPS_PORTS = frozenset({443, 8443, 9443})


class TargetScope(NamedTuple):
    targets: list[ipaddress.IPv4Network | ipaddress.IPv6Network]
    excludes: list[ipaddress.IPv4Network | ipaddress.IPv6Network]


@dataclass(frozen=True)
class AppConfig:
    ranges_file: Path
    ports: str
    output_dir: Path
    http_timeout: float = 5.0
    screenshot_timeout: float = 15.0
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
    use_sudo: bool = True


@dataclass(frozen=True)
class ArchiveResult:
    target: tuple[str, int]
    html_ok: bool
    html_error: str | None = None
    screenshot_attempted: bool = False
    screenshot_ok: bool = False
    screenshot_error: str | None = None

    @property
    def ok(self) -> bool:
        return self.html_ok and (not self.screenshot_attempted or self.screenshot_ok)


def parse_args(argv: Sequence[str] | None = None) -> AppConfig:
    parser = argparse.ArgumentParser(description="Scan authorized IP ranges and archive discovered web services.")
    parser.add_argument("--version", action="version", version=f"masscan-webscanner {__version__}")
    parser.add_argument("--ranges", "-r", required=True, type=Path)
    parser.add_argument("--ports", "-p", required=True, help="masscan port expression, e.g. 80,443,8000-8100")
    parser.add_argument("--output-dir", "-o", type=Path, help="output root (default: timestamped directory)")
    parser.add_argument("--http-timeout", type=float, default=5.0, help="HTTP request timeout in seconds")
    parser.add_argument("--screenshot-timeout", type=float, default=15.0, help="browser page-load timeout in seconds")
    parser.add_argument(
        "--timeout",
        "-t",
        dest="legacy_timeout",
        type=float,
        help="set both timeouts to one value (backward-compatible alias)",
    )
    parser.add_argument("--rate", "-R", type=int, default=1_000, help="global packet rate shared by scan workers")
    parser.add_argument("--scan-workers", type=int, default=4)
    parser.add_argument("--fetch-workers", type=int, default=8)
    parser.add_argument("--max-ipv6-host-bits", "--max-ipv6-bits", dest="max_ipv6_host_bits", type=int, default=32)
    parser.add_argument("--masscan", default="masscan", help="masscan executable path")
    parser.add_argument(
        "--no-sudo",
        action="store_true",
        help="run masscan directly (for capabilities or an already privileged account)",
    )
    parser.add_argument("--browser", help="Chrome/Chromium executable path")
    parser.add_argument("--skip-fetch", action="store_true", help="only scan and create summaries")
    parser.add_argument(
        "--screenshots", action="store_true", help="opt in to browser screenshots (may load external resources)"
    )
    parser.add_argument("--verify-tls", action="store_true", help="verify HTTPS certificates while fetching HTML")
    parser.add_argument("--max-html-bytes", type=int, default=5_000_000, help="maximum HTML bytes stored per endpoint")
    parser.add_argument("--dry-run", action="store_true", help="validate and print planned scans only")
    ns = parser.parse_args(argv)

    if ns.legacy_timeout is not None:
        ns.http_timeout = ns.legacy_timeout
        ns.screenshot_timeout = ns.legacy_timeout

    for name in ("http_timeout", "screenshot_timeout", "rate", "scan_workers", "fetch_workers", "max_html_bytes"):
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
        http_timeout=ns.http_timeout,
        screenshot_timeout=ns.screenshot_timeout,
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
        use_sudo=not ns.no_sudo,
    )


def parse_range_line(raw_line: str) -> tuple[bool, str]:
    """Parse a single line from a ranges file into (is_exclude, clean_value)."""
    value = raw_line.split("#", 1)[0].strip()
    if not value:
        return False, ""
    if value.startswith("!"):
        return True, value[1:].strip()
    if value.startswith("-"):
        return True, value[1:].strip()
    lower = value.lower()
    if lower.startswith("exclude:"):
        return True, value[len("exclude:") :].strip()
    if lower.startswith("exclude ") or lower.startswith("exclude\t"):
        return True, value[len("exclude") :].strip()
    return False, value


def is_excluded(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    excluded_networks: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    """Return True if ip falls within any excluded network."""
    return any(ip.version == network.version and ip in network for network in excluded_networks)


def load_ranges(path: Path) -> TargetScope:
    """Read, validate and de-duplicate target and optional exclude networks.

    Comments and blank lines are ignored.
    Exclusions start with '!', '-', or 'exclude:'/'exclude '.
    Individual host IPs are normalized to /32 or /128.
    """
    if not path.is_file():
        raise ValueError(f"ranges file does not exist: {path}")
    targets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    excludes: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    seen_targets: set[str] = set()
    seen_excludes: set[str] = set()
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        is_exclude, value = parse_range_line(raw_line)
        if not value:
            if is_exclude:
                raise ValueError(f"{path}:{line_number}: missing address in exclusion entry {raw_line.strip()!r}")
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            kind = "excluded network" if is_exclude else "network"
            raise ValueError(f"{path}:{line_number}: invalid {kind} {value!r}: {exc}") from exc
        canonical = str(network)
        if is_exclude:
            if canonical not in seen_excludes:
                excludes.append(network)
                seen_excludes.add(canonical)
        else:
            if canonical not in seen_targets:
                targets.append(network)
                seen_targets.add(canonical)
    if not targets:
        raise ValueError(f"ranges file contains no target networks: {path}")
    return TargetScope(targets=targets, excludes=excludes)


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
    class ConsoleFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            return not getattr(record, "file_only", False)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter("%(levelname)-7s | %(message)s"))
    console_handler.addFilter(ConsoleFilter())
    info_handler = RotatingFileHandler(log_dir / "scanner.log", maxBytes=5_000_000, backupCount=3)
    error_handler = RotatingFileHandler(log_dir / "errors.log", maxBytes=1_000_000, backupCount=2)
    file_formatter = logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s")
    info_handler.setFormatter(file_formatter)
    error_handler.setFormatter(file_formatter)
    error_handler.setLevel(logging.WARNING)
    logging.basicConfig(level=logging.INFO, handlers=[console_handler, info_handler, error_handler], force=True)


def configure_tls_warnings(config: AppConfig) -> None:
    if config.verify_tls:
        return
    from urllib3 import disable_warnings
    from urllib3.exceptions import InsecureRequestWarning

    disable_warnings(InsecureRequestWarning)
    LOGGER.info("TLS certificate verification disabled; repetitive urllib3 warnings suppressed")


def find_browser(explicit: str | None = None) -> str | None:
    if explicit:
        path = shutil.which(explicit) or (explicit if Path(explicit).is_file() else None)
        return str(path) if path else None
    return next((path for name in DEFAULT_BROWSERS if (path := shutil.which(name))), None)


def find_chromedriver() -> str | None:
    """Return an OS-provided ChromeDriver so Selenium Manager is not needed."""
    return next((path for name in DEFAULT_CHROMEDRIVERS if (path := shutil.which(name))), None)


def require_dependencies(config: AppConfig) -> str | None:
    """Check only dependencies needed for the selected execution mode."""
    if config.dry_run:
        return None
    if not (shutil.which(config.masscan) or Path(config.masscan).is_file()):
        raise RuntimeError(f"masscan executable not found: {config.masscan}")
    if should_use_sudo(config) and not shutil.which("sudo"):
        raise RuntimeError("sudo not found; install it or use --no-sudo with a suitably privileged masscan")
    if config.skip_fetch or not config.screenshots:
        return None
    browser = find_browser(config.browser)
    if not browser:
        raise RuntimeError("Chrome/Chromium not found; install it or use --browser/--skip-fetch")
    if not find_chromedriver():
        raise RuntimeError("ChromeDriver not found; install chromedriver/chromium-driver or use --skip-fetch")
    return browser


def should_use_sudo(config: AppConfig) -> bool:
    """Use sudo only for masscan, never for Python or the browser."""
    return config.use_sudo and hasattr(os, "geteuid") and os.geteuid() != 0


def authorize_masscan(config: AppConfig) -> None:
    """Prompt once before worker threads start; later sudo calls are non-interactive."""
    if should_use_sudo(config):
        LOGGER.info("Requesting sudo authorization for masscan")
        subprocess.run(["sudo", "-v"], check=True)


def executable_version(executable: str) -> str:
    result = subprocess.run([executable, "--version"], check=True, capture_output=True, text=True)
    return (result.stdout or result.stderr).strip().splitlines()[0]


def version_major(version_text: str) -> str | None:
    for token in version_text.split():
        if token and token[0].isdigit():
            return token.split(".", 1)[0]
    return None


def run_precheck(
    config: AppConfig,
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
    directories: dict[str, Path],
    excludes: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network] = (),
) -> str | None:
    """Validate the complete runtime before any network scan starts."""
    LOGGER.info("Precheck PASS | Masscan Web Scanner %s", __version__)
    LOGGER.info("Precheck PASS | %d authorized network range(s)", len(networks))
    if excludes:
        LOGGER.info("Precheck PASS | %d excluded target range(s)", len(excludes))
    LOGGER.info("Precheck PASS | output directory writable: %s", config.output_dir.resolve())
    LOGGER.info(
        "Precheck PASS | timeouts: HTTP %.1fs, screenshot %.1fs", config.http_timeout, config.screenshot_timeout
    )

    if config.dry_run:
        LOGGER.info("Precheck SKIP | runtime executables and sudo are not required for --dry-run")
        return None

    for module_name in ("requests",):
        if importlib.util.find_spec(module_name) is None:
            raise RuntimeError(f"required Python package not installed: {module_name}")
        LOGGER.info("Precheck PASS | Python package available: %s", module_name)

    browser = require_dependencies(config)
    LOGGER.info("Precheck PASS | masscan executable: %s", shutil.which(config.masscan) or config.masscan)
    if should_use_sudo(config):
        authorize_masscan(config)
        LOGGER.info("Precheck PASS | sudo authorization for masscan")
    else:
        LOGGER.info("Precheck SKIP | sudo disabled or already running with sufficient privileges")

    if not config.screenshots:
        LOGGER.info("Precheck SKIP | browser checks (screenshots disabled)")
        return browser

    if importlib.util.find_spec("selenium") is None:
        raise RuntimeError('required Python package not installed: selenium (install the "screenshots" extra)')
    LOGGER.info("Precheck PASS | Python package available: selenium")
    driver = find_chromedriver()
    browser_version = executable_version(browser or "")
    driver_version = executable_version(driver or "")
    LOGGER.info("Precheck PASS | browser: %s", browser_version)
    LOGGER.info("Precheck PASS | driver: %s", driver_version)
    browser_major = version_major(browser_version)
    driver_major = version_major(driver_version)
    if not browser_major or not driver_major or browser_major != driver_major:
        raise RuntimeError(f"browser/driver version mismatch: {browser_version!r} vs {driver_version!r}")
    LOGGER.info("Precheck PASS | browser and driver major version match: %s", browser_major)
    return browser


def safe_name(value: str) -> str:
    return value.replace(".", "_").replace(":", "_").replace("/", "_")


def run_scan(
    network: str,
    index: int,
    config: AppConfig,
    output_dir: Path,
    worker_rate: int,
    exclude_file: Path | None = None,
) -> Path | None:
    output_file = output_dir / f"range_{index:04d}_{safe_name(network)}.lst"
    command = [config.masscan, network, "-p", config.ports, "--rate", str(worker_rate)]
    if exclude_file:
        command.extend(["--excludefile", str(exclude_file)])
    command.extend(["-oL", str(output_file)])
    if should_use_sudo(config):
        command = ["sudo", "-n", *command]
    if config.dry_run:
        LOGGER.info("DRY RUN: %s", " ".join(command))
        return None
    LOGGER.info("Scanning %s", network)
    subprocess.run(command, check=True, capture_output=True, text=True)
    return output_file


def parse_masscan(
    list_file: Path,
    summary_dir: Path,
    excludes: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network] = (),
) -> list[tuple[str, int]]:
    targets: set[tuple[str, int]] = set()
    for line in list_file.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "open":
            if parts[1].lower() != "tcp":
                LOGGER.warning("Ignoring non-TCP masscan line: %s", line)
                continue
            try:
                ip_obj = ipaddress.ip_address(parts[3])
                if is_excluded(ip_obj, excludes):
                    LOGGER.warning("Ignoring masscan result for excluded IP: %s", parts[3])
                    continue
                targets.add((str(ip_obj), int(parts[2].split("/", 1)[0])))
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


def fetch_target(target: tuple[str, int], html_dir: Path, config: AppConfig, browser_exec: str | None) -> ArchiveResult:
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
                timeout=config.http_timeout,
                verify=config.verify_tls,
                allow_redirects=False,
                stream=True,
                headers={"User-Agent": "masscan-webscanner/2"},
            ) as response:
                html_file = host_dir / f"{stem}.html"
                written = 0
                with html_file.open("wb") as handle:
                    for chunk in response.iter_content(chunk_size=65_536):
                        written += len(chunk)
                        if written > config.max_html_bytes:
                            raise ValueError(f"response exceeds --max-html-bytes={config.max_html_bytes}")
                        handle.write(chunk)

    except Exception as exc:  # Network/browser failures are isolated per target.
        LOGGER.warning("Could not archive HTML from %s: %s", url, exc, extra={"file_only": True})
        (host_dir / f"{stem}.html").unlink(missing_ok=True)
        return ArchiveResult(target=target, html_ok=False, html_error=str(exc))

    if not config.screenshots or not browser_exec:
        return ArchiveResult(target=target, html_ok=True)

    try:
        capture_screenshot(url, host_dir / f"{stem}.png", browser_exec, config)
        return ArchiveResult(target=target, html_ok=True, screenshot_attempted=True, screenshot_ok=True)
    except Exception as exc:  # A screenshot failure must not remove valid HTML.
        LOGGER.warning("Could not capture screenshot of %s: %s", url, exc, extra={"file_only": True})
        (host_dir / f"{stem}.png").unlink(missing_ok=True)
        return ArchiveResult(
            target=target,
            html_ok=True,
            screenshot_attempted=True,
            screenshot_error=str(exc),
        )


def capture_screenshot(url: str, destination: Path, browser_exec: str, config: AppConfig) -> None:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service

    options = Options()
    options.binary_location = browser_exec
    chrome_arguments = ["--headless=new", "--disable-gpu", "--window-size=1920,1080"]
    if not config.verify_tls:
        chrome_arguments.append("--ignore-certificate-errors")
    for option in chrome_arguments:
        options.add_argument(option)
    driver_exec = find_chromedriver()
    if not driver_exec:
        raise RuntimeError("ChromeDriver not found")
    driver = webdriver.Chrome(service=Service(executable_path=driver_exec), options=options)
    try:
        driver.set_page_load_timeout(config.screenshot_timeout)
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
    archive_results: list[ArchiveResult],
    fetch_skipped: int,
    authorized_ranges: int = 0,
    excluded_ranges: int = 0,
    excluded_cidrs: Sequence[str] = (),
) -> None:
    html_failures = [result for result in archive_results if not result.html_ok]
    screenshot_results = [result for result in archive_results if result.screenshot_attempted]
    screenshot_failures = [result for result in screenshot_results if not result.screenshot_ok]
    payload = {
        "scan_jobs": {"succeeded": scan_succeeded, "failed": scan_failed},
        "ranges": {
            "authorized": authorized_ranges,
            "excluded": excluded_ranges,
        },
        "endpoints_discovered": len(targets),
        "fetches": {
            "attempted": len(archive_results),
            "succeeded": len(archive_results) - len(html_failures),
            "failed": len(html_failures),
            "skipped": fetch_skipped,
        },
        "screenshots": {
            "attempted": len(screenshot_results),
            "succeeded": len(screenshot_results) - len(screenshot_failures),
            "failed": len(screenshot_failures),
            "skipped": len(targets) - len(screenshot_results),
        },
        "fetch_failures": [
            {"ip": result.target[0], "port": result.target[1], "error": result.html_error} for result in html_failures
        ],
        "screenshot_failures": [
            {"ip": result.target[0], "port": result.target[1], "error": result.screenshot_error}
            for result in screenshot_failures
        ],
        "excluded_cidrs": list(excluded_cidrs),
    }
    (root / "run-summary.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def run(config: AppConfig) -> int:
    scope = load_ranges(config.ranges_file)
    networks = scope.targets
    excludes = scope.excludes
    directories = setup_output(config.output_dir)
    setup_logging(directories["logs"])
    browser = run_precheck(config, networks, directories, excludes=excludes)
    configure_tls_warnings(config)
    exclude_file: Path | None = None
    if excludes:
        exclude_file = directories["output"] / "exclude.lst"
        exclude_file.write_text("".join(f"{net}\n" for net in excludes), encoding="utf-8")
    expanded = (str(subnet) for network in networks for subnet in expand_network(network, config.max_ipv6_host_bits))
    targets: set[tuple[str, int]] = set()
    scan_succeeded = 0
    scan_failed = 0
    archive_results: list[ArchiveResult] = []
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
            if exclude_file:
                futures = {
                    executor.submit(
                        run_scan, network, index, config, directories["output"], worker_rate, exclude_file
                    ): network
                    for index, network in batch
                }
            else:
                futures = {
                    executor.submit(run_scan, network, index, config, directories["output"], worker_rate): network
                    for index, network in batch
                }
            for future in as_completed(futures):
                try:
                    output_file = future.result()
                    if output_file:
                        targets.update(parse_masscan(output_file, directories["output"], excludes=excludes))
                        scan_succeeded += 1
                except subprocess.CalledProcessError as exc:
                    scan_failed += 1
                    LOGGER.error("Scan failed for %s: %s", futures[future], exc.stderr or exc)
    if not config.skip_fetch and targets:
        with ThreadPoolExecutor(max_workers=config.fetch_workers) as executor:
            archive_results = list(
                executor.map(lambda target: fetch_target(target, directories["html"], config, browser), targets)
            )
    write_run_summary(
        config.output_dir,
        scan_succeeded=scan_succeeded,
        scan_failed=scan_failed,
        targets=targets,
        archive_results=archive_results,
        fetch_skipped=len(targets) if config.skip_fetch else 0,
        authorized_ranges=len(networks),
        excluded_ranges=len(excludes),
        excluded_cidrs=[str(net) for net in excludes],
    )
    html_failures = sum(not result.html_ok for result in archive_results)
    screenshot_failures = sum(result.screenshot_attempted and not result.screenshot_ok for result in archive_results)
    LOGGER.info("Result summary")
    LOGGER.info("  Authorized ranges    : %d", len(networks))
    if excludes:
        LOGGER.info("  Excluded ranges      : %d", len(excludes))
    LOGGER.info("  Endpoints discovered : %d", len(targets))
    LOGGER.info("  Scan failures        : %d", scan_failed)
    LOGGER.info("  HTML fetch failures  : %d", html_failures)
    LOGGER.info("  Screenshot failures  : %d", screenshot_failures)
    if scan_failed or html_failures or screenshot_failures:
        LOGGER.warning(
            "Failure details: %s and %s",
            directories["logs"] / "errors.log",
            config.output_dir / "run-summary.json",
        )
    LOGGER.info(
        "Completed: %d endpoints, %d total failures",
        len(targets),
        scan_failed + html_failures + screenshot_failures,
    )
    return 1 if scan_failed or html_failures or screenshot_failures else 0


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return run(parse_args(argv))
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
