import ipaddress
import json
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

import masscan_webscanner as scanner
from masscan_webscanner import AppConfig, expand_network, load_ranges, parse_args, parse_masscan, target_url


def test_load_ranges_ignores_comments_deduplicates_and_normalizes(tmp_path: Path) -> None:
    source = tmp_path / "ranges.txt"
    source.write_text("# approved\n192.0.2.10/24\n192.0.2.0/24 # duplicate\n2001:db8::/126\n")
    assert [str(item) for item in load_ranges(source)] == ["192.0.2.0/24", "2001:db8::/126"]


def test_load_ranges_reports_line_number(tmp_path: Path) -> None:
    source = tmp_path / "ranges.txt"
    source.write_text("192.0.2.0/24\nnot-a-network\n")
    with pytest.raises(ValueError, match=r":2: invalid network"):
        load_ranges(source)


def test_expand_ipv6_is_lazy_and_bounded() -> None:
    parts = expand_network(ipaddress.ip_network("2001:db8::/124"), 2)
    assert [str(item) for item in parts] == ["2001:db8::/126", "2001:db8::4/126", "2001:db8::8/126", "2001:db8::c/126"]


def test_ipv4_is_not_split() -> None:
    network = ipaddress.ip_network("192.0.2.0/24")
    assert list(expand_network(network, 8)) == [network]


def test_parse_masscan_deduplicates_and_sorts(tmp_path: Path) -> None:
    result = tmp_path / "result.lst"
    result.write_text("open tcp 443 2001:db8::2 0\nopen tcp 80 192.0.2.1 0\nopen tcp 80 192.0.2.1 0\n")
    assert parse_masscan(result, tmp_path) == [("192.0.2.1", 80), ("2001:db8::2", 443)]
    assert (tmp_path / "result_summary.txt").read_text() == ("192.0.2.1: open port 80\n2001:db8::2: open port 443\n")


def test_target_url_supports_ipv6_and_alternate_https() -> None:
    assert target_url("2001:db8::1", 8443) == "https://[2001:db8::1]:8443"
    assert target_url("192.0.2.1", 8080) == "http://192.0.2.1:8080"


def test_cli_rejects_non_positive_workers(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        parse_args(["-r", str(tmp_path / "ranges"), "-p", "80", "--scan-workers", "0"])


def test_cli_uses_python_310_compatible_utc_timestamp(tmp_path: Path) -> None:
    config = parse_args(["-r", str(tmp_path / "ranges"), "-p", "80"])
    assert config.output_dir.name.startswith("Masscan_WebScanner_")


def test_cli_rejects_screenshots_with_skip_fetch(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        parse_args(["-r", str(tmp_path / "ranges"), "-p", "80", "--screenshots", "--skip-fetch"])


def test_cli_rejects_udp_port_expressions(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        parse_args(["-r", str(tmp_path / "ranges"), "-p", "U:53,T:80"])


def test_parse_masscan_ignores_non_tcp_results(tmp_path: Path) -> None:
    result = tmp_path / "result.lst"
    result.write_text("open udp 53 192.0.2.1 0\nopen tcp 80 192.0.2.1 0\n")
    assert parse_masscan(result, tmp_path) == [("192.0.2.1", 80)]


def test_run_scan_shares_explicit_worker_rate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = AppConfig(tmp_path / "ranges", "80", tmp_path, dry_run=True, rate=1000)
    assert scanner.run_scan("192.0.2.0/24", 1, config, tmp_path, 250) is None


def test_run_scan_invokes_masscan_without_shell(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> None:
        calls.append(command)

    monkeypatch.setattr(subprocess, "run", fake_run)
    config = AppConfig(tmp_path / "ranges", "80,443", tmp_path, masscan="masscan")
    result = scanner.run_scan("192.0.2.0/24", 2, config, tmp_path, 500)
    assert result == tmp_path / "range_0002_192_0_2_0_24.lst"
    assert calls[0] == [
        "masscan",
        "192.0.2.0/24",
        "-p",
        "80,443",
        "--rate",
        "500",
        "-oL",
        str(result),
    ]


class FakeResponse:
    def __init__(self, chunks: list[bytes], status_code: int = 200) -> None:
        self.chunks = chunks
        self.status_code = status_code

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def raise_for_status(self) -> None:
        return None

    def iter_content(self, chunk_size: int) -> list[bytes]:
        return self.chunks


class FakeSession:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.trust_env = True
        self.get = Mock(return_value=response)

    def __enter__(self) -> "FakeSession":
        return self

    def __exit__(self, *args: object) -> None:
        return None


def test_fetch_does_not_follow_redirects(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    session = FakeSession(FakeResponse([b"hello"]))
    monkeypatch.setattr("requests.Session", Mock(return_value=session))
    config = AppConfig(tmp_path / "ranges", "80", tmp_path)
    target, ok, error = scanner.fetch_target(("192.0.2.1", 80), tmp_path, config, None)
    assert (target, ok, error) == (("192.0.2.1", 80), True, None)
    assert session.get.call_args.kwargs["allow_redirects"] is False
    assert session.trust_env is False
    assert (tmp_path / "192_0_2_1" / "192_0_2_1_80.html").read_bytes() == b"hello"


def test_fetch_removes_partial_file_above_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    session = FakeSession(FakeResponse([b"1234", b"5678"]))
    monkeypatch.setattr("requests.Session", Mock(return_value=session))
    config = AppConfig(tmp_path / "ranges", "80", tmp_path, max_html_bytes=5)
    _, ok, error = scanner.fetch_target(("192.0.2.1", 80), tmp_path, config, None)
    assert not ok
    assert "max-html-bytes" in (error or "")
    assert not (tmp_path / "192_0_2_1" / "192_0_2_1_80.html").exists()


def test_run_summary_is_machine_readable(tmp_path: Path) -> None:
    scanner.write_run_summary(
        tmp_path,
        scan_succeeded=2,
        scan_failed=1,
        targets={("192.0.2.1", 80)},
        fetch_attempted=1,
        fetch_failed=[(("192.0.2.1", 80), "timeout")],
    )
    summary = json.loads((tmp_path / "run-summary.json").read_text())
    assert summary["scan_jobs"] == {"succeeded": 2, "failed": 1}
    assert summary["fetches"] == {"attempted": 1, "succeeded": 0, "failed": 1, "skipped": 0}


def test_main_returns_configuration_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    result = scanner.main(["-r", str(tmp_path / "missing"), "-p", "80", "--dry-run"])
    assert result == 2
    assert "ranges file does not exist" in capsys.readouterr().err


def test_dry_run_completes_and_writes_summary(tmp_path: Path) -> None:
    ranges = tmp_path / "ranges"
    ranges.write_text("192.0.2.0/30\n")
    output = tmp_path / "result"
    config = AppConfig(ranges, "80", output, dry_run=True, scan_workers=2)
    assert scanner.run(config) == 0
    summary = json.loads((output / "run-summary.json").read_text())
    assert summary["scan_jobs"] == {"succeeded": 0, "failed": 0}


def test_run_reports_scan_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ranges = tmp_path / "ranges"
    ranges.write_text("192.0.2.0/30\n")
    output = tmp_path / "result"
    config = AppConfig(ranges, "80", output, skip_fetch=True)
    monkeypatch.setattr(scanner, "require_dependencies", lambda config: None)

    def fail_scan(*args: object, **kwargs: object) -> None:
        raise subprocess.CalledProcessError(1, "masscan", stderr="failed")

    monkeypatch.setattr(scanner, "run_scan", fail_scan)
    assert scanner.run(config) == 1
    summary = json.loads((output / "run-summary.json").read_text())
    assert summary["scan_jobs"] == {"succeeded": 0, "failed": 1}


def test_run_collects_targets_and_fetch_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ranges = tmp_path / "ranges"
    ranges.write_text("192.0.2.0/30\n")
    output = tmp_path / "result"
    config = AppConfig(ranges, "80", output)
    monkeypatch.setattr(scanner, "require_dependencies", lambda config: None)

    def successful_scan(network: str, index: int, config: AppConfig, output_dir: Path, worker_rate: int) -> Path:
        result = output_dir / "result.lst"
        result.write_text("open tcp 80 192.0.2.1 0\n")
        return result

    monkeypatch.setattr(scanner, "run_scan", successful_scan)
    monkeypatch.setattr(
        scanner,
        "fetch_target",
        lambda target, html_dir, config, browser: (target, False, "timeout"),
    )
    assert scanner.run(config) == 1
    summary = json.loads((output / "run-summary.json").read_text())
    assert summary["endpoints_discovered"] == 1
    assert summary["fetches"] == {"attempted": 1, "succeeded": 0, "failed": 1, "skipped": 0}


def test_dependency_checks_match_execution_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base = AppConfig(tmp_path / "ranges", "80", tmp_path, dry_run=True)
    assert scanner.require_dependencies(base) is None

    monkeypatch.setattr(scanner.shutil, "which", lambda name: None)
    with pytest.raises(RuntimeError, match="masscan executable not found"):
        scanner.require_dependencies(AppConfig(tmp_path / "ranges", "80", tmp_path))

    executable = tmp_path / "masscan"
    executable.touch()
    scan_only = AppConfig(tmp_path / "ranges", "80", tmp_path, masscan=str(executable), skip_fetch=True)
    assert scanner.require_dependencies(scan_only) is None


def test_capture_screenshot_keeps_chrome_sandbox_enabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from selenium import webdriver

    driver = Mock()
    monkeypatch.setattr(webdriver, "Chrome", Mock(return_value=driver))
    config = AppConfig(tmp_path / "ranges", "80", tmp_path, screenshots=True)
    scanner.capture_screenshot("http://192.0.2.1:80", tmp_path / "page.png", "chrome", config)
    options = webdriver.Chrome.call_args.kwargs["options"]
    assert "--no-sandbox" not in options.arguments
    driver.quit.assert_called_once()
