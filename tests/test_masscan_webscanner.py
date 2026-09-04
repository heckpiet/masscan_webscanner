import ipaddress
import json
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

import masscan_webscanner as scanner
from masscan_webscanner import (
    AppConfig,
    ArchiveResult,
    TargetScope,
    expand_network,
    extract_title,
    load_ranges,
    parse_args,
    parse_masscan,
    target_url,
    write_endpoints_csv,
    write_html_report,
)


def test_load_ranges_ignores_comments_deduplicates_and_normalizes(tmp_path: Path) -> None:
    source = tmp_path / "ranges.txt"
    source.write_text("# approved\n192.0.2.10/24\n192.0.2.0/24 # duplicate\n2001:db8::/126\n")
    scope = load_ranges(source)
    assert isinstance(scope, TargetScope)
    assert [str(item) for item in scope.targets] == ["192.0.2.0/24", "2001:db8::/126"]
    assert scope.excludes == []
    # Test tuple unpacking compatibility
    targets, excludes = scope
    assert len(targets) == 2
    assert excludes == []


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


def test_cli_reports_package_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        parse_args(["--version"])
    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"masscan-webscanner {scanner.__version__}"


def test_cli_uses_separate_timeout_defaults(tmp_path: Path) -> None:
    config = parse_args(["-r", str(tmp_path / "ranges"), "-p", "80"])
    assert config.http_timeout == 5.0
    assert config.screenshot_timeout == 15.0


def test_cli_accepts_independent_timeouts(tmp_path: Path) -> None:
    config = parse_args(
        [
            "-r",
            str(tmp_path / "ranges"),
            "-p",
            "80",
            "--http-timeout",
            "7",
            "--screenshot-timeout",
            "20",
        ]
    )
    assert config.http_timeout == 7.0
    assert config.screenshot_timeout == 20.0


def test_legacy_timeout_sets_both_values(tmp_path: Path) -> None:
    config = parse_args(["-r", str(tmp_path / "ranges"), "-p", "80", "--timeout", "9"])
    assert config.http_timeout == 9.0
    assert config.screenshot_timeout == 9.0


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
    config = AppConfig(tmp_path / "ranges", "80,443", tmp_path, masscan="masscan", use_sudo=False)
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


def test_run_scan_uses_noninteractive_sudo_after_authorization(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scanner, "should_use_sudo", lambda config: True)
    run = Mock()
    monkeypatch.setattr(subprocess, "run", run)
    config = AppConfig(tmp_path / "ranges", "80", tmp_path)
    scanner.run_scan("192.0.2.0/24", 1, config, tmp_path, 250)
    assert run.call_args.args[0][:3] == ["sudo", "-n", "masscan"]


def test_authorize_masscan_prompts_once(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(scanner, "should_use_sudo", lambda config: True)
    run = Mock()
    monkeypatch.setattr(subprocess, "run", run)
    scanner.authorize_masscan(AppConfig(tmp_path / "ranges", "80", tmp_path))
    run.assert_called_once_with(["sudo", "-v"], check=True)


def test_precheck_accepts_matching_browser_and_driver_versions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = AppConfig(tmp_path / "ranges", "80", tmp_path, screenshots=True, use_sudo=False)
    monkeypatch.setattr(scanner, "require_dependencies", lambda config: "/usr/bin/chromium")
    monkeypatch.setattr(scanner, "find_chromedriver", lambda: "/usr/bin/chromedriver")
    monkeypatch.setattr(scanner.importlib.util, "find_spec", lambda name: object())
    monkeypatch.setattr(
        scanner,
        "executable_version",
        lambda executable: "Chromium 148.0" if executable.endswith("chromium") else "ChromeDriver 148.0",
    )
    result = scanner.run_precheck(config, [ipaddress.ip_network("192.0.2.0/24")], {"output": tmp_path})
    assert result == "/usr/bin/chromium"


def test_precheck_rejects_browser_driver_version_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = AppConfig(tmp_path / "ranges", "80", tmp_path, screenshots=True, use_sudo=False)
    monkeypatch.setattr(scanner, "require_dependencies", lambda config: "/usr/bin/chromium")
    monkeypatch.setattr(scanner, "find_chromedriver", lambda: "/usr/bin/chromedriver")
    monkeypatch.setattr(scanner.importlib.util, "find_spec", lambda name: object())
    monkeypatch.setattr(
        scanner,
        "executable_version",
        lambda executable: "Chromium 148.0" if executable.endswith("chromium") else "ChromeDriver 147.0",
    )
    with pytest.raises(RuntimeError, match="version mismatch"):
        scanner.run_precheck(config, [ipaddress.ip_network("192.0.2.0/24")], {"output": tmp_path})


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
    result = scanner.fetch_target(("192.0.2.1", 80), tmp_path, config, None)
    assert result == scanner.ArchiveResult(
        ("192.0.2.1", 80),
        html_ok=True,
        scheme="http",
        status_code=200,
        content_length=5,
    )
    assert session.get.call_args.kwargs["allow_redirects"] is False
    assert session.get.call_args.kwargs["timeout"] == 5.0
    assert session.trust_env is False
    assert (tmp_path / "192_0_2_1" / "192_0_2_1_80.html").read_bytes() == b"hello"


def test_fetch_archives_http_error_response(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    session = FakeSession(FakeResponse([b"not found"], status_code=404))
    monkeypatch.setattr("requests.Session", Mock(return_value=session))
    config = AppConfig(tmp_path / "ranges", "80", tmp_path)
    result = scanner.fetch_target(("192.0.2.1", 80), tmp_path, config, None)
    assert result.html_ok
    assert (tmp_path / "192_0_2_1" / "192_0_2_1_80.html").read_bytes() == b"not found"


def test_fetch_removes_partial_file_above_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    session = FakeSession(FakeResponse([b"1234", b"5678"]))
    monkeypatch.setattr("requests.Session", Mock(return_value=session))
    config = AppConfig(tmp_path / "ranges", "80", tmp_path, max_html_bytes=5)
    result = scanner.fetch_target(("192.0.2.1", 80), tmp_path, config, None)
    assert not result.html_ok
    assert "max-html-bytes" in (result.html_error or "")
    assert not (tmp_path / "192_0_2_1" / "192_0_2_1_80.html").exists()


def test_screenshot_failure_preserves_archived_html(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    session = FakeSession(FakeResponse([b"hello"]))
    monkeypatch.setattr("requests.Session", Mock(return_value=session))
    monkeypatch.setattr(scanner, "capture_screenshot", Mock(side_effect=RuntimeError("browser failed")))
    config = AppConfig(tmp_path / "ranges", "80", tmp_path, screenshots=True)
    result = scanner.fetch_target(("192.0.2.1", 80), tmp_path, config, "/usr/bin/chromium")
    assert result.html_ok
    assert result.screenshot_attempted
    assert not result.screenshot_ok
    assert result.screenshot_error == "browser failed"
    assert (tmp_path / "192_0_2_1" / "192_0_2_1_80.html").read_bytes() == b"hello"


def test_run_summary_is_machine_readable(tmp_path: Path) -> None:
    scanner.write_run_summary(
        tmp_path,
        scan_succeeded=2,
        scan_failed=1,
        targets={("192.0.2.1", 80)},
        archive_results=[scanner.ArchiveResult(("192.0.2.1", 80), html_ok=False, html_error="timeout")],
        fetch_skipped=0,
    )
    summary = json.loads((tmp_path / "run-summary.json").read_text())
    assert summary["scan_jobs"] == {"succeeded": 2, "failed": 1}
    assert summary["fetches"] == {"attempted": 1, "succeeded": 0, "failed": 1, "skipped": 0}
    assert summary["screenshots"] == {"attempted": 0, "succeeded": 0, "failed": 0, "skipped": 1}


def test_console_hides_file_only_endpoint_details(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    scanner.setup_logging(tmp_path)
    scanner.LOGGER.warning("endpoint detail", extra={"file_only": True})
    scanner.LOGGER.info("visible progress")
    for handler in scanner.LOGGER.handlers or scanner.logging.getLogger().handlers:
        handler.flush()
    console = capsys.readouterr().err
    assert "visible progress" in console
    assert "endpoint detail" not in console
    assert "endpoint detail" in (tmp_path / "errors.log").read_text()


def test_tls_warning_suppression_only_when_verification_is_disabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import urllib3

    disable_warnings = Mock()
    monkeypatch.setattr(urllib3, "disable_warnings", disable_warnings)
    scanner.configure_tls_warnings(AppConfig(tmp_path / "ranges", "443", tmp_path))
    disable_warnings.assert_called_once()
    disable_warnings.reset_mock()
    scanner.configure_tls_warnings(AppConfig(tmp_path / "ranges", "443", tmp_path, verify_tls=True))
    disable_warnings.assert_not_called()


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
    config = AppConfig(ranges, "80", output, skip_fetch=True, use_sudo=False)
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
    config = AppConfig(ranges, "80", output, use_sudo=False)
    monkeypatch.setattr(scanner, "require_dependencies", lambda config: None)

    def successful_scan(network: str, index: int, config: AppConfig, output_dir: Path, worker_rate: int) -> Path:
        result = output_dir / "result.lst"
        result.write_text("open tcp 80 192.0.2.1 0\n")
        return result

    monkeypatch.setattr(scanner, "run_scan", successful_scan)
    monkeypatch.setattr(
        scanner,
        "fetch_target",
        lambda target, html_dir, config, browser: scanner.ArchiveResult(target, html_ok=False, html_error="timeout"),
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
    scan_only = AppConfig(tmp_path / "ranges", "80", tmp_path, masscan=str(executable), skip_fetch=True, use_sudo=False)
    assert scanner.require_dependencies(scan_only) is None


def test_screenshot_dependencies_require_chromedriver(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    available = {"masscan": "/usr/bin/masscan", "sudo": "/usr/bin/sudo", "chromium": "/usr/bin/chromium"}
    monkeypatch.setattr(scanner.shutil, "which", lambda name: available.get(name))
    config = AppConfig(tmp_path / "ranges", "80", tmp_path, screenshots=True)
    with pytest.raises(RuntimeError, match="ChromeDriver not found"):
        scanner.require_dependencies(config)


def test_capture_screenshot_keeps_chrome_sandbox_enabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from selenium import webdriver

    driver = Mock()
    monkeypatch.setattr(webdriver, "Chrome", Mock(return_value=driver))
    monkeypatch.setattr(scanner, "find_chromedriver", lambda: "/usr/bin/chromedriver")
    config = AppConfig(tmp_path / "ranges", "80", tmp_path, screenshots=True)
    scanner.capture_screenshot("http://192.0.2.1:80", tmp_path / "page.png", "chrome", config)
    options = webdriver.Chrome.call_args.kwargs["options"]
    service = webdriver.Chrome.call_args.kwargs["service"]
    assert service.path == "/usr/bin/chromedriver"
    assert "--no-sandbox" not in options.arguments
    driver.set_page_load_timeout.assert_called_once_with(15.0)
    driver.quit.assert_called_once()


def test_load_ranges_with_excludes_syntax_and_normalization(tmp_path: Path) -> None:
    source = tmp_path / "targets.txt"
    source.write_text(
        "# Targets\n"
        "192.168.1.0/24\n"
        "2001:db8:1234::/64\n"
        "\n"
        "# Excludes via !\n"
        "!192.168.1.1\n"
        "!192.168.1.254 # gateway\n"
        "!2001:db8:1234::1\n"
        "!10.0.99.0/24\n"
        "!192.168.1.128/28\n"
        "!192.168.1.1 # duplicate exclude\n"
        "\n"
        "# Excludes via - and exclude prefix\n"
        "-192.168.1.5\n"
        "exclude 192.168.1.6\n"
        "exclude: 10.1.0.0/16\n"
    )
    scope = load_ranges(source)
    assert [str(item) for item in scope.targets] == ["192.168.1.0/24", "2001:db8:1234::/64"]
    assert [str(item) for item in scope.excludes] == [
        "192.168.1.1/32",
        "192.168.1.254/32",
        "2001:db8:1234::1/128",
        "10.0.99.0/24",
        "192.168.1.128/28",
        "192.168.1.5/32",
        "192.168.1.6/32",
        "10.1.0.0/16",
    ]


def test_load_ranges_requires_target_networks(tmp_path: Path) -> None:
    source = tmp_path / "only_excludes.txt"
    source.write_text("!192.168.1.1\n!10.0.0.0/8\n")
    with pytest.raises(ValueError, match="ranges file contains no target networks"):
        load_ranges(source)


def test_load_ranges_reports_line_number_for_invalid_exclude(tmp_path: Path) -> None:
    source = tmp_path / "bad_exclude.txt"
    source.write_text("192.168.1.0/24\n!not-an-ip\n")
    with pytest.raises(ValueError, match=r":2: invalid excluded network 'not-an-ip'"):
        load_ranges(source)


def test_load_ranges_reports_missing_address_in_exclude(tmp_path: Path) -> None:
    source = tmp_path / "empty_exclude.txt"
    source.write_text("192.168.1.0/24\n!\n")
    with pytest.raises(ValueError, match=r":2: missing address in exclusion entry"):
        load_ranges(source)


def test_run_scan_includes_excludefile_when_provided(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> None:
        calls.append(command)

    monkeypatch.setattr(subprocess, "run", fake_run)
    config = AppConfig(tmp_path / "ranges", "80", tmp_path, use_sudo=False)
    exclude_file = tmp_path / "exclude.lst"
    result = scanner.run_scan("192.168.1.0/24", 1, config, tmp_path, 500, exclude_file=exclude_file)
    assert result == tmp_path / "range_0001_192_168_1_0_24.lst"
    assert calls[0] == [
        "masscan",
        "192.168.1.0/24",
        "-p",
        "80",
        "--rate",
        "500",
        "--excludefile",
        str(exclude_file),
        "-oL",
        str(result),
    ]


def test_parse_masscan_filters_excluded_ips(tmp_path: Path) -> None:
    result = tmp_path / "result.lst"
    result.write_text(
        "open tcp 80 192.168.1.5 0\n"
        "open tcp 80 192.168.1.10 0\n"
        "open tcp 443 192.168.1.200 0\n"
        "open tcp 443 2001:db8::1 0\n"
        "open tcp 443 2001:db8::2 0\n"
    )
    excludes = [
        ipaddress.ip_network("192.168.1.5/32"),
        ipaddress.ip_network("192.168.1.128/25"),
        ipaddress.ip_network("2001:db8::1/128"),
    ]
    parsed = parse_masscan(result, tmp_path, excludes=excludes)
    assert parsed == [("192.168.1.10", 80), ("2001:db8::2", 443)]
    summary_content = (tmp_path / "result_summary.txt").read_text()
    assert "192.168.1.10: open port 80" in summary_content
    assert "2001:db8::2: open port 443" in summary_content
    assert "192.168.1.5" not in summary_content
    assert "192.168.1.200" not in summary_content
    assert "2001:db8::1" not in summary_content


def test_run_precheck_reports_excludes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = AppConfig(tmp_path / "ranges", "80", tmp_path, dry_run=True)
    networks = [ipaddress.ip_network("192.168.1.0/24")]
    excludes = [ipaddress.ip_network("192.168.1.1/32")]
    directories = {"output": tmp_path}
    logs: list[str] = []
    monkeypatch.setattr(scanner.LOGGER, "info", lambda msg, *args: logs.append(msg % args if args else msg))
    scanner.run_precheck(config, networks, directories, excludes=excludes)
    assert any("1 authorized network range(s)" in log for log in logs)
    assert any("1 excluded target range(s)" in log for log in logs)


def test_dry_run_with_excludes_writes_exclude_file_and_summary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ranges = tmp_path / "ranges.txt"
    ranges.write_text("192.168.1.0/24\n!192.168.1.1\n!192.168.1.254\n")
    output = tmp_path / "output"
    config = AppConfig(ranges, "80,443", output, dry_run=True, use_sudo=False)
    status = scanner.run(config)
    assert status == 0
    exclude_file = output / "output" / "exclude.lst"
    assert exclude_file.is_file()
    assert exclude_file.read_text() == "192.168.1.1/32\n192.168.1.254/32\n"
    summary = json.loads((output / "run-summary.json").read_text())
    assert summary["ranges"]["authorized"] == 1
    assert summary["ranges"]["excluded"] == 2
    assert summary["excluded_cidrs"] == ["192.168.1.1/32", "192.168.1.254/32"]
    assert (output / "report.html").is_file()


def test_extract_title_variants() -> None:
    assert extract_title(b"<html><head><title>Welcome to Test</title></head></html>") == "Welcome to Test"
    assert extract_title(b"<title>\n &lt;Admin&gt; &amp; Dashboard \n</title>") == "<Admin> & Dashboard"
    assert extract_title(b"<html><body><h1>No Title</h1></body></html>") is None
    long_raw = b"<title>" + b"A" * 300 + b"</title>"
    extracted = extract_title(long_raw)
    assert extracted is not None
    assert len(extracted) == 200
    assert extracted == "A" * 200


def test_target_url_supports_scheme_override() -> None:
    assert target_url("192.0.2.1", 80, scheme="https") == "https://192.0.2.1:80"
    assert target_url("192.0.2.1", 443, scheme="http") == "http://192.0.2.1:443"
    assert target_url("2001:db8::1", 8080, scheme="https") == "https://[2001:db8::1]:8080"


def test_cli_parses_exclude_file_and_cli_excludes(tmp_path: Path) -> None:
    ranges = tmp_path / "ranges.txt"
    ranges.write_text("10.0.0.0/8\n")
    ex_file = tmp_path / "ex.txt"
    ex_file.write_text("10.1.0.0/16\n")
    config = parse_args(
        [
            "-r",
            str(ranges),
            "-p",
            "80",
            "--exclude-file",
            str(ex_file),
            "--exclude",
            "10.2.0.0/16",
            "--exclude",
            "10.3.0.1",
        ]
    )
    assert config.exclude_file == ex_file
    assert config.cli_excludes == ("10.2.0.0/16", "10.3.0.1")


def test_cli_rejects_missing_exclude_file(tmp_path: Path) -> None:
    ranges = tmp_path / "ranges.txt"
    ranges.write_text("10.0.0.0/8\n")
    missing = tmp_path / "does_not_exist.txt"
    with pytest.raises(SystemExit):
        parse_args(["-r", str(ranges), "-p", "80", "--exclude-file", str(missing)])


def test_load_ranges_merges_exclude_file_and_cli(tmp_path: Path) -> None:
    ranges = tmp_path / "ranges.txt"
    ranges.write_text("192.168.0.0/16\n!192.168.1.1\n")
    ex_file = tmp_path / "excludes.txt"
    ex_file.write_text("192.168.2.0/24\n192.168.3.1\n")
    scope = load_ranges(ranges, exclude_file=ex_file, cli_excludes=["192.168.4.0/24", "192.168.1.1"])
    target_strs = [str(n) for n in scope.targets]
    exclude_strs = [str(n) for n in scope.excludes]
    assert target_strs == ["192.168.0.0/16"]
    assert "192.168.1.1/32" in exclude_strs
    assert "192.168.2.0/24" in exclude_strs
    assert "192.168.3.1/32" in exclude_strs
    assert "192.168.4.0/24" in exclude_strs
    # deduplicated
    assert exclude_strs.count("192.168.1.1/32") == 1


def test_write_endpoints_csv(tmp_path: Path) -> None:
    dest = tmp_path / "endpoints.csv"
    results = [
        ArchiveResult(
            target=("192.168.1.10", 80),
            html_ok=True,
            scheme="http",
            status_code=200,
            title="Gateway Login",
            server="nginx/1.24",
            redirect_location=None,
            content_type="text/html",
            content_length=1234,
        ),
        ArchiveResult(
            target=("192.168.1.20", 8443),
            html_ok=False,
            html_error="Connection refused",
            scheme="https",
        ),
    ]
    write_endpoints_csv(dest, results)
    assert dest.is_file()
    lines = dest.read_text(encoding="utf-8").splitlines()
    assert lines[0] == (
        "ip,port,scheme,url,status_code,title,server,redirect_location,content_type,"
        "content_length,html_ok,screenshot_ok,html_error,screenshot_error"
    )
    assert "192.168.1.10,80,http,http://192.168.1.10:80,200,Gateway Login,nginx/1.24" in lines[1]
    assert "192.168.1.20,8443,https,https://192.168.1.20:8443,,,," in lines[2]
    assert "Connection refused" in lines[2]


def test_write_html_report_and_run_summary(tmp_path: Path) -> None:
    report = tmp_path / "report.html"
    results = [
        ArchiveResult(
            target=("192.168.1.10", 443),
            html_ok=True,
            screenshot_attempted=True,
            screenshot_ok=True,
            scheme="https",
            status_code=200,
            title="Secure Portal",
            server="Apache/2.4",
            content_type="text/html",
            content_length=4567,
        )
    ]
    summary = {
        "scan_jobs": {"succeeded": 1, "failed": 0},
        "ranges": {"authorized": 1, "excluded": 0},
        "fetches": {"succeeded": 1, "failed": 0},
        "screenshots": {"succeeded": 1, "failed": 0},
    }
    write_html_report(report, results, summary)
    assert report.is_file()
    content = report.read_text(encoding="utf-8")
    assert "Masscan Webscanner" in content
    assert "Secure Portal" in content
    assert "192.168.1.10:443" in content
    assert "Apache/2.4" in content
    assert "endpoints.csv" in content


def test_fetch_target_fallback_from_http_to_https(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import requests

    call_urls: list[str] = []

    class FakeResponse:
        def __init__(self, status_code: int, content: bytes, headers: dict[str, str]) -> None:
            self.status_code = status_code
            self._content = content
            self.headers = headers

        def iter_content(self, chunk_size: int = 65536):
            yield self._content

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    class FakeSession:
        def __init__(self) -> None:
            self.trust_env = True

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def get(self, url: str, **kwargs: object) -> FakeResponse:
            call_urls.append(url)
            if url.startswith("http://"):
                return FakeResponse(
                    400,
                    b"<html><body>The plain HTTP request was sent to HTTPS port</body></html>",
                    {},
                )
            return FakeResponse(
                200,
                b"<html><head><title>HTTPS Portal</title></head><body>Secure</body></html>",
                {"Server": "nginx/custom", "Content-Type": "text/html"},
            )

    monkeypatch.setattr(requests, "Session", FakeSession)
    config = AppConfig(tmp_path / "ranges", "8080", tmp_path, screenshots=False)
    result = scanner.fetch_target(("192.0.2.1", 8080), tmp_path, config, browser_exec=None)

    assert result.html_ok is True
    assert result.scheme == "https"
    assert result.status_code == 200
    assert result.title == "HTTPS Portal"
    assert result.server == "nginx/custom"
    assert call_urls == ["http://192.0.2.1:8080", "https://192.0.2.1:8080"]


def test_fetch_target_fallback_from_https_to_http_on_ssl_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import requests

    call_urls: list[str] = []

    class FakeResponse:
        def __init__(self, status_code: int, content: bytes, headers: dict[str, str]) -> None:
            self.status_code = status_code
            self._content = content
            self.headers = headers

        def iter_content(self, chunk_size: int = 65536):
            yield self._content

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    class FakeSession:
        def __init__(self) -> None:
            self.trust_env = True

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def get(self, url: str, **kwargs: object) -> FakeResponse:
            call_urls.append(url)
            if url.startswith("https://"):
                raise requests.exceptions.SSLError("WRONG_VERSION_NUMBER")
            return FakeResponse(
                200,
                b"<html><head><title>Plain HTTP</title></head><body>Plain</body></html>",
                {"Server": "lighttpd", "Content-Type": "text/html"},
            )

    monkeypatch.setattr(requests, "Session", FakeSession)
    config = AppConfig(tmp_path / "ranges", "443", tmp_path, screenshots=False)
    result = scanner.fetch_target(("192.0.2.1", 443), tmp_path, config, browser_exec=None)

    assert result.html_ok is True
    assert result.scheme == "http"
    assert result.status_code == 200
    assert result.title == "Plain HTTP"
    assert result.server == "lighttpd"
    assert call_urls == ["https://192.0.2.1:443", "http://192.0.2.1:443"]
