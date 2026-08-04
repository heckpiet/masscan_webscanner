import ipaddress
from pathlib import Path

import pytest

from masscan_webscanner import expand_network, load_ranges, parse_args, parse_masscan, target_url


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
    assert [str(item) for item in parts] == [
        "2001:db8::/126", "2001:db8::4/126", "2001:db8::8/126", "2001:db8::c/126"
    ]


def test_ipv4_is_not_split() -> None:
    network = ipaddress.ip_network("192.0.2.0/24")
    assert list(expand_network(network, 8)) == [network]


def test_parse_masscan_deduplicates_and_sorts(tmp_path: Path) -> None:
    result = tmp_path / "result.lst"
    result.write_text("open tcp 443 2001:db8::2 0\nopen tcp 80 192.0.2.1 0\nopen tcp 80 192.0.2.1 0\n")
    assert parse_masscan(result, tmp_path) == [("192.0.2.1", 80), ("2001:db8::2", 443)]
    assert (tmp_path / "result_summary.txt").read_text() == (
        "192.0.2.1: open port 80\n2001:db8::2: open port 443\n"
    )


def test_target_url_supports_ipv6_and_alternate_https() -> None:
    assert target_url("2001:db8::1", 8443) == "https://[2001:db8::1]:8443"
    assert target_url("192.0.2.1", 8080) == "http://192.0.2.1:8080"


def test_cli_rejects_non_positive_workers(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        parse_args(["-r", str(tmp_path / "ranges"), "-p", "80", "--scan-workers", "0"])
