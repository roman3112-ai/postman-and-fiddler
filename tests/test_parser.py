from __future__ import annotations

from pathlib import Path

from sazcheck.parser import parse_saz


def test_parses_both_sessions_sorted_by_number(mixed_saz: Path) -> None:
    sessions = parse_saz(mixed_saz)
    assert [s.number for s in sessions] == [1, 2]


def test_parses_request_line(mixed_saz: Path) -> None:
    sessions = parse_saz(mixed_saz)
    vulnerable = sessions[0]
    assert vulnerable.method == "GET"
    assert vulnerable.url == "http://insecure.example.com/login"


def test_parses_response_status_and_reason(mixed_saz: Path) -> None:
    sessions = parse_saz(mixed_saz)
    assert sessions[0].status_code == 200
    assert sessions[0].reason == "OK"


def test_headers_are_lowercased_keys(mixed_saz: Path) -> None:
    sessions = parse_saz(mixed_saz)
    protected = sessions[1]
    assert protected.response_headers["content-security-policy"] == "default-src 'self'"
    assert protected.response_headers["x-frame-options"] == "DENY"


def test_collects_set_cookie_header(mixed_saz: Path) -> None:
    sessions = parse_saz(mixed_saz)
    vulnerable = sessions[0]
    assert vulnerable.set_cookie_headers == ["session=abc123; Path=/"]


def test_empty_archive_returns_no_sessions(empty_saz: Path) -> None:
    assert parse_saz(empty_saz) == []
