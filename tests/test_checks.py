from __future__ import annotations

from pathlib import Path

from sazcheck.checks import run_checks_all
from sazcheck.parser import parse_saz
from sazcheck.report import has_high_failures, summarize


def test_vulnerable_session_has_failing_high_checks(mixed_saz: Path) -> None:
    sessions = parse_saz(mixed_saz)
    findings = run_checks_all([s for s in sessions if s.number == 1])
    assert has_high_failures(findings)


def test_vulnerable_cookie_flags_all_false(mixed_saz: Path) -> None:
    sessions = parse_saz(mixed_saz)
    findings = run_checks_all([s for s in sessions if s.number == 1])
    cookie_finding = next(f for f in findings if f.check.startswith("cookie:"))
    assert cookie_finding.passed is False


def test_vulnerable_plaintext_http_flagged(mixed_saz: Path) -> None:
    sessions = parse_saz(mixed_saz)
    findings = run_checks_all([s for s in sessions if s.number == 1])
    scheme_finding = next(f for f in findings if f.check == "scheme:https")
    assert scheme_finding.passed is False


def test_protected_session_passes_everything(protected_only_saz: Path) -> None:
    sessions = parse_saz(protected_only_saz)
    findings = run_checks_all(sessions)
    passed, total = summarize(findings)
    assert passed == total
    assert not has_high_failures(findings)


def test_server_banner_leaks_version_on_vulnerable_session(mixed_saz: Path) -> None:
    sessions = parse_saz(mixed_saz)
    findings = run_checks_all([s for s in sessions if s.number == 1])
    banner_finding = next(f for f in findings if f.check == "server-banner")
    assert banner_finding.passed is False
    assert "nginx/1.18.0" in banner_finding.detail
