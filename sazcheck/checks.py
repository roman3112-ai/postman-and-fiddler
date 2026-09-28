"""Пассивные security-проверки над уже пойманной сессией из .saz.

Тот же набор проверок, что и в соседнем пет-проекте web-security-check,
только источник данных другой: там — живой GET-запрос, тут — то, что уже
записал Fiddler на трафике браузера/приложения. Сети скрипт не трогает
вообще: читает только то, что лежит в разобранном .saz.
"""

from __future__ import annotations

from .models import Finding, Session, Severity

SECURITY_HEADERS: dict[str, Severity] = {
    "content-security-policy": Severity.HIGH,
    "strict-transport-security": Severity.HIGH,
    "x-content-type-options": Severity.MEDIUM,
    "x-frame-options": Severity.MEDIUM,
    "referrer-policy": Severity.LOW,
    "permissions-policy": Severity.LOW,
}


def check_security_headers(session: Session) -> list[Finding]:
    findings: list[Finding] = []
    for name, severity in SECURITY_HEADERS.items():
        ok = name in session.response_headers
        findings.append(
            Finding(
                session_number=session.number,
                check=f"header:{name}",
                passed=ok,
                severity=severity,
                detail="есть" if ok else "отсутствует",
            )
        )
    return findings


def check_server_banner(session: Session) -> list[Finding]:
    server = session.response_headers.get("server", "")
    leaks_version = any(ch.isdigit() for ch in server)
    return [
        Finding(
            session_number=session.number,
            check="server-banner",
            passed=not leaks_version,
            severity=Severity.LOW,
            detail=f"Server: {server or '(нет)'}",
        )
    ]


def check_cookie_flags(session: Session) -> list[Finding]:
    findings: list[Finding] = []
    for raw in session.set_cookie_headers:
        low = raw.lower()
        name = raw.split("=", 1)[0].strip()
        secure = "secure" in low
        httponly = "httponly" in low
        samesite = "samesite" in low
        findings.append(
            Finding(
                session_number=session.number,
                check=f"cookie:{name}",
                passed=secure and httponly and samesite,
                severity=Severity.MEDIUM,
                detail=f"secure={secure} httponly={httponly} samesite={samesite}",
            )
        )
    return findings


def check_plaintext_http(session: Session) -> list[Finding]:
    """Отметить сессию, которая ушла по http:// вместо https://."""
    is_http = session.url.lower().startswith("http://")
    return [
        Finding(
            session_number=session.number,
            check="scheme:https",
            passed=not is_http,
            severity=Severity.HIGH,
            detail=session.url,
        )
    ]


def run_checks(session: Session) -> list[Finding]:
    """Прогнать все проверки над одной сессией."""
    findings: list[Finding] = []
    findings += check_security_headers(session)
    findings += check_server_banner(session)
    findings += check_cookie_flags(session)
    findings += check_plaintext_http(session)
    return findings


def run_checks_all(sessions: list[Session]) -> list[Finding]:
    """Прогнать все проверки над списком сессий (весь разобранный .saz)."""
    findings: list[Finding] = []
    for session in sessions:
        findings += run_checks(session)
    return findings
