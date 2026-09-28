"""Формирование текстового отчёта и подсчёт очков по найденным результатам."""

from __future__ import annotations

from collections.abc import Sequence

from .models import Finding, Severity


def summarize(findings: Sequence[Finding]) -> tuple[int, int]:
    passed = sum(1 for f in findings if f.passed)
    return passed, len(findings)


def has_high_failures(findings: Sequence[Finding]) -> bool:
    return any((not f.passed) and f.severity == Severity.HIGH for f in findings)


def render(findings: Sequence[Finding]) -> str:
    lines: list[str] = []
    for f in findings:
        mark = "OK" if f.passed else "ОШИБКА"
        lines.append(
            f"[{mark:<6}] сессия {f.session_number:<3} {f.severity.value:<8} "
            f"{f.check} — {f.detail}"
        )
    passed, total = summarize(findings)
    lines.append("")
    lines.append(f"Итог: {passed}/{total} проверок пройдено")
    if has_high_failures(findings):
        lines.append("Хотя бы одна проверка высокой критичности провалена.")
    return "\n".join(lines)
