from __future__ import annotations

from pathlib import Path

import pytest

from sazcheck.cli import main


def test_exits_zero_when_all_sessions_protected(
    protected_only_saz: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main([str(protected_only_saz), "--fail-on-high"])
    out = capsys.readouterr().out
    assert code == 0
    assert "Разобрано сессий: 1" in out


def test_exits_one_on_high_failure_with_fail_on_high(
    mixed_saz: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main([str(mixed_saz), "--fail-on-high"])
    assert code == 1


def test_without_fail_on_high_exits_zero_even_with_failures(mixed_saz: Path) -> None:
    code = main([str(mixed_saz)])
    assert code == 0


def test_empty_archive_exits_two(empty_saz: Path) -> None:
    code = main([str(empty_saz)])
    assert code == 2


def test_missing_file_exits_two() -> None:
    code = main(["/no/such/file.saz"])
    assert code == 2
