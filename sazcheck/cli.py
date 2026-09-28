"""Точка входа CLI: проверить security-заголовки и куки в .saz-архиве Fiddler."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from .checks import run_checks_all
from .parser import parse_saz
from .report import has_high_failures, render


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sazcheck",
        description=(
            "Разбор сессий Fiddler (.saz) и офлайн-проверка security-заголовков "
            "и флагов кук. Ничего не отправляет в сеть — только читает файл."
        ),
    )
    parser.add_argument(
        "saz_file", help="путь к .saz-файлу, экспортированному из Fiddler"
    )
    parser.add_argument(
        "--fail-on-high",
        action="store_true",
        help="завершиться с кодом 1, если провалена хоть одна HIGH-проверка (для CI)",
    )
    args = parser.parse_args(argv)

    try:
        sessions = parse_saz(args.saz_file)
    except OSError as exc:
        print(f"не удалось прочитать файл: {exc}", file=sys.stderr)
        return 2

    if not sessions:
        print("в архиве не найдено ни одной полной сессии (запрос + ответ)")
        return 2

    findings = run_checks_all(sessions)
    print(f"Разобрано сессий: {len(sessions)}")
    print(render(findings))

    if args.fail_on_high and has_high_failures(findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
