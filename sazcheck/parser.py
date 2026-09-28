"""Разбор .saz-архива Fiddler.

.saz — это обычный ZIP-архив. Внутри лежит папка ``raw/`` с сырыми HTTP-сессиями:
на каждую пойманную Fiddler-ом сессию номер N приходится два файла —
``N_c.txt`` (client, то есть запрос) и ``N_s.txt`` (server, то есть ответ).
Формат самих файлов — обычный сырой HTTP: стартовая строка, заголовки,
пустая строка, тело.

Парсер здесь читает только заголовки (для security-проверок тело не нужно)
и не выполняет никаких сетевых запросов — просто читает файл на диске.
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path

from .models import Session

_RAW_NAME_RE = re.compile(r"(?:^|/)(\d+)_([cs])\.txt$")


def _split_headers(raw_text: str) -> tuple[str, list[str]]:
    """Разделить сырой HTTP-текст на стартовую строку и список строк-заголовков."""
    # Fiddler пишет файлы с CRLF, но на всякий случай нормализуем и то, и то.
    lines = raw_text.replace("\r\n", "\n").split("\n")
    start_line = lines[0] if lines else ""
    header_lines: list[str] = []
    for line in lines[1:]:
        if line == "":
            break
        header_lines.append(line)
    return start_line, header_lines


def _parse_header_lines(header_lines: list[str]) -> dict[str, str]:
    """Собрать заголовки в dict. Одноимённые (кроме Set-Cookie) — через запятую."""
    headers: dict[str, str] = {}
    for line in header_lines:
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip()
        value = value.strip()
        key = name.lower()
        if key in headers:
            headers[key] = f"{headers[key]}, {value}"
        else:
            headers[key] = value
    return headers


def _collect_set_cookie(header_lines: list[str]) -> list[str]:
    return [
        line.split(":", 1)[1].strip()
        for line in header_lines
        if line.lower().startswith("set-cookie:")
    ]


def _parse_request(raw_text: str) -> tuple[str, str, dict[str, str]]:
    start_line, header_lines = _split_headers(raw_text)
    parts = start_line.split(" ")
    method = parts[0] if parts else ""
    url = parts[1] if len(parts) > 1 else ""
    return method, url, _parse_header_lines(header_lines)


def _parse_response(raw_text: str) -> tuple[int, str, dict[str, str], list[str]]:
    start_line, header_lines = _split_headers(raw_text)
    parts = start_line.split(" ", 2)
    try:
        status_code = int(parts[1]) if len(parts) > 1 else 0
    except ValueError:
        status_code = 0
    reason = parts[2] if len(parts) > 2 else ""
    headers = _parse_header_lines(header_lines)
    set_cookies = _collect_set_cookie(header_lines)
    return status_code, reason, headers, set_cookies


def parse_saz(path: str | Path) -> list[Session]:
    """Прочитать .saz-файл и вернуть список сессий, отсортированный по номеру.

    Сессия без пары (есть запрос, но потерян ответ, или наоборот) пропускается —
    Fiddler так не сохраняет, но на битом архиве лучше молча пропустить,
    чем упасть.
    """
    requests: dict[int, str] = {}
    responses: dict[int, str] = {}

    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            match = _RAW_NAME_RE.search(name)
            if not match:
                continue
            number = int(match.group(1))
            side = match.group(2)
            text = archive.read(name).decode("utf-8", errors="replace")
            if side == "c":
                requests[number] = text
            else:
                responses[number] = text

    sessions: list[Session] = []
    for number in sorted(set(requests) & set(responses)):
        method, url, request_headers = _parse_request(requests[number])
        status_code, reason, response_headers, set_cookies = _parse_response(
            responses[number]
        )
        sessions.append(
            Session(
                number=number,
                method=method,
                url=url,
                request_headers=request_headers,
                status_code=status_code,
                reason=reason,
                response_headers=response_headers,
                set_cookie_headers=set_cookies,
            )
        )
    return sessions
