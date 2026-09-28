"""Сборка фиктивного .saz-архива для тестов.

Настоящий Fiddler здесь, конечно, не поднимаем — .saz это обычный zip
с парами файлов ``N_c.txt`` / ``N_s.txt`` в папке ``raw/``, так что для
тестов проще и надёжнее собрать такой архив руками, зная формат, чем
таскать в репозитории бинарный файл, снятый один раз вручную.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

VULNERABLE_REQUEST = (
    "GET http://insecure.example.com/login HTTP/1.1\r\n"
    "Host: insecure.example.com\r\n"
    "User-Agent: TestClient/1.0\r\n"
    "\r\n"
)

VULNERABLE_RESPONSE = (
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Server: nginx/1.18.0\r\n"
    "Set-Cookie: session=abc123; Path=/\r\n"
    "\r\n"
    "<html>ok</html>"
)

PROTECTED_REQUEST = (
    "GET https://secure.example.com/login HTTP/1.1\r\n"
    "Host: secure.example.com\r\n"
    "User-Agent: TestClient/1.0\r\n"
    "\r\n"
)

PROTECTED_RESPONSE = (
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Content-Security-Policy: default-src 'self'\r\n"
    "Strict-Transport-Security: max-age=63072000\r\n"
    "X-Content-Type-Options: nosniff\r\n"
    "X-Frame-Options: DENY\r\n"
    "Referrer-Policy: no-referrer\r\n"
    "Permissions-Policy: geolocation=()\r\n"
    "Set-Cookie: session=xyz789; Secure; HttpOnly; SameSite=Strict\r\n"
    "\r\n"
    "<html>ok</html>"
)


def build_saz(path: Path, sessions: dict[int, tuple[str, str]]) -> Path:
    """Записать .saz по словарю {номер_сессии: (запрос, ответ)}."""
    with zipfile.ZipFile(path, mode="w") as archive:
        for number, (request_text, response_text) in sessions.items():
            archive.writestr(f"raw/{number}_c.txt", request_text)
            archive.writestr(f"raw/{number}_s.txt", response_text)
    return path


@pytest.fixture
def mixed_saz(tmp_path: Path) -> Path:
    """Архив с одной уязвимой (1) и одной защищённой (2) сессией."""
    return build_saz(
        tmp_path / "mixed.saz",
        {
            1: (VULNERABLE_REQUEST, VULNERABLE_RESPONSE),
            2: (PROTECTED_REQUEST, PROTECTED_RESPONSE),
        },
    )


@pytest.fixture
def protected_only_saz(tmp_path: Path) -> Path:
    """Архив, где все сессии защищённые — для проверки зелёного прогона."""
    return build_saz(
        tmp_path / "protected.saz", {1: (PROTECTED_REQUEST, PROTECTED_RESPONSE)}
    )


@pytest.fixture
def empty_saz(tmp_path: Path) -> Path:
    """Архив без единой валидной пары запрос/ответ."""
    path = tmp_path / "empty.saz"
    with zipfile.ZipFile(path, mode="w") as archive:
        archive.writestr("raw/readme.txt", "тут пусто")
    return path
