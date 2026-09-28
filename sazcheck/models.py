"""Датаклассы, общие для парсера и проверок."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    HIGH = "высокий"
    MEDIUM = "средний"
    LOW = "низкий"


@dataclass
class Session:
    """Одна HTTP-сессия (запрос + ответ) из .saz-архива Fiddler."""

    number: int
    method: str
    url: str
    request_headers: dict[str, str]
    status_code: int
    reason: str
    response_headers: dict[str, str]
    set_cookie_headers: list[str] = field(default_factory=list)


@dataclass
class Finding:
    """Результат одной проверки для одной сессии."""

    session_number: int
    check: str
    passed: bool
    severity: Severity
    detail: str
