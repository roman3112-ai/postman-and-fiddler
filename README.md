# postman-and-fiddler

Учебный пет-проект про два классических инструмента QA-инженера для работы
с HTTP-трафиком: **Postman** (ручное и автоматизированное тестирование API)
и **Fiddler** (перехват и разбор трафика браузера/приложения). В одном
репозитории — два независимых мини-проекта, но связаны они одной идеей:
посмотреть на HTTP-запросы и ответы и проверить, что с ними всё в порядке —
и по функциональности, и по безопасности.

> ⚠️ Как и в соседних пет-проектах, здесь нет ничего атакующего: Postman-часть
> гоняет обычные тестовые запросы к публичному echo-сервису, а Fiddler-часть
> вообще не лезет в сеть — только читает уже сохранённый файл.

## Часть 1. Postman — функциональные и негативные API-тесты

Коллекция `postman/api-traffic-audit.postman_collection.json` гоняется
против [httpbin.org](https://httpbin.org) — публичного сервиса, который
просто "эхом" возвращает то, что ему прислали. Он не требует ключей и
регистрации, поэтому коллекцию можно смело гонять в CI.

Что внутри (5 папок, 14 запросов):

| Папка | Что проверяется |
|-------|------------------|
| `01 - Basic Auth` | позитивный и негативный сценарий Basic-авторизации (верный/неверный пароль) |
| `02 - CRUD (echo)` | POST/PUT/DELETE, проверка тела и метода в ответе, chaining — имя пользователя из ответа POST сохраняется в переменную окружения и используется в следующем PUT |
| `03 - Коды ответа` | 200 / 404 / 500 — что сервис действительно возвращает то, что обещает URL |
| `04 - Заголовки и cookies` | security-заголовки в ответе, установка cookie и то, что Postman сам подставляет её в следующий запрос (cookie jar) |
| `05 - Негативные сценарии` | "плохое" тело запроса, код 400, проверка времени ответа |

Каждый запрос — это отдельный тест-кейс с проверками в `pm.test()`:
позитивные и негативные проверки, разбор JSON-тела, заголовков, кук и
времени ответа.

### Как запустить руками

1. Импортировать в Postman `postman/api-traffic-audit.postman_collection.json`
   и `postman/api-traffic-audit.postman_environment.json`.
2. Выбрать окружение `httpbin (public)`.
3. Run collection → Run.

### Как запустить из терминала (Newman)

```bash
npm install -g newman
newman run postman/api-traffic-audit.postman_collection.json \
  -e postman/api-traffic-audit.postman_environment.json
```

Именно эта команда гоняется в CI (см. `.github/workflows/ci.yml`,
джоба `postman-tests`).

## Часть 2. sazcheck — офлайн-разбор трафика из Fiddler

`.saz` — формат, в который Fiddler сохраняет пойманные сессии. Это обычный
ZIP-архив: внутри папка `raw/`, а в ней на каждую сессию по два файла —
`N_c.txt` (запрос, "client") и `N_s.txt` (ответ, "server") в виде сырого
HTTP-текста.

`sazcheck` — маленькая Python-утилита, которая открывает такой архив,
разбирает все сессии и прогоняет по каждой те же security-проверки, что и
в соседнем проекте [web-security-check](https://github.com/roman3112-ai/web-security-check),
только источник данных другой: там — живой запрос, тут — уже пойманный
Fiddler-ом трафик. Полезно, когда нужно проверить, например, весь трафик
мобильного приложения или desktop-клиента, снятый через Fiddler как
прокси, а не только один GET-запрос.

### Что проверяется на каждой сессии

| Проверка | Критичность |
|----------|-------------|
| `Content-Security-Policy` | высокая |
| `Strict-Transport-Security` | высокая |
| Схема `https://`, а не `http://` | высокая |
| `X-Content-Type-Options` | средняя |
| `X-Frame-Options` | средняя |
| Флаги cookie (`Secure` + `HttpOnly` + `SameSite`) | средняя |
| `Referrer-Policy` | низкая |
| `Permissions-Policy` | низкая |
| Server-баннер (светит версию) | низкая |

### Установка и запуск

```bash
pip install -r requirements.txt
pip install -e .

sazcheck examples/demo.saz
sazcheck examples/demo.saz --fail-on-high   # для CI: код выхода 1, если есть HIGH-провал
```

`examples/demo.saz` — небольшой синтетический пример на 2 сессии (одна
уязвимая, одна защищённая), сгенерированный тем же кодом, что использует
`tests/conftest.py`, — чтобы можно было сразу пощупать утилиту без
настоящего Fiddler под рукой.

### Пример вывода

```
Разобрано сессий: 2
[ОШИБКА] сессия 1   высокий  header:content-security-policy — отсутствует
[ОШИБКА] сессия 1   высокий  scheme:https — http://insecure.example.com/login
[OK    ] сессия 2   высокий  header:content-security-policy — есть
...
Итог: 9/18 проверок пройдено
Хотя бы одна проверка высокой критичности провалена.
```

### Docker

```bash
docker build -t sazcheck .
docker run --rm -v "$(pwd)/examples:/data" sazcheck /data/demo.saz
```

## Как это устроено

```
postman/
  api-traffic-audit.postman_collection.json
  api-traffic-audit.postman_environment.json
sazcheck/
  models.py   # Session, Finding, Severity
  parser.py   # разбор .saz → список Session (без сети, только zipfile)
  checks.py   # те же проверки, что в web-security-check, но над Session
  report.py   # подсчёт очков и текстовый отчёт
  cli.py      # точка входа argparse
examples/
  demo.saz    # синтетический пример для ручного знакомства с утилитой
tests/
  conftest.py     # сборка фиктивных .saz-архивов для тестов
  test_parser.py
  test_checks.py
  test_cli.py
```

Тесты не поднимают настоящий Fiddler и не ходят в сеть — `conftest.py`
руками собирает валидный `.saz` (обычный zip с текстовыми файлами внутри),
зная формат, а `sazcheck` затем разбирает этот файл так же, как разобрал
бы настоящий экспорт из Fiddler.

## Что можно было бы добавить

- вывод `sazcheck` в JSON (`--format json`) для машинной обработки
- поддержку `.har` (HAR — ещё один популярный формат экспорта трафика,
  например из DevTools) тем же CLI
- Postman-коллекцию на реальном REST-API с БД вместо echo-сервиса
