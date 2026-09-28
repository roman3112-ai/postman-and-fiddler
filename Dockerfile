FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml .
COPY sazcheck ./sazcheck
RUN pip install --no-cache-dir .

ENTRYPOINT ["sazcheck"]
