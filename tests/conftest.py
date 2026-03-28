"""Shared test fixtures."""

import pytest


GOOD_DOCKERFILE = """\
FROM python:3.12-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim
RUN groupadd -r appuser && useradd -r -g appuser appuser
WORKDIR /app
COPY --from=builder /app /app
COPY src/ ./src/
USER appuser
EXPOSE 8080
HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"
CMD ["python", "-m", "src.main"]
"""

BAD_DOCKERFILE = """\
FROM python:latest
ENV API_KEY=supersecret123
ENV DB_PASSWORD=admin
RUN apt-get update && apt-get install -y curl wget
COPY . .
EXPOSE 22 80 443
CMD ["python", "app.py"]
"""

PARTIAL_DOCKERFILE = """\
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY . .
EXPOSE 3000
USER node
CMD ["node", "server.js"]
"""


@pytest.fixture
def good_dockerfile():
    return GOOD_DOCKERFILE


@pytest.fixture
def bad_dockerfile():
    return BAD_DOCKERFILE


@pytest.fixture
def partial_dockerfile():
    return PARTIAL_DOCKERFILE
