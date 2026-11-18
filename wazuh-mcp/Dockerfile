# Base image pinned by digest (python:3.14-slim of 2026-11-08); bump it in the dependency routine.
FROM python:3.14-slim@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    POETRY_VERSION=2.5.1 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_CREATE=false \
    MCP_TRANSPORT=stdio

RUN pip install "poetry==${POETRY_VERSION}"

WORKDIR /app

# Copy everything Poetry needs to install the project, then install (main deps + root pkg).
COPY pyproject.toml poetry.lock* README.md ./
COPY src ./src
RUN poetry install --only main

# Run as a non-root user.
RUN useradd --create-home --uid 10001 app && chown -R app /app
USER app

# stdio MCP server: Claude Code talks to it over the container's stdin/stdout.
ENTRYPOINT ["wazuh-mcp"]
