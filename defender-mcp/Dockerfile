# Slim, non-root image for the Defender XDR MCP server (read-only unless DEFENDER_ALLOW_WRITE=true).
# Run for Claude Code (stdio):  docker run -i --rm --env-file ./defender.env defender-mcp
FROM python:3.14-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    POETRY_VERSION=2.4.1

WORKDIR /app

RUN pip install --no-cache-dir "poetry==${POETRY_VERSION}"

# Install dependencies first (better layer caching), then the package itself.
COPY pyproject.toml poetry.lock* README.md ./
RUN poetry config virtualenvs.create false \
    && poetry install --only main --no-root

COPY src ./src
RUN poetry install --only main

# Drop privileges. The token cache dir (DEFENDER_AUTH=delegated) exists in the image so a named volume
# mounted there inherits appuser ownership and 0700.
RUN useradd --create-home --uid 10001 appuser     && install -d -m 0700 -o appuser -g appuser /home/appuser/.defender-mcp
USER appuser

# stdio transport by default. For streamable-http, set MCP_TRANSPORT=streamable-http and
# FASTMCP_HOST=0.0.0.0, and publish the port (see compose.yml).
ENTRYPOINT ["defender-mcp"]
