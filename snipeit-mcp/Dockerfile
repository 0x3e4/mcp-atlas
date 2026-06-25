# Slim, non-root image for the Snipe-IT MCP server.
# Run for Claude Code (stdio):  docker run -i --rm --env-file ./snipeit.env snipeit-mcp
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

# Drop privileges.
RUN useradd --create-home --uid 10001 appuser
USER appuser

# stdio transport by default. For streamable-http, set MCP_TRANSPORT=streamable-http and
# MCP_HOST=0.0.0.0 / FASTMCP_HOST=0.0.0.0, and publish the port (see compose.yml).
ENTRYPOINT ["snipeit-mcp"]
