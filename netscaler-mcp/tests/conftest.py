"""Shared fixtures for the flow tests: a fake NITRO appliance wired into the server module."""

from __future__ import annotations

import httpx
import pytest

from fake_netscaler import FakeNetScaler
from netscaler_mcp import server
from netscaler_mcp.config import Settings


@pytest.fixture
def ns(tmp_path):
    """A fresh fake appliance wired into the server; ns.use(allow_write=False) flips the write flag."""
    fake = FakeNetScaler()

    def use(allow_write: bool = True) -> None:
        env = {
            "NETSCALER_BASE_URL": "https://ns",
            "NETSCALER_USER": "u",
            "NETSCALER_PASSWORD": "p",
            "NETSCALER_ALLOW_WRITE": str(allow_write).lower(),
            "NETSCALER_EXPORT_DIR": str(tmp_path),
        }
        client = server.NitroClient(Settings.from_env(env))
        client._client = httpx.AsyncClient(transport=httpx.MockTransport(fake))
        server._client = client

    fake.use = use
    use()
    yield fake
    server._client = None
