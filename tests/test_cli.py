"""Tests for the CLI entry point."""

import pytest

from frida_mcp.cli import parse_args


def test_defaults():
    args = parse_args([])
    assert args.transport == "stdio"
    assert args.host == "127.0.0.1"
    assert args.port == 1337


def test_http_transport():
    args = parse_args(
        ["--transport", "streamable-http", "--host", "0.0.0.0", "--port", "9000"]
    )
    assert args.transport == "streamable-http"
    assert args.host == "0.0.0.0"
    assert args.port == 9000


def test_invalid_transport():
    with pytest.raises(SystemExit):
        parse_args(["--transport", "websocket"])
