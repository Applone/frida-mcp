# AGENTS.md

## What this is

An MCP (Model Context Protocol) server that exposes the Frida dynamic
instrumentation toolkit to LLM clients (Claude Desktop, Crush, Claude Code,
etc.). Built on **FastMCP 3.x** (the `fastmcp` package), not the low-level
`mcp` SDK.

## Structure

- `src/frida_mcp/server.py` — the FastMCP app, all `@mcp.tool()` /
  `@mcp.resource()` definitions, and the `SessionManager` class that owns
  sessions, persistent scripts, and message queues.
- `src/frida_mcp/cli.py` — argparse entry point (`frida-mcp`), selects
  transport (`stdio` default, `streamable-http`, `sse`) and host/port.
- `tests/` — pytest suite. `tests/conftest.py` installs a **fake `frida`
  module into `sys.modules` before any test imports the server**, so tests run
  without a real Frida install or device. Keep it that way: any file touching
  `frida_mcp.server` inherits the fake.
- `pyproject.toml` — build backend is `uv_build`; deps are `frida` and
  `fastmcp` (no upper bounds).

## Commands (uv-based)

```bash
uv venv && uv pip install -e ".[dev]"
.venv/bin/python -m pytest tests -q      # tests
frida-mcp                                # stdio server
frida-mcp --transport streamable-http --host 0.0.0.0 --port 1337
```

## Gotchas

- **Dependencies are unpinned** (lower bounds only). `fastmcp` itself pulls in
  the legacy `mcp` 1.x SDK it builds on (its constraint is `mcp<2`, since
  `mcp>=2` removed `mcp.server.fastmcp`) — do not add a second `mcp` pin
  here; let fastmcp's own requirement control it.
- **Default device is USB.** Every device-targeting tool takes optional
  `device_id`; when omitted it calls `frida.get_usb_device()`. Tools fail on
  machines without an attached USB device unless `device_id` is passed (e.g.
  the local device id from `enumerate_devices`).
- **Error convention**: return-style tools return dicts with
  `{"status"/"success": ...}`; failures that the LLM should see as tool errors
  `raise ValueError` (FastMCP converts these to `isError` tool results). Keep
  this split.
- **`attach_to_process` now returns a `session_id`** and stores the session in
  the global `sessions` SessionManager. `execute_in_session`,
  `get_session_messages`, and `detach_session` all key off it. There is no
  separate `create_interactive_session` anymore.
- **`execute_in_session` wraps user JS** in an eval-based IIFE
  (`_EXECUTION_WRAPPER`) that hijacks `console.log` and sends a one-shot
  `execution_receipt`; user code is embedded via `json.dumps`, not Python
  `repr` (repr produces invalid JS for some strings). With `keep_alive=True`
  the script stays loaded, messages accumulate in the session queue, and
  `get_session_messages` drains (and clears) it. The `time.sleep(0.2)` before
  unloading non-persistent scripts is a pragmatic race heuristic — tightening
  it will drop receipts.
- Tool parameters are documented via `Annotated[..., Field(description=...)]`
  with `None` defaults — FastMCP turns these into the tool JSON schema.
  `Optional[X] = None` (not bare `X = None`) is required for correct schemas.
- Runtime verification of real instrumentation needs an actual Frida
  device/process; the test suite deliberately mocks all of it.
