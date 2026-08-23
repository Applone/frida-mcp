# Frida MCP

A Model Context Protocol (MCP) implementation for Frida dynamic instrumentation toolkit.

## Overview

This package provides an MCP-compliant server for Frida, enabling AI systems to interact with mobile and desktop applications through Frida's dynamic instrumentation capabilities. It is built on [FastMCP](https://github.com/jlowin/fastmcp) to enable seamless integration with AI applications.

## Features

- Built with FastMCP
- stdio (default), streamable HTTP, and SSE transports
- Comprehensive Frida tools exposed through MCP:
  - Process management (list, attach, spawn, resume, kill)
  - Device management (USB, remote devices)
  - Interactive JavaScript REPL with real-time execution
  - Script injection with progress tracking
  - Process and device monitoring
- Resources for providing Frida data to models
- Prompts for guided Frida analysis workflows
- Progress tracking for long-running operations
- Full support for all MCP transport methods

## Installation

### Prerequisites

- Python 3.10 or later
- pip package manager
- Frida 16.0.0 or later

### Quick Install

```bash
pip install frida-mcp
```

### Development Install

```bash
# Clone the repository
git clone https://github.com/yourusername/frida-mcp.git
cd frida-mcp

# Install in development mode with extra tools
uv venv && uv pip install -e ".[dev]"
```

## Running

```bash
# stdio (default, what MCP clients expect)
frida-mcp

# streamable HTTP
frida-mcp --transport streamable-http --host 0.0.0.0 --port 1337

# legacy SSE
frida-mcp --transport sse --port 1337
```

## Client Integration

### Claude Code

Add `frida-mcp` via the CLI:

```bash
# Stdio transport (default)
claude mcp add frida --transport stdio -- frida-mcp

# Or streamable HTTP transport
claude mcp add frida --transport http http://127.0.0.1:1337/mcp
```

Or add it directly to your configuration file (`.mcp.json` or `~/.claude.json`):

```json
{
  "mcpServers": {
    "frida": {
      "command": "frida-mcp"
    }
  }
}
```

### Codex

Add `frida-mcp` via the Codex CLI:

```bash
# Stdio transport (default)
codex mcp add frida -- frida-mcp

# Or streamable HTTP transport
codex mcp add frida --url http://127.0.0.1:1337/mcp
```

Or configure it in `~/.codex/config.toml` (or project `.codex/config.toml`):

```toml
# Stdio transport
[mcp_servers.frida]
command = "frida-mcp"

# Or HTTP transport
# [mcp_servers.frida]
# url = "http://127.0.0.1:1337/mcp"
```

### Crush

Add `frida-mcp` to your `~/.config/crush/crushrc` (or `.crushrc`):

```bash
# Stdio transport
mcp add frida \
  --command frida-mcp

# Or streamable HTTP transport
mcp add frida --type http \
  --url "http://127.0.0.1:1337/mcp"
```

Or configure it in `crush.json`:

```json
{
  "mcp": {
    "frida": {
      "type": "stdio",
      "command": "frida-mcp"
    }
  }
}
```

## Usage

Once configured, you can use Frida MCP directly from your AI agent/client (Claude Code, Codex, Crush, etc.). The server provides the following capabilities:

### Process Management
- List all running processes
- Attach to specific processes
- Spawn new processes
- Resume suspended processes
- Kill processes

### Device Management
- List all connected devices (USB, remote)
- Get device information
- Connect to specific devices

### Interactive JavaScript REPL
- Create interactive sessions with processes
- Execute JavaScript code in real-time
- Monitor process state and memory
- Hook functions and intercept calls
- Capture console.log output
- Handle errors and exceptions gracefully

### Script Injection
- Inject custom JavaScript scripts
- Track injection progress
- Handle script errors and exceptions

### Resources
- Get Frida version information
- Access process list in human-readable format
- Access device list in human-readable format

## Development

```bash
# Clone repository
git clone https://github.com/yourusername/frida-mcp.git
cd frida-mcp

# Install development dependencies
uv venv && uv pip install -e ".[dev]"

# Run tests (frida is mocked, no device needed)
python -m pytest tests -q
```

## License

GNU GPL v3.0
