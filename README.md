# frida-mcp

A Go MCP server for persistent Frida instrumentation, primarily for developer-signed apps on jailed iOS from Linux.

It supports stdio, Streamable HTTP (`/mcp`), and legacy HTTP+SSE (`/sse`). Sessions and scripts belong to the server process, so HTTP clients can reconnect and continue debugging. All clients of a server share the same user's sessions.

## Build

Requirements: Linux x86_64 or arm64, Go 1.25+, [just](https://github.com/casey/just), a C compiler and libc development headers, Python 3.11+, and network access for initial dependency downloads.

```sh
just build
./bin/frida-mcp -version
```

`just build` resolves the pinned MCP SDK, verifies its Go module checksums, downloads the official Frida Core **17.24.3** devkit, verifies the release asset's SHA-256 digest, and builds with CGO. Native files stay under `.deps/`; nothing is installed into system directories. Keep the generated `go.sum` when preparing a release.

For jailed iOS automatic injection, explicitly install matching Gadget into the current user's Frida cache:

```sh
just gadget
```

This downloads the matching universal iOS Gadget. Cache location follows `XDG_CACHE_HOME`, defaulting to `~/.cache/frida/gadget-ios.dylib`. Frida's attachment error is authoritative if your setup expects another location. A readable cache file alone does not establish that its version or signature is compatible.

The server uses the official [Go MCP SDK v1.8.0](https://github.com/modelcontextprotocol/go-sdk/releases/tag/v1.8.0). The Frida adapter calls the public Frida Core C API directly through Go/CGO: it does not launch the Frida CLI or require Python at runtime. This avoids the released `frida-go` binding's [recent Core API incompatibility](https://github.com/frida/frida-go/issues/76), and lets every blocking native operation receive a `GCancellable`. Frida callbacks and RPC correlation are owned by this project.

Builds without the `frida` tag are useful for transport development and tests. They expose diagnostics explaining that the native backend is unavailable. Use `just build` for a working instrumentation binary.

## Connect

### Stdio

```sh
./bin/frida-mcp
```

An MCP client configuration for this checkout:

```json
{
  "mcpServers": {
    "frida": {
      "command": "/home/applone/Projects/frida-mcp/bin/frida-mcp",
      "args": ["-transport", "stdio", "-timeout", "30s"]
    }
  }
}
```

Adjust the executable path when using another checkout. All operational logging goes to stderr; stdout carries only MCP messages. Ending the stdio process detaches its instrumentation sessions.

### Streamable HTTP and SSE

```sh
./bin/frida-mcp -transport http -listen 127.0.0.1:8080
```

Point modern clients at `http://127.0.0.1:8080/mcp`. For legacy SSE clients use `http://127.0.0.1:8080/sse`; the SDK advertises the message POST URL in the initial SSE event. Both endpoints are served concurrently and share the same tools/state.

Streamable HTTP is configured without protocol-owned sessions; instrumentation uses explicit `session_id` handles. The SDK handles protocol negotiation, initialization and transport framing. Client reconnects do not destroy instrumentation. Sessions, handles and event cursors reset when the server restarts.

HTTP is local and single user: the listen address must be a literal loopback IP. Host and browser Origin headers are checked, including the listener's port. No remote access, authentication, reverse-proxy trust or multi-user isolation is provided in this version.

## Jailed iOS workflow

1. Connect and unlock the device. Establish trust/pairing using your existing host tools.
2. Call `health_check`, optionally with a `device_id` from `list_devices`.
3. Call `list_applications` for the selected device, equivalent to `frida-ps -Uai`.
4. Call `spawn` with the target `bundle_id`, optionally passing initial scripts. Alternatively, `attach` to an existing PID or exact running bundle identifier.
5. Use `load_script`, `evaluate`, `call_rpc`, `post_message` and `read_events` to instrument the app.
6. Call `detach` when finished.

The target must be debuggable, typically a developer-signed app with `get-task-allow`. Listing an app does **not** imply it can be instrumented. App Store apps, IPA repackaging, app signing/installation, pairing, Developer Mode changes, Developer Disk Image mounting and privileged host setup are outside this server's scope. See [Frida's jailed iOS requirements](https://frida.re/docs/ios/).

Health checks distinguish connectivity from target readiness. They inspect Frida/device parameters, Linux usbmuxd socket access and CoreDevice service access through Frida's chosen transport. Frida can establish its own transport, so absence of a separate tunnel daemon or usbmuxd socket is not automatically a failure. The CoreDevice probe opens and closes `xpc:com.apple.coredevice.appservice`; it does not launch an app. On older iOS, that probe can be inapplicable even when legacy debugging works. Developer Mode, image mount state, debugserver readiness and target entitlements remain `unknown` unless directly established; actual attachment is the decisive target check.

If multiple USB devices are connected, supply `device_id`. Explicit IDs also allow local or already discovered network Frida devices. USB selection is never based on whichever device happened to enumerate first.

## Tools

| Tool | Main arguments | Result |
| --- | --- | --- |
| `health_check` | optional `device_id` | Version, devices, parameters, individual checks and remediation |
| `list_devices` | none | `devices` with ID, name and type |
| `list_applications` | optional `device_id` | `device_id`, installed `applications` with identifier/name/PID |
| `spawn` | `bundle_id`, optional `device_id`, `paused`, `scripts` | Session with `session_id`, PID, state and script IDs |
| `attach` | exactly one of `pid` or `bundle_id`; optional `device_id` | Session |
| `list_sessions` | none | Active and retained terminal sessions |
| `resume` | `session_id` | Current session |
| `detach` | `session_id` | Terminal session; application remains running |
| `load_script` | `session_id`, `source`, optional `name` | `script_id` |
| `unload_script` | `session_id`, `script_id` | `unloaded` |
| `evaluate` | `session_id`, `source` | `value`, `undefined` |
| `call_rpc` | `session_id`, `script_id`, `method`, optional `args` | `value` |
| `post_message` | `session_id`, `script_id`, `message`, optional `data_base64` | `queued` |
| `read_events` | optional `session_id`, `cursor`, `limit`, `wait_ms` | `events`, `next_cursor`, `oldest_cursor`, `dropped` |

Tool failures use MCP `isError: true`, with structured `error.code`, `error.message`, and optional `error.remediation`. Spawn setup failures include recovery details such as session ID and PID when available. Schema violations are rejected by the MCP SDK. Script errors and console output also arrive as retained message events.

### Hook before the app runs

Example arguments for `spawn`:

```json
{
  "bundle_id": "com.example.DebugApp",
  "paused": true,
  "scripts": [
    {"name": "early.js", "source": "send({ ready: true, platform: Process.platform });"}
  ]
}
```

This orders operations as spawn → attach → create/load scripts → optional resume. When `paused` is false or omitted, the process resumes after scripts load. Explicit pause is for short setup windows: iOS can terminate apps that remain paused too long. There is no global spawn gating.

If setup fails, the server detaches and attempts to terminate only the process created by that spawn. Normal detach resumes a server-created paused process before detaching. A failed resume leaves the session available for inspection and retry. No spawn, evaluation or RPC call is automatically retried after a timeout.

### Evaluate and RPC

`evaluate` lazily creates a session-owned agent. Its `globalThis` properties persist across calls:

```js
globalThis.counter = (globalThis.counter || 0) + 1;
globalThis.counter;
```

Evaluation awaits promises and returns JSON-compatible values. `undefined` is reported explicitly; bigint results become decimal strings; cyclic or unsupported results produce JavaScript errors. Top-level lexical `let`/`const` bindings are not a persistent REPL namespace. The evaluator's script ID appears in `list_sessions` and counts toward the script limit. Each separately loaded script has its own JavaScript context.

A script for `load_script`:

```js
rpc.exports = {
  add(a, b) { return a + b; },
  platform() { return Process.platform; }
};
console.log('agent loaded');
recv('command', message => send({ received: message }));
```

Call `call_rpc` with `method: "add"` and `args: [2, 3]`. Use `post_message` with `message: {"type":"command","value":42}` to invoke the receive handler. Its optional binary field is standard base64. Queuing a message does not acknowledge that the target processed it.

### Objective-C agents

Frida 17 agents use an explicit Objective-C bridge. Install the matching Frida tools in your development environment and bundle the example:

```sh
python3 -m venv .deps/agent-tools
.deps/agent-tools/bin/pip install 'frida==17.24.3' frida-tools
npm install --prefix examples
.deps/agent-tools/bin/frida-compile examples/objc-agent.ts -o .deps/objc-agent.js
```

The example pins `frida-objc-bridge` and the Frida TypeScript definitions in `examples/package.json`. Pass the resulting `.deps/objc-agent.js` text to `load_script.source`. For projects with their own agent build, use that project's pinned bridge dependency and compiler. The server accepts prebundled agents and does not resolve npm modules, fetch CodeShare scripts or read arbitrary source files on behalf of clients.

## Events and lifecycle

Call `read_events` with cursor zero for retained history. Save `next_cursor` and pass it on subsequent calls; polling is non-consuming, so clients maintain independent cursors. Optional `wait_ms` long-polls for up to 20 seconds. `limit` defaults to 100 and is capped at 1000. Cursors refer to the global event stream even when filtering by session.

Events include a sequence number, UTC timestamp, type, session ID, optional script ID, raw Frida JSON payload and optional base64 binary data. Native messages above 64 KiB are replaced with an explicit size-limit error. Retention defaults to 2048 events and 8 MiB, with a 64 KiB per-event budget; oversized retained events report `truncated`. `dropped: true` indicates the cursor predates retained history. Large telemetry is deliberately bounded; use an agent-side summarization strategy for noisy hooks.

Operations have a default 30-second deadline, configurable with `-timeout`. Session mutations are serialized; callbacks do not block on session locks. Device loss, app termination and script destruction close pending RPC waits and produce lifecycle events. Late RPC replies after timeout are discarded. Cancellation cannot undo JavaScript effects already performed in the app; inspect sessions/events before retrying.

There are at most 64 retained sessions per process and 32 scripts per session, including the evaluator. When session capacity is reached, the oldest idle terminal session can be evicted. Detach active sessions to free capacity. Events have separate bounded retention. Shutdown cancels active operations and attempts to detach every session; an unreachable device may prevent remote cleanup and is logged as an error.

## Tests and verification

```sh
just test-core       # backend-independent behavior tests, offline
just test            # full suite, including stdio and both HTTP transports
just check           # vet, formatting, asset extraction tests
just test-native     # opt-in local native attach/script/RPC integration
```

Physical jailed iOS test, **which launches the specified app**:

```sh
FRIDA_MCP_DEVICE_ID=00008000-0011223344556677 \
FRIDA_MCP_IOS_BUNDLE_ID=com.example.DebugApp \
just test-ios
```

The local native integration test attaches to its own `/bin/sleep` child; host ptrace policy must permit this. The iOS test checks diagnostics, application enumeration, paused spawn with an initial script, resume, messages, persistent evaluation, RPC/error handling, unloading and detach. Device loss and late replies are covered with the deterministic fake. Manually verify unplug/replug with your real device: the old session should become terminal, the reconnected device should be discoverable, and a new session should be created explicitly.

Hardware compatibility is not certified by fake-backend tests. Record the host architecture, iOS version, device model, Frida/Gadget versions and results when validating a device combination.
