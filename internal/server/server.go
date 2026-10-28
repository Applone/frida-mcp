// Package server registers the shared Frida MCP tool surface.
package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/applone/frida-mcp/internal/core"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const Version = "0.1.0"

type Empty struct{}
type DeviceInput struct {
	DeviceID string `json:"device_id,omitempty" jsonschema:"Device ID from list_devices; required when multiple USB devices are present"`
}
type SessionInput struct {
	SessionID string `json:"session_id" jsonschema:"Persistent session ID returned by spawn or attach"`
}
type AttachInput struct {
	DeviceID string `json:"device_id,omitempty"`
	PID      int    `json:"pid,omitempty" jsonschema:"Running process ID; supply this or bundle_id"`
	BundleID string `json:"bundle_id,omitempty" jsonschema:"Exact identifier of a running app; supply this or pid"`
}
type LoadInput struct {
	SessionID string `json:"session_id"`
	Name      string `json:"name,omitempty"`
	Source    string `json:"source" jsonschema:"Inline JavaScript or prebundled agent; at most 1 MiB"`
}
type ScriptInput struct {
	SessionID string `json:"session_id"`
	ScriptID  string `json:"script_id"`
}
type EvaluateInput struct {
	SessionID string `json:"session_id"`
	Source    string `json:"source" jsonschema:"JavaScript evaluated in a persistent session-owned agent; use globalThis for persistent variables"`
}
type RPCInput struct {
	SessionID string `json:"session_id"`
	ScriptID  string `json:"script_id"`
	Method    string `json:"method" jsonschema:"Name exported through rpc.exports"`
	Args      []any  `json:"args,omitempty"`
}
type PostInput struct {
	SessionID string `json:"session_id"`
	ScriptID  string `json:"script_id"`
	Message   any    `json:"message" jsonschema:"JSON message delivered to the script's recv handler"`
	Data      string `json:"data_base64,omitempty" jsonschema:"Optional base64-encoded binary payload; at most 1 MiB decoded"`
}
type EventsInput struct {
	SessionID string `json:"session_id,omitempty"`
	Cursor    uint64 `json:"cursor,omitempty" jsonschema:"Last next_cursor, or zero to read retained history; resets at server restart"`
	Limit     int    `json:"limit,omitempty" jsonschema:"Maximum events, 1..1000; default 100"`
	WaitMS    int    `json:"wait_ms,omitempty" jsonschema:"Long-poll wait, 0..20000 milliseconds"`
}

func New(manager *core.Manager, logger *slog.Logger) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "frida-mcp", Version: Version}, &mcp.ServerOptions{
		Logger:       logger,
		Capabilities: &mcp.ServerCapabilities{},
		Instructions: "Use health_check, list_devices, list_applications, then spawn or attach. Jailed iOS requires a developer-signed debuggable target. Load scripts before resume for early hooks. Sessions outlive HTTP connections. Retrieve messages with read_events and retain next_cursor. Inspect sessions/events before retrying a timed-out mutation. All local clients share sessions.",
	})
	add(s, "health_check", "Diagnose Frida and device access without launching an app or changing host setup.", true, func(ctx context.Context, in DeviceInput) (any, error) { return manager.Health(ctx, in.DeviceID) })
	add(s, "list_devices", "List discovered Frida devices and their stable identifiers.", true, func(ctx context.Context, _ Empty) (any, error) {
		devices, err := manager.Devices(ctx)
		return map[string]any{"devices": devices}, err
	})
	add(s, "list_applications", "List installed applications, bundle identifiers and running PIDs (frida-ps -Uai equivalent). Installation does not imply debuggability.", true, func(ctx context.Context, in DeviceInput) (any, error) { return manager.Applications(ctx, in.DeviceID) })
	add(s, "spawn", "Spawn a bundle, attach, load optional initial scripts, then resume unless paused=true. Returns a persistent session_id. Failed setup cleans up only the created process.", false, func(ctx context.Context, in core.SpawnRequest) (any, error) { return manager.Spawn(ctx, in) })
	add(s, "attach", "Attach to a running PID or exact bundle identifier. Does not launch an application.", false, func(ctx context.Context, in AttachInput) (any, error) {
		return manager.Attach(ctx, in.DeviceID, in.PID, in.BundleID)
	})
	add(s, "list_sessions", "List shared instrumentation sessions, state, and script IDs.", true, func(ctx context.Context, _ Empty) (any, error) {
		sessions, err := manager.List(ctx)
		return map[string]any{"sessions": sessions}, err
	})
	add(s, "resume", "Resume a process left paused by spawn. Already-running sessions are unchanged.", false, func(ctx context.Context, in SessionInput) (any, error) { return manager.Resume(ctx, in.SessionID) })
	add(s, "detach", "Detach and unload scripts, leaving the application running. Resumes server-created paused processes first.", false, func(ctx context.Context, in SessionInput) (any, error) { return manager.Detach(ctx, in.SessionID) })
	add(s, "load_script", "Load inline or prebundled JavaScript into a session; returns a script_id. Script messages and errors appear in read_events.", false, func(ctx context.Context, in LoadInput) (any, error) {
		return manager.Load(ctx, in.SessionID, core.ScriptSource{Name: in.Name, Source: in.Source})
	})
	add(s, "unload_script", "Unload a script and release its native resources.", false, func(ctx context.Context, in ScriptInput) (any, error) {
		err := manager.Unload(ctx, in.SessionID, in.ScriptID)
		return map[string]any{"unloaded": err == nil}, err
	})
	add(s, "evaluate", "Evaluate JavaScript in a persistent session-owned agent. Awaits promises and returns JSON-compatible results; globalThis properties persist between calls.", false, func(ctx context.Context, in EvaluateInput) (any, error) {
		return manager.Evaluate(ctx, in.SessionID, in.Source)
	})
	add(s, "call_rpc", "Call a loaded script's rpc.exports method. Returns its JSON result or a JavaScript error. Never automatically retries.", false, func(ctx context.Context, in RPCInput) (any, error) {
		value, err := manager.Call(ctx, in.SessionID, in.ScriptID, in.Method, in.Args)
		return map[string]any{"value": value}, err
	})
	add(s, "post_message", "Send JSON and optional base64 binary data to a script's recv handler. Delivery is queued; completion is not an acknowledgement from the script.", false, func(ctx context.Context, in PostInput) (any, error) {
		if len(in.Data) > base64.StdEncoding.EncodedLen(core.MaxScriptBytes) {
			return nil, core.Error("invalid_argument", "binary data must be at most 1 MiB decoded")
		}
		data, err := base64.StdEncoding.DecodeString(in.Data)
		if err != nil {
			return nil, core.Error("invalid_argument", "data_base64 must be valid standard base64")
		}
		message, err := json.Marshal(in.Message)
		if err == nil {
			err = manager.Post(ctx, in.SessionID, in.ScriptID, message, data)
		}
		return map[string]any{"queued": err == nil}, err
	})
	add(s, "read_events", "Read retained script logs/messages/errors and lifecycle events by cursor. Non-consuming, transport-independent; dropped=true indicates missing evicted events.", true, func(ctx context.Context, in EventsInput) (any, error) {
		if in.WaitMS < 0 || in.WaitMS > 20000 {
			return nil, core.Error("invalid_argument", "wait_ms must be 0..20000")
		}
		return manager.Events.Read(ctx, in.SessionID, in.Cursor, in.Limit, time.Duration(in.WaitMS)*time.Millisecond)
	})
	return s
}

func add[In any](s *mcp.Server, name, description string, readOnly bool, run func(context.Context, In) (any, error)) {
	mcp.AddTool(s, &mcp.Tool{Name: name, Description: description, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: readOnly}}, func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, map[string]any, error) {
		value, err := run(ctx, in)
		if err != nil {
			failure := map[string]any{"error": core.DescribeError(err)}
			// Include recovery handles when setup failed after allocating a target.
			if value != nil {
				failure["details"] = value
			}
			encoded, _ := json.Marshal(failure)
			// A typed nil map is still a non-nil interface in the SDK's
			// generic handler. Return the failure as Out as well, so its
			// output validation preserves the structured error object.
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: string(encoded)}}}, failure, nil
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, nil, err
		}
		var object map[string]any
		if json.Unmarshal(encoded, &object) != nil || object == nil {
			object = map[string]any{"value": value}
		}
		return nil, object, nil
	})
}
