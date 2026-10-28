package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/applone/frida-mcp/internal/core"
	"github.com/applone/frida-mcp/internal/testutil"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type wireResponse struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

func request(id int, method string, params any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}
}
func initialization() map[string]any {
	return request(1, "initialize", map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "frida-mcp-test", "version": "1"}})
}
func initialized() map[string]any {
	return map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}
}

func testManager(t *testing.T) *core.Manager {
	t.Helper()
	m := core.NewManager(testutil.New(), core.Options{})
	t.Cleanup(func() { m.Close(context.Background()) })
	return m
}
func testServer(m *core.Manager) *mcp.Server {
	return New(m, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func assertTools(t *testing.T, response wireResponse) {
	t.Helper()
	if len(response.Error) > 0 {
		t.Fatalf("RPC error: %s", response.Error)
	}
	var list struct {
		Tools []struct {
			Name        string         `json:"name"`
			InputSchema map[string]any `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(response.Result, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Tools) != 14 {
		t.Fatalf("got %d tools: %s", len(list.Tools), response.Result)
	}
	for _, tool := range list.Tools {
		if tool.InputSchema["type"] != "object" {
			t.Fatalf("invalid schema for %s: %v", tool.Name, tool.InputSchema)
		}
	}
}

func assertTool(t *testing.T, response wireResponse, wantError bool) map[string]any {
	t.Helper()
	if len(response.Error) > 0 {
		t.Fatalf("protocol error: %s", response.Error)
	}
	var result struct {
		IsError    bool           `json:"isError"`
		Structured map[string]any `json:"structuredContent"`
		Content    []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatal(err)
	}
	if result.IsError != wantError {
		t.Fatalf("isError=%v want=%v: %s", result.IsError, wantError, response.Result)
	}
	if result.Structured == nil {
		t.Fatalf("missing structured content: %s", response.Result)
	}
	return result.Structured
}

func TestStdioHelper(t *testing.T) {
	if os.Getenv("FRIDA_MCP_STDIO_HELPER") != "1" {
		return
	}
	m := core.NewManager(testutil.New(), core.Options{})
	err := testServer(m).Run(context.Background(), &mcp.StdioTransport{})
	m.Close(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func TestStdioTransport(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStdioHelper$")
	cmd.Env = append(os.Environ(), "FRIDA_MCP_STDIO_HELPER=1")
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { input.Close(); cmd.Process.Kill(); cmd.Wait() })
	encoder, decoder := json.NewEncoder(input), json.NewDecoder(output)
	call := func(value any) wireResponse {
		t.Helper()
		if err := encoder.Encode(value); err != nil {
			t.Fatal(err)
		}
		var response wireResponse
		if err := decoder.Decode(&response); err != nil {
			t.Fatal(err)
		}
		return response
	}
	init := call(initialization())
	if len(init.Error) > 0 {
		t.Fatalf("initialize: %s", init.Error)
	}
	if err = encoder.Encode(initialized()); err != nil {
		t.Fatal(err)
	}
	assertTools(t, call(request(2, "tools/list", map[string]any{})))
	assertTool(t, call(request(3, "tools/call", map[string]any{"name": "list_devices", "arguments": map[string]any{}})), false)
	assertTool(t, call(request(4, "tools/call", map[string]any{"name": "resume", "arguments": map[string]any{"session_id": "missing"}})), true)
	input.Close()
	if err = cmd.Wait(); err != nil {
		t.Fatalf("helper: %v; stderr: %s", err, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Logf("helper stderr: %s", stderr.String())
	}
}

func startHTTP(t *testing.T, m *core.Manager) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skip("sandbox does not permit loopback sockets")
	}
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	s := httptest.NewUnstartedServer(HTTP(testServer(m), port))
	s.Listener.Close()
	s.Listener = listener
	s.Start()
	t.Cleanup(s.Close)
	return s
}

func postHTTP(t *testing.T, client *http.Client, endpoint string, value any) (wireResponse, int) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2025-11-25")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusAccepted {
		return wireResponse{}, response.StatusCode
	}
	var result wireResponse
	if strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		scanner := bufio.NewScanner(response.Body)
		scanner.Buffer(make([]byte, 4096), 4<<20)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data:") {
				if err := json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data:"))), &result); err != nil {
					t.Fatal(err)
				}
				if result.ID != 0 {
					break
				}
			}
		}
		if err := scanner.Err(); err != nil {
			t.Fatal(err)
		}
	} else if err = json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatalf("HTTP %d: %v", response.StatusCode, err)
	}
	return result, response.StatusCode
}

func TestStreamableHTTPAndSessionPersistence(t *testing.T) {
	m := testManager(t)
	s := startHTTP(t, m)
	client := s.Client()
	client.Timeout = 5 * time.Second
	init, status := postHTTP(t, client, s.URL+"/mcp", initialization())
	if status != 200 || len(init.Error) > 0 {
		t.Fatalf("%d %+v", status, init)
	}
	postHTTP(t, client, s.URL+"/mcp", initialized())
	tools, _ := postHTTP(t, client, s.URL+"/mcp", request(2, "tools/list", map[string]any{}))
	assertTools(t, tools)
	spawned, _ := postHTTP(t, client, s.URL+"/mcp", request(3, "tools/call", map[string]any{"name": "spawn", "arguments": map[string]any{"bundle_id": "com.example.test"}}))
	id := assertTool(t, spawned, false)["session_id"].(string)
	// A fresh client can recover the same instrumentation state without an
	// MCP-Session-Id. HTTP connections never own Frida sessions.
	client.CloseIdleConnections()
	listed, _ := postHTTP(t, client, s.URL+"/mcp", request(4, "tools/call", map[string]any{"name": "list_sessions", "arguments": map[string]any{}}))
	list := assertTool(t, listed, false)["sessions"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["session_id"] != id {
		t.Fatalf("%v", list)
	}
	failure, _ := postHTTP(t, client, s.URL+"/mcp", request(5, "tools/call", map[string]any{"name": "resume", "arguments": map[string]any{"session_id": "missing"}}))
	assertTool(t, failure, true)
}

type sseEvent struct{ name, data string }

func readSSE(reader *bufio.Reader) (sseEvent, error) {
	var event sseEvent
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return event, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" && event.data != "" {
			return event, nil
		}
		if strings.HasPrefix(line, "event:") {
			event.name = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		}
		if strings.HasPrefix(line, "data:") {
			event.data += strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		}
	}
}

func TestLegacySSETransport(t *testing.T) {
	s := startHTTP(t, testManager(t))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", s.URL+"/sse", nil)
	req.Header.Set("Accept", "text/event-stream")
	stream, err := s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Body.Close()
	if stream.StatusCode != 200 {
		t.Fatalf("GET SSE: %d", stream.StatusCode)
	}
	reader := bufio.NewReader(stream.Body)
	endpoint, err := readSSE(reader)
	if err != nil || endpoint.name != "endpoint" {
		t.Fatalf("%+v %v", endpoint, err)
	}
	base, _ := url.Parse(s.URL + "/sse")
	target, err := url.Parse(endpoint.data)
	if err != nil {
		t.Fatal(err)
	}
	postURL := base.ResolveReference(target).String()
	call := func(message any) wireResponse {
		t.Helper()
		_, status := postHTTP(t, s.Client(), postURL, message)
		if status != http.StatusAccepted {
			t.Fatalf("SSE POST: %d", status)
		}
		event, err := readSSE(reader)
		if err != nil {
			t.Fatal(err)
		}
		var response wireResponse
		if err = json.Unmarshal([]byte(event.data), &response); err != nil {
			t.Fatal(err)
		}
		return response
	}
	init := call(initialization())
	if len(init.Error) > 0 {
		t.Fatalf("initialize: %s", init.Error)
	}
	postHTTP(t, s.Client(), postURL, initialized())
	assertTools(t, call(request(2, "tools/list", map[string]any{})))
	assertTool(t, call(request(3, "tools/call", map[string]any{"name": "list_devices", "arguments": map[string]any{}})), false)
	assertTool(t, call(request(4, "tools/call", map[string]any{"name": "resume", "arguments": map[string]any{"session_id": "missing"}})), true)
}
