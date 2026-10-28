package server

import (
	"net/http"

	"github.com/applone/frida-mcp/internal/localhttp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func HTTP(s *mcp.Server, port string) http.Handler {
	get := func(*http.Request) *mcp.Server { return s }
	mux := http.NewServeMux()
	// Instrumentation state belongs to core.Manager rather than MCP protocol
	// sessions. Stateless HTTP also supports the SDK's newest protocol revision.
	mux.Handle("/mcp", mcp.NewStreamableHTTPHandler(get, &mcp.StreamableHTTPOptions{Stateless: true, MaxRequestBodyBytes: 4 << 20}))
	sse := mcp.NewSSEHandler(get, &mcp.SSEOptions{MaxRequestBodyBytes: 4 << 20})
	mux.Handle("/sse", sse)
	mux.Handle("/sse/", sse)
	return localhttp.Guard(mux, port)
}
