//go:build !frida || !cgo || !linux

// Package native implements the Frida Core backend. Production builds use the
// frida build tag, CGO, and the pinned Linux Frida Core devkit.
package native

import (
	"context"
	"github.com/applone/frida-mcp/internal/core"
)

type Backend struct{}

func New() *Backend              { return &Backend{} }
func (*Backend) Version() string { return "unavailable (build with just build)" }
func unavailable() error {
	return &core.ToolError{Code: "backend_unavailable", Message: "Native Frida backend is not linked into this build.", Remediation: "On Linux, run just devkit && just build with CGO enabled; use bin/frida-mcp."}
}
func (*Backend) Devices(context.Context) ([]core.Device, error) { return nil, unavailable() }
func (*Backend) Parameters(context.Context, string) (map[string]any, error) {
	return nil, unavailable()
}
func (*Backend) Probe(context.Context, string) []core.Check {
	return []core.Check{{Name: "developer_services", Status: "unknown", Evidence: unavailable().Error()}}
}
func (*Backend) Applications(context.Context, string) ([]core.Application, error) {
	return nil, unavailable()
}
func (*Backend) Spawn(context.Context, string, string) (int, error) { return 0, unavailable() }
func (*Backend) Attach(context.Context, string, int, func(string)) (core.NativeSession, error) {
	return nil, unavailable()
}
func (*Backend) Resume(context.Context, string, int) error { return unavailable() }
func (*Backend) Kill(context.Context, string, int) error   { return unavailable() }
func (*Backend) Close(context.Context) error               { return nil }
