// Package core implements transport-independent Frida session management.
package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

type Device struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

type Application struct {
	Identifier string `json:"identifier"`
	Name       string `json:"name"`
	PID        int    `json:"pid"`
}

type Check struct {
	Name        string `json:"name"`
	Status      string `json:"status"` // passed, failed, unknown, not_applicable
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation,omitempty"`
}

// Native objects remain owned by the backend until Close. Close is local,
// idempotent resource disposal; Detach/Unload perform the remote operation.
// Callbacks must never wait for a manager lock or perform native operations.
type Backend interface {
	Version() string
	Devices(context.Context) ([]Device, error)
	Parameters(context.Context, string) (map[string]any, error)
	Probe(context.Context, string) []Check
	Applications(context.Context, string) ([]Application, error)
	Spawn(context.Context, string, string) (int, error)
	Attach(context.Context, string, int, func(string)) (NativeSession, error)
	Resume(context.Context, string, int) error
	Kill(context.Context, string, int) error
	Close(context.Context) error
}

type NativeSession interface {
	CreateScript(context.Context, string, string, func(json.RawMessage, []byte), func()) (NativeScript, error)
	Detach(context.Context) error
	Close()
}

type NativeScript interface {
	Load(context.Context) error
	Unload(context.Context) error
	Post(context.Context, json.RawMessage, []byte) error
	Close()
}

type ToolError struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
}

func (e *ToolError) Error() string { return e.Message }

func Error(code, message string) error { return &ToolError{Code: code, Message: message} }

func DescribeError(err error) *ToolError {
	var e *ToolError
	if errors.As(err, &e) {
		return e
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return &ToolError{Code: "cancelled_or_timed_out", Message: err.Error(), Remediation: "Inspect sessions and events before retrying a state-changing operation; it may already have taken effect."}
	}
	return &ToolError{Code: "frida_error", Message: err.Error(), Remediation: "Run health_check for this device and inspect read_events for details."}
}

func required(value, name string) error {
	if value == "" {
		return Error("invalid_argument", fmt.Sprintf("%s is required", name))
	}
	return nil
}
