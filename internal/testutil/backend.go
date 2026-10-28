// Package testutil provides a deterministic Frida fake for behavioral tests.
package testutil

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/applone/frida-mcp/internal/core"
)

type Backend struct {
	mu                                              sync.Mutex
	Calls                                           []string
	DeviceList                                      []core.Device
	Params                                          map[string]any
	SpawnError, AttachError, LoadError, ResumeError error
	ResumeFailures                                  int
	CreateError                                     error
	OnSpawn                                         func(context.Context)
	OnPost                                          func(context.Context, *Script, json.RawMessage)
	Sessions                                        []*Session
	Apps                                            []core.Application
}

func New() *Backend {
	return &Backend{DeviceList: []core.Device{{ID: "iphone", Name: "Test iPhone", Type: "usb"}}, Params: map[string]any{"os": map[string]any{"id": "ios", "version": "18.0"}}, Apps: []core.Application{{Identifier: "com.example.test", Name: "Test", PID: 42}}}
}
func (b *Backend) Record(s string) { b.mu.Lock(); defer b.mu.Unlock(); b.Calls = append(b.Calls, s) }
func (b *Backend) History() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.Calls...)
}
func (*Backend) Version() string { return "test-core" }
func (b *Backend) Devices(ctx context.Context) ([]core.Device, error) {
	return append([]core.Device(nil), b.DeviceList...), ctx.Err()
}
func (b *Backend) Parameters(ctx context.Context, _ string) (map[string]any, error) {
	return b.Params, ctx.Err()
}
func (*Backend) Probe(context.Context, string) []core.Check {
	return []core.Check{{Name: "coredevice_tunnel", Status: "passed", Evidence: "fake probe"}}
}
func (b *Backend) Applications(ctx context.Context, _ string) ([]core.Application, error) {
	b.Record("applications")
	return b.Apps, ctx.Err()
}
func (b *Backend) Spawn(ctx context.Context, _ string, _ string) (int, error) {
	b.Record("spawn")
	if b.OnSpawn != nil {
		b.OnSpawn(ctx)
	}
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	if b.SpawnError != nil {
		return 0, b.SpawnError
	}
	return 42, nil
}
func (b *Backend) Attach(ctx context.Context, _ string, _ int, detached func(string)) (core.NativeSession, error) {
	b.Record("attach")
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if b.AttachError != nil {
		return nil, b.AttachError
	}
	s := &Session{Backend: b, Detached: detached}
	b.mu.Lock()
	b.Sessions = append(b.Sessions, s)
	b.mu.Unlock()
	return s, nil
}
func (b *Backend) Resume(ctx context.Context, _ string, _ int) error {
	b.Record("resume")
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if b.ResumeFailures > 0 {
		b.ResumeFailures--
		return b.ResumeError
	}
	return nil
}
func (b *Backend) Kill(ctx context.Context, _ string, _ int) error {
	b.Record("kill")
	return ctx.Err()
}
func (b *Backend) Close(context.Context) error { b.Record("backend.close"); return nil }

type Session struct {
	Backend  *Backend
	Detached func(string)
	Scripts  []*Script
	once     sync.Once
}

func (s *Session) CreateScript(ctx context.Context, _ string, _ string, message func(json.RawMessage, []byte), destroyed func()) (core.NativeScript, error) {
	s.Backend.Record("create")
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if s.Backend.CreateError != nil {
		return nil, s.Backend.CreateError
	}
	sc := &Script{Backend: s.Backend, Message: message, Destroyed: destroyed}
	s.Scripts = append(s.Scripts, sc)
	return sc, nil
}
func (s *Session) Detach(ctx context.Context) error {
	s.Backend.Record("detach")
	if ctx.Err() != nil {
		return ctx.Err()
	}
	s.Detached("requested")
	return nil
}
func (s *Session) Close() { s.once.Do(func() { s.Backend.Record("session.close") }) }

type Script struct {
	Backend   *Backend
	Message   func(json.RawMessage, []byte)
	Destroyed func()
	once      sync.Once
}

func (s *Script) Load(ctx context.Context) error {
	s.Backend.Record("load")
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.Backend.LoadError
}
func (s *Script) Unload(ctx context.Context) error {
	s.Backend.Record("unload")
	if ctx.Err() != nil {
		return ctx.Err()
	}
	s.Destroyed()
	return nil
}
func (s *Script) Post(ctx context.Context, msg json.RawMessage, data []byte) error {
	s.Backend.Record("post")
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if s.Backend.OnPost != nil {
		s.Backend.OnPost(ctx, s, msg)
		return nil
	}
	var rpc []json.RawMessage
	if json.Unmarshal(msg, &rpc) == nil && len(rpc) == 5 {
		var id, method string
		json.Unmarshal(rpc[1], &id)
		json.Unmarshal(rpc[3], &method)
		value := any("rpc-result")
		if method == "evaluate" {
			value = map[string]any{"value": 42, "undefined": false}
		}
		s.Reply(id, "ok", value)
	} else {
		s.Message(json.RawMessage(`{"type":"send","payload":"received"}`), data)
	}
	return nil
}
func (s *Script) Reply(id, status string, value any) {
	msg, _ := json.Marshal(map[string]any{"type": "send", "payload": []any{"frida:rpc", id, status, value}})
	s.Message(msg, nil)
}
func (s *Script) Close() { s.once.Do(func() { s.Backend.Record("script.close") }) }
