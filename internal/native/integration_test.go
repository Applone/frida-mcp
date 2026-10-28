//go:build frida && cgo && linux

package native

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/applone/frida-mcp/internal/core"
)

// This exercises native ownership and GLib parameter conversion without
// requiring ptrace or injection privileges. Run with go test -tags frida.
func TestNativeDiscovery(t *testing.T) {
	b := New()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := b.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	if got := b.Version(); got != CoreVersion {
		t.Fatalf("linked Frida version %s, want %s", got, CoreVersion)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	devices, err := b.Devices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range devices {
		if device.Type != "local" {
			continue
		}
		parameters, err := b.Parameters(ctx, device.ID)
		if err != nil {
			t.Fatal(err)
		}
		if parameters["os"] == nil || parameters["arch"] == nil {
			t.Fatalf("missing native system parameters: %v", parameters)
		}
		return
	}
	t.Fatal("no local Frida device discovered")
}

func TestLocalNativePipeline(t *testing.T) {
	if os.Getenv("FRIDA_MCP_NATIVE_TEST") != "1" {
		t.Skip("set FRIDA_MCP_NATIVE_TEST=1 or use just test-native")
	}
	fixture := exec.Command("/bin/sleep", "60")
	if err := fixture.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { fixture.Process.Kill(); fixture.Wait() }()
	m := core.NewManager(New(), core.Options{})
	defer m.Close(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	devices, err := m.Devices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	local := ""
	for _, d := range devices {
		if d.Type == "local" {
			local = d.ID
			break
		}
	}
	if local == "" {
		t.Fatal("no local Frida device")
	}
	t.Logf("attaching to fixture PID %d on device %s", fixture.Process.Pid, local)
	info, err := m.Attach(ctx, local, fixture.Process.Pid, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("attached; exercising script messages, evaluation, and RPC")
	assertInstrumentation(t, ctx, m, info)
	if _, err = m.Detach(ctx, info.ID); err != nil {
		t.Fatal(err)
	}
}

func TestIOSPipeline(t *testing.T) {
	if os.Getenv("FRIDA_MCP_IOS_TEST") != "1" {
		t.Skip("use just test-ios with an explicit device and developer-signed bundle")
	}
	device, bundle := os.Getenv("FRIDA_MCP_DEVICE_ID"), os.Getenv("FRIDA_MCP_IOS_BUNDLE_ID")
	if device == "" || bundle == "" {
		t.Fatal("FRIDA_MCP_DEVICE_ID and FRIDA_MCP_IOS_BUNDLE_ID are required")
	}
	m := core.NewManager(New(), core.Options{OperationTimeout: 45 * time.Second})
	defer m.Close(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	health, err := m.Health(ctx, device)
	if err != nil || !health.ConnectivityReady {
		t.Fatalf("health=%+v err=%v", health, err)
	}
	apps, err := m.Applications(ctx, device)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, app := range apps.Applications {
		if app.Identifier == bundle {
			found = true
		}
	}
	if !found {
		t.Fatal("target bundle is not installed")
	}
	info, err := m.Spawn(ctx, core.SpawnRequest{DeviceID: device, BundleID: bundle, Paused: true, Scripts: []core.ScriptSource{{Name: "early.js", Source: "send({early: true});"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Resume(ctx, info.ID); err != nil {
		t.Fatal(err)
	}
	assertInstrumentation(t, ctx, m, info)
	if _, err = m.Detach(ctx, info.ID); err != nil {
		t.Fatal(err)
	}
}

func assertInstrumentation(t *testing.T, ctx context.Context, m *core.Manager, info core.SessionInfo) {
	t.Helper()
	script, err := m.Load(ctx, info.ID, core.ScriptSource{Name: "integration.js", Source: `send({ready: true}); console.log('integration log'); rpc.exports = { add(a, b) { return a + b; }, fail() { throw new Error('expected error'); } };`})
	if err != nil {
		t.Fatal(err)
	}
	value, err := m.Call(ctx, info.ID, script.ScriptID, "add", []any{2, 3})
	if err != nil || string(value) != "5" {
		t.Fatalf("%s %v", value, err)
	}
	if _, err = m.Call(ctx, info.ID, script.ScriptID, "fail", nil); core.DescribeError(err).Code != "javascript_error" {
		t.Fatal(err)
	}
	for _, source := range []string{"globalThis.mcpCounter = 40; mcpCounter", "globalThis.mcpCounter += 2; mcpCounter"} {
		if _, err = m.Evaluate(ctx, info.ID, source); err != nil {
			t.Fatal(err)
		}
	}
	value, err = m.Evaluate(ctx, info.ID, "globalThis.mcpCounter")
	if err != nil || !strings.Contains(string(value), "42") {
		t.Fatalf("%s %v", value, err)
	}
	page, err := m.Events.Read(ctx, info.ID, 0, 100, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range page.Events {
		var payload map[string]any
		if json.Unmarshal(event.Payload, &payload) == nil && payload["type"] == "send" {
			found = true
		}
	}
	if !found {
		t.Fatal("script send event not retained")
	}
	if err = m.Unload(ctx, info.ID, script.ScriptID); err != nil {
		t.Fatal(err)
	}
}
