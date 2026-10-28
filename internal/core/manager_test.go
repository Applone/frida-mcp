package core_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/applone/frida-mcp/internal/core"
	"github.com/applone/frida-mcp/internal/testutil"
)

func manager(t *testing.T) (*core.Manager, *testutil.Backend) {
	t.Helper()
	backend := testutil.New()
	m := core.NewManager(backend, core.Options{})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := m.Close(ctx); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return m, backend
}

func spawn(t *testing.T, m *core.Manager, paused bool) core.SessionInfo {
	t.Helper()
	info, err := m.Spawn(context.Background(), core.SpawnRequest{BundleID: "com.example.test", Paused: paused})
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestSpawnOrderingAndNormalDetach(t *testing.T) {
	m, b := manager(t)
	info, err := m.Spawn(context.Background(), core.SpawnRequest{BundleID: "com.example.test", Scripts: []core.ScriptSource{{Source: "send('ready')"}}})
	if err != nil {
		t.Fatal(err)
	}
	if info.State != "running" || len(info.Scripts) != 1 {
		t.Fatalf("info: %+v", info)
	}
	if got, want := b.History(), []string{"spawn", "attach", "create", "load", "resume"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("%v != %v", got, want)
	}
	if _, err = m.Detach(context.Background(), info.ID); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(b.History(), ","), "kill") {
		t.Fatal("normal detach killed target")
	}
}

func TestSpawnPartialFailureCleansOwnedTarget(t *testing.T) {
	for _, stage := range []string{"attach", "create", "load", "resume"} {
		t.Run(stage, func(t *testing.T) {
			m, b := manager(t)
			failure := errors.New("setup failed")
			switch stage {
			case "attach":
				b.AttachError = failure
			case "create":
				b.CreateError = failure
			case "load":
				b.LoadError = failure
			case "resume":
				b.ResumeError = failure
				b.ResumeFailures = 1
			}
			info, err := m.Spawn(context.Background(), core.SpawnRequest{BundleID: "com.example.test", Scripts: []core.ScriptSource{{Source: "send(1)"}}})
			if err == nil || info.ID == "" || info.State != "detached" {
				t.Fatalf("info=%+v err=%v", info, err)
			}
			calls := b.History()
			if !strings.Contains(strings.Join(calls, ","), "kill") {
				t.Fatalf("target not cleaned: %v", calls)
			}
			if stage != "attach" && !strings.Contains(strings.Join(calls, ","), "detach") {
				t.Fatalf("session not detached: %v", calls)
			}
		})
	}
}

func TestPausedSpawnResumesBeforeDetach(t *testing.T) {
	m, b := manager(t)
	info := spawn(t, m, true)
	if info.State != "paused" {
		t.Fatal(info.State)
	}
	if _, err := m.Detach(context.Background(), info.ID); err != nil {
		t.Fatal(err)
	}
	if got, want := b.History(), []string{"spawn", "attach", "resume", "detach", "session.close"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestResumeFailurePreservesSessionForRetry(t *testing.T) {
	m, b := manager(t)
	info := spawn(t, m, true)
	b.ResumeError = errors.New("offline")
	b.ResumeFailures = 1
	if _, err := m.Detach(context.Background(), info.ID); err == nil {
		t.Fatal("expected failure")
	}
	list, err := m.List(context.Background())
	if err != nil || list[0].State != "paused" {
		t.Fatalf("%+v %v", list, err)
	}
	if _, err = m.Detach(context.Background(), info.ID); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceSelectionAndAttachTarget(t *testing.T) {
	m, b := manager(t)
	b.DeviceList = append(b.DeviceList, core.Device{ID: "other", Type: "usb"})
	if _, err := m.Spawn(context.Background(), core.SpawnRequest{BundleID: "com.example.test"}); core.DescribeError(err).Code != "ambiguous_device" {
		t.Fatal(err)
	}
	if len(b.History()) != 0 {
		t.Fatal("spawn ran before device selection")
	}
	info, err := m.Attach(context.Background(), "iphone", 0, "com.example.test")
	if err != nil || info.PID != 42 {
		t.Fatalf("%+v %v", info, err)
	}
	if _, err = m.Attach(context.Background(), "iphone", 42, "com.example.test"); err == nil {
		t.Fatal("accepted two targets")
	}
	if _, err = m.Attach(context.Background(), "iphone", 0, "missing"); core.DescribeError(err).Code != "app_not_running" {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(b.History(), ","), "spawn") {
		t.Fatal("attach launched app")
	}
}

func TestSessionAndScriptIsolation(t *testing.T) {
	m, _ := manager(t)
	one := spawn(t, m, false)
	two := spawn(t, m, false)
	sc, err := m.Load(context.Background(), one.ID, core.ScriptSource{Source: "rpc.exports={hello(){return 1}}"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Call(context.Background(), two.ID, sc.ScriptID, "hello", nil); core.DescribeError(err).Code != "script_not_found" {
		t.Fatal(err)
	}
	if _, err = m.Call(context.Background(), one.ID, sc.ScriptID, "hello", nil); err != nil {
		t.Fatal(err)
	}
	if err = m.Unload(context.Background(), one.ID, sc.ScriptID); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Call(context.Background(), one.ID, sc.ScriptID, "hello", nil); err == nil {
		t.Fatal("used unloaded script")
	}
}

func TestEvaluateReusesAgentAndReturnsErrors(t *testing.T) {
	m, b := manager(t)
	info := spawn(t, m, false)
	for i := 0; i < 2; i++ {
		value, err := m.Evaluate(context.Background(), info.ID, "21 * 2")
		if err != nil || !strings.Contains(string(value), "42") {
			t.Fatalf("%s %v", value, err)
		}
	}
	if strings.Count(strings.Join(b.History(), ","), "create") != 1 {
		t.Fatal("evaluator was recreated")
	}
	b.OnPost = func(_ context.Context, sc *testutil.Script, msg json.RawMessage) {
		var rpc []json.RawMessage
		json.Unmarshal(msg, &rpc)
		var id string
		json.Unmarshal(rpc[1], &id)
		sc.Reply(id, "error", "ReferenceError: missing is not defined")
	}
	if _, err := m.Evaluate(context.Background(), info.ID, "missing"); core.DescribeError(err).Code != "javascript_error" {
		t.Fatal(err)
	}
}

func TestRPCLateReplyDoesNotCompleteNextCall(t *testing.T) {
	m, b := manager(t)
	info := spawn(t, m, false)
	sc, err := m.Load(context.Background(), info.ID, core.ScriptSource{Source: "rpc.exports={x(){}}"})
	if err != nil {
		t.Fatal(err)
	}
	var firstID string
	calls := 0
	b.OnPost = func(_ context.Context, script *testutil.Script, msg json.RawMessage) {
		var rpc []json.RawMessage
		json.Unmarshal(msg, &rpc)
		var id string
		json.Unmarshal(rpc[1], &id)
		calls++
		if calls == 1 {
			firstID = id
			return
		}
		script.Reply(firstID, "ok", "stale")
		script.Reply(id, "ok", "fresh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err = m.Call(ctx, info.ID, sc.ScriptID, "x", nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	value, err := m.Call(context.Background(), info.ID, sc.ScriptID, "x", nil)
	if err != nil || string(value) != `"fresh"` {
		t.Fatalf("%s %v", value, err)
	}
}

func TestDeviceLossUnblocksRPC(t *testing.T) {
	m, b := manager(t)
	info := spawn(t, m, false)
	sc, err := m.Load(context.Background(), info.ID, core.ScriptSource{Source: "send(1)"})
	if err != nil {
		t.Fatal(err)
	}
	b.OnPost = func(_ context.Context, _ *testutil.Script, _ json.RawMessage) { b.Sessions[0].Detached("device_lost") }
	if _, err = m.Call(context.Background(), info.ID, sc.ScriptID, "wait", nil); core.DescribeError(err).Code != "script_destroyed" {
		t.Fatal(err)
	}
	list, err := m.List(context.Background())
	if err != nil || list[0].State != "detached" {
		t.Fatalf("%+v %v", list, err)
	}
}

func TestWaitingSessionMutationRespectsCancellation(t *testing.T) {
	m, b := manager(t)
	info := spawn(t, m, false)
	sc, err := m.Load(context.Background(), info.ID, core.ScriptSource{Source: "rpc.exports = { wait() {} };"})
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan string, 1)
	b.OnPost = func(_ context.Context, _ *testutil.Script, message json.RawMessage) {
		var rpc []json.RawMessage
		json.Unmarshal(message, &rpc)
		var id string
		json.Unmarshal(rpc[1], &id)
		entered <- id
	}
	finished := make(chan error, 1)
	go func() { _, err := m.Call(context.Background(), info.ID, sc.ScriptID, "wait", nil); finished <- err }()
	id := <-entered
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := m.Detach(ctx, info.ID); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(b.History(), ","), "detach") {
		t.Fatal("cancelled queued operation detached the target")
	}
	// Delivery on the callback path remains live while the session gate is held.
	b.Sessions[0].Scripts[0].Reply(id, "ok", true)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if _, err := m.Detach(context.Background(), info.ID); err != nil {
		t.Fatal(err)
	}
}

func TestCloseCancelsInFlightOperationAndRejectsNewWork(t *testing.T) {
	m, b := manager(t)
	entered := make(chan struct{})
	b.OnSpawn = func(ctx context.Context) { close(entered); <-ctx.Done() }
	finished := make(chan error, 1)
	go func() {
		_, err := m.Spawn(context.Background(), core.SpawnRequest{BundleID: "com.example.test"})
		finished <- err
	}()
	<-entered
	if err := m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := m.Devices(context.Background()); core.DescribeError(err).Code != "server_closed" {
		t.Fatal(err)
	}
}

func TestConcurrentSessionsAndRetentionLimit(t *testing.T) {
	b := testutil.New()
	m := core.NewManager(b, core.Options{MaxSessions: 2})
	defer m.Close(context.Background())
	one := spawn(t, m, false)
	two := spawn(t, m, false)
	if _, err := m.Spawn(context.Background(), core.SpawnRequest{BundleID: "com.example.test"}); core.DescribeError(err).Code != "session_limit" {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, id := range []string{one.ID, two.ID} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := m.Detach(context.Background(), id); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	spawn(t, m, false)
}

func TestInputValidationPreventsNativeCalls(t *testing.T) {
	m, b := manager(t)
	for _, source := range []string{"", strings.Repeat("x", core.MaxScriptBytes+1), "send(1)\x00"} {
		if _, err := m.Spawn(context.Background(), core.SpawnRequest{BundleID: "com.example.test", Scripts: []core.ScriptSource{{Source: source}}}); err == nil {
			t.Fatal("invalid source accepted")
		}
	}
	if len(b.History()) != 0 {
		t.Fatal(b.History())
	}
}

func TestHealthSeparatesConnectivityFromTargetReadiness(t *testing.T) {
	m, _ := manager(t)
	h, err := m.Health(context.Background(), "iphone")
	if err != nil || !h.ConnectivityReady || h.InstrumentationReady != "unknown_until_target_attach" {
		t.Fatalf("%+v %v", h, err)
	}
	for _, check := range h.Checks {
		if check.Name == "target_debuggable" && check.Status != "unknown" {
			t.Fatal(check)
		}
	}
}
