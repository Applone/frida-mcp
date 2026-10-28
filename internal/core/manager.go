package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const MaxScriptBytes = 1 << 20

type Options struct {
	OperationTimeout time.Duration
	MaxSessions      int
	MaxScripts       int
	Events           *Events
}

type Manager struct {
	backend  Backend
	opts     Options
	Events   *Events
	mu       sync.Mutex
	sessions map[string]*session
	closed   bool
	ctx      context.Context
	cancel   context.CancelFunc
	ops      sync.WaitGroup
}

type SessionInfo struct {
	ID        string    `json:"session_id"`
	DeviceID  string    `json:"device_id"`
	PID       int       `json:"pid"`
	BundleID  string    `json:"bundle_id,omitempty"`
	State     string    `json:"state"`
	Spawned   bool      `json:"spawned"`
	Scripts   []string  `json:"script_ids"`
	CreatedAt time.Time `json:"created_at"`
}

type session struct {
	gate      chan struct{}
	info      SessionInfo
	native    NativeSession
	scripts   map[string]*script
	evaluator *script
	ended     atomic.Bool
	peers     sync.Map // script ID -> *rpcPeer, safe in native callbacks
	disposed  bool
}

type script struct {
	id        string
	native    NativeScript
	rpc       *rpcPeer
	destroyed atomic.Bool
}

func NewManager(backend Backend, opts Options) *Manager {
	if opts.OperationTimeout <= 0 {
		opts.OperationTimeout = 30 * time.Second
	}
	if opts.MaxSessions <= 0 {
		opts.MaxSessions = 64
	}
	if opts.MaxScripts <= 0 {
		opts.MaxScripts = 32
	}
	if opts.Events == nil {
		opts.Events = NewEvents(0, 0, 0)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{backend: backend, opts: opts, Events: opts.Events, sessions: make(map[string]*session), ctx: ctx, cancel: cancel}
}

func opaqueID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

func (m *Manager) begin(ctx context.Context) (context.Context, func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, nil, Error("server_closed", "server is shutting down")
	}
	m.ops.Add(1)
	ctx, cancel := context.WithTimeout(ctx, m.opts.OperationTimeout)
	stop := context.AfterFunc(m.ctx, cancel)
	return ctx, func() { stop(); cancel(); m.ops.Done() }, nil
}

func (s *session) lock(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.gate:
	}
	if err := ctx.Err(); err != nil {
		s.unlock()
		return err
	}
	return nil
}
func (s *session) unlock() { s.gate <- struct{}{} }

func (m *Manager) get(ctx context.Context, id string, allowEnded bool) (*session, error) {
	m.mu.Lock()
	s := m.sessions[id]
	m.mu.Unlock()
	if s == nil {
		return nil, Error("session_not_found", "unknown session_id")
	}
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	if s.ended.Load() && !allowEnded {
		s.unlock()
		return nil, Error("session_ended", "session has ended; inspect read_events")
	}
	return s, nil
}

func (m *Manager) emit(s *session, typ string, value any) {
	payload, _ := json.Marshal(value)
	m.Events.Add(Event{SessionID: s.info.ID, Type: typ, Payload: payload})
}

func (m *Manager) end(s *session, reason string) {
	if s.ended.CompareAndSwap(false, true) {
		s.peers.Range(func(_, value any) bool { value.(*rpcPeer).close(); return true })
		m.emit(s, "detached", map[string]string{"reason": reason})
	}
}

func (s *session) snapshot() SessionInfo {
	info := s.info
	if s.ended.Load() {
		info.State = "detached"
	}
	info.Scripts = []string{}
	for id, script := range s.scripts {
		if !script.destroyed.Load() {
			info.Scripts = append(info.Scripts, id)
		}
	}
	sort.Strings(info.Scripts)
	return info
}

func (m *Manager) Devices(ctx context.Context) ([]Device, error) {
	ctx, done, err := m.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	return m.backend.Devices(ctx)
}

func (m *Manager) selectDevice(ctx context.Context, id string) (Device, error) {
	devices, err := m.backend.Devices(ctx)
	if err != nil {
		return Device{}, err
	}
	eligible := []Device{}
	for _, d := range devices {
		if id != "" && d.ID == id {
			return d, nil
		}
		if d.Type == "usb" {
			eligible = append(eligible, d)
		}
	}
	if id != "" {
		return Device{}, Error("device_not_found", "device_id was not found; call list_devices")
	}
	if len(eligible) == 0 {
		return Device{}, Error("device_not_found", "no USB devices found; specify device_id for a local or network device")
	}
	if len(eligible) != 1 {
		return Device{}, Error("ambiguous_device", "multiple USB devices found; supply device_id from list_devices")
	}
	return eligible[0], nil
}

type ApplicationsResult struct {
	DeviceID     string        `json:"device_id"`
	Applications []Application `json:"applications"`
}

func (m *Manager) Applications(ctx context.Context, deviceID string) (ApplicationsResult, error) {
	ctx, done, err := m.begin(ctx)
	if err != nil {
		return ApplicationsResult{}, err
	}
	defer done()
	d, err := m.selectDevice(ctx, deviceID)
	if err != nil {
		return ApplicationsResult{}, err
	}
	apps, err := m.backend.Applications(ctx, d.ID)
	if apps == nil {
		apps = []Application{}
	}
	sort.Slice(apps, func(i, j int) bool { return apps[i].Identifier < apps[j].Identifier })
	return ApplicationsResult{DeviceID: d.ID, Applications: apps}, err
}

type ScriptSource struct {
	Name   string `json:"name,omitempty"`
	Source string `json:"source"`
}
type SpawnRequest struct {
	DeviceID string         `json:"device_id,omitempty"`
	BundleID string         `json:"bundle_id"`
	Paused   bool           `json:"paused,omitempty"`
	Scripts  []ScriptSource `json:"scripts,omitempty"`
}

func validSource(source string) error {
	if strings.TrimSpace(source) == "" || len(source) > MaxScriptBytes || strings.ContainsRune(source, 0) {
		return Error("invalid_argument", "source must be nonempty JavaScript, at most 1 MiB, without NUL bytes")
	}
	return nil
}

func (m *Manager) reserve() (*session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sessions) >= m.opts.MaxSessions {
		// Evict only terminal sessions whose operations have finished.
		var oldest *session
		for _, candidate := range m.sessions {
			if candidate.ended.Load() && (oldest == nil || candidate.info.CreatedAt.Before(oldest.info.CreatedAt)) {
				oldest = candidate
			}
		}
		if oldest != nil {
			select {
			case <-oldest.gate:
				oldest.dispose()
				delete(m.sessions, oldest.info.ID)
				oldest.unlock()
			default:
			}
		}
	}
	if len(m.sessions) >= m.opts.MaxSessions {
		return nil, Error("session_limit", "session limit reached; detach an existing session")
	}
	s := &session{gate: make(chan struct{}, 1), scripts: make(map[string]*script), info: SessionInfo{ID: opaqueID(), State: "starting", CreatedAt: time.Now().UTC()}}
	// The caller owns the gate until setup is complete.
	m.sessions[s.info.ID] = s
	return s, nil
}

func (m *Manager) Spawn(ctx context.Context, req SpawnRequest) (info SessionInfo, err error) {
	if err = required(req.BundleID, "bundle_id"); err != nil {
		return
	}
	if strings.ContainsRune(req.BundleID, 0) {
		return info, Error("invalid_argument", "bundle_id contains a NUL byte")
	}
	if len(req.Scripts) > m.opts.MaxScripts {
		return info, Error("script_limit", "too many initial scripts")
	}
	for _, source := range req.Scripts {
		if err = validSource(source.Source); err != nil {
			return
		}
	}
	ctx, done, err := m.begin(ctx)
	if err != nil {
		return info, err
	}
	defer done()
	d, err := m.selectDevice(ctx, req.DeviceID)
	if err != nil {
		return info, err
	}
	s, err := m.reserve()
	if err != nil {
		return info, err
	}
	defer s.unlock()
	s.info.DeviceID, s.info.BundleID, s.info.Spawned = d.ID, req.BundleID, true
	defer func() {
		if err == nil {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var cleanupErr error
		if s.native != nil {
			cleanupErr = s.native.Detach(cleanupCtx)
		}
		if s.info.PID != 0 {
			cleanupErr = errors.Join(cleanupErr, m.backend.Kill(cleanupCtx, d.ID, s.info.PID))
		}
		if cleanupErr != nil {
			m.emit(s, "cleanup_error", map[string]string{"error": cleanupErr.Error()})
			err = errors.Join(err, fmt.Errorf("cleanup for session %s, pid %d: %w", s.info.ID, s.info.PID, cleanupErr))
		}
		m.end(s, "spawn_setup_failed")
		s.dispose()
		info = s.snapshot()
	}()
	s.info.PID, err = m.backend.Spawn(ctx, d.ID, req.BundleID)
	if err != nil {
		return info, err
	}
	s.info.State = "paused"
	s.native, err = m.backend.Attach(ctx, d.ID, s.info.PID, func(reason string) { m.end(s, reason) })
	if err != nil {
		return info, err
	}
	for _, source := range req.Scripts {
		if _, err = m.load(ctx, s, source); err != nil {
			return info, err
		}
	}
	if !req.Paused {
		if err = m.backend.Resume(ctx, d.ID, s.info.PID); err != nil {
			return info, err
		}
		s.info.State = "running"
	}
	if s.ended.Load() {
		return info, Error("session_ended", "target detached during spawn setup")
	}
	m.emit(s, "spawned", s.snapshot())
	return s.snapshot(), nil
}

func (m *Manager) Attach(ctx context.Context, deviceID string, pid int, bundleID string) (SessionInfo, error) {
	if (pid > 0) == (bundleID != "") || pid < 0 || uint64(pid) > uint64(^uint32(0)) {
		return SessionInfo{}, Error("invalid_argument", "provide exactly one of a positive pid or bundle_id")
	}
	ctx, done, err := m.begin(ctx)
	if err != nil {
		return SessionInfo{}, err
	}
	defer done()
	d, err := m.selectDevice(ctx, deviceID)
	if err != nil {
		return SessionInfo{}, err
	}
	if bundleID != "" {
		apps, err := m.backend.Applications(ctx, d.ID)
		if err != nil {
			return SessionInfo{}, err
		}
		for _, app := range apps {
			if app.Identifier == bundleID && app.PID > 0 {
				pid = app.PID
				break
			}
		}
		if pid == 0 {
			return SessionInfo{}, Error("app_not_running", "bundle_id has no running process; use spawn or open it on the device")
		}
	}
	s, err := m.reserve()
	if err != nil {
		return SessionInfo{}, err
	}
	defer s.unlock()
	s.info.DeviceID, s.info.PID, s.info.BundleID = d.ID, pid, bundleID
	s.native, err = m.backend.Attach(ctx, d.ID, pid, func(reason string) { m.end(s, reason) })
	if err != nil {
		m.end(s, "attach_failed")
		s.dispose()
		return s.snapshot(), err
	}
	s.info.State = "running"
	if s.ended.Load() {
		s.dispose()
		return s.snapshot(), Error("session_ended", "target detached during attach")
	}
	m.emit(s, "attached", s.snapshot())
	return s.snapshot(), nil
}

func (m *Manager) List(ctx context.Context) ([]SessionInfo, error) {
	ctx, done, err := m.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	m.mu.Lock()
	sessions := make([]*session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.mu.Unlock()
	result := []SessionInfo{}
	for _, s := range sessions {
		if err := s.lock(ctx); err != nil {
			return nil, err
		}
		if s.ended.Load() {
			s.dispose()
		}
		result = append(result, s.snapshot())
		s.unlock()
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.Before(result[j].CreatedAt) })
	return result, nil
}

func (m *Manager) Resume(ctx context.Context, id string) (SessionInfo, error) {
	ctx, done, err := m.begin(ctx)
	if err != nil {
		return SessionInfo{}, err
	}
	defer done()
	s, err := m.get(ctx, id, false)
	if err != nil {
		return SessionInfo{}, err
	}
	defer s.unlock()
	if s.info.State == "paused" {
		if err = m.backend.Resume(ctx, s.info.DeviceID, s.info.PID); err != nil {
			return s.snapshot(), err
		}
		s.info.State = "running"
		m.emit(s, "resumed", nil)
	}
	return s.snapshot(), nil
}

func (s *session) dispose() {
	if s.disposed {
		return
	}
	for _, sc := range s.scripts {
		sc.rpc.close()
		sc.native.Close()
	}
	s.scripts = make(map[string]*script)
	if s.native != nil {
		s.native.Close()
	}
	s.disposed = true
}

func (m *Manager) detach(ctx context.Context, s *session) error {
	if s.ended.Load() {
		s.dispose()
		return nil
	}
	if s.info.Spawned && s.info.State == "paused" {
		if err := m.backend.Resume(ctx, s.info.DeviceID, s.info.PID); err != nil {
			return err
		}
		s.info.State = "running"
	}
	if err := s.native.Detach(ctx); err != nil {
		return err
	}
	m.end(s, "requested")
	s.dispose()
	return nil
}

func (m *Manager) Detach(ctx context.Context, id string) (SessionInfo, error) {
	ctx, done, err := m.begin(ctx)
	if err != nil {
		return SessionInfo{}, err
	}
	defer done()
	s, err := m.get(ctx, id, true)
	if err != nil {
		return SessionInfo{}, err
	}
	defer s.unlock()
	err = m.detach(ctx, s)
	return s.snapshot(), err
}

func (m *Manager) load(ctx context.Context, s *session, source ScriptSource) (*script, error) {
	if len(s.scripts) >= m.opts.MaxScripts {
		return nil, Error("script_limit", "script limit reached; unload a script")
	}
	sc := &script{id: opaqueID(), rpc: newRPC()}
	if source.Name == "" {
		source.Name = sc.id + ".js"
	}
	if len(source.Name) > 256 || strings.ContainsRune(source.Name, 0) {
		return nil, Error("invalid_argument", "script name exceeds 256 bytes or contains NUL")
	}
	s.peers.Store(sc.id, sc.rpc)
	native, err := s.native.CreateScript(ctx, source.Name, source.Source, func(message json.RawMessage, data []byte) {
		if sc.rpc.receive(message) {
			return
		}
		m.Events.Add(Event{SessionID: s.info.ID, ScriptID: sc.id, Type: "message", Payload: message, Data: data})
	}, func() {
		if sc.destroyed.CompareAndSwap(false, true) {
			sc.rpc.close()
			m.Events.Add(Event{SessionID: s.info.ID, ScriptID: sc.id, Type: "script_destroyed"})
		}
	})
	if err != nil {
		sc.rpc.close()
		s.peers.Delete(sc.id)
		return nil, err
	}
	sc.native = native
	if err = native.Load(ctx); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cleanupErr := native.Unload(cleanupCtx)
		cancel()
		sc.rpc.close()
		native.Close()
		s.peers.Delete(sc.id)
		return nil, errors.Join(err, cleanupErr)
	}
	if sc.destroyed.Load() || s.ended.Load() {
		sc.rpc.close()
		native.Close()
		s.peers.Delete(sc.id)
		return nil, Error("script_destroyed", "script destroyed while loading")
	}
	s.scripts[sc.id] = sc
	m.Events.Add(Event{SessionID: s.info.ID, ScriptID: sc.id, Type: "script_loaded"})
	return sc, nil
}

type ScriptInfo struct {
	SessionID string `json:"session_id"`
	ScriptID  string `json:"script_id"`
}

func (m *Manager) Load(ctx context.Context, id string, source ScriptSource) (ScriptInfo, error) {
	if err := validSource(source.Source); err != nil {
		return ScriptInfo{}, err
	}
	ctx, done, err := m.begin(ctx)
	if err != nil {
		return ScriptInfo{}, err
	}
	defer done()
	s, err := m.get(ctx, id, false)
	if err != nil {
		return ScriptInfo{}, err
	}
	defer s.unlock()
	sc, err := m.load(ctx, s, source)
	if err != nil {
		return ScriptInfo{}, err
	}
	return ScriptInfo{SessionID: id, ScriptID: sc.id}, nil
}

func findScript(s *session, id string) (*script, error) {
	sc := s.scripts[id]
	if sc == nil {
		return nil, Error("script_not_found", "script_id does not belong to this session")
	}
	if sc.destroyed.Load() {
		return nil, Error("script_destroyed", "script is no longer available")
	}
	return sc, nil
}

func (m *Manager) Unload(ctx context.Context, id, scriptID string) error {
	ctx, done, err := m.begin(ctx)
	if err != nil {
		return err
	}
	defer done()
	s, err := m.get(ctx, id, false)
	if err != nil {
		return err
	}
	defer s.unlock()
	sc := s.scripts[scriptID]
	if sc == nil {
		return Error("script_not_found", "unknown script_id")
	}
	if !sc.destroyed.Load() {
		if err = sc.native.Unload(ctx); err != nil {
			return err
		}
	}
	sc.destroyed.Store(true)
	sc.rpc.close()
	sc.native.Close()
	delete(s.scripts, scriptID)
	s.peers.Delete(scriptID)
	if s.evaluator == sc {
		s.evaluator = nil
	}
	m.Events.Add(Event{SessionID: id, ScriptID: scriptID, Type: "script_unloaded"})
	return nil
}

func (m *Manager) Evaluate(ctx context.Context, id, source string) (json.RawMessage, error) {
	if err := validSource(source); err != nil {
		return nil, err
	}
	ctx, done, err := m.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	s, err := m.get(ctx, id, false)
	if err != nil {
		return nil, err
	}
	defer s.unlock()
	if s.evaluator == nil || s.evaluator.destroyed.Load() {
		s.evaluator, err = m.load(ctx, s, ScriptSource{Name: "mcp-evaluator.js", Source: evaluatorSource})
		if err != nil {
			return nil, err
		}
	}
	return s.evaluator.rpc.call(ctx, s.evaluator.native.Post, "evaluate", []any{source})
}

func (m *Manager) Call(ctx context.Context, id, scriptID, method string, args []any) (json.RawMessage, error) {
	if err := required(method, "method"); err != nil {
		return nil, err
	}
	ctx, done, err := m.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	s, err := m.get(ctx, id, false)
	if err != nil {
		return nil, err
	}
	defer s.unlock()
	sc, err := findScript(s, scriptID)
	if err != nil {
		return nil, err
	}
	return sc.rpc.call(ctx, sc.native.Post, method, args)
}

func (m *Manager) Post(ctx context.Context, id, scriptID string, message json.RawMessage, data []byte) error {
	if !json.Valid(message) || len(message) > MaxScriptBytes || len(data) > MaxScriptBytes {
		return Error("invalid_argument", "message must be valid JSON; message and binary data must each be at most 1 MiB")
	}
	ctx, done, err := m.begin(ctx)
	if err != nil {
		return err
	}
	defer done()
	s, err := m.get(ctx, id, false)
	if err != nil {
		return err
	}
	defer s.unlock()
	sc, err := findScript(s, scriptID)
	if err != nil {
		return err
	}
	return sc.native.Post(ctx, message, data)
}

func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	m.cancel()
	m.mu.Unlock()
	// All native operations receive cancellation, and must return before we free
	// native objects. Never release pointers underneath an in-flight operation.
	m.ops.Wait()
	var result error
	for _, s := range m.sessions {
		result = errors.Join(result, m.detach(ctx, s))
		m.end(s, "server_shutdown")
		s.dispose()
	}
	return errors.Join(result, m.backend.Close(ctx))
}

func (m *Manager) String() string { return fmt.Sprintf("Frida %s", m.backend.Version()) }
