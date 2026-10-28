//go:build frida && cgo && linux

package native

/*
#cgo LDFLAGS: -lfrida-core -ldl -lrt -lresolv -lm -lpthread
#cgo CFLAGS: -pthread
#include "bridge.h"
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/applone/frida-mcp/internal/core"
)

const CoreVersion = "17.24.3"

var initialize sync.Once
var callbackIDs atomic.Uint64
var callbackRegistry sync.Map

type callbacks struct {
	message   func(json.RawMessage, []byte)
	destroyed func()
	detached  func(string)
}

// An integer ID crosses C; no Go pointer is retained by GLib. Removing an ID is
// safe even when a callback already entered Go: its loaded value remains alive.
func register(cb callbacks) C.uintptr_t {
	id := callbackIDs.Add(1)
	callbackRegistry.Store(id, cb)
	return C.uintptr_t(id)
}

//export goFridaDetached
func goFridaDetached(id C.uintptr_t, reason *C.char) {
	if value, ok := callbackRegistry.Load(uint64(id)); ok {
		if fn := value.(callbacks).detached; fn != nil {
			fn(C.GoString(reason))
		}
	}
}

//export goFridaDestroyed
func goFridaDestroyed(id C.uintptr_t) {
	if value, ok := callbackRegistry.Load(uint64(id)); ok {
		if fn := value.(callbacks).destroyed; fn != nil {
			fn()
		}
	}
}

//export goFridaMessage
func goFridaMessage(id C.uintptr_t, message *C.char, data unsafe.Pointer, size C.size_t) {
	value, ok := callbackRegistry.Load(uint64(id))
	if !ok {
		return
	}
	cb := value.(callbacks)
	if cb.message == nil {
		return
	}
	// Never copy an unbounded target-controlled message onto the Go heap.
	if size > 64<<10 || C.strnlen(message, 65537) > 64<<10 {
		cb.message(json.RawMessage(`{"type":"error","description":"native message exceeded 64 KiB; payload omitted","truncated":true}`), nil)
		return
	}
	var bytes []byte
	if size > 0 {
		bytes = C.GoBytes(data, C.int(size))
	}
	cb.message(json.RawMessage(C.GoString(message)), bytes)
}

type Backend struct {
	manager *C.FridaDeviceManager
	once    sync.Once
}

func New() *Backend {
	initialize.Do(func() { C.frida_init() })
	return &Backend{manager: C.frida_device_manager_new()}
}
func (*Backend) Version() string { return C.GoString(C.frida_version_string()) }

// The native call runs on the caller. Only the cancellation signal is scheduled
// with AfterFunc; wait for it to finish before releasing GCancellable.
func cancellation(ctx context.Context) (*C.GCancellable, func()) {
	c := C.g_cancellable_new()
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { C.g_cancellable_cancel(c); close(finished) })
	return c, func() {
		if !stop() {
			<-finished
		}
		C.g_object_unref(C.gpointer(c))
	}
}

func nativeError(ctx context.Context, e *C.GError) error {
	if e == nil {
		return nil
	}
	message := C.GoString(e.message)
	C.g_error_free(e)
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %s", err, message)
	}
	remediation := "Run health_check for this device. On jailed iOS, use a developer-signed debuggable application and matching Gadget."
	lower := strings.ToLower(message)
	if strings.Contains(lower, "gadget") {
		remediation = "Install Gadget matching Frida Core " + CoreVersion + " at the path reported by Frida; see just gadget."
	}
	if strings.Contains(lower, "pair") || strings.Contains(lower, "trust") {
		remediation = "Unlock the device and establish trust/pairing using existing iOS setup tools."
	}
	return &core.ToolError{Code: "frida_error", Message: message, Remediation: remediation}
}

func (b *Backend) Devices(ctx context.Context) ([]core.Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c, done := cancellation(ctx)
	defer done()
	var e *C.GError
	list := C.frida_device_manager_enumerate_devices_sync(b.manager, c, &e)
	if err := nativeError(ctx, e); err != nil {
		return nil, err
	}
	defer C.frida_unref(C.gpointer(list))
	result := []core.Device{}
	for i := C.gint(0); i < C.frida_device_list_size(list); i++ {
		d := C.frida_device_list_get(list, i)
		typ := "remote"
		switch C.frida_device_get_dtype(d) {
		case C.FRIDA_DEVICE_TYPE_LOCAL:
			typ = "local"
		case C.FRIDA_DEVICE_TYPE_USB:
			typ = "usb"
		}
		result = append(result, core.Device{ID: C.GoString(C.frida_device_get_id(d)), Name: C.GoString(C.frida_device_get_name(d)), Type: typ})
		C.frida_unref(C.gpointer(d))
	}
	return result, nil
}

func (b *Backend) device(ctx context.Context, id string, c *C.GCancellable) (*C.FridaDevice, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	name := C.CString(id)
	defer C.free(unsafe.Pointer(name))
	var e *C.GError
	d := C.frida_device_manager_get_device_by_id_sync(b.manager, name, 0, c, &e)
	return d, nativeError(ctx, e)
}

func variant(v *C.GVariant, depth int) any {
	if v == nil || depth > 16 {
		return nil
	}
	typ := C.GoString(C.g_variant_get_type_string(v))
	switch typ {
	case "s", "o", "g":
		return C.GoString(C.g_variant_get_string(v, nil))
	case "b":
		return C.g_variant_get_boolean(v) != 0
	case "y":
		return uint8(C.g_variant_get_byte(v))
	case "n":
		return int16(C.g_variant_get_int16(v))
	case "q":
		return uint16(C.g_variant_get_uint16(v))
	case "i":
		return int32(C.g_variant_get_int32(v))
	case "u":
		return uint32(C.g_variant_get_uint32(v))
	case "x":
		return int64(C.g_variant_get_int64(v))
	case "t":
		return uint64(C.g_variant_get_uint64(v))
	case "d":
		return float64(C.g_variant_get_double(v))
	case "v":
		inner := C.g_variant_get_variant(v)
		defer C.g_variant_unref(inner)
		return variant(inner, depth+1)
	case "a{sv}":
		result := map[string]any{}
		count := C.g_variant_n_children(v)
		if count > 4096 {
			count = 4096
		}
		for i := C.gsize(0); i < count; i++ {
			entry := C.g_variant_get_child_value(v, i)
			key := C.g_variant_get_child_value(entry, 0)
			value := C.g_variant_get_child_value(entry, 1)
			result[C.GoString(C.g_variant_get_string(key, nil))] = variant(value, depth+1)
			C.g_variant_unref(value)
			C.g_variant_unref(key)
			C.g_variant_unref(entry)
		}
		return result
	default:
		if strings.HasPrefix(typ, "a") || strings.HasPrefix(typ, "(") {
			result := []any{}
			count := C.g_variant_n_children(v)
			if count > 4096 {
				count = 4096
			}
			for i := C.gsize(0); i < count; i++ {
				item := C.g_variant_get_child_value(v, i)
				result = append(result, variant(item, depth+1))
				C.g_variant_unref(item)
			}
			return result
		}
		return nil
	}
}

func (b *Backend) Parameters(ctx context.Context, id string) (map[string]any, error) {
	c, done := cancellation(ctx)
	defer done()
	d, err := b.device(ctx, id, c)
	if err != nil {
		return nil, err
	}
	defer C.frida_unref(C.gpointer(d))
	var e *C.GError
	params := C.frida_device_query_system_parameters_sync(d, c, &e)
	if err = nativeError(ctx, e); err != nil {
		return nil, err
	}
	defer C.g_hash_table_unref(params)
	keys := C.g_hash_table_get_keys(params)
	defer C.g_list_free(keys)
	result := map[string]any{}
	for node := keys; node != nil; node = node.next {
		key := C.GoString((*C.char)(node.data))
		result[key] = variant((*C.GVariant)(C.g_hash_table_lookup(params, C.gconstpointer(node.data))), 0)
	}
	return result, nil
}

func (b *Backend) Probe(ctx context.Context, id string) []core.Check {
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c, done := cancellation(probeCtx)
	defer done()
	d, err := b.device(probeCtx, id, c)
	if err != nil {
		return []core.Check{{Name: "developer_services", Status: "failed", Evidence: err.Error(), Remediation: "Check device connectivity and trust."}}
	}
	defer C.frida_unref(C.gpointer(d))
	// CoreDevice is a version-dependent capability: opening a service is a
	// read-only reachability probe, never an application launch.
	address := C.CString("xpc:com.apple.coredevice.appservice")
	defer C.free(unsafe.Pointer(address))
	var e *C.GError
	service := C.frida_device_open_service_sync(d, address, c, &e)
	if err = nativeError(probeCtx, e); err != nil {
		return []core.Check{{Name: "coredevice_tunnel", Status: "unknown", Evidence: err.Error(), Remediation: "On iOS 17+, verify pairing, developer image/services and tunnel access. Older iOS versions use legacy developer services; this probe alone does not establish failure."},
			{Name: "developer_image", Status: "unknown", Evidence: "Frida could not verify developer-service access.", Remediation: "Use existing host tooling to verify/mount the appropriate Developer Disk Image."}}
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Second)
	defer cleanupCancel()
	cleanupC, cleanupDone := cancellation(cleanupCtx)
	defer cleanupDone()
	var cleanupError *C.GError
	C.frida_service_cancel_sync(service, cleanupC, &cleanupError)
	if cleanupError != nil {
		C.g_error_free(cleanupError)
	}
	C.frida_unref(C.gpointer(service))
	return []core.Check{{Name: "coredevice_tunnel", Status: "passed", Evidence: "Frida opened com.apple.coredevice.appservice through its selected transport."},
		{Name: "developer_image", Status: "unknown", Evidence: "CoreDevice is reachable; image mount state and debugserver readiness were not directly queried.", Remediation: "If attachment fails, verify the appropriate Developer Disk Image and debugging services using host tooling."}}
}

func (b *Backend) Applications(ctx context.Context, id string) ([]core.Application, error) {
	c, done := cancellation(ctx)
	defer done()
	d, err := b.device(ctx, id, c)
	if err != nil {
		return nil, err
	}
	defer C.frida_unref(C.gpointer(d))
	opts := C.frida_application_query_options_new()
	defer C.frida_unref(C.gpointer(opts))
	C.frida_application_query_options_set_scope(opts, C.FRIDA_SCOPE_MINIMAL)
	var e *C.GError
	list := C.frida_device_enumerate_applications_sync(d, opts, c, &e)
	if err = nativeError(ctx, e); err != nil {
		return nil, err
	}
	defer C.frida_unref(C.gpointer(list))
	result := []core.Application{}
	for i := C.gint(0); i < C.frida_application_list_size(list); i++ {
		app := C.frida_application_list_get(list, i)
		result = append(result, core.Application{Identifier: C.GoString(C.frida_application_get_identifier(app)), Name: C.GoString(C.frida_application_get_name(app)), PID: int(C.frida_application_get_pid(app))})
		C.frida_unref(C.gpointer(app))
	}
	return result, nil
}

func (b *Backend) Spawn(ctx context.Context, id, bundle string) (int, error) {
	c, done := cancellation(ctx)
	defer done()
	d, err := b.device(ctx, id, c)
	if err != nil {
		return 0, err
	}
	defer C.frida_unref(C.gpointer(d))
	name := C.CString(bundle)
	defer C.free(unsafe.Pointer(name))
	opts := C.frida_spawn_options_new()
	defer C.frida_unref(C.gpointer(opts))
	// Local child output must never leak onto the MCP stdio transport.
	C.frida_spawn_options_set_stdio(opts, C.FRIDA_STDIO_PIPE)
	var e *C.GError
	pid := C.frida_device_spawn_sync(d, name, opts, c, &e)
	return int(pid), nativeError(ctx, e)
}

func (b *Backend) Resume(ctx context.Context, id string, pid int) error {
	c, done := cancellation(ctx)
	defer done()
	d, err := b.device(ctx, id, c)
	if err != nil {
		return err
	}
	defer C.frida_unref(C.gpointer(d))
	var e *C.GError
	C.frida_device_resume_sync(d, C.guint(pid), c, &e)
	return nativeError(ctx, e)
}

func (b *Backend) Kill(ctx context.Context, id string, pid int) error {
	c, done := cancellation(ctx)
	defer done()
	d, err := b.device(ctx, id, c)
	if err != nil {
		return err
	}
	defer C.frida_unref(C.gpointer(d))
	var e *C.GError
	C.frida_device_kill_sync(d, C.guint(pid), c, &e)
	return nativeError(ctx, e)
}

type nativeSession struct {
	ptr      *C.FridaSession
	callback C.uintptr_t
	signal   C.gulong
	once     sync.Once
}

func (b *Backend) Attach(ctx context.Context, id string, pid int, onDetach func(string)) (core.NativeSession, error) {
	c, done := cancellation(ctx)
	defer done()
	d, err := b.device(ctx, id, c)
	if err != nil {
		return nil, err
	}
	defer C.frida_unref(C.gpointer(d))
	opts := C.frida_session_options_new()
	defer C.frida_unref(C.gpointer(opts))
	var e *C.GError
	ptr := C.frida_device_attach_sync(d, C.guint(pid), opts, c, &e)
	if err = nativeError(ctx, e); err != nil {
		return nil, err
	}
	s := &nativeSession{ptr: ptr, callback: register(callbacks{detached: onDetach})}
	s.signal = C.fm_connect_detached(ptr, s.callback)
	if C.frida_session_is_detached(ptr) != 0 {
		onDetach("detached_during_attach")
	}
	return s, nil
}

func (s *nativeSession) Detach(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c, done := cancellation(ctx)
	defer done()
	var e *C.GError
	C.frida_session_detach_sync(s.ptr, c, &e)
	return nativeError(ctx, e)
}

func (s *nativeSession) Close() {
	s.once.Do(func() {
		C.g_signal_handler_disconnect(C.gpointer(s.ptr), s.signal)
		callbackRegistry.Delete(uint64(s.callback))
		C.frida_unref(C.gpointer(s.ptr))
	})
}

type nativeScript struct {
	ptr                          *C.FridaScript
	callback                     C.uintptr_t
	messageSignal, destroySignal C.gulong
	once                         sync.Once
}

func (s *nativeSession) CreateScript(ctx context.Context, name, source string, onMessage func(json.RawMessage, []byte), onDestroyed func()) (core.NativeScript, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c, done := cancellation(ctx)
	defer done()
	text := C.CString(source)
	defer C.free(unsafe.Pointer(text))
	label := C.CString(name)
	defer C.free(unsafe.Pointer(label))
	opts := C.frida_script_options_new()
	defer C.frida_unref(C.gpointer(opts))
	C.frida_script_options_set_name(opts, label)
	C.frida_script_options_set_runtime(opts, C.FRIDA_SCRIPT_RUNTIME_QJS)
	var e *C.GError
	ptr := C.frida_session_create_script_sync(s.ptr, text, opts, c, &e)
	if err := nativeError(ctx, e); err != nil {
		return nil, err
	}
	sc := &nativeScript{ptr: ptr, callback: register(callbacks{message: onMessage, destroyed: onDestroyed})}
	sc.messageSignal = C.fm_connect_message(ptr, sc.callback)
	sc.destroySignal = C.fm_connect_destroyed(ptr, sc.callback)
	if C.frida_script_is_destroyed(ptr) != 0 {
		onDestroyed()
	}
	return sc, nil
}

func (s *nativeScript) Load(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c, done := cancellation(ctx)
	defer done()
	var e *C.GError
	C.frida_script_load_sync(s.ptr, c, &e)
	return nativeError(ctx, e)
}

func (s *nativeScript) Unload(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c, done := cancellation(ctx)
	defer done()
	var e *C.GError
	C.frida_script_unload_sync(s.ptr, c, &e)
	return nativeError(ctx, e)
}

func (s *nativeScript) Post(ctx context.Context, message json.RawMessage, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	text := C.CString(string(message))
	defer C.free(unsafe.Pointer(text))
	var bytes *C.GBytes
	if len(data) > 0 {
		bytes = C.g_bytes_new(C.gconstpointer(&data[0]), C.gsize(len(data)))
		defer C.g_bytes_unref(bytes)
	}
	// post copies/queues the data synchronously; RPC completion has its own
	// deadline and pending map in core. No blocking native wait is introduced.
	C.frida_script_post(s.ptr, text, bytes)
	return nil
}

func (s *nativeScript) Close() {
	s.once.Do(func() {
		C.g_signal_handler_disconnect(C.gpointer(s.ptr), s.messageSignal)
		C.g_signal_handler_disconnect(C.gpointer(s.ptr), s.destroySignal)
		callbackRegistry.Delete(uint64(s.callback))
		C.frida_unref(C.gpointer(s.ptr))
	})
}

func (b *Backend) Close(ctx context.Context) (err error) {
	b.once.Do(func() {
		c, done := cancellation(ctx)
		defer done()
		var e *C.GError
		C.frida_device_manager_close_sync(b.manager, c, &e)
		err = nativeError(ctx, e)
		C.frida_unref(C.gpointer(b.manager))
	})
	return err
}
