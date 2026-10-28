package core

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type Health struct {
	FridaVersion         string         `json:"frida_version"`
	HostOS               string         `json:"host_os"`
	Devices              []Device       `json:"devices"`
	DeviceID             string         `json:"device_id,omitempty"`
	Parameters           map[string]any `json:"parameters,omitempty"`
	Checks               []Check        `json:"checks"`
	ConnectivityReady    bool           `json:"connectivity_ready"`
	InstrumentationReady string         `json:"instrumentation_ready"`
}

func (m *Manager) Health(ctx context.Context, deviceID string) (Health, error) {
	ctx, done, err := m.begin(ctx)
	if err != nil {
		return Health{}, err
	}
	defer done()
	h := Health{FridaVersion: m.backend.Version(), HostOS: runtime.GOOS, Devices: []Device{}, Checks: []Check{}, InstrumentationReady: "unknown_until_target_attach"}
	h.Checks = append(h.Checks, Check{Name: "frida_core", Status: "passed", Evidence: m.backend.Version()})
	devices, err := m.backend.Devices(ctx)
	if err != nil {
		h.Checks[0] = Check{Name: "frida_core", Status: "failed", Evidence: err.Error(), Remediation: "Build with the pinned Frida Core devkit using just build; inspect host USB permissions."}
		return h, nil
	}
	h.Devices = devices
	d, err := m.selectDeviceFrom(devices, deviceID)
	if err != nil {
		h.Checks = append(h.Checks, Check{Name: "device_selection", Status: "failed", Evidence: err.Error(), Remediation: "Connect and unlock the iPhone, or pass an explicit device_id from list_devices."})
		if runtime.GOOS == "linux" {
			h.Checks = append(h.Checks, checkUsbmux(ctx))
		}
		return h, nil
	}
	h.DeviceID = d.ID
	h.Checks = append(h.Checks, Check{Name: "device_selection", Status: "passed", Evidence: d.Name + " (" + d.ID + ")"})
	h.Parameters, err = m.backend.Parameters(ctx, d.ID)
	if err != nil {
		h.Checks = append(h.Checks, Check{Name: "device_access", Status: "failed", Evidence: err.Error(), Remediation: "Unlock the device and establish trust/pairing using Frida's device tooling or your existing iOS setup tools."})
		return h, nil
	}
	h.ConnectivityReady = true
	h.Checks = append(h.Checks, Check{Name: "device_access", Status: "passed", Evidence: "Frida queried device system parameters successfully."})
	ios := isIOS(h.Parameters)
	if !ios {
		h.Checks = append(h.Checks, Check{Name: "jailed_ios", Status: "not_applicable", Evidence: "Device parameters do not identify iOS/iPadOS; generic Frida operations remain available."})
		return h, nil
	}
	if runtime.GOOS == "linux" {
		h.Checks = append(h.Checks, checkUsbmux(ctx))
	}
	h.Checks = append(h.Checks, m.backend.Probe(ctx, d.ID)...)
	h.Checks = append(h.Checks,
		Check{Name: "developer_mode", Status: "unknown", Evidence: "Generic Frida system parameters do not reliably expose Developer Mode state.", Remediation: "Enable Developer Mode on supported iOS versions; verify with your device setup tools if developer services fail."},
		Check{Name: "target_debuggable", Status: "unknown", Evidence: "No target app has been attached. An installed app is not proof of debuggability.", Remediation: "Use a developer-signed app with get-task-allow; App Store applications are outside the jailed workflow."},
	)
	cache, cacheErr := os.UserCacheDir()
	if cacheErr != nil {
		h.Checks = append(h.Checks, Check{Name: "gadget_cache", Status: "unknown", Evidence: cacheErr.Error()})
		return h, nil
	}
	path := filepath.Join(cache, "frida", "gadget-ios.dylib")
	file, openErr := os.Open(path)
	if openErr != nil {
		h.Checks = append(h.Checks, Check{Name: "gadget_cache", Status: "unknown", Evidence: fmt.Sprintf("Default cache %s is not readable: %v", path, openErr), Remediation: "Install matching Gadget using just gadget. The authoritative required path is supplied by Frida if attach fails."})
	} else {
		file.Close()
		h.Checks = append(h.Checks, Check{Name: "gadget_cache", Status: "passed", Evidence: path + " is readable; version/signature compatibility is verified only by attachment."})
	}
	return h, nil
}

func (m *Manager) selectDeviceFrom(devices []Device, id string) (Device, error) {
	var eligible []Device
	for _, d := range devices {
		if id != "" && d.ID == id {
			return d, nil
		}
		if d.Type == "usb" {
			eligible = append(eligible, d)
		}
	}
	if id != "" {
		return Device{}, Error("device_not_found", "specified device was not discovered")
	}
	if len(eligible) == 1 {
		return eligible[0], nil
	}
	if len(eligible) > 1 {
		return Device{}, Error("ambiguous_device", "multiple USB devices; provide device_id")
	}
	return Device{}, Error("device_not_found", "no USB devices discovered")
}

func isIOS(params map[string]any) bool {
	if info, ok := params["os"].(map[string]any); ok {
		for _, key := range []string{"id", "name"} {
			name := strings.ToLower(fmt.Sprint(info[key]))
			if name == "ios" || name == "ipados" || strings.Contains(name, "iphone") {
				return true
			}
		}
	}
	return false
}

func checkUsbmux(ctx context.Context) Check {
	network, address := "unix", "/var/run/usbmuxd"
	if override := os.Getenv("USBMUXD_SOCKET_ADDRESS"); override != "" {
		if strings.HasPrefix(override, "UNIX:") {
			address = strings.TrimPrefix(override, "UNIX:")
		} else if strings.HasPrefix(override, "unix://") {
			address = strings.TrimPrefix(override, "unix://")
		} else {
			network = "tcp"
			address = strings.TrimPrefix(override, "TCP:")
			if strings.HasPrefix(address, "tcp://") {
				if u, err := url.Parse(address); err == nil {
					address = u.Host
				}
			}
		}
	}
	dialer := net.Dialer{Timeout: time.Second}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return Check{Name: "usbmuxd", Status: "unknown", Evidence: address + ": " + err.Error(), Remediation: "If this Frida transport needs usbmuxd, start it externally and check socket permissions. A working native tunnel does not require this check to pass."}
	}
	conn.Close()
	return Check{Name: "usbmuxd", Status: "passed", Evidence: "Socket is reachable at " + address + "; device trust is checked separately through Frida."}
}
