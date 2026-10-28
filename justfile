FRIDA_VERSION := `cat .frida-version`
ARCH := `uname -m`
FRIDA_ARCH := if ARCH == "aarch64" { "arm64" } else if ARCH == "arm64" { "arm64" } else { "x86_64" }
DEVKIT := justfile_directory() / ".deps/frida-" + FRIDA_VERSION + "-linux-" + FRIDA_ARCH
export GOCACHE := env_var_or_default("GOCACHE", justfile_directory() / ".deps/go-build")
export GOMODCACHE := env_var_or_default("GOMODCACHE", justfile_directory() / ".deps/go-mod")
NATIVE_ENV := 'CGO_ENABLED=1 CGO_CFLAGS="-I' + DEVKIT + '" CGO_LDFLAGS="-L' + DEVKIT + '"'

deps:
    go mod tidy
    go mod verify

devkit:
    python3 tools/fetch_frida.py devkit

gadget:
    python3 tools/fetch_frida.py gadget

build: deps devkit
    mkdir -p bin
    {{ NATIVE_ENV }} go build -trimpath -tags frida -o bin/frida-mcp ./cmd/frida-mcp

test: deps
    go test -race ./...

test-core:
    GOPROXY=off go test -race ./internal/core ./internal/localhttp ./internal/native ./internal/testutil

test-native: deps devkit
    {{ NATIVE_ENV }} FRIDA_MCP_NATIVE_TEST=1 go test -race -tags frida ./internal/native -v

# Requires FRIDA_MCP_DEVICE_ID and FRIDA_MCP_IOS_BUNDLE_ID. This launches the app.
test-ios: deps devkit
    {{ NATIVE_ENV }} FRIDA_MCP_IOS_TEST=1 go test -race -tags frida ./internal/native -run TestIOSPipeline -v

check: deps
    go vet ./...
    test -z "$(gofmt -l cmd internal)"
