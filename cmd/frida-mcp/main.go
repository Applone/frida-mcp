package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/applone/frida-mcp/internal/core"
	"github.com/applone/frida-mcp/internal/localhttp"
	"github.com/applone/frida-mcp/internal/native"
	"github.com/applone/frida-mcp/internal/server"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	if err := run(); err != nil {
		slog.Error("frida-mcp stopped", "error", err)
		os.Exit(1)
	}
}

func run() (result error) {
	transport := flag.String("transport", "stdio", "stdio or http (http serves both Streamable HTTP and legacy SSE)")
	listen := flag.String("listen", "127.0.0.1:8080", "HTTP loopback listen address")
	timeout := flag.Duration("timeout", 30*time.Second, "maximum duration of a Frida operation")
	version := flag.Bool("version", false, "print server and linked Frida versions to stderr")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if *transport != "stdio" && *transport != "http" {
		return fmt.Errorf("transport must be stdio or http")
	}
	if *timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	if *transport == "http" {
		if err := localhttp.ValidateListen(*listen); err != nil {
			return err
		}
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)
	backend := native.New()
	if *version {
		fmt.Fprintf(os.Stderr, "frida-mcp %s; Frida %s\n", server.Version, backend.Version())
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		return backend.Close(ctx)
	}
	manager := core.NewManager(backend, core.Options{OperationTimeout: *timeout})
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		result = errors.Join(result, manager.Close(ctx))
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s := server.New(manager, logger)
	if *transport == "stdio" {
		err := s.Run(ctx, &mcp.StdioTransport{MaxLineLength: 4 << 20})
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	httpServer := &http.Server{Handler: server.HTTP(s, port), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	// No WriteTimeout: legacy SSE intentionally holds its response open.
	errCh := make(chan error, 1)
	go func() { errCh <- httpServer.Serve(listener) }()
	logger.Info("HTTP MCP listening", "streamable_http", "http://"+listener.Addr().String()+"/mcp", "sse", "http://"+listener.Addr().String()+"/sse")
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		// Close MCP streams before waiting for HTTP shutdown: legacy SSE
		// responses otherwise remain open for the entire grace period.
		for session := range s.Sessions() {
			session.Close()
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := httpServer.Shutdown(shutdownCtx)
		if err != nil {
			httpServer.Close()
		}
		return nil
	}
}
