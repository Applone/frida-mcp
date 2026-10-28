// Package localhttp enforces the server's local, single-user HTTP boundary.
package localhttp

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

func ValidateListen(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	// Require a literal loopback address to avoid DNS or wildcard surprises.
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("HTTP listen address must be a literal loopback IP, for example 127.0.0.1:8080")
	}
	return nil
}

func localAuthority(authority, port string) bool {
	host, p, err := net.SplitHostPort(authority)
	if err != nil || p != port {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Guard checks Host even in requests without Origin. Proxy headers never
// override this boundary. Browser origins must refer to this local listener.
func Guard(next http.Handler, port string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !localAuthority(r.Host, port) {
			http.Error(w, "invalid Host", http.StatusForbidden)
			return
		}
		if origins := r.Header.Values("Origin"); len(origins) > 0 {
			if len(origins) != 1 {
				http.Error(w, "invalid Origin", http.StatusForbidden)
				return
			}
			u, err := url.Parse(origins[0])
			if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || !localAuthority(u.Host, port) {
				http.Error(w, "invalid Origin", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
