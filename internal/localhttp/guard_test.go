package localhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHostAndOriginBoundary(t *testing.T) {
	guard := Guard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }), "8080")
	for _, test := range []struct {
		name, host, origin string
		want               int
	}{
		{"local", "127.0.0.1:8080", "", 204},
		{"localhost", "localhost:8080", "http://localhost:8080", 204},
		{"ipv6", "[::1]:8080", "http://[::1]:8080", 204},
		{"rebind", "evil.example:8080", "", 403},
		{"remote_origin", "127.0.0.1:8080", "https://evil.example", 403},
		{"null_origin", "127.0.0.1:8080", "null", 403},
		{"wrong_port", "127.0.0.1:9000", "", 403},
		{"wrong_origin_port", "127.0.0.1:8080", "http://localhost:9000", 403},
		{"userinfo", "127.0.0.1:8080", "http://evil@localhost:8080", 403},
		{"path", "127.0.0.1:8080", "http://localhost:8080/path", 403},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "http://127.0.0.1:8080/mcp", nil)
			r.Host = test.host
			if test.origin != "" {
				r.Header.Set("Origin", test.origin)
			}
			w := httptest.NewRecorder()
			guard.ServeHTTP(w, r)
			if w.Code != test.want {
				t.Fatalf("got %d want %d", w.Code, test.want)
			}
		})
	}
}

func TestListenRequiresLoopbackLiteral(t *testing.T) {
	for _, address := range []string{"0.0.0.0:8080", ":8080", "example.com:8080", "localhost:8080", "192.168.1.2:8080"} {
		if ValidateListen(address) == nil {
			t.Fatal(address)
		}
	}
	for _, address := range []string{"127.0.0.1:8080", "[::1]:0"} {
		if err := ValidateListen(address); err != nil {
			t.Fatal(err)
		}
	}
}
