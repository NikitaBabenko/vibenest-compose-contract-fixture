package privatefixture

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func tlsClient(t *testing.T, h http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(h)
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	c, err := NewClient(server.URL, ca)
	if err != nil {
		t.Fatal(err)
	}
	return c, server
}

func TestPinnedTLSRoundTrip(t *testing.T) {
	s, _ := testStore(t)
	scope := testScope()
	delivery := issue(t, s, scope, true)
	submission := issue(t, s, scope, false)
	c, _ := tlsClient(t, s.Handler())
	expected := []byte("private settings")
	got, err := c.Fetch(delivery, scope, "settings", Hash(expected), len(expected))
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatal("delivery failed", err)
	}
	if err := c.Revoke(delivery, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Fetch(delivery, scope, "settings", Hash(expected), len(expected)); err == nil {
		t.Fatal("revocation ineffective")
	}
	data := artifact(t, scope)
	if _, err := c.Submit(submission, scope, data); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Receipt(submission, scope, Hash(data)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Submit(submission, scope, data); err == nil {
		t.Fatal("replay")
	}
}

func TestRefusePlainHTTPAndMalformedScope(t *testing.T) {
	s, _ := testStore(t)
	scope := testScope()
	token := issue(t, s, scope, true)
	r := httptest.NewRequest("GET", "http://fixture.invalid/v1/delivery/settings", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("X-Fixture-Scope", scopeHeader(scope))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 || strings.Contains(w.Body.String(), token) {
		t.Fatal("HTTP accepted or token reflected")
	}
	if _, err := NewClient("http://fixture.invalid", nil); err == nil {
		t.Fatal("client accepts HTTP")
	}
	if _, err := parseScope(scopeHeader(scope) + "!"); err == nil {
		t.Fatal("malformed scope")
	}
}

func TestClientRejectsRedirectSizeHashAndPartialResponse(t *testing.T) {
	for _, mode := range []string{"redirect", "oversize", "undersize", "hash", "status"} {
		t.Run(mode, func(t *testing.T) {
			c, _ := tlsClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "redirect":
					http.Redirect(w, r, "https://example.invalid/token", 307)
				case "oversize":
					_, _ = w.Write([]byte("xxxx"))
				case "undersize":
					_, _ = w.Write([]byte("x"))
				case "hash":
					_, _ = w.Write([]byte("bad"))
				case "status":
					w.WriteHeader(204)
				}
			}))
			if _, err := c.Fetch(strings.Repeat("a", 64), testScope(), "settings", Hash([]byte("yes")), 3); err == nil {
				t.Fatal("unsafe response accepted")
			}
		})
	}
}

func TestWrongTrustRootFails(t *testing.T) {
	s, _ := testStore(t)
	c, server := tlsClient(t, s.Handler())
	// Use a deliberately empty trust pool: no OS or environment fallback.
	c.http.Transport.(*http.Transport).TLSClientConfig.RootCAs = x509.NewCertPool()
	if _, err := c.Fetch(strings.Repeat("a", 64), testScope(), "settings", Hash([]byte("yes")), 3); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
	// A malformed CA must be rejected before any HTTP request.
	if _, err := NewClient(server.URL, []byte("invalid CA")); err == nil {
		t.Fatal("invalid root accepted")
	}
}
