package privatefixture

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func scopeHeader(scope Scope) string {
	b, _ := json.Marshal(scope)
	return base64.RawURLEncoding.EncodeToString(b)
}

func parseScope(h string) (Scope, error) {
	var scope Scope
	if len(h) > 2048 {
		return scope, ErrDenied
	}
	b, err := base64.RawURLEncoding.DecodeString(h)
	if err != nil || !strictJSON(b) {
		return scope, ErrDenied
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&scope) != nil || d.Decode(new(any)) != io.EOF || !scope.valid(true) {
		return scope, ErrDenied
	}
	return scope, nil
}

// Handler has no management endpoints and never echoes input, URLs, or errors.
// Run behind TLS with bounded headers/timeouts; disable request-body logging.
func (s *Store) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		deny := func() { http.Error(w, "fixture request denied", http.StatusForbidden) }
		if r.TLS == nil || r.URL.RawQuery != "" || r.URL.RawPath != "" || len(r.Header.Values("Authorization")) != 1 || len(r.Header.Values("X-Fixture-Scope")) != 1 {
			deny()
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			deny()
			return
		}
		t := strings.TrimPrefix(auth, "Bearer ")
		scope, err := parseScope(r.Header.Get("X-Fixture-Scope"))
		if err != nil {
			deny()
			return
		}
		switch {
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/delivery/"):
			b, err := s.Fetch(t, scope, strings.TrimPrefix(r.URL.Path, "/v1/delivery/"))
			if err != nil {
				deny()
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("X-Content-SHA256", Hash(b))
			_, _ = w.Write(b)
		case r.Method == "POST" && r.URL.Path == "/v1/artifact":
			if r.Header.Get("Content-Type") != "application/json" {
				deny()
				return
			}
			b, err := io.ReadAll(io.LimitReader(r.Body, MaxArtifact+1))
			if err != nil || len(b) > MaxArtifact {
				deny()
				return
			}
			h, err := s.Submit(t, scope, b)
			if err != nil {
				deny()
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"digest": h})
		case r.Method == "GET" && r.URL.Path == "/v1/receipt":
			h, err := s.Receipt(t, scope)
			if err != nil {
				deny()
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"digest": h})
		case r.Method == "POST" && r.URL.Path == "/v1/revoke":
			s.mu.Lock()
			g, err := s.lookup(t)
			if err != nil || g.scope != scope {
				s.mu.Unlock()
				deny()
				return
			}
			g.revoked = true
			g.slots = nil
			s.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			deny()
		}
	})
}

type Client struct {
	origin string
	http   *http.Client
}

// CA bytes must be hash-verified by the bootstrap before this constructor.
// There is no proxy/env trust, TLS fallback, alternate URL, redirect, or retry.
func NewClient(origin string, ca []byte) (*Client, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, ErrDenied
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, ErrDenied
	}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}, DisableCompression: true, MaxResponseHeaderBytes: 4096, ResponseHeaderTimeout: 10 * time.Second}
	return &Client{origin, &http.Client{Transport: tr, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrDenied }}}, nil
}

func (c *Client) request(method, path, t string, scope Scope, body []byte, limit int) ([]byte, int, error) {
	if !digest.MatchString(t) || !scope.valid(true) {
		return nil, 0, ErrDenied
	}
	r, err := http.NewRequest(method, c.origin+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, ErrDenied
	}
	r.Header.Set("Authorization", "Bearer "+t)
	r.Header.Set("X-Fixture-Scope", scopeHeader(scope))
	if method == "POST" {
		r.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(r)
	if err != nil {
		return nil, 0, ErrDenied
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return nil, resp.StatusCode, ErrDenied
	}
	if resp.ContentLength > int64(limit) {
		return nil, resp.StatusCode, ErrDenied
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit+1)))
	if err != nil || len(b) > limit {
		return nil, resp.StatusCode, ErrDenied
	}
	return b, resp.StatusCode, nil
}

func (c *Client) Fetch(t string, scope Scope, slot, expected string, expectedSize int) ([]byte, error) {
	limit := MaxArtifact
	if slot == "helper" {
		limit = MaxHelper
	}
	if (slot != "helper" && slot != "settings" && slot != "runtime") || !digest.MatchString(expected) || expectedSize < 1 || expectedSize > limit {
		return nil, ErrDenied
	}
	b, status, err := c.request("GET", "/v1/delivery/"+slot, t, scope, nil, expectedSize)
	if err != nil || status != http.StatusOK || len(b) != expectedSize || Hash(b) != expected {
		return nil, ErrDenied
	}
	return b, nil
}

func (c *Client) Submit(t string, scope Scope, data []byte) (string, error) {
	if len(data) == 0 || len(data) > MaxArtifact {
		return "", ErrDenied
	}
	b, status, err := c.request("POST", "/v1/artifact", t, scope, data, 256)
	if err != nil || status != http.StatusOK {
		return "", ErrDenied
	}
	return receiptDigest(b, Hash(data))
}

func receiptDigest(b []byte, expected string) (string, error) {
	var receipt struct {
		Digest string `json:"digest"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if !strictJSON(b) || d.Decode(&receipt) != nil || d.Decode(new(any)) != io.EOF || receipt.Digest != expected {
		return "", ErrDenied
	}
	return receipt.Digest, nil
}

func (c *Client) Receipt(t string, scope Scope, expected string) (string, error) {
	if !digest.MatchString(expected) {
		return "", ErrDenied
	}
	b, status, err := c.request("GET", "/v1/receipt", t, scope, nil, 256)
	if err != nil || status != http.StatusOK {
		return "", ErrDenied
	}
	return receiptDigest(b, expected)
}

func (c *Client) Revoke(t string, scope Scope) error {
	b, status, err := c.request("POST", "/v1/revoke", t, scope, nil, 1)
	if err != nil || status != http.StatusNoContent || len(b) != 0 {
		return ErrDenied
	}
	return nil
}
