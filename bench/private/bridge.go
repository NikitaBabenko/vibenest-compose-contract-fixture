package privatefixture

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"sync"
)

// Bridge is disposable runner coordination, not production workload authority.
// Management methods are reachable only from the broker's private stdin channel.
type Bridge struct {
	Store          *Store
	mu             sync.Mutex
	capsules       map[string]envelope
	bootstrapReads map[string]int
	released       map[Scope]bool
}

func NewBridge(s *Store) *Bridge {
	return &Bridge{Store: s, capsules: map[string]envelope{}, bootstrapReads: map[string]int{}, released: map[Scope]bool{}}
}

func (b *Bridge) Pair(delivery, submission string) error {
	b.Store.mu.Lock()
	defer b.Store.mu.Unlock()
	d, e1 := b.Store.lookup(delivery)
	s, e2 := b.Store.lookup(submission)
	if e1 != nil || e2 != nil || !d.delivery || s.delivery || d.scope != s.scope {
		return ErrDenied
	}
	nonce := make([]byte, b.Store.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return ErrDenied
	}
	h := Hash([]byte(delivery))
	sealed := b.Store.aead.Seal(nil, nonce, []byte(submission), []byte(h))
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.capsules[h]; ok {
		return ErrDenied
	}
	b.capsules[h] = envelope{nonce, sealed}
	b.bootstrapReads[h] = 6
	return nil
}

type ManifestSlot struct {
	Digest string `json:"digest"`
	Size   int    `json:"size"`
}
type Manifest struct {
	Scope      Scope                   `json:"scope"`
	Slots      map[string]ManifestSlot `json:"slots"`
	Submission string                  `json:"submission"`
}

func (b *Bridge) manifest(t, deployment string) (Manifest, error) {
	b.Store.mu.Lock()
	defer b.Store.mu.Unlock()
	g, err := b.Store.lookup(t)
	if err != nil || !g.delivery || !g.scope.valid(true) || g.scope.Deployment != deployment {
		return Manifest{}, ErrDenied
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	h := Hash([]byte(t))
	e, ok := b.capsules[h]
	if !ok || b.bootstrapReads[h] <= 0 {
		return Manifest{}, ErrDenied
	}
	plain, err := b.Store.aead.Open(nil, e.Nonce, e.Ciphertext, []byte(h))
	if err != nil {
		return Manifest{}, ErrDenied
	}
	b.bootstrapReads[h]--
	m := Manifest{Scope: g.scope, Slots: map[string]ManifestSlot{}, Submission: string(plain)}
	for name, slot := range g.slots {
		m.Slots[name] = ManifestSlot{slot.Digest, len(slot.Data)}
	}
	return m, nil
}

// ReleaseFixture is explicitly runner-only and is NOT a production start gate.
func (b *Bridge) ReleaseFixture(scope Scope) error {
	b.Store.mu.Lock()
	defer b.Store.mu.Unlock()
	if _, ok := b.Store.sealed[scope]; !ok {
		return ErrDenied
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.released[scope] {
		return ErrDenied
	}
	b.released[scope] = true
	return nil
}

func (b *Bridge) Handler() http.Handler {
	base := b.Store.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		deny := func() { http.Error(w, "fixture request denied", 403) }
		if r.URL.Path == "/v1/bootstrap/helper" || r.URL.Path == "/v1/bootstrap/manifest" {
			if r.TLS == nil || r.Method != "GET" || r.URL.RawQuery != "" || r.URL.RawPath != "" || len(r.Header.Values("Authorization")) != 1 || len(r.Header.Values("X-Fixture-Deployment")) != 1 {
				deny()
				return
			}
			auth := r.Header.Get("Authorization")
			if len(auth) != 71 || auth[:7] != "Bearer " {
				deny()
				return
			}
			t := auth[7:]
			m, err := b.manifest(t, r.Header.Get("X-Fixture-Deployment"))
			if err != nil {
				deny()
				return
			}
			if r.URL.Path == "/v1/bootstrap/helper" {
				data, err := b.Store.Fetch(t, m.Scope, "helper")
				if err != nil {
					deny()
					return
				}
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = w.Write(data)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(m)
			return
		}
		if r.URL.Path == "/v1/release" {
			if r.TLS == nil || r.Method != "GET" || r.URL.RawQuery != "" || r.URL.RawPath != "" || len(r.Header.Values("Authorization")) != 1 || len(r.Header.Values("X-Fixture-Scope")) != 1 {
				deny()
				return
			}
			auth := r.Header.Get("Authorization")
			if len(auth) != 71 || auth[:7] != "Bearer " {
				deny()
				return
			}
			scope, err := parseScope(r.Header.Get("X-Fixture-Scope"))
			if err != nil {
				deny()
				return
			}
			b.Store.mu.Lock()
			g, err := b.Store.lookup(auth[7:])
			valid := err == nil && !g.delivery && g.used && g.scope == scope
			b.Store.mu.Unlock()
			if !valid {
				deny()
				return
			}
			b.mu.Lock()
			ready := b.released[scope]
			b.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]bool{"ready": ready})
			return
		}
		base.ServeHTTP(w, r)
	})
}

func (c *Client) Bootstrap(t, deployment string) (Manifest, error) {
	var m Manifest
	if !digest.MatchString(t) || !atom.MatchString(deployment) {
		return m, ErrDenied
	}
	r, err := http.NewRequest("GET", c.origin+"/v1/bootstrap/manifest", nil)
	if err != nil {
		return m, ErrDenied
	}
	r.Header.Set("Authorization", "Bearer "+t)
	r.Header.Set("X-Fixture-Deployment", deployment)
	resp, err := c.http.Do(r)
	if err != nil {
		return m, ErrDenied
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return m, ErrDenied
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(data) > 4096 {
		return m, ErrDenied
	}
	obj, ok := exactObject(data, "scope", "slots", "submission")
	if !ok || !exactScope(obj["scope"]) {
		return m, ErrDenied
	}
	var slots map[string]json.RawMessage
	if json.Unmarshal(obj["slots"], &slots) != nil || len(slots) < 2 || len(slots) > 3 {
		return m, ErrDenied
	}
	for name, value := range slots {
		if name != "helper" && name != "settings" && name != "runtime" {
			return m, ErrDenied
		}
		if _, ok := exactObject(value, "digest", "size"); !ok {
			return m, ErrDenied
		}
	}
	if json.Unmarshal(data, &m) != nil || !m.Scope.valid(true) || m.Scope.Deployment != deployment || !digest.MatchString(m.Submission) {
		return m, ErrDenied
	}
	for _, slot := range m.Slots {
		if !digest.MatchString(slot.Digest) || slot.Size < 1 || slot.Size > MaxHelper {
			return Manifest{}, ErrDenied
		}
	}
	if m.Slots["helper"].Digest != m.Scope.HelperDigest || m.Slots["settings"].Digest != m.Scope.SettingsDigest {
		return Manifest{}, ErrDenied
	}
	return m, nil
}

func (c *Client) Released(t string, scope Scope) (bool, error) {
	data, status, err := c.request("GET", "/v1/release", t, scope, nil, 128)
	if err != nil || status != 200 {
		return false, ErrDenied
	}
	if _, ok := exactObject(data, "ready"); !ok {
		return false, ErrDenied
	}
	var r struct {
		Ready bool `json:"ready"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if d.Decode(&r) != nil {
		return false, ErrDenied
	}
	return r.Ready, nil
}
