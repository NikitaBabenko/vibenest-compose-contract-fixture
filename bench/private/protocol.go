// Package privatefixture implements disposable test capabilities, not production
// workload identity, admission, or authenticated physical-storage observations.
package privatefixture

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sync"
	"time"
)

var ErrDenied = errors.New("fixture request denied")
var atom = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,96}$`)
var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var commit = regexp.MustCompile(`^[a-f0-9]{40}$`)

const MaxArtifact = 4 << 20
const MaxHelper = 16 << 20

// Scope is immutable. Deployment must be bound after the native dispatch ACK.
// Matching these fields is a capability check, never host proof-of-possession.
type Scope struct {
	Project        string `json:"project"`
	Application    string `json:"application"`
	Attempt        string `json:"attempt"`
	Deployment     string `json:"deployment"`
	Generation     uint64 `json:"generation"`
	SourceSHA      string `json:"sourceSha"`
	HelperDigest   string `json:"helperDigest"`
	SettingsDigest string `json:"settingsDigest"`
}

func (s Scope) valid(bound bool) bool {
	return atom.MatchString(s.Project) && atom.MatchString(s.Application) && atom.MatchString(s.Attempt) &&
		((!bound && s.Deployment == "") || atom.MatchString(s.Deployment)) && s.Generation > 0 &&
		commit.MatchString(s.SourceSHA) && digest.MatchString(s.HelperDigest) && digest.MatchString(s.SettingsDigest)
}

func Hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

type Slot struct {
	Data   []byte
	Digest string
	Reads  int // A small finite allowance for identical, bounded delivery retries.
}

type grant struct {
	scope    Scope
	expires  time.Time
	revoked  bool
	delivery bool
	slots    map[string]Slot
	used     bool
}

type envelope struct{ Nonce, Ciphertext []byte }

// Store contains only token hashes, encrypted submitted config, and delivery
// artifacts. The AEAD key is runner-only and must never enter the native helper.
type Store struct {
	mu       sync.Mutex
	now      func() time.Time
	aead     cipher.AEAD
	grants   map[string]*grant
	sealed   map[Scope]envelope
	receipts map[Scope]string
}

func NewStore(key []byte, now func() time.Time) (*Store, error) {
	if len(key) != 32 || now == nil {
		return nil, ErrDenied
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrDenied
	}
	aead, err := cipher.NewGCM(b)
	if err != nil {
		return nil, ErrDenied
	}
	return &Store{now: now, aead: aead, grants: map[string]*grant{}, sealed: map[Scope]envelope{}, receipts: map[Scope]string{}}, nil
}

func token() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Issue is a runner-side method. It is deliberately not exposed over HTTP.
func (s *Store) Issue(scope Scope, ttl time.Duration, slots map[string]Slot, delivery bool) (string, error) {
	if !scope.valid(false) || ttl <= 0 || ttl > 10*time.Minute || (delivery && len(slots) == 0) || (!delivery && len(slots) != 0) {
		return "", ErrDenied
	}
	copySlots := map[string]Slot{}
	for name, slot := range slots {
		limit := MaxArtifact
		if name == "helper" {
			limit = MaxHelper
		}
		if (name != "helper" && name != "settings" && name != "runtime") || len(slot.Data) == 0 || len(slot.Data) > limit || slot.Reads < 1 || slot.Reads > 3 || slot.Digest != Hash(slot.Data) {
			return "", ErrDenied
		}
		copySlots[name] = Slot{bytes.Clone(slot.Data), slot.Digest, slot.Reads}
	}
	t, err := token()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grants[Hash([]byte(t))] = &grant{scope: scope, expires: s.now().Add(ttl), delivery: delivery, slots: copySlots}
	return t, nil
}

func (s *Store) lookup(t string) (*grant, error) {
	if !digest.MatchString(t) {
		return nil, ErrDenied
	}
	g := s.grants[Hash([]byte(t))]
	if g == nil || g.revoked || !s.now().Before(g.expires) {
		return nil, ErrDenied
	}
	return g, nil
}

// Bind can run once, before redemption, after an unambiguous native ACK.
func (s *Store) Bind(t, deployment string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, err := s.lookup(t)
	if err != nil || !atom.MatchString(deployment) {
		return ErrDenied
	}
	if g.scope.Deployment != "" {
		return ErrDenied
	}
	g.scope.Deployment = deployment
	return nil
}

func (s *Store) Revoke(t string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if g := s.grants[Hash([]byte(t))]; g != nil {
		g.revoked = true
		g.slots = nil
	}
}

func (s *Store) Fetch(t string, scope Scope, name string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, err := s.lookup(t)
	if err != nil || !scope.valid(true) || g.scope != scope || !g.delivery {
		return nil, ErrDenied
	}
	slot, ok := g.slots[name]
	if !ok || slot.Reads <= 0 {
		return nil, ErrDenied
	}
	slot.Reads--
	g.slots[name] = slot
	return bytes.Clone(slot.Data), nil
}

// Submit is one-shot and atomic: a lost response is reconciled with Receipt,
// never by repeating the upload. An upload proves token possession only.
func (s *Store) Submit(t string, scope Scope, data []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, err := s.lookup(t)
	if err != nil || !scope.valid(true) || g.scope != scope || g.delivery || g.used || len(data) == 0 || len(data) > MaxArtifact {
		return "", ErrDenied
	}
	if _, ok := s.sealed[scope]; ok {
		return "", ErrDenied
	}
	var artifact RuntimeArtifact
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if !exactArtifact(data) || d.Decode(&artifact) != nil || d.Decode(new(any)) != io.EOF || artifact.Validate(scope) != nil {
		return "", ErrDenied
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", ErrDenied
	}
	aad, _ := json.Marshal(scope)
	s.sealed[scope] = envelope{nonce, s.aead.Seal(nil, nonce, data, aad)}
	h := Hash(data)
	s.receipts[scope] = h
	g.used = true
	return h, nil
}

func (s *Store) Receipt(t string, scope Scope) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, err := s.lookup(t)
	if err != nil || g.delivery || g.scope != scope || !g.used {
		return "", ErrDenied
	}
	h, ok := s.receipts[scope]
	if !ok {
		return "", ErrDenied
	}
	return h, nil
}

// Open is runner-only. Rehydration gets a new exact-scope delivery capability.
func (s *Store) Open(scope Scope) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.sealed[scope]
	if !ok {
		return nil, ErrDenied
	}
	aad, _ := json.Marshal(scope)
	b, err := s.aead.Open(nil, e.Nonce, e.Ciphertext, aad)
	if err != nil {
		return nil, ErrDenied
	}
	return b, nil
}

type RuntimeArtifact struct {
	Schema                int               `json:"schema"`
	Scope                 Scope             `json:"scope"`
	EffectiveConfig       json.RawMessage   `json:"effectiveConfig"`
	EffectiveConfigDigest string            `json:"effectiveConfigDigest"`
	Images                map[string]string `json:"images"`
}

func (a RuntimeArtifact) Validate(s Scope) error {
	if a.Schema != 1 || a.Scope != s || len(a.EffectiveConfig) == 0 || !strictJSON(a.EffectiveConfig) || Hash(a.EffectiveConfig) != a.EffectiveConfigDigest || len(a.Images) != 2 {
		return ErrDenied
	}
	var config map[string]json.RawMessage
	if json.Unmarshal(a.EffectiveConfig, &config) != nil || config == nil || config["services"] == nil {
		return ErrDenied
	}
	for _, name := range []string{"web", "redis"} {
		v := a.Images[name]
		if len(v) != 71 || v[:7] != "sha256:" || !digest.MatchString(v[7:]) {
			return ErrDenied
		}
	}
	// Detailed image/mount/limit validation is a separate required pre-start gate.
	return nil
}
