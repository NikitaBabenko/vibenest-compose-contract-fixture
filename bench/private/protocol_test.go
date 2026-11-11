package privatefixture

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testScope() Scope {
	return Scope{"project", "app", "attempt", "deployment", 1, strings.Repeat("a", 40), strings.Repeat("b", 64), strings.Repeat("c", 64)}
}
func testStore(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	s, err := NewStore(bytes.Repeat([]byte{17}, 32), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return s, &now
}
func issue(t *testing.T, s *Store, scope Scope, delivery bool) string {
	t.Helper()
	var slots map[string]Slot
	if delivery {
		slots = map[string]Slot{"settings": {[]byte("private settings"), Hash([]byte("private settings")), 2}}
	}
	v, err := s.Issue(scope, time.Minute, slots, delivery)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func artifact(t *testing.T, scope Scope) []byte {
	t.Helper()
	config := json.RawMessage(`{"services":{"web":{"environment":{"LITERAL":"a$b\n${UNSET}"}}}}`)
	b, err := json.Marshal(RuntimeArtifact{1, scope, config, Hash(config), map[string]string{"web": "sha256:" + strings.Repeat("1", 64), "redis": "sha256:" + strings.Repeat("2", 64)}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestUnboundGrantDoesNotRedeem(t *testing.T) {
	s, _ := testStore(t)
	scope := testScope()
	unbound := scope
	unbound.Deployment = ""
	token := issue(t, s, unbound, true)
	if _, err := s.Fetch(token, scope, "settings"); err == nil {
		t.Fatal("unbound allowed")
	}
	if err := s.Bind(token, scope.Deployment); err != nil {
		t.Fatal(err)
	}
	if err := s.Bind(token, scope.Deployment); err == nil {
		t.Fatal("rebind allowed")
	}
	if _, err := s.Fetch(token, scope, "settings"); err != nil {
		t.Fatal(err)
	}
}

func TestDeliveryScopeExpiryRevocationAndReadBudget(t *testing.T) {
	scope := testScope()
	for name, mutate := range map[string]func(*Scope){"project": func(s *Scope) { s.Project = "other" }, "app": func(s *Scope) { s.Application = "other" }, "attempt": func(s *Scope) { s.Attempt = "other" }, "deployment": func(s *Scope) { s.Deployment = "other" }, "generation": func(s *Scope) { s.Generation++ }, "source": func(s *Scope) { s.SourceSHA = strings.Repeat("d", 40) }, "helper": func(s *Scope) { s.HelperDigest = strings.Repeat("d", 64) }, "settings": func(s *Scope) { s.SettingsDigest = strings.Repeat("d", 64) }} {
		t.Run(name, func(t *testing.T) {
			s, _ := testStore(t)
			token := issue(t, s, scope, true)
			wrong := scope
			mutate(&wrong)
			if _, err := s.Fetch(token, wrong, "settings"); err == nil {
				t.Fatal("scope bypass")
			}
			if _, err := s.Fetch(token, scope, "settings"); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, mode := range []string{"missing", "wrong", "expired", "revoked", "spent", "arbitrary-slot"} {
		t.Run(mode, func(t *testing.T) {
			s, now := testStore(t)
			token := issue(t, s, scope, true)
			slot := "settings"
			switch mode {
			case "missing":
				token = ""
			case "wrong":
				token = strings.Repeat("0", 64)
			case "expired":
				*now = now.Add(time.Minute)
			case "revoked":
				s.Revoke(token)
			case "spent":
				for range 2 {
					if _, err := s.Fetch(token, scope, slot); err != nil {
						t.Fatal(err)
					}
				}
			case "arbitrary-slot":
				slot = "source"
			}
			if _, err := s.Fetch(token, scope, slot); err == nil {
				t.Fatal("invalid redemption allowed")
			}
		})
	}
}

func TestIssueRejectsSourceAndDigestMismatch(t *testing.T) {
	s, _ := testStore(t)
	scope := testScope()
	for _, slot := range []map[string]Slot{{"source": {[]byte("x"), Hash([]byte("x")), 1}}, {"settings": {[]byte("x"), strings.Repeat("0", 64), 1}}, {"settings": {[]byte("x"), Hash([]byte("x")), 4}}} {
		if _, err := s.Issue(scope, time.Minute, slot, true); err == nil {
			t.Fatal("invalid slot")
		}
	}
}

func TestOneShotSubmissionEncryptedAndReconciled(t *testing.T) {
	s, _ := testStore(t)
	scope := testScope()
	token := issue(t, s, scope, false)
	data := artifact(t, scope)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Submit(token, scope, data); err == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("submission was not one-shot")
	}
	if got, err := s.Receipt(token, scope); err != nil || got != Hash(data) {
		t.Fatal("lost-ACK reconciliation failed")
	}
	if bytes.Contains(s.sealed[scope].Ciphertext, []byte("LITERAL")) {
		t.Fatal("plaintext retained")
	}
	got, err := s.Open(scope)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("exact literal config lost")
	}
	s.Revoke(token)
	if _, err := s.Receipt(token, scope); err == nil {
		t.Fatal("revoked receipt allowed")
	}
	if _, err := s.Open(scope); err != nil {
		t.Fatal("retained artifact depends on capability lifetime")
	}
	other := scope
	other.Generation++
	s.sealed[other] = s.sealed[scope]
	if _, err := s.Open(other); err == nil {
		t.Fatal("AAD identity bypass")
	}
	e := s.sealed[scope]
	e.Ciphertext[0] ^= 1
	s.sealed[scope] = e
	if _, err := s.Open(scope); err == nil {
		t.Fatal("corruption accepted")
	}
}

func TestGrantRolesAndArtifactValidation(t *testing.T) {
	s, _ := testStore(t)
	scope := testScope()
	delivery := issue(t, s, scope, true)
	submit := issue(t, s, scope, false)
	data := artifact(t, scope)
	if _, err := s.Submit(delivery, scope, data); err == nil {
		t.Fatal("delivery uploaded")
	}
	if _, err := s.Fetch(submit, scope, "settings"); err == nil {
		t.Fatal("submission fetched")
	}
	if _, err := s.Receipt(submit, scope); err == nil {
		t.Fatal("receipt before upload")
	}
	for _, bad := range [][]byte{[]byte(`{}`), append(bytes.Clone(data), []byte(` {}`)...), bytes.Replace(data, []byte(`"schema":1`), []byte(`"schema":2`), 1), bytes.Replace(data, []byte(`"schema":1`), []byte(`"unexpected":1,"schema":1`), 1), bytes.Replace(data, []byte(`a$b`), []byte(`drift`), 1), bytes.Repeat([]byte("x"), MaxArtifact+1)} {
		if _, err := s.Submit(submit, scope, bad); err == nil {
			t.Fatal("invalid artifact accepted")
		}
	}
	if _, err := s.Submit(submit, scope, data); err != nil {
		t.Fatal(err)
	}
	second := issue(t, s, scope, false)
	if _, err := s.Submit(second, scope, data); err == nil {
		t.Fatal("same identity overwritten")
	}
}
