package privatefixture

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestAmbiguousJSONRefused(t *testing.T) {
	for _, bad := range []string{`{"a":1,"a":2}`, `{"a":{"x":1,"x":2}}`, `{} {}`, `{"x":NaN}`, strings.Repeat("[", 70) + "0" + strings.Repeat("]", 70)} {
		if strictJSON([]byte(bad)) {
			t.Fatal("ambiguous JSON allowed")
		}
	}
	s, _ := testStore(t)
	scope := testScope()
	token := issue(t, s, scope, false)
	bad := bytes.Replace(artifact(t, scope), []byte(`"schema":1`), []byte(`"schema":2,"schema":1`), 1)
	if _, err := s.Submit(token, scope, bad); err == nil {
		t.Fatal("duplicate artifact field allowed")
	}
}

func TestSubmissionExpiryAndRevocation(t *testing.T) {
	for _, mode := range []string{"expired", "revoked", "wrong-scope"} {
		t.Run(mode, func(t *testing.T) {
			s, now := testStore(t)
			scope := testScope()
			token := issue(t, s, scope, false)
			data := artifact(t, scope)
			switch mode {
			case "expired":
				*now = now.Add(time.Minute)
			case "revoked":
				s.Revoke(token)
			case "wrong-scope":
				scope.Generation++
			}
			if _, err := s.Submit(token, scope, data); err == nil {
				t.Fatal("invalid submission allowed")
			}
		})
	}
}
