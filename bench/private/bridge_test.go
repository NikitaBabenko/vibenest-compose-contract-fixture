package privatefixture

import (
	"testing"
)

func TestBootstrapAndRunnerReleaseAreSeparate(t *testing.T) {
	s, _ := testStore(t)
	scope := testScope()
	unbound := scope
	unbound.Deployment = ""
	d := issue(t, s, unbound, true)
	u := issue(t, s, unbound, false)
	b := NewBridge(s)
	if b.Pair(d, u) != nil {
		t.Fatal("pair failed")
	}
	if _, err := b.manifest(d, scope.Deployment); err == nil {
		t.Fatal("unbound bootstrap")
	}
	if s.Bind(d, scope.Deployment) != nil || s.Bind(u, scope.Deployment) != nil {
		t.Fatal("bind failed")
	}
	m, err := b.manifest(d, scope.Deployment)
	if err != nil || m.Submission != u || m.Scope != scope {
		t.Fatal("manifest failed")
	}
	if _, err := b.manifest(d, "wrong"); err == nil {
		t.Fatal("deployment bypass")
	}
	if b.ReleaseFixture(scope) == nil {
		t.Fatal("release before receipt")
	}
	if _, err := s.Submit(u, scope, artifact(t, scope)); err != nil {
		t.Fatal(err)
	}
	c, _ := tlsClient(t, b.Handler())
	if ready, err := c.Released(u, scope); err != nil || ready {
		t.Fatal("early release")
	}
	if b.ReleaseFixture(scope) != nil {
		t.Fatal("runner release failed")
	}
	if ready, err := c.Released(u, scope); err != nil || !ready {
		t.Fatal("missing release")
	}
	s.Revoke(u)
	if _, err := c.Released(u, scope); err == nil {
		t.Fatal("revoked submission released")
	}
	s.Revoke(d)
	if _, err := b.manifest(d, scope.Deployment); err == nil {
		t.Fatal("revoked delivery bootstrap")
	}
}
