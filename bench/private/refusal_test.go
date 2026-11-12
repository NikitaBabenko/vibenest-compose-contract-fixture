package privatefixture

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func refusalBytes(t *testing.T, scope Scope) []byte {
	t.Helper()
	b, err := json.Marshal(Refusal{1, scope, "retained-volume-inspection", "assigned-volume-missing", Hash([]byte("vnprivate11-web")), Hash([]byte(`[]`)), false})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRefusalOneShotTLSAndNoRelease(t *testing.T) {
	s, _ := testStore(t)
	scope := testScope()
	grant := issue(t, s, scope, false)
	bridge := NewBridge(s)
	c, _ := tlsClient(t, bridge.Handler())
	data := refusalBytes(t, scope)
	if _, err := c.SubmitRefusal(grant, scope, data); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Receipt(grant, scope, Hash(data)); err != nil {
		t.Fatal("lost ACK receipt", err)
	}
	if bridge.ReleaseFixture(scope) == nil {
		t.Fatal("refusal unlocked runtime")
	}
	if _, err := s.Open(scope); err == nil {
		t.Fatal("refusal became runtime artifact")
	}
	if _, err := c.SubmitRefusal(grant, scope, data); err == nil {
		t.Fatal("replay")
	}
	for _, other := range []string{grant, issue(t, s, scope, false)} {
		if _, err := s.Submit(other, scope, artifact(t, scope)); err == nil {
			t.Fatal("artifact after refusal")
		}
		if _, err := s.SubmitRefusal(other, scope, data); err == nil {
			t.Fatal("second refusal")
		}
	}
	s.Revoke(grant)
	if got, err := s.Refusal(scope); err != nil || got.VolumeNameDigest != Hash([]byte("vnprivate11-web")) {
		t.Fatal("runner lost retained refusal")
	}
	wrong := scope
	wrong.Attempt = "other"
	if _, err := s.Refusal(wrong); err == nil {
		t.Fatal("runner scope mismatch")
	}
	s2, _ := testStore(t)
	g := issue(t, s2, scope, false)
	if _, err := s2.Submit(g, scope, artifact(t, scope)); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.SubmitRefusal(issue(t, s2, scope, false), scope, data); err == nil {
		t.Fatal("refusal after artifact")
	}
}

func TestRefusalGrantAndExactSchema(t *testing.T) {
	scope := testScope()
	data := refusalBytes(t, scope)
	for _, mode := range []string{"delivery", "expired", "revoked", "wrong-scope", "unbound", "missing"} {
		t.Run(mode, func(t *testing.T) {
			s, now := testStore(t)
			grantScope := scope
			if mode == "unbound" {
				grantScope.Deployment = ""
			}
			g := issue(t, s, grantScope, mode == "delivery")
			requestScope := scope
			switch mode {
			case "expired":
				*now = now.Add(time.Minute)
			case "revoked":
				s.Revoke(g)
			case "wrong-scope":
				requestScope.Generation++
			case "missing":
				g = ""
			}
			if _, err := s.SubmitRefusal(g, requestScope, data); err == nil {
				t.Fatal("invalid grant accepted")
			}
		})
	}
	var original map[string]any
	_ = json.Unmarshal(data, &original)
	for key := range original {
		var bad map[string]any
		_ = json.Unmarshal(data, &bad)
		delete(bad, key)
		b, _ := json.Marshal(bad)
		if _, err := parseRefusal(b, scope); err == nil {
			t.Fatal("missing field", key)
		}
	}
	for _, pair := range [][2]string{
		{`"createIssued":false`, `"createIssued":null`}, {`"createIssued":false`, `"createIssued":true`},
		{`"createIssued":false`, `"createIssued":0`}, {`"stage":"retained-volume-inspection"`, `"stage":"source-verification"`},
		{`"code":"assigned-volume-missing"`, `"code":"unrelated-error"`},
		{`"schema":1`, `"Schema":1`}, {`"schema":1`, `"schema":1,"schema":1`},
		{`"project":"project"`, `"Project":"project"`}, {`"project":"project"`, `"project":"other"`},
		{`"volumeNameDigest":"`, `"volumeNameDigest":"\ud800`},
	} {
		bad := bytes.Replace(data, []byte(pair[0]), []byte(pair[1]), 1)
		if bytes.Equal(data, bad) {
			t.Fatal("bad test fixture", pair)
		}
		s, _ := testStore(t)
		g := issue(t, s, scope, false)
		if _, err := s.SubmitRefusal(g, scope, bad); err == nil {
			t.Fatal("invalid receipt accepted", pair)
		}
		if _, err := s.SubmitRefusal(g, scope, data); err != nil {
			t.Fatal("rejected upload consumed grant", err)
		}
	}
}

func TestHelperMissingRefusalRequiresAssignedAbsentRetainedAndNoCreate(t *testing.T) {
	makeSession := func() helperSession {
		return helperSession{Manifest: Manifest{Scope: testScope()}, Settings: NativeSettings{VolumeMode: "RetainedInspect", Volumes: map[string]string{"app-data": "vnprivate11-web", "redis-data": "vnprivate1-redis"}}}
	}
	s := makeSession()
	got, err := s.missingVolumeRefusal("vnprivate11-web", []string{"vnprivate1-redis", "baseline"})
	if err != nil || got.InventoryDigest != Hash([]byte(`["baseline","vnprivate1-redis"]`)) || got.CreateIssued {
		t.Fatal("valid observation refused", err)
	}
	data, _ := json.Marshal(got)
	if strings.Contains(string(data), "vnprivate") {
		t.Fatal("physical name exported")
	}
	empty, err := s.missingVolumeRefusal("vnprivate11-web", nil)
	if err != nil || empty.InventoryDigest != Hash([]byte(`[]`)) {
		t.Fatal("empty complete inventory not canonical")
	}
	for _, mode := range []string{"new", "create-attempt", "present", "duplicate", "invalid-name", "unassigned"} {
		t.Run(mode, func(t *testing.T) {
			s := makeSession()
			names := []string{"baseline"}
			name := "vnprivate11-web"
			switch mode {
			case "new":
				s.Settings.VolumeMode = "NewCreate"
			case "create-attempt":
				s.VolumeCreateAttempts = 1
			case "present":
				names = append(names, name)
			case "duplicate":
				names = append(names, "baseline")
			case "invalid-name":
				names = append(names, "bad name")
			case "unassigned":
				name = "vnprivate12-web"
			}
			if _, err := s.missingVolumeRefusal(name, names); err == nil {
				t.Fatal("false absence/create evidence accepted")
			}
		})
	}
}
