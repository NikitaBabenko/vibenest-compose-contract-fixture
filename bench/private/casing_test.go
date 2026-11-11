package privatefixture

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestExactScopeFieldCasing(t *testing.T) {
	b, _ := json.Marshal(testScope())
	for _, field := range []string{"project", "application", "attempt", "deployment", "generation", "sourceSha", "helperDigest", "settingsDigest"} {
		t.Run(field, func(t *testing.T) {
			needle := []byte(`"` + field + `":`)
			upper := []byte(`"` + strings.ToUpper(field[:1]) + field[1:] + `":`)
			for _, bad := range [][]byte{bytes.Replace(b, needle, upper, 1), bytes.Replace(b, needle, append(append(bytes.Clone(upper), []byte(`null,`)...), needle...), 1)} {
				if _, err := parseScope(base64.RawURLEncoding.EncodeToString(bad)); err == nil {
					t.Fatal("casing alias accepted")
				}
			}
		})
	}
}

func TestExactArtifactAndReceiptFieldCasing(t *testing.T) {
	scope := testScope()
	b := artifact(t, scope)
	for _, field := range []string{"schema", "scope", "effectiveConfig", "effectiveConfigDigest", "images", "sourceSha"} {
		t.Run(field, func(t *testing.T) {
			needle := []byte(`"` + field + `":`)
			upper := []byte(`"` + strings.ToUpper(field[:1]) + field[1:] + `":`)
			for _, bad := range [][]byte{bytes.Replace(b, needle, upper, 1), bytes.Replace(b, needle, append(append(bytes.Clone(upper), []byte(`null,`)...), needle...), 1)} {
				s, _ := testStore(t)
				cap := issue(t, s, scope, false)
				if _, err := s.Submit(cap, scope, bad); err == nil {
					t.Fatal("artifact casing alias accepted")
				}
			}
		})
	}
	h := strings.Repeat("a", 64)
	for _, bad := range []string{`{"Digest":"` + h + `"}`, `{"digest":"` + h + `","Digest":"` + h + `"}`, `{"dige\u017ft":"` + h + `"}`} {
		if _, err := receiptDigest([]byte(bad), h); err == nil {
			t.Fatal("receipt casing alias accepted")
		}
	}
}

func TestUnicodeAmbiguityRejectedAtAllBoundaries(t *testing.T) {
	badStrings := [][]byte{[]byte(`"\ud800"`), []byte(`"\udc00"`), []byte(`"\ud800\u0041"`), []byte(`"\ud800x\udc00"`), {'"', 0xff, '"'}, {'"', 0xed, 0xa0, 0x80, '"'}}
	for _, bad := range badStrings {
		if strictJSON(bad) {
			t.Fatal("invalid Unicode accepted")
		}
		scope := testScope()
		b, _ := json.Marshal(scope)
		b = bytes.Replace(b, []byte(`"project":"project"`), append([]byte(`"project":`), bad...), 1)
		if _, err := parseScope(base64.RawURLEncoding.EncodeToString(b)); err == nil {
			t.Fatal("invalid scope Unicode")
		}
		s, _ := testStore(t)
		cap := issue(t, s, scope, false)
		config := append(append([]byte(`{"services":{},"canary":`), bad...), '}')
		data, _ := json.Marshal(RuntimeArtifact{1, scope, json.RawMessage(`{}`), Hash(config), map[string]string{"web": "sha256:" + strings.Repeat("1", 64), "redis": "sha256:" + strings.Repeat("2", 64)}})
		data = bytes.Replace(data, []byte(`"effectiveConfig":{}`), append([]byte(`"effectiveConfig":`), config...), 1)
		if _, err := s.Submit(cap, scope, data); err == nil {
			t.Fatal("invalid artifact Unicode")
		}
		if _, err := receiptDigest(append(append([]byte(`{"digest":`), bad...), '}'), strings.Repeat("a", 64)); err == nil {
			t.Fatal("invalid receipt Unicode")
		}
	}
	for _, good := range []string{`"\ud83d\ude00"`, `"😀"`, `"\\ud800"`, `{"Foo":1,"FOO":2}`, `{"source\u0053ha":1}`, `"\ufffd"`} {
		if !strictJSON([]byte(good)) {
			t.Fatal("valid Unicode or case-sensitive map refused")
		}
	}
}
