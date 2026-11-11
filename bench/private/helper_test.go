package privatefixture

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestLiteralJSONRoundTripInput(t *testing.T) {
	raw := []byte(`{"services":{"web":{"environment":{"LITERAL":"$x\n${CHANGED}\n<quote>","CASE":"A","case":"B"}}}}`)
	escaped, err := literalBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if json.Unmarshal(escaped, &doc) != nil {
		t.Fatal("bad JSON")
	}
	env := doc["services"].(map[string]any)["web"].(map[string]any)["environment"].(map[string]any)
	if env["LITERAL"] != "$$x\n$${CHANGED}\n<quote>" || env["CASE"] != "A" || env["case"] != "B" {
		t.Fatal("literal transform changed semantics")
	}
	canonical, err := canonicalJSON(raw)
	if err != nil || !sameJSON(canonical, raw) {
		t.Fatal("canonical roundtrip")
	}
}

func TestChildOutputScannerAndBound(t *testing.T) {
	cap := strings.Repeat("0123456789abcdef", 4)
	for _, data := range []string{cap, base64.StdEncoding.EncodeToString([]byte(cap)), hex.EncodeToString([]byte(cap)), strings.Join(strings.Split(cap, ""), "\n"), cap[16:32]} {
		if !scanSecrets([]byte(data), cap) {
			t.Fatal("leak missed")
		}
	}
	if scanSecrets([]byte("safe output"), cap) {
		t.Fatal("false positive")
	}
	b := &boundedOutput{limit: 3}
	if _, err := b.Write([]byte("four")); err == nil || b.Len() != 0 {
		t.Fatal("output bound bypass")
	}
}
