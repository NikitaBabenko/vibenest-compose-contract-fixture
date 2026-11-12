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

func TestDecodeComposeConfigTransportEscapes(t *testing.T) {
	transport := []byte(`{"services":{"web":{"build":{"args":{"SYNTHETIC":"ordinary-$$x"}},"environment":{"LITERAL":"$$ $$x $$$$ $${NAME}\nline 2","KEY$$":"value"}}}}`)
	semantic := []byte(`{"services":{"web":{"build":{"args":{"SYNTHETIC":"ordinary-$x"}},"environment":{"LITERAL":"$ $x $$ ${NAME}\nline 2","KEY$":"value"}}}}`)
	decoded, err := decodeComposeConfig(transport)
	if err != nil || !sameJSON(decoded, semantic) {
		t.Fatal("Compose transport escaping changed literal values or keys")
	}
	written, err := literalBytes(decoded)
	if err != nil || !sameJSON(written, []byte(`{"services":{"web":{"build":{"args":{"SYNTHETIC":"ordinary-$$x"}},"environment":{"LITERAL":"$$ $$x $$$$ $${NAME}\nline 2","KEY$":"value"}}}}`)) {
		t.Fatal("literal writer did not preserve value escaping and mapping keys")
	}
	for _, input := range []string{`{"value":"odd-$$$"}`, `{"value":"$"}`, `{"value":`, `{"$$":"x","\u0024":"y"}`} {
		if _, err := decodeComposeConfig([]byte(input)); err == nil {
			t.Fatalf("accepted invalid Compose config output %q", input)
		}
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

func TestBuildFailureProjectsOnlyKnownCodes(t *testing.T) {
	for _, tc := range []struct {
		name, stderr, want string
		timedOut, leak     bool
	}{
		{name: "probe", stderr: "#8 0.219 FIXTURE_BUILD_PROBE argument\n", want: "probe-argument"},
		{name: "bare", stderr: "FIXTURE_BUILD_PROBE transport-env\n", want: "probe-transport-env"},
		{name: "ambiguous", stderr: "FIXTURE_BUILD_PROBE argument\nFIXTURE_BUILD_PROBE session-path\n", want: "ambiguous-probe"},
		{name: "command text", stderr: "RUN echo 'FIXTURE_BUILD_PROBE argument'\n", want: "unknown-child-failure"},
		{name: "extra text", stderr: "#8 0.219 FIXTURE_BUILD_PROBE argument private-detail\n", want: "unknown-child-failure"},
		{name: "registry", stderr: "failed to resolve source metadata for private-image", want: "base-image-resolution"},
		{name: "timeout", stderr: "FIXTURE_BUILD_PROBE argument\n", timedOut: true, want: "child-timeout"},
		{name: "leak", stderr: "FIXTURE_BUILD_PROBE argument\n", leak: true, want: "child-output-leak"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := buildFailure(nil, []byte(tc.stderr), tc.timedOut, tc.leak); got != tc.want {
				t.Fatalf("buildFailure = %q, want %q", got, tc.want)
			}
		})
	}
}
