package privatefixture

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"unicode/utf8"
)

// Reject ambiguous duplicate keys, trailing values, and excessive nesting before
// typed decoding. Digests must not mask differing interpretations of one JSON.
func strictJSON(data []byte) bool {
	if !validUnicodeJSON(data) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 64 {
			return false
		}
		t, err := d.Token()
		if err != nil {
			return false
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return true
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return false
				}
				key, ok := k.(string)
				if !ok || seen[key] {
					return false
				}
				seen[key] = true
				if !value(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim('}')
		case '[':
			for d.More() {
				if !value(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim(']')
		default:
			return false
		}
	}
	if !value(0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}

// encoding/json v1 repairs malformed UTF-8 and lone UTF-16 surrogates. Reject
// those bytes before decoding, while preserving valid escaped pairs/literals.
func validUnicodeJSON(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	inString := false
	for i := 0; i < len(data); i++ {
		if !inString {
			if data[i] == '"' {
				inString = true
			}
			continue
		}
		if data[i] == '"' {
			inString = false
			continue
		}
		if data[i] != '\\' {
			continue
		}
		if i+1 >= len(data) {
			return false
		}
		if data[i+1] != 'u' {
			i++
			continue
		}
		if i+5 >= len(data) {
			return false
		}
		v, err := strconv.ParseUint(string(data[i+2:i+6]), 16, 16)
		if err != nil {
			return false
		}
		i += 5
		if v >= 0xdc00 && v <= 0xdfff {
			return false
		}
		if v >= 0xd800 && v <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

// Struct decoding is case-insensitive in encoding/json v1. Check the exact
// schema on decoded object keys first, including required fields. User config
// maps remain case-sensitive and may legitimately contain both Foo and FOO.
func exactObject(data []byte, fields ...string) (map[string]json.RawMessage, bool) {
	if !strictJSON(data) {
		return nil, false
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil || object == nil || len(object) != len(fields) {
		return nil, false
	}
	for _, field := range fields {
		if _, ok := object[field]; !ok {
			return nil, false
		}
	}
	return object, true
}

func exactScope(data []byte) bool {
	_, ok := exactObject(data, "project", "application", "attempt", "deployment", "generation", "sourceSha", "helperDigest", "settingsDigest")
	return ok
}

func exactArtifact(data []byte) bool {
	object, ok := exactObject(data, "schema", "scope", "effectiveConfig", "effectiveConfigDigest", "images")
	if !ok || !exactScope(object["scope"]) {
		return false
	}
	_, ok = exactObject(object["images"], "web", "redis")
	return ok
}
