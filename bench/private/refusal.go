package privatefixture

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"sort"
)

var inventoryName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

// Refusal is a bounded, secret-free helper observation, not production authority
// or host proof-of-possession. Only the runner control pipe can retrieve it.
type Refusal struct {
	Schema           int    `json:"schema"`
	Scope            Scope  `json:"scope"`
	Stage            string `json:"stage"`
	Code             string `json:"code"`
	VolumeNameDigest string `json:"volumeNameDigest"`
	InventoryDigest  string `json:"inventoryDigest"`
	CreateIssued     bool   `json:"createIssued"`
}

func parseRefusal(data []byte, scope Scope) (Refusal, error) {
	var value Refusal
	obj, ok := exactObject(data, "schema", "scope", "stage", "code", "volumeNameDigest", "inventoryDigest", "createIssued")
	if !ok || !exactScope(obj["scope"]) || !bytes.Equal(bytes.TrimSpace(obj["createIssued"]), []byte("false")) || json.Unmarshal(data, &value) != nil ||
		value.Schema != 1 || value.Scope != scope || !scope.valid(true) || value.Stage != "retained-volume-inspection" || value.Code != "assigned-volume-missing" ||
		!digest.MatchString(value.VolumeNameDigest) || !digest.MatchString(value.InventoryDigest) {
		return Refusal{}, ErrDenied
	}
	return value, nil
}

func (s *Store) SubmitRefusal(t string, scope Scope, data []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, err := s.lookup(t)
	if err != nil || g.scope != scope || g.delivery || g.used || len(data) == 0 || len(data) > 4096 {
		return "", ErrDenied
	}
	if _, exists := s.receipts[scope]; exists {
		return "", ErrDenied
	}
	value, err := parseRefusal(data, scope)
	if err != nil {
		return "", ErrDenied
	}
	s.refusals[scope] = value
	s.receipts[scope] = Hash(data)
	g.used = true
	return s.receipts[scope], nil
}

func (s *Store) Refusal(scope Scope) (Refusal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.refusals[scope]
	if !ok {
		return Refusal{}, ErrDenied
	}
	return value, nil
}

func (c *Client) SubmitRefusal(t string, scope Scope, data []byte) (string, error) {
	if _, err := parseRefusal(data, scope); err != nil || len(data) > 4096 {
		return "", ErrDenied
	}
	b, status, err := c.request("POST", "/v1/refusal", t, scope, data, 256)
	if err != nil || status != http.StatusOK {
		return "", ErrDenied
	}
	return receiptDigest(b, Hash(data))
}

// Called only after a successful complete Docker volume inventory. Validate
// absence and the full inventory before constructing any positive observation.
func (s *helperSession) missingVolumeRefusal(name string, inventory []string) (Refusal, error) {
	if s.Settings.VolumeMode != "RetainedInspect" || s.VolumeCreateAttempts != 0 || !physicalName.MatchString(name) ||
		(name != s.Settings.Volumes["app-data"] && name != s.Settings.Volumes["redis-data"]) {
		return Refusal{}, ErrDenied
	}
	names := append([]string{}, inventory...)
	sort.Strings(names)
	for i, n := range names {
		if !inventoryName.MatchString(n) || n == name || (i > 0 && names[i-1] == n) {
			return Refusal{}, ErrDenied
		}
	}
	data, _ := json.Marshal(names)
	return Refusal{1, s.Manifest.Scope, "retained-volume-inspection", "assigned-volume-missing", Hash([]byte(name)), Hash(data), false}, nil
}

func (s *helperSession) reportMissingVolume(name string, inventory []string) {
	value, err := s.missingVolumeRefusal(name, inventory)
	if err != nil {
		return
	}
	ca, err := os.ReadFile(privateDir + "/ca.pem")
	if err != nil {
		return
	}
	client, err := NewClient(s.Origin, ca)
	if err != nil {
		return
	}
	data, _ := json.Marshal(value)
	// Never retry a mutation. The private runner can read a stored receipt after
	// a lost ACK; missing receipt remains unknown and fails the scenario.
	if _, err = client.SubmitRefusal(s.Manifest.Submission, s.Manifest.Scope, data); err == nil {
		_ = client.Revoke(s.Manifest.Submission, s.Manifest.Scope)
	}
}
