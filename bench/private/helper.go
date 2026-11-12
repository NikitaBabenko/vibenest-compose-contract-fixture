package privatefixture

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const privateDir = "/tmp/vn-private"
const reserved = "VN_ARTIFACT_CAPABILITY"
const composeConfigVersion = "5.6.1"

var physicalName = regexp.MustCompile(`^vnprivate[0-9]{1,20}-(web|redis)$`)
var buildProbe = regexp.MustCompile(`(?m)^(?:#[0-9]+ [0-9]+(?:\.[0-9]+)? )?FIXTURE_BUILD_PROBE (argument|artifact-path|session-path|transport-env)\r?$`)

type NativeSettings struct {
	SourceFiles          map[string]SourceFile      `json:"sourceFiles"`
	DockerfileBodyDigest string                     `json:"dockerfileBodyDigest"`
	Mode                 string                     `json:"mode"`
	UtilityImage         string                     `json:"utilityImage"`
	Volumes              map[string]string          `json:"volumes"`
	VolumeMode           string                     `json:"volumeMode"`
	Intents              map[string]string          `json:"intents"`
	VolumeObservations   map[string]json.RawMessage `json:"volumeObservations"`
	RedisImage           string                     `json:"redisImage"`
	RetainedScope        *Scope                     `json:"retainedScope"`
}

type helperSession struct {
	Origin               string
	Manifest             Manifest
	Delivery             string
	Settings             NativeSettings
	Config               json.RawMessage
	Images               map[string]string
	VolumeCreateAttempts int
}

type boundedOutput struct {
	bytes.Buffer
	limit int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, ErrDenied
	}
	return b.Buffer.Write(p)
}

func scanSecrets(data []byte, caps ...string) bool {
	compact := bytes.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, data)
	for _, cap := range caps {
		if cap == "" {
			continue
		}
		raw := []byte(cap)
		for _, v := range [][]byte{raw, []byte(base64.StdEncoding.EncodeToString(raw)), []byte(hex.EncodeToString(raw))} {
			if bytes.Contains(data, v) || bytes.Contains(compact, v) {
				return true
			}
		}
		for i := 0; i+16 <= len(raw); i += 16 {
			if bytes.Contains(data, raw[i:i+16]) {
				return true
			}
		}
	}
	return false
}

func buildFailure(stdout, stderr []byte, timedOut, leak bool) string {
	if leak {
		return "child-output-leak"
	}
	if timedOut {
		return "child-timeout"
	}
	var reason string
	for _, output := range [][]byte{stdout, stderr} {
		for _, match := range buildProbe.FindAllSubmatch(output, 5) {
			code := string(match[1])
			if reason != "" && reason != code {
				return "ambiguous-probe"
			}
			reason = code
		}
	}
	if reason != "" {
		return "probe-" + reason
	}
	lower := bytes.ToLower(stderr)
	switch {
	case bytes.Contains(lower, []byte("buildx component is missing or broken")),
		bytes.Contains(lower, []byte("requires buildx")):
		return "buildx-unavailable"
	case bytes.Contains(lower, []byte("failed to read dockerfile")):
		return "dockerfile-unreadable"
	case bytes.Contains(lower, []byte("failed to resolve source metadata")),
		bytes.Contains(lower, []byte("pull access denied")),
		bytes.Contains(lower, []byte("toomanyrequests:")):
		return "base-image-resolution"
	case bytes.Contains(lower, []byte("cannot connect to the docker daemon")):
		return "daemon-unavailable"
	case bytes.Contains(lower, []byte("no space left on device")):
		return "disk-exhausted"
	case bytes.Contains(lower, []byte("did not complete successfully: exit code:")):
		return "dockerfile-step-exit"
	default:
		return "unknown-child-failure"
	}
}

func (s *helperSession) run(stage string, input []byte, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdin = bytes.NewReader(input)
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "DOCKER_CONFIG=/root/.docker", "DOCKER_BUILDKIT=1"}
	var out, errout boundedOutput
	out.limit = 16 << 20
	errout.limit = 16 << 20
	cmd.Stdout = &out
	cmd.Stderr = &errout
	err := cmd.Run()
	leak := scanSecrets(out.Bytes(), s.Delivery, s.Manifest.Submission) || scanSecrets(errout.Bytes(), s.Delivery, s.Manifest.Submission)
	// Fixed stage names and digests only; raw child output never reaches logs.
	fmt.Printf("FIXTURE_SCAN %s %s %d leak=%t\n", stage, Hash(append(bytes.Clone(out.Bytes()), errout.Bytes()...)), out.Len()+errout.Len(), leak)
	if err != nil || leak {
		if stage == "user-image-build" {
			fmt.Fprintln(os.Stderr, "FIXTURE_BUILD_FAILURE", buildFailure(out.Bytes(), errout.Bytes(), ctx.Err() != nil, leak))
		}
		return nil, ErrDenied
	}
	return bytes.Clone(out.Bytes()), nil
}

func (s *helperSession) compose(stage string, extra ...string) ([]byte, error) {
	cwd, _ := os.Getwd()
	args := []string{"docker", "compose", "--env-file", privateDir + "/empty.env", "--project-name", s.Manifest.Scope.Application, "--project-directory", cwd, "-f", privateDir + "/effective.json"}
	if stage == "user-image-build" {
		args = append(args, "--progress", "plain")
	}
	args = append(args, extra...)
	return s.run(stage, nil, args...)
}

func (s *helperSession) render(mode string, config json.RawMessage, images map[string]string, extra map[string]any) (map[string]json.RawMessage, error) {
	cwd, _ := os.Getwd()
	request := map[string]any{"mode": mode, "config": config, "settings": map[string]any{"application": s.Manifest.Scope.Application, "workdir": cwd, "volumes": s.Settings.Volumes}, "images": images}
	for k, v := range extra {
		request[k] = v
	}
	data, _ := json.Marshal(request)
	out, err := s.run("renderer", data, "docker", "run", "--rm", "-i", "--pull=never", "--log-driver", "none", "--network", "none", "--read-only", "--memory", "128m", "--cpus", "0.25", "--pids-limit", "32", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", s.Settings.UtilityImage)
	if err != nil || !strictJSON(out) {
		return nil, ErrDenied
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(out, &result) != nil {
		return nil, ErrDenied
	}
	return result, nil
}

func writePrivate(name string, data []byte) error {
	if filepath.Base(name) != name {
		return ErrDenied
	}
	path := privateDir + "/" + name
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return ErrDenied
	}
	return os.WriteFile(path, data, 0600)
}

func literalBytes(raw json.RawMessage) ([]byte, error) {
	if !strictJSON(raw) {
		return nil, ErrDenied
	}
	var value any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&value) != nil {
		return nil, ErrDenied
	}
	var escape func(any) any
	escape = func(v any) any {
		switch x := v.(type) {
		case string:
			return strings.ReplaceAll(x, "$", "$$")
		case []any:
			for i := range x {
				x[i] = escape(x[i])
			}
		case map[string]any:
			for k, v := range x {
				x[k] = escape(v)
			}
		}
		return v
	}
	return json.Marshal(escape(value))
}

func sameJSON(a, b []byte) bool {
	if !strictJSON(a) || !strictJSON(b) {
		return false
	}
	var x, y any
	d := json.NewDecoder(bytes.NewReader(a))
	d.UseNumber()
	if d.Decode(&x) != nil {
		return false
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if d.Decode(&y) != nil {
		return false
	}
	u, _ := json.Marshal(x)
	v, _ := json.Marshal(y)
	return bytes.Equal(u, v)
}

func canonicalJSON(raw []byte) ([]byte, error) {
	if !strictJSON(raw) {
		return nil, ErrDenied
	}
	var value any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&value) != nil {
		return nil, ErrDenied
	}
	return json.Marshal(value)
}

func decodeComposeConfig(raw []byte) ([]byte, error) {
	// Compose 5.6.1 doubles every dollar in the serialized config output.
	// Undo that transport escaping before rendering or comparing resolved values.
	literal := bytes.ReplaceAll(raw, []byte("$$"), []byte("$"))
	if !bytes.Equal(bytes.ReplaceAll(literal, []byte("$"), []byte("$$")), raw) {
		return nil, ErrDenied
	}
	return canonicalJSON(literal)
}

func (s *helperSession) save() error {
	b, err := json.Marshal(s)
	if err != nil {
		return ErrDenied
	}
	return writePrivate("session.json", b)
}

func parseSettings(data []byte) (NativeSettings, error) {
	var settings NativeSettings
	obj, ok := exactObject(data, "mode", "utilityImage", "volumes", "volumeMode", "intents", "volumeObservations", "redisImage", "retainedScope", "sourceFiles", "dockerfileBodyDigest")
	if !ok {
		return settings, ErrDenied
	}
	for _, name := range []string{"volumes", "intents"} {
		if _, ok := exactObject(obj[name], "app-data", "redis-data"); !ok {
			return settings, ErrDenied
		}
	}
	if string(obj["retainedScope"]) != "null" && !exactScope(obj["retainedScope"]) {
		return settings, ErrDenied
	}
	if json.Unmarshal(data, &settings) != nil || (settings.Mode != "prepare" && settings.Mode != "activate" && settings.Mode != "fault") || !strings.HasPrefix(settings.UtilityImage, "sha256:") || !digest.MatchString(strings.TrimPrefix(settings.UtilityImage, "sha256:")) {
		return settings, ErrDenied
	}
	for _, key := range []string{"app-data", "redis-data"} {
		if !physicalName.MatchString(settings.Volumes[key]) || !digest.MatchString(settings.Intents[key]) {
			return settings, ErrDenied
		}
	}
	if settings.Volumes["app-data"] == settings.Volumes["redis-data"] || (settings.VolumeMode != "NewCreate" && settings.VolumeMode != "RetainedInspect") {
		return settings, ErrDenied
	}
	if len(settings.SourceFiles) == 0 || len(settings.SourceFiles) > 256 || !digest.MatchString(settings.DockerfileBodyDigest) || (settings.Mode == "prepare") != (settings.RetainedScope == nil) {
		return settings, ErrDenied
	}
	var sourceObjects map[string]json.RawMessage
	if json.Unmarshal(obj["sourceFiles"], &sourceObjects) != nil {
		return settings, ErrDenied
	}
	for _, value := range sourceObjects {
		if _, ok := exactObject(value, "digest", "mode"); !ok {
			return settings, ErrDenied
		}
	}
	if settings.VolumeMode == "NewCreate" && (settings.Mode != "prepare" || len(settings.VolumeObservations) != 0) {
		return settings, ErrDenied
	}
	if settings.VolumeMode == "RetainedInspect" && len(settings.VolumeObservations) != 2 {
		return settings, ErrDenied
	}
	if settings.RedisImage != "" && (!strings.HasPrefix(settings.RedisImage, "sha256:") || !digest.MatchString(strings.TrimPrefix(settings.RedisImage, "sha256:"))) {
		return settings, ErrDenied
	}
	return settings, nil
}

func (s *helperSession) verifyNativeSource() error {
	// Coolify cleanup_git() removes .git before the native custom build. Verify
	// digest-only source metadata against that native checkout; never refetch it.
	return verifyCheckout(os.DirFS("."), s.Settings.SourceFiles, s.Settings.DockerfileBodyDigest)
}

func (s *helperSession) inventoryVolumes(create bool) error {
	names, err := s.run("volume-list", nil, "docker", "volume", "ls", "-q")
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, name := range strings.Fields(string(names)) {
		if seen[name] {
			return ErrDenied
		}
		seen[name] = true
	}
	for _, key := range []string{"app-data", "redis-data"} {
		name := s.Settings.Volumes[key]
		if create {
			if seen[name] || s.Settings.VolumeMode != "NewCreate" {
				return ErrDenied
			}
			// Durable typed intent was fsynced by the runner before native dispatch.
			s.VolumeCreateAttempts++
			if _, err := s.run("volume-create", nil, "docker", "volume", "create", "--driver", "local", "--label", "fixture.intent="+s.Settings.Intents[key], "--label", "fixture.project="+s.Manifest.Scope.Project, name); err != nil {
				return ErrDenied
			}
		} else if !seen[name] {
			s.reportMissingVolume(name, strings.Fields(string(names)))
			return ErrDenied
		}
		actual, err := s.run("volume-inspect", nil, "docker", "volume", "inspect", name)
		if err != nil {
			return err
		}
		var rows []map[string]json.RawMessage
		if json.Unmarshal(actual, &rows) != nil || len(rows) != 1 {
			return ErrDenied
		}
		row := rows[0]
		var observedName, driver, scope string
		_ = json.Unmarshal(row["Name"], &observedName)
		_ = json.Unmarshal(row["Driver"], &driver)
		_ = json.Unmarshal(row["Scope"], &scope)
		var labels map[string]string
		_ = json.Unmarshal(row["Labels"], &labels)
		if observedName != name || driver != "local" || scope != "local" || (string(row["Options"]) != "null" && string(row["Options"]) != "{}") || labels["fixture.intent"] != s.Settings.Intents[key] || labels["fixture.project"] != s.Manifest.Scope.Project {
			return ErrDenied
		}
		if !create {
			b, _ := json.Marshal(row)
			if !sameJSON(b, s.Settings.VolumeObservations[key]) {
				return ErrDenied
			}
		}
	}
	return nil
}

func (s *helperSession) scrub() error {
	if _, err := os.Lstat("/artifacts/run-with-build-time-env"); err == nil {
		return ErrDenied
	}
	data, err := os.ReadFile("/artifacts/build-time.env")
	if err != nil {
		return ErrDenied
	}
	var kept []string
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, reserved+"=") {
			count++
			continue
		}
		kept = append(kept, line)
	}
	if count != 1 {
		return ErrDenied
	}
	if os.WriteFile("/artifacts/build-time.env", []byte(strings.Join(kept, "\n")), 0600) != nil {
		return ErrDenied
	}
	_ = os.Unsetenv(reserved)
	path := "private-app/Dockerfile"
	data, err = os.ReadFile(path)
	if err != nil {
		return ErrDenied
	}
	kept = nil
	for _, line := range strings.Split(string(data), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "ARG "+reserved || strings.HasPrefix(trim, "ARG "+reserved+"=") {
			continue
		}
		kept = append(kept, line)
	}
	clean := strings.Join(kept, "\n")
	if strings.Contains(clean, reserved) || scanSecrets([]byte(clean), s.Delivery, s.Manifest.Submission) {
		return ErrDenied
	}
	if os.WriteFile(path, []byte(clean), 0644) != nil {
		return ErrDenied
	}
	return nil
}

func (s *helperSession) scanContext() error {
	total := int64(0)
	cwd, _ := os.Getwd()
	return filepath.WalkDir(cwd, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return ErrDenied
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return ErrDenied
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return ErrDenied
		}
		total += info.Size()
		if total > 16<<20 {
			return ErrDenied
		}
		data, err := os.ReadFile(path)
		if err != nil || scanSecrets(data, s.Delivery, s.Manifest.Submission) {
			return ErrDenied
		}
		return nil
	})
}

func RunHelper(phase, origin string) (result error) {
	stage := "helper-entry"
	defer func() {
		if result != nil {
			fmt.Fprintln(os.Stderr, "FIXTURE_REFUSAL", stage)
		}
	}()
	if os.Getenv("GOOS") == "windows" {
		return ErrDenied
	}
	_ = os.Setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	stage = "helper-workdir"
	cwd, err := os.Getwd()
	if err != nil || filepath.Dir(cwd) != "/artifacts" || !atom.MatchString(filepath.Base(cwd)) {
		return ErrDenied
	}
	stage = "helper-private-directory"
	info, err := os.Lstat(privateDir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return ErrDenied
	}
	stage = "helper-ca-read"
	ca, err := os.ReadFile(privateDir + "/ca.pem")
	if err != nil {
		return ErrDenied
	}
	var s helperSession
	stage = "helper-compose-version"
	version, err := s.run("compose-version", nil, "docker", "compose", "version", "--short")
	if err != nil || strings.TrimPrefix(strings.TrimSpace(string(version)), "v") != composeConfigVersion {
		return ErrDenied
	}
	if phase == "load" {
		stage = "helper-tls-client"
		client, err := NewClient(origin, ca)
		if err != nil {
			return err
		}
		stage = "helper-delivery-read"
		token, err := os.ReadFile(privateDir + "/delivery")
		if err != nil {
			return ErrDenied
		}
		s.Origin = origin
		s.Delivery = string(token)
		stage = "helper-manifest"
		s.Manifest, err = client.Bootstrap(s.Delivery, filepath.Base(cwd))
		if err != nil {
			return ErrDenied
		}
		stage = "helper-binary-pin"
		self, err := os.ReadFile(privateDir + "/helper")
		if err != nil || Hash(self) != s.Manifest.Scope.HelperDigest {
			return ErrDenied
		}
		slot := s.Manifest.Slots["settings"]
		stage = "helper-settings-fetch"
		settings, err := client.Fetch(s.Delivery, s.Manifest.Scope, "settings", slot.Digest, slot.Size)
		if err != nil {
			return err
		}
		stage = "helper-settings-parse"
		s.Settings, err = parseSettings(settings)
		if err != nil {
			return err
		}
		stage = "helper-source-verify"
		if err = s.verifyNativeSource(); err != nil {
			return err
		}
		if s.Settings.Mode != "prepare" {
			stage = "helper-retained-fetch"
			slot := s.Manifest.Slots["runtime"]
			data, err := client.Fetch(s.Delivery, s.Manifest.Scope, "runtime", slot.Digest, slot.Size)
			if err != nil || !exactArtifact(data) {
				return ErrDenied
			}
			var a RuntimeArtifact
			if json.Unmarshal(data, &a) != nil || s.Settings.RetainedScope == nil || a.Scope != *s.Settings.RetainedScope || a.Scope.Application != s.Manifest.Scope.Application || a.Scope.SourceSHA != s.Manifest.Scope.SourceSHA || a.Validate(a.Scope) != nil {
				return ErrDenied
			}
			s.Config = a.EffectiveConfig
			s.Images = a.Images
		}
		stage = "helper-scrub"
		if err = s.scrub(); err != nil {
			return err
		}
		if os.Remove(privateDir+"/delivery") != nil {
			return ErrDenied
		}
		if writePrivate("empty.env", nil) != nil {
			return ErrDenied
		}
		// Resolve native YAML without runtime .env; scrub generated ARG references
		// and overwrite only the provider-generated config, never application source.
		stage = "helper-native-normalization"
		raw, err := s.run("native-normalization", nil, "docker", "compose", "--env-file", "/artifacts/build-time.env", "--project-name", s.Manifest.Scope.Application, "--project-directory", cwd, "-f", "private-compose.yaml", "config", "--no-env-resolution", "--format", "json")
		if err != nil {
			return err
		}
		raw, err = decodeComposeConfig(raw)
		if err != nil {
			return err
		}
		stage = "helper-renderer-scrub"
		rendered, err := s.render("scrub", raw, nil, nil)
		if err != nil {
			return err
		}
		safe, err := literalBytes(rendered["config"])
		if err != nil || os.WriteFile("private-compose.yaml", safe, 0600) != nil {
			return ErrDenied
		}
		stage = "helper-delivery-revoke"
		if err = client.Revoke(s.Delivery, s.Manifest.Scope); err != nil {
			return err
		}
		stage = "helper-context-scan"
		if err = s.scanContext(); err != nil {
			return err
		}
		stage = "helper-volume-inventory"
		if err = s.inventoryVolumes(s.Settings.VolumeMode == "NewCreate"); err != nil {
			return err
		}
		if s.Settings.Mode == "prepare" {
			stage = "helper-renderer-prepare"
			prepared, err := s.render("prepare", rendered["config"], nil, nil)
			if err != nil {
				return err
			}
			safe, err := literalBytes(prepared["config"])
			if err != nil || writePrivate("effective.json", safe) != nil {
				return ErrDenied
			}
			stage = "helper-image-build"
			if _, err = s.compose("user-image-build", "build", "--no-cache"); err != nil {
				return err
			}
			if s.Settings.RedisImage == "" {
				stage = "helper-dependency-pull"
				if _, err = s.compose("dependency-pull", "pull", "--ignore-buildable"); err != nil {
					return err
				}
			}
		}
		stage = "helper-session-save"
		return s.save()
	}
	stage = "helper-start-session"
	if phase != "start" {
		return ErrDenied
	}
	state, err := os.ReadFile(privateDir + "/session.json")
	if err != nil || !strictJSON(state) || json.Unmarshal(state, &s) != nil {
		return ErrDenied
	}
	client, err := NewClient(s.Origin, ca)
	if err != nil {
		return ErrDenied
	}
	if s.Manifest.Scope.Deployment != filepath.Base(cwd) {
		return ErrDenied
	}
	stage = "helper-start-prepare"
	if s.Settings.Mode == "prepare" {
		raw, err := s.run("runtime-normalization", nil, "docker", "compose", "--project-name", s.Manifest.Scope.Application, "--project-directory", cwd, "-f", "private-compose.yaml", "config", "--format", "json")
		if err != nil {
			return err
		}
		raw, err = decodeComposeConfig(raw)
		if err != nil {
			return err
		}
		var doc struct {
			Services map[string]struct {
				Image string `json:"image"`
			} `json:"services"`
		}
		if json.Unmarshal(raw, &doc) != nil || len(doc.Services) != 2 {
			return ErrDenied
		}
		s.Images = map[string]string{}
		for _, name := range []string{"web", "redis"} {
			ref := doc.Services[name].Image
			if name == "redis" && s.Settings.RedisImage != "" {
				ref = s.Settings.RedisImage
			}
			id, err := s.run("image-pin", nil, "docker", "image", "inspect", "--format", "{{.Id}}", ref)
			if err != nil {
				return err
			}
			s.Images[name] = strings.TrimSpace(string(id))
		}
		frozen, err := s.render("freeze", raw, s.Images, nil)
		if err != nil {
			return err
		}
		s.Config = frozen["config"]
	} else {
		if err = s.inventoryVolumes(false); err != nil {
			return err
		}
		for _, name := range s.Settings.Volumes {
			ids, err := s.run("writer-absence", nil, "docker", "ps", "-aq", "--filter", "volume="+name)
			if err != nil || len(bytes.TrimSpace(ids)) != 0 {
				return ErrDenied
			}
		}
	}
	if scanSecrets(s.Config, s.Delivery, s.Manifest.Submission) {
		return ErrDenied
	}
	for _, id := range s.Images {
		actual, err := s.run("retained-image", nil, "docker", "image", "inspect", "--format", "{{.Id}}", id)
		if err != nil || strings.TrimSpace(string(actual)) != id {
			return ErrDenied
		}
	}
	safe, err := literalBytes(s.Config)
	if err != nil || writePrivate("effective.json", safe) != nil {
		return ErrDenied
	}
	resolved, err := s.compose("literal-roundtrip", "config", "--format", "json")
	if err != nil {
		return ErrDenied
	}
	resolved, err = decodeComposeConfig(resolved)
	if err != nil {
		return err
	}
	if s.Settings.Mode == "prepare" {
		s.Config = resolved
		safe, err = literalBytes(s.Config)
		if err != nil || writePrivate("effective.json", safe) != nil {
			return ErrDenied
		}
		resolved, err = s.compose("frozen-roundtrip", "config", "--format", "json")
		if err != nil {
			return ErrDenied
		}
		resolved, err = decodeComposeConfig(resolved)
		if err != nil {
			return err
		}
	}
	if !sameJSON(resolved, s.Config) {
		return ErrDenied
	}
	if s.Settings.Mode != "prepare" {
		if s.Settings.Mode == "fault" {
			var doc map[string]any
			_ = json.Unmarshal(s.Config, &doc)
			web := doc["services"].(map[string]any)["web"].(map[string]any)
			web["entrypoint"] = []string{"/bin/sh", "-c", "exit 42"}
			web["command"] = []string{}
			fault, _ := json.Marshal(doc)
			safe, err = literalBytes(fault)
			if err != nil || writePrivate("effective.json", safe) != nil {
				return ErrDenied
			}
		}
		if _, err = s.compose("create-without-start", "create", "--no-build", "--pull", "never"); err != nil {
			return err
		}
	}
	artifact := RuntimeArtifact{1, s.Manifest.Scope, s.Config, Hash(s.Config), s.Images}
	data, _ := json.Marshal(artifact)
	stage = "helper-artifact-submit"
	if _, err = client.Submit(s.Manifest.Submission, s.Manifest.Scope, data); err != nil {
		return ErrDenied
	}
	stage = "helper-release-wait"
	{
		deadline := time.Now().Add(90 * time.Second)
		released := false
		for time.Now().Before(deadline) {
			ready, err := client.Released(s.Manifest.Submission, s.Manifest.Scope)
			if err != nil {
				return err
			}
			if ready {
				released = true
				break
			}
			time.Sleep(time.Second)
		}
		if !released {
			return ErrDenied
		}
	}
	stage = "helper-after-release"
	if err = client.Revoke(s.Manifest.Submission, s.Manifest.Scope); err != nil {
		return err
	}
	s.Delivery = ""
	s.Manifest.Submission = ""
	if s.save() != nil {
		return ErrDenied
	}
	if s.Settings.Mode != "prepare" {
		stage = "helper-runtime-start"
		_, err = s.compose("start-after-runner-inspection", "start", "--wait", "--wait-timeout", "20")
		if err != nil {
			return err
		}
	}
	return nil
}

var _ io.Writer = (*boundedOutput)(nil)
