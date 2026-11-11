package privatefixture

import (
	"fmt"
	"io/fs"
	"strings"
)

type SourceFile struct {
	Digest string `json:"digest"`
	Mode   uint32 `json:"mode"`
}

// Match the pinned provider's one contiguous insertion immediately after FROM.
// Keep original ARG statements in place; never strip arbitrary ARG lines.
// This synthetic profile disables provider default/source-commit build variables,
// leaving exactly these two explicitly created build-time variables.
func verifyDockerfile(data []byte, expected string) error {
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 4 || !strings.HasPrefix(lines[0], "FROM ") {
		return ErrDenied
	}
	seen := map[string]bool{}
	i := 1
	for i < len(lines) && strings.HasPrefix(lines[i], "ARG ") {
		if (lines[i] != "ARG "+reserved && lines[i] != "ARG FIXTURE_BUILD_ALLOWED") || seen[lines[i]] {
			return ErrDenied
		}
		seen[lines[i]] = true
		i++
	}
	if len(seen) != 2 {
		return ErrDenied
	}
	original := append([]string{lines[0]}, lines[i:]...)
	if Hash([]byte(strings.Join(original, "\n"))) != expected {
		return ErrDenied
	}
	return nil
}

func verifyCheckout(tree fs.FS, manifest map[string]SourceFile, dockerfileDigest string) error {
	if len(manifest) == 0 || len(manifest) > 256 || !digest.MatchString(dockerfileDigest) {
		return ErrDenied
	}
	wantDirs := map[string]bool{".": true}
	expected := map[string]bool{"private-compose.yaml": true, "private-app/Dockerfile": true}
	for path, file := range manifest {
		if !fs.ValidPath(path) || strings.Contains(path, "\\") || path == "private-compose.yaml" || path == "private-app/Dockerfile" || !digest.MatchString(file.Digest) || (file.Mode != 0644 && file.Mode != 0755) {
			return ErrDenied
		}
		expected[path] = true
	}
	for path := range expected {
		parts := strings.Split(path, "/")
		for i := 1; i < len(parts); i++ {
			wantDirs[strings.Join(parts[:i], "/")] = true
		}
	}
	seen := map[string]bool{}
	total := int64(0)
	err := fs.WalkDir(tree, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.Type()&fs.ModeSymlink != 0 {
			return ErrDenied
		}
		if entry.IsDir() {
			if !wantDirs[path] {
				return ErrDenied
			}
			return nil
		}
		if !expected[path] || seen[path] {
			return ErrDenied
		}
		seen[path] = true
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 {
			return ErrDenied
		}
		total += info.Size()
		if total > 16<<20 {
			return ErrDenied
		}
		mode := uint32(info.Mode().Perm())
		data, err := fs.ReadFile(tree, path)
		if err != nil {
			return ErrDenied
		}
		if path == "private-compose.yaml" {
			if mode != 0644 || len(data) == 0 {
				return ErrDenied
			}
			return nil
		}
		if path == "private-app/Dockerfile" {
			if mode != 0644 {
				return ErrDenied
			}
			return verifyDockerfile(data, dockerfileDigest)
		}
		file := manifest[path]
		if mode != file.Mode || Hash(data) != file.Digest {
			return ErrDenied
		}
		return nil
	})
	if err != nil || len(seen) != len(expected) {
		return ErrDenied
	}
	fmt.Println("FIXTURE_NATIVE_SOURCE exact-files-modes-and-provider-insertion-verified")
	return nil
}
