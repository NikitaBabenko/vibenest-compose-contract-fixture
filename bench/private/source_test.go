package privatefixture

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

const originalDockerfile = "FROM node:24-alpine\nWORKDIR /app\nARG FIXTURE_BUILD_ALLOWED\nRUN test -n \"$FIXTURE_BUILD_ALLOWED\"\nUSER node"

func sourceTree() fstest.MapFS {
	return fstest.MapFS{
		"private-compose.yaml":   &fstest.MapFile{Data: []byte("provider generated"), Mode: 0644},
		"private-app/Dockerfile": &fstest.MapFile{Data: []byte(strings.Replace(originalDockerfile, "\n", "\nARG VN_ARTIFACT_CAPABILITY\nARG FIXTURE_BUILD_ALLOWED\n", 1)), Mode: 0644},
		"private-app/server.mjs": &fstest.MapFile{Data: []byte("trusted source"), Mode: 0644},
	}
}
func sourceManifest() map[string]SourceFile {
	return map[string]SourceFile{"private-app/server.mjs": {Hash([]byte("trusted source")), 0644}}
}

func TestNativeSourceExactFilesModesAndInsertion(t *testing.T) {
	if err := verifyCheckout(sourceTree(), sourceManifest(), Hash([]byte(originalDockerfile))); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tamper", "missing", "extra-file", "extra-dir", "symlink", "mode", "extra-command", "moved-original-arg", "extra-arg", "duplicate-arg"} {
		t.Run(name, func(t *testing.T) {
			tree := sourceTree()
			file := tree["private-app/Dockerfile"]
			switch name {
			case "tamper":
				tree["private-app/server.mjs"].Data = []byte("changed source")
			case "missing":
				delete(tree, "private-app/server.mjs")
			case "extra-file":
				tree["unexpected.sh"] = &fstest.MapFile{Data: []byte("echo unsafe"), Mode: 0644}
			case "extra-dir":
				tree["unexpected"] = &fstest.MapFile{Mode: fs.ModeDir | 0755}
			case "symlink":
				tree["private-app/server.mjs"].Mode = fs.ModeSymlink | 0777
			case "mode":
				tree["private-app/server.mjs"].Mode = 0755
			case "extra-command":
				file.Data = append(file.Data, []byte("\nRUN unexpected-command")...)
			case "moved-original-arg":
				file.Data = []byte(strings.Replace(string(file.Data), "WORKDIR /app\nARG FIXTURE_BUILD_ALLOWED", "ARG FIXTURE_BUILD_ALLOWED\nWORKDIR /app", 1))
			case "extra-arg":
				file.Data = []byte(strings.Replace(string(file.Data), "WORKDIR /app", "ARG EXTRA\nWORKDIR /app", 1))
			case "duplicate-arg":
				file.Data = []byte(strings.Replace(string(file.Data), "ARG VN_ARTIFACT_CAPABILITY", "ARG VN_ARTIFACT_CAPABILITY\nARG VN_ARTIFACT_CAPABILITY", 1))
			}
			if verifyCheckout(tree, sourceManifest(), Hash([]byte(originalDockerfile))) == nil {
				t.Fatal("unverified native source allowed")
			}
		})
	}
}

func TestNativeSourceManifestPathAndSchemaRefusal(t *testing.T) {
	for _, path := range []string{"../escape", "/absolute", "private-app\\server.mjs", "private-compose.yaml"} {
		m := sourceManifest()
		m[path] = SourceFile{Hash([]byte("x")), 0644}
		if verifyCheckout(sourceTree(), m, Hash([]byte(originalDockerfile))) == nil {
			t.Fatal("invalid manifest path")
		}
	}
}
