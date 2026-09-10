package assets

import (
	"path/filepath"
	"testing"
)

func TestGetRootAppDirNormalizesRelativeOverride(t *testing.T) {
	workingDirectory := t.TempDir()
	t.Chdir(workingDirectory)
	t.Setenv(envVarName, "relative-root")

	got := GetRootAppDir()
	want := filepath.Join(workingDirectory, "relative-root")
	if got != want || !filepath.IsAbs(got) {
		t.Fatalf("GetRootAppDir() = %q; want absolute %q", got, want)
	}
}
