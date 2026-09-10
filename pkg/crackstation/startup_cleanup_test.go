package crackstation

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sliverarmory/sliver-crackstation/pkg/hashcat"
)

func TestHasNonemptyPrefix(t *testing.T) {
	prefixes := []string{"hashes", ".recovered-"}
	tests := map[string]bool{
		"hashes123":          true,
		"hashes-orphan":      true,
		".recovered-123":     true,
		".recovered-orphan":  true,
		"hashes":             false,
		".recovered-":        false,
		".hashes123":         false,
		"recovered-123":      false,
		"unrelated-dot-file": false,
	}
	for name, want := range tests {
		t.Run(name, func(t *testing.T) {
			if got := hasNonemptyPrefix(name, prefixes); got != want {
				t.Fatalf("hasNonemptyPrefix(%q) = %t, want %t", name, got, want)
			}
		})
	}
}

func TestCleanupStaleTaskMaterializationsRemovesOnlyReservedRegularFiles(t *testing.T) {
	root := t.TempDir()
	station := &Crackstation{dataDir: filepath.Join(root, "data")}
	taskDir := filepath.Join(station.dataDir, "tasks")
	appTmpDir := filepath.Join(root, ".tmp")
	for _, directory := range []string{taskDir, appTmpDir} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}

	taskStale := []string{".recovered-123456789", ".recovered-interrupted"}
	taskPreserved := []string{".recovered-", ".recovered", ".keep", "recovered-123"}
	appStale := make([]string, 0, 2*len(hashcatTaskMaterializationPrefixes))
	appPreserved := []string{".keep", ".env", "unrelated", ".hashes123"}
	for _, prefix := range hashcatTaskMaterializationPrefixes {
		appStale = append(appStale, prefix+"123456789", prefix+"-interrupted")
		appPreserved = append(appPreserved, prefix)
	}
	for _, fixture := range []struct {
		directory string
		names     []string
	}{
		{directory: taskDir, names: append(append([]string{}, taskStale...), taskPreserved...)},
		{directory: appTmpDir, names: append(append([]string{}, appStale...), appPreserved...)},
	} {
		for _, name := range fixture.names {
			if err := os.WriteFile(filepath.Join(fixture.directory, name), []byte("secret sentinel"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	matchingDirectories := []string{
		filepath.Join(taskDir, ".recovered-directory"),
		filepath.Join(appTmpDir, "hashesdirectory"),
		filepath.Join(appTmpDir, hashcat.ManagedWorkDirPrefix),
	}
	for _, directory := range matchingDirectories {
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	staleWorkDirectory := filepath.Join(appTmpDir, hashcat.ManagedWorkDirPrefix+"interrupted")
	if err := os.Mkdir(staleWorkDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staleWorkDirectory, "task-data"), []byte("secret sentinel"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := station.CleanupStaleTaskMaterializations(appTmpDir); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		directory string
		stale     []string
		preserved []string
	}{
		{directory: taskDir, stale: taskStale, preserved: taskPreserved},
		{directory: appTmpDir, stale: appStale, preserved: appPreserved},
	} {
		for _, name := range fixture.stale {
			path := filepath.Join(fixture.directory, name)
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("stale materialization %q was not removed: %v", path, err)
			}
		}
		for _, name := range fixture.preserved {
			path := filepath.Join(fixture.directory, name)
			if _, err := os.Stat(path); err != nil {
				t.Errorf("unrelated file %q was removed: %v", path, err)
			}
		}
	}
	for _, directory := range matchingDirectories {
		if info, err := os.Stat(directory); err != nil || !info.IsDir() {
			t.Errorf("matching directory %q was removed: %v", directory, err)
		}
	}
	if _, err := os.Stat(staleWorkDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale managed Hashcat working directory was not removed: %v", err)
	}
}

func TestCleanupStaleTaskMaterializationsAllowsMissingDirectories(t *testing.T) {
	root := t.TempDir()
	station := &Crackstation{dataDir: filepath.Join(root, "data")}
	if err := station.CleanupStaleTaskMaterializations(filepath.Join(root, ".tmp")); err != nil {
		t.Fatal(err)
	}
}

func TestNewCrackstationCleansStaleTaskMaterializations(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", root)
	dataDir := filepath.Join(root, "data")
	taskDir := filepath.Join(dataDir, "tasks")
	appTmpDir := filepath.Join(root, ".tmp")
	for _, directory := range []string{taskDir, appTmpDir} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	recoveredPath := filepath.Join(taskDir, ".recovered-interrupted")
	hashesPath := filepath.Join(appTmpDir, "hashes-interrupted")
	for _, path := range []string{recoveredPath, hashesPath} {
		if err := os.WriteFile(path, []byte("credential material"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	station, err := NewCrackstation("worker", dataDir, &hashcat.Hashcat{})
	if err != nil {
		t.Fatal(err)
	}
	if station == nil {
		t.Fatal("NewCrackstation() returned a nil station")
	}
	for _, path := range []string{recoveredPath, hashesPath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("constructor left stale materialization %q: %v", path, err)
		}
	}
}

func TestNewCrackstationPropagatesCleanupFailure(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", root)
	dataDir := filepath.Join(root, "data")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "tasks"), []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}

	station, err := NewCrackstation("worker", dataDir, &hashcat.Hashcat{})
	if err == nil || !strings.Contains(err.Error(), "clean stale crack task files") {
		t.Fatalf("NewCrackstation() = %v, %v; want cleanup failure", station, err)
	}
	if station != nil {
		t.Fatal("NewCrackstation() returned a partially initialized station after cleanup failure")
	}
}
