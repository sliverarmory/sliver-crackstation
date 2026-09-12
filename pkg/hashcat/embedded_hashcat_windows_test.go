package hashcat

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sliverarmory/sliver-crackstation/assets"
)

func TestEmbeddedWindowsHashcatPackage(t *testing.T) {
	appRoot := filepath.Join(t.TempDir(), "TITAN package, with spaces")
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", appRoot)
	assets.Setup(true, false)

	hashcatDir := assets.GetHashcatDir()
	for _, name := range []string{
		"hashcat.exe",
		"hashcat.dll",
		"hashcat.hcstat2",
		"liblzma.dll",
		"libzstd.dll",
		"zlib1.dll",
		filepath.FromSlash("docs/hashcat-build-provenance.txt"),
		filepath.FromSlash("modules/module_00000.dll"),
		filepath.FromSlash("OpenCL/shared.cl"),
		filepath.FromSlash("OpenCL/inc_common.cl"),
		filepath.FromSlash("OpenCL/inc_common.h"),
		filepath.FromSlash("OpenCL/m00000_a3-pure.cl"),
		filepath.FromSlash("OpenCL/m00400-pure.cl"),
	} {
		if _, err := os.Stat(filepath.Join(hashcatDir, name)); err != nil {
			t.Errorf("required Windows package file %s: %v", name, err)
		}
	}

	modules, err := filepath.Glob(filepath.Join(hashcatDir, "modules", "module_*.dll"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(modules), 595; got != want {
		t.Fatalf("extracted module DLLs = %d, want %d", got, want)
	}

	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		t.Fatal("SystemRoot is not set")
	}
	t.Setenv("PATH", strings.Join([]string{filepath.Join(systemRoot, "System32"), systemRoot}, string(os.PathListSeparator)))

	isolatedWorkingDirectory := filepath.Join(t.TempDir(), "hashcat isolated cwd")
	if err := os.MkdirAll(isolatedWorkingDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	hashcat := NewHashcat(hashcatDir)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	versionResult, err := hashcat.runHashcatStreamingInDirectory(
		ctx,
		[]string{"--version"},
		nil,
		nil,
		isolatedWorkingDirectory,
	)
	versionContextErr := ctx.Err()
	cancel()
	if err != nil || versionResult.ExitCode != 0 {
		t.Fatalf("run embedded Hashcat version probe: exit=%d err=%v context=%v stderr=%q", versionResult.ExitCode, err, versionContextErr, versionResult.Stderr)
	}
	if got, want := strings.TrimSpace(string(versionResult.Stdout)), "v7.1.2-armory.2"; got != want {
		t.Fatalf("embedded Hashcat version = %q, want %q", got, want)
	}

	hashInfoCtx, hashInfoCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	hashInfoResult, err := hashcat.runHashcatStreamingInDirectory(
		hashInfoCtx,
		[]string{"--hash-info", "--quiet"},
		nil,
		nil,
		isolatedWorkingDirectory,
	)
	hashInfoContextErr := hashInfoCtx.Err()
	hashInfoCancel()
	if err != nil || hashInfoResult.ExitCode != 0 {
		t.Fatalf("load embedded Hashcat modules: exit=%d err=%v context=%v stderr=%q", hashInfoResult.ExitCode, err, hashInfoContextErr, hashInfoResult.Stderr)
	}
	loadedModules := 0
	for _, line := range strings.Split(string(hashInfoResult.Stdout), "\n") {
		if strings.HasPrefix(strings.TrimSuffix(line, "\r"), "Hash mode #") {
			loadedModules++
		}
	}
	if loadedModules != len(modules) {
		t.Fatalf("Hashcat loaded %d of %d packaged modules from an isolated working directory", loadedModules, len(modules))
	}

	keyspaceCtx, keyspaceCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	keyspaceResult, err := hashcat.runHashcatStreamingInDirectory(
		keyspaceCtx,
		[]string{"-m", "0", "-a", "3", "--keyspace", "?d?d"},
		nil,
		nil,
		isolatedWorkingDirectory,
	)
	keyspaceContextErr := keyspaceCtx.Err()
	keyspaceCancel()
	if err != nil || keyspaceResult.ExitCode != 0 {
		t.Fatalf("run embedded Hashcat outside its package directory: exit=%d err=%v context=%v stderr=%q", keyspaceResult.ExitCode, err, keyspaceContextErr, keyspaceResult.Stderr)
	}
	if got, want := strings.TrimSpace(string(keyspaceResult.Stdout)), "10"; got != want {
		t.Fatalf("isolated-working-directory keyspace = %q, want %q", got, want)
	}
}
