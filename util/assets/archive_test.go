package main

import (
	"archive/zip"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPinnedHashcatArchivesMatchRelease(t *testing.T) {
	for _, download := range hashcatDownloads(defaultHashcatVersion) {
		t.Run(download.name, func(t *testing.T) {
			archivePath := filepath.Join(repositoryRoot(t), download.path)
			archive, err := os.Open(archivePath)
			if err != nil {
				t.Fatalf("open generated archive (run make assets first): %v", err)
			}
			hasher := sha256.New()
			if _, err := io.Copy(hasher, archive); err != nil {
				archive.Close()
				t.Fatal(err)
			}
			if err := archive.Close(); err != nil {
				t.Fatal(err)
			}
			if got, want := fmt.Sprintf("%x", hasher.Sum(nil)), pinnedHashcatChecksums[download.name]; got != want {
				t.Fatalf("archive SHA-256 = %s, want %s", got, want)
			}

			reader, err := zip.OpenReader(archivePath)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			provenance, err := readZipFile(reader.File, "docs/hashcat-build-provenance.txt")
			if err != nil {
				t.Fatal(err)
			}
			wantProvenance := []string{
				"HASHCAT_REPOSITORY: https://github.com/sliverarmory/hashcat.git",
				"HASHCAT_REF: " + defaultHashcatSourceCommit,
			}
			// The cross-built archives record the release tag in addition to the
			// source ref; the native Darwin provenance records only the source ref.
			if download.name != "hashcat-darwin_arm64.zip" {
				wantProvenance = append(wantProvenance, "VERSION_TAG: v"+defaultHashcatVersion)
			}
			for _, want := range wantProvenance {
				if !strings.Contains(string(provenance), want) {
					t.Fatalf("build provenance does not contain %q:\n%s", want, provenance)
				}
			}
		})
	}
}

func TestPinnedWindowsHashcatArchiveIsComplete(t *testing.T) {
	archivePath := filepath.Join(repositoryRoot(t), "assets", "windows", "amd64", "hashcat.zip")
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		t.Fatalf("open generated Windows archive (run make assets first): %v", err)
	}
	defer reader.Close()

	entries := make(map[string]struct{}, len(reader.File))
	moduleCount := 0
	openCLSourceCount := 0
	for _, file := range reader.File {
		entries[file.Name] = struct{}{}
		if strings.HasPrefix(file.Name, "modules/module_") && strings.HasSuffix(file.Name, ".dll") {
			moduleCount++
		}
		if strings.HasPrefix(file.Name, "OpenCL/") && (strings.HasSuffix(file.Name, ".cl") || strings.HasSuffix(file.Name, ".h")) {
			openCLSourceCount++
		}
	}
	if got, want := len(reader.File), 2861; got != want {
		t.Errorf("Windows archive entries = %d, want %d", got, want)
	}
	if got, want := moduleCount, 595; got != want {
		t.Errorf("Windows module DLLs = %d, want %d", got, want)
	}
	if got, want := openCLSourceCount, 1838; got != want {
		t.Errorf("Windows OpenCL source files = %d, want %d", got, want)
	}
	for _, name := range []string{
		"hashcat.exe",
		"hashcat.dll",
		"hashcat.hcstat2",
		"liblzma.dll",
		"libzstd.dll",
		"zlib1.dll",
		"modules/module_00000.dll",
		"OpenCL/shared.cl",
		"OpenCL/inc_common.cl",
		"OpenCL/inc_common.h",
		"OpenCL/m00000_a3-pure.cl",
		"OpenCL/m00400-pure.cl",
	} {
		if _, ok := entries[name]; !ok {
			t.Errorf("Windows archive is missing %s", name)
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate archive test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func readZipFile(files []*zip.File, name string) ([]byte, error) {
	for _, file := range files {
		if file.Name != name {
			continue
		}
		reader, err := file.Open()
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return io.ReadAll(reader)
	}
	return nil, fmt.Errorf("archive is missing %s", name)
}
