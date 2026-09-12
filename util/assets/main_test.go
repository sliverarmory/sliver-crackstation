package main

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestHashcatDownloads(t *testing.T) {
	if defaultHashcatVersion != "7.1.2-armory.2" {
		t.Fatalf("default Hashcat version = %q", defaultHashcatVersion)
	}
	if defaultHashcatSourceCommit != "f108828b55f2ab514cbdc0eede253e2f17046382" {
		t.Fatalf("default Hashcat source commit = %q", defaultHashcatSourceCommit)
	}

	want := []assetDownload{
		{
			name: "hashcat-windows_amd64.zip",
			path: filepath.FromSlash("assets/windows/amd64/hashcat.zip"),
			url:  "https://github.com/sliverarmory/hashcat/releases/download/v7.1.2-armory.2/hashcat-windows_amd64.zip",
		},
		{
			name: "hashcat-linux_amd64.zip",
			path: filepath.FromSlash("assets/linux/amd64/hashcat.zip"),
			url:  "https://github.com/sliverarmory/hashcat/releases/download/v7.1.2-armory.2/hashcat-linux_amd64.zip",
		},
		{
			name: "hashcat-darwin_arm64.zip",
			path: filepath.FromSlash("assets/darwin/arm64/hashcat.zip"),
			url:  "https://github.com/sliverarmory/hashcat/releases/download/v7.1.2-armory.2/hashcat-darwin_arm64.zip",
		},
	}
	wantChecksums := map[string]string{
		"hashcat-darwin_arm64.zip":  "b90e83dc25706e9acf0554c5bd8f6c5356f2987f8346a56f7ef538f5a530fc4f",
		"hashcat-linux_amd64.zip":   "2b8e60ddec4243df786affdcd54b8776569d44fbeee4d3d9c093794ba1f9c235",
		"hashcat-windows_amd64.zip": "494c1c72ab025e71bb747dbe720f2021c152959c261b61f648c4a6b33e4a5187",
	}

	got := hashcatDownloads(defaultHashcatVersion)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected downloads:\n got: %#v\nwant: %#v", got, want)
	}
	if !reflect.DeepEqual(pinnedHashcatChecksums, wantChecksums) {
		t.Fatalf("unexpected pinned checksums:\n got: %#v\nwant: %#v", pinnedHashcatChecksums, wantChecksums)
	}
}

func TestParseChecksums(t *testing.T) {
	input := strings.NewReader(
		"B90E83DC25706E9ACF0554C5BD8F6C5356F2987F8346A56F7EF538F5A530FC4F  hashcat-darwin_arm64.zip\n" +
			"2b8e60ddec4243df786affdcd54b8776569d44fbeee4d3d9c093794ba1f9c235 *hashcat-linux_amd64.zip\n",
	)

	got, err := parseChecksums(input)
	if err != nil {
		t.Fatalf("parseChecksums returned an error: %v", err)
	}
	want := map[string]string{
		"hashcat-darwin_arm64.zip": "b90e83dc25706e9acf0554c5bd8f6c5356f2987f8346a56f7ef538f5a530fc4f",
		"hashcat-linux_amd64.zip":  "2b8e60ddec4243df786affdcd54b8776569d44fbeee4d3d9c093794ba1f9c235",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected checksums:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestParseChecksumsRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{
		"",
		"not-a-checksum hashcat.zip\n",
		"2b8e60ddec4243df786affdcd54b8776569d44fbeee4d3d9c093794ba1f9c235\n",
	} {
		if _, err := parseChecksums(strings.NewReader(input)); err == nil {
			t.Errorf("expected %q to be rejected", input)
		}
	}
}

func TestVerifyPinnedChecksums(t *testing.T) {
	published, err := parseChecksums(strings.NewReader(
		"b90e83dc25706e9acf0554c5bd8f6c5356f2987f8346a56f7ef538f5a530fc4f  hashcat-darwin_arm64.zip\n" +
			"2b8e60ddec4243df786affdcd54b8776569d44fbeee4d3d9c093794ba1f9c235  hashcat-linux_amd64.zip\n" +
			"494c1c72ab025e71bb747dbe720f2021c152959c261b61f648c4a6b33e4a5187  hashcat-windows_amd64.zip\n",
	))
	if err != nil {
		t.Fatal(err)
	}
	downloads := hashcatDownloads(defaultHashcatVersion)
	if err := verifyPinnedChecksums(downloads, published); err != nil {
		t.Fatalf("release manifest did not match pins: %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(map[string]string)
	}{
		{
			name: "missing",
			mutate: func(checksums map[string]string) {
				delete(checksums, "hashcat-windows_amd64.zip")
			},
		},
		{
			name: "mismatch",
			mutate: func(checksums map[string]string) {
				checksums["hashcat-windows_amd64.zip"] = strings.Repeat("0", 64)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			checksums := map[string]string{}
			for name, checksum := range published {
				checksums[name] = checksum
			}
			test.mutate(checksums)
			if err := verifyPinnedChecksums(downloads, checksums); err == nil {
				t.Fatal("modified release manifest matched pinned checksums")
			}
		})
	}
}
