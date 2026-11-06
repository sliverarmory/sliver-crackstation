package main

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestHashcatDownloads(t *testing.T) {
	if defaultHashcatVersion != "8.0.0-armory.2" {
		t.Fatalf("default Hashcat version = %q", defaultHashcatVersion)
	}
	if defaultHashcatSourceCommit != "d745d3074dd296fdc1e91c9e48dee8a317d3c2d8" {
		t.Fatalf("default Hashcat source commit = %q", defaultHashcatSourceCommit)
	}

	want := []assetDownload{
		{
			name: "hashcat-windows_amd64.zip",
			path: filepath.FromSlash("assets/windows/amd64/hashcat.zip"),
			url:  "https://github.com/sliverarmory/hashcat/releases/download/v8.0.0-armory.2/hashcat-windows_amd64.zip",
		},
		{
			name: "hashcat-linux_amd64.zip",
			path: filepath.FromSlash("assets/linux/amd64/hashcat.zip"),
			url:  "https://github.com/sliverarmory/hashcat/releases/download/v8.0.0-armory.2/hashcat-linux_amd64.zip",
		},
		{
			name: "hashcat-darwin_arm64.zip",
			path: filepath.FromSlash("assets/darwin/arm64/hashcat.zip"),
			url:  "https://github.com/sliverarmory/hashcat/releases/download/v8.0.0-armory.2/hashcat-darwin_arm64.zip",
		},
	}
	wantChecksums := map[string]string{
		"hashcat-darwin_arm64.zip":  "5aac57923cd92952b7b6d9b58bd18493647b01a3af4e60e8c46a1998e21ea98e",
		"hashcat-linux_amd64.zip":   "75c13262a37d65c3e02732805f24f28de548fd2bc9e241aaa9d0d4aa4b6f9e12",
		"hashcat-windows_amd64.zip": "7fdd7e098fe3e88661413348b54a3881174c1da7626f94e541456e7c9811ad72",
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
		"5AAC57923CD92952B7B6D9B58BD18493647B01A3AF4E60E8C46A1998E21EA98E  hashcat-darwin_arm64.zip\n" +
			"75c13262a37d65c3e02732805f24f28de548fd2bc9e241aaa9d0d4aa4b6f9e12 *hashcat-linux_amd64.zip\n",
	)

	got, err := parseChecksums(input)
	if err != nil {
		t.Fatalf("parseChecksums returned an error: %v", err)
	}
	want := map[string]string{
		"hashcat-darwin_arm64.zip": "5aac57923cd92952b7b6d9b58bd18493647b01a3af4e60e8c46a1998e21ea98e",
		"hashcat-linux_amd64.zip":  "75c13262a37d65c3e02732805f24f28de548fd2bc9e241aaa9d0d4aa4b6f9e12",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected checksums:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestParseChecksumsRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{
		"",
		"not-a-checksum hashcat.zip\n",
		"75c13262a37d65c3e02732805f24f28de548fd2bc9e241aaa9d0d4aa4b6f9e12\n",
	} {
		if _, err := parseChecksums(strings.NewReader(input)); err == nil {
			t.Errorf("expected %q to be rejected", input)
		}
	}
}

func TestVerifyPinnedChecksums(t *testing.T) {
	published, err := parseChecksums(strings.NewReader(
		"5aac57923cd92952b7b6d9b58bd18493647b01a3af4e60e8c46a1998e21ea98e  hashcat-darwin_arm64.zip\n" +
			"75c13262a37d65c3e02732805f24f28de548fd2bc9e241aaa9d0d4aa4b6f9e12  hashcat-linux_amd64.zip\n" +
			"7fdd7e098fe3e88661413348b54a3881174c1da7626f94e541456e7c9811ad72  hashcat-windows_amd64.zip\n",
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
