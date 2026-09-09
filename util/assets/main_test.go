package main

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestHashcatDownloads(t *testing.T) {
	want := []assetDownload{
		{
			name: "hashcat-windows_amd64.zip",
			path: filepath.FromSlash("assets/windows/amd64/hashcat.zip"),
			url:  "https://github.com/sliverarmory/hashcat/releases/download/v7.1.2-armory.1/hashcat-windows_amd64.zip",
		},
		{
			name: "hashcat-linux_amd64.zip",
			path: filepath.FromSlash("assets/linux/amd64/hashcat.zip"),
			url:  "https://github.com/sliverarmory/hashcat/releases/download/v7.1.2-armory.1/hashcat-linux_amd64.zip",
		},
		{
			name: "hashcat-darwin_arm64.zip",
			path: filepath.FromSlash("assets/darwin/arm64/hashcat.zip"),
			url:  "https://github.com/sliverarmory/hashcat/releases/download/v7.1.2-armory.1/hashcat-darwin_arm64.zip",
		},
	}

	got := hashcatDownloads(defaultHashcatVersion)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected downloads:\n got: %#v\nwant: %#v", got, want)
	}
	for _, download := range got {
		if pinnedHashcatChecksums[download.name] == "" {
			t.Errorf("missing pinned checksum for %s", download.name)
		}
	}
}

func TestParseChecksums(t *testing.T) {
	input := strings.NewReader(
		"8F8676A7526C4F6FC46E02231B0B245125F9BDDCDA20BD86248E381D38A24273  hashcat-darwin_arm64.zip\n" +
			"00f650995ff1c61bae4cbb0ac9a0afbb755484b555d5ecfe902c8a0614e17b12 *hashcat-linux_amd64.zip\n",
	)

	got, err := parseChecksums(input)
	if err != nil {
		t.Fatalf("parseChecksums returned an error: %v", err)
	}
	want := map[string]string{
		"hashcat-darwin_arm64.zip": "8f8676a7526c4f6fc46e02231b0b245125f9bddcda20bd86248e381d38a24273",
		"hashcat-linux_amd64.zip":  "00f650995ff1c61bae4cbb0ac9a0afbb755484b555d5ecfe902c8a0614e17b12",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected checksums:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestParseChecksumsRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{
		"",
		"not-a-checksum hashcat.zip\n",
		"00f650995ff1c61bae4cbb0ac9a0afbb755484b555d5ecfe902c8a0614e17b12\n",
	} {
		if _, err := parseChecksums(strings.NewReader(input)); err == nil {
			t.Errorf("expected %q to be rejected", input)
		}
	}
}
