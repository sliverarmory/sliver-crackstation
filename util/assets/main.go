package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultHashcatVersion = "7.1.2-armory.2"
	// defaultHashcatSourceCommit is recorded in each archive's build provenance.
	defaultHashcatSourceCommit = "f108828b55f2ab514cbdc0eede253e2f17046382"
	hashcatReleaseBaseURL      = "https://github.com/sliverarmory/hashcat/releases/download"
)

var pinnedHashcatChecksums = map[string]string{
	"hashcat-darwin_arm64.zip":  "b90e83dc25706e9acf0554c5bd8f6c5356f2987f8346a56f7ef538f5a530fc4f",
	"hashcat-linux_amd64.zip":   "2b8e60ddec4243df786affdcd54b8776569d44fbeee4d3d9c093794ba1f9c235",
	"hashcat-windows_amd64.zip": "494c1c72ab025e71bb747dbe720f2021c152959c261b61f648c4a6b33e4a5187",
}

type assetDownload struct {
	name string
	path string
	url  string
}

func main() {
	version := flag.String("version", defaultHashcatVersion, "hashcat version to download")
	flag.Parse()

	downloads := hashcatDownloads(*version)
	checksumsSource := fmt.Sprintf("%s/v%s/SHA256SUMS", hashcatReleaseBaseURL, *version)
	checksums, err := fetchChecksums(checksumsSource)
	if err != nil {
		exitError(err)
	}
	if *version == defaultHashcatVersion {
		if err := verifyPinnedChecksums(downloads, checksums); err != nil {
			exitError(err)
		}
		checksums = pinnedHashcatChecksums
	}

	fmt.Println("-----------------------------------------------------------------")
	fmt.Println(" Hashcat")
	fmt.Println("-----------------------------------------------------------------")

	for _, download := range downloads {
		expectedChecksum, ok := checksums[download.name]
		if !ok {
			exitError(fmt.Errorf("checksum for %s not found in %s", download.name, checksumsSource))
		}
		if err := fetch(download.path, download.url, expectedChecksum); err != nil {
			exitError(err)
		}
	}
}

func verifyPinnedChecksums(downloads []assetDownload, published map[string]string) error {
	for _, download := range downloads {
		pinned, ok := pinnedHashcatChecksums[download.name]
		if !ok {
			return fmt.Errorf("pinned checksum for %s not found", download.name)
		}
		releaseChecksum, ok := published[download.name]
		if !ok {
			return fmt.Errorf("checksum for %s not found in release manifest", download.name)
		}
		if pinned != releaseChecksum {
			return fmt.Errorf("release checksum mismatch for %s: got %s, expected pinned %s", download.name, releaseChecksum, pinned)
		}
	}
	return nil
}

func hashcatDownloads(version string) []assetDownload {
	return []assetDownload{
		{
			name: "hashcat-windows_amd64.zip",
			path: filepath.FromSlash("assets/windows/amd64/hashcat.zip"),
			url:  fmt.Sprintf("%s/v%s/hashcat-windows_amd64.zip", hashcatReleaseBaseURL, version),
		},
		{
			name: "hashcat-linux_amd64.zip",
			path: filepath.FromSlash("assets/linux/amd64/hashcat.zip"),
			url:  fmt.Sprintf("%s/v%s/hashcat-linux_amd64.zip", hashcatReleaseBaseURL, version),
		},
		{
			name: "hashcat-darwin_arm64.zip",
			path: filepath.FromSlash("assets/darwin/arm64/hashcat.zip"),
			url:  fmt.Sprintf("%s/v%s/hashcat-darwin_arm64.zip", hashcatReleaseBaseURL, version),
		},
	}
}

func fetchChecksums(url string) (map[string]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("unexpected status for %s: %s", url, resp.Status)
	}

	checksums, err := parseChecksums(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", url, err)
	}
	return checksums, nil
}

func parseChecksums(r io.Reader) (map[string]string, error) {
	checksums := map[string]string{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			return nil, fmt.Errorf("invalid checksum line %q", scanner.Text())
		}
		digest, err := hex.DecodeString(fields[0])
		if err != nil || len(digest) != sha256.Size {
			return nil, fmt.Errorf("invalid SHA-256 checksum %q", fields[0])
		}
		name := strings.TrimPrefix(fields[1], "*")
		if name == "" {
			return nil, fmt.Errorf("missing asset name in checksum line %q", scanner.Text())
		}
		checksums[name] = strings.ToLower(fields[0])
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(checksums) == 0 {
		return nil, fmt.Errorf("checksum file is empty")
	}
	return checksums, nil
}

func fetch(dst, url, expectedChecksum string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("create asset directory for %s: %w", dst, err)
	}

	fmt.Printf("download %s -> %s\n", url, dst)

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("request %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("unexpected status for %s: %s", url, resp.Status)
	}

	out, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+"-*")
	if err != nil {
		return fmt.Errorf("create temporary asset for %s: %w", dst, err)
	}
	tmpPath := out.Name()
	defer os.Remove(tmpPath)

	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, hasher), resp.Body); err != nil {
		out.Close()
		return fmt.Errorf("write %s: %w", dst, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpPath, err)
	}

	actualChecksum := hex.EncodeToString(hasher.Sum(nil))
	if actualChecksum != strings.ToLower(expectedChecksum) {
		return fmt.Errorf("checksum mismatch for %s: got %s, expected %s", url, actualChecksum, expectedChecksum)
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		return fmt.Errorf("replace %s: %w", dst, err)
	}

	return nil
}

func exitError(err error) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	os.Exit(1)
}
