package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const defaultHashcatVersion = "6.2.6"

type assetDownload struct {
	path string
	url  string
}

func main() {
	version := flag.String("version", defaultHashcatVersion, "hashcat version to download")
	flag.Parse()

	downloads := []assetDownload{
		{
			path: filepath.FromSlash("assets/windows/amd64/hashcat.zip"),
			url:  fmt.Sprintf("https://github.com/moloch--/hashcat/releases/download/v%s/hashcat-windows_amd64.zip", *version),
		},
		{
			path: filepath.FromSlash("assets/linux/amd64/hashcat.zip"),
			url:  fmt.Sprintf("https://github.com/moloch--/hashcat/releases/download/v%s/hashcat-linux_amd64.zip", *version),
		},
		{
			path: filepath.FromSlash("assets/darwin/amd64/hashcat.zip"),
			url:  fmt.Sprintf("https://github.com/moloch--/hashcat/releases/download/v%s/hashcat-darwin_universal.zip", *version),
		},
		{
			path: filepath.FromSlash("assets/darwin/arm64/hashcat.zip"),
			url:  fmt.Sprintf("https://github.com/moloch--/hashcat/releases/download/v%s/hashcat-darwin_universal.zip", *version),
		},
	}

	fmt.Println("-----------------------------------------------------------------")
	fmt.Println(" Hashcat")
	fmt.Println("-----------------------------------------------------------------")

	for _, download := range downloads {
		if err := fetch(download.path, download.url); err != nil {
			exitError(err)
		}
	}
}

func fetch(dst, url string) error {
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

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("write %s: %w", dst, err)
	}

	return nil
}

func exitError(err error) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	os.Exit(1)
}
