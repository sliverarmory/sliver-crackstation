package assets

import "embed"

const hashcatExe = "hashcat"

var (
	//go:embed darwin/arm64/hashcat.zip
	assetsFs embed.FS
)
