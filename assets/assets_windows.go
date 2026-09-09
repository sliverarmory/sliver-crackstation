package assets

import "embed"

const hashcatExe = "hashcat.exe"

var (
	//go:embed windows/amd64/hashcat.zip
	assetsFs embed.FS
)
