package assets

import "embed"

const hashcatExe = "hashcat.bin"

var (
	//go:embed linux/amd64/hashcat.zip
	assetsFs embed.FS
)
