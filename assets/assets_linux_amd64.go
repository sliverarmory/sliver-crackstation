package assets

import "embed"

var (
	//go:embed linux/amd64/*
	assetsFs embed.FS
)
