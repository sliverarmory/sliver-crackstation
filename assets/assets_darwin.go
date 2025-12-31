package assets

import "embed"

var (
	//go:embed darwin/arm64/*
	assetsFs embed.FS
)
