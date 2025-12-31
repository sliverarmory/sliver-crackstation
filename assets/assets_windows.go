package assets

import "embed"

var (
	//go:embed windows/amd64/*
	assetsFs embed.FS
)
