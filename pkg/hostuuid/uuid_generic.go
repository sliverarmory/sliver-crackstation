//go:build !(linux || darwin || windows)

package hostuuid

// GetUUID falls back to a MAC-derived UUID on unsupported platforms.
func GetUUID() string {
	return UUIDFromMAC()
}
