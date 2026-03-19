//go:build windows

package hostuuid

import "golang.org/x/sys/windows/registry"

var uuidKeyPath = "SYSTEM\\HardwareConfig"
var uuidKey = "LastConfig"

// GetUUID returns the Windows hardware config UUID when available.
func GetUUID() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, uuidKeyPath, registry.QUERY_VALUE)
	if err == nil {
		uuidStr, _, err := key.GetStringValue(uuidKey)
		if err == nil && 37 <= len(uuidStr) {
			return uuidStr[1:37]
		}
	}
	return UUIDFromMAC()
}
