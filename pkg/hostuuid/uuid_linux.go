//go:build linux

package hostuuid

import (
	"fmt"
	"os"
)

// GetUUID returns the Linux machine ID when available.
func GetUUID() string {
	identifier, err := os.ReadFile("/etc/machine-id")
	if err != nil || len(identifier) != 33 {
		identifier, err = os.ReadFile("/var/lib/dbus/machine-id")
		if err != nil || len(identifier) != 33 {
			return UUIDFromMAC()
		}
	}

	return fmt.Sprintf("%s-%s-%s-%s-%s",
		identifier[0:8],
		identifier[8:12],
		identifier[12:16],
		identifier[16:20],
		identifier[20:32],
	)
}
