package hostuuid

import (
	"crypto/sha256"
	"net"
	"sort"

	"github.com/gofrs/uuid"
)

var zeroGUID = uuid.Must(uuid.FromString("00000000-0000-0000-0000-000000000000"))

// UUIDFromMAC derives a stable UUID from the machine MAC addresses.
func UUIDFromMAC() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return zeroGUID.String()
	}

	hardwareAddrs := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface.HardwareAddr != nil {
			hardwareAddrs = append(hardwareAddrs, iface.HardwareAddr.String())
		}
	}
	if len(hardwareAddrs) == 0 {
		return zeroGUID.String()
	}

	sort.Strings(hardwareAddrs)
	digest := sha256.New()
	for _, addr := range hardwareAddrs {
		digest.Write([]byte(addr))
	}
	value, err := uuid.FromBytes(digest.Sum(nil)[:16])
	if err != nil {
		return zeroGUID.String()
	}
	return value.String()
}
