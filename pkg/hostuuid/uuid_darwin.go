//go:build darwin

package hostuuid

import (
	"fmt"
	"syscall"
	"unsafe"
)

type uuidT struct {
	timeLow               uint32
	timeMid               uint16
	timeHiAndVersion      uint16
	clockSeqHiAndReserved uint8
	clockSeqLow           uint8
	node                  [6]uint8
}

type timespec struct {
	tvSec  uint32
	tvNsec int32
}

const gethostuuid = 142

// GetUUID returns the host UUID on Darwin.
func GetUUID() string {
	identifier := uuidT{}
	timeout := timespec{tvSec: 5, tvNsec: 0}
	syscall.Syscall(
		gethostuuid,
		uintptr(unsafe.Pointer(&identifier)),
		uintptr(unsafe.Pointer(&timeout)),
		0,
	)
	return fmt.Sprintf(
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		byte(identifier.timeLow), byte(identifier.timeLow>>8), byte(identifier.timeLow>>16), byte(identifier.timeLow>>24),
		byte(identifier.timeMid), byte(identifier.timeMid>>8),
		byte(identifier.timeHiAndVersion), byte(identifier.timeHiAndVersion>>8),
		byte(identifier.clockSeqHiAndReserved), byte(identifier.clockSeqLow),
		byte(identifier.node[0]), byte(identifier.node[1]), byte(identifier.node[2]),
		byte(identifier.node[3]), byte(identifier.node[4]), byte(identifier.node[5]),
	)
}
