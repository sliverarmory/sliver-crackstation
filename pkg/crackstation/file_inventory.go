package crackstation

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
)

// SyncedFileSnapshot is metadata for a crack file whose content has been
// verified in the local cache. It intentionally omits RPC identifiers, chunk
// metadata, and local filesystem paths. Presentation layers must sanitize the
// server-provided Name before displaying it in a terminal or other UI.
type SyncedFileSnapshot struct {
	Name             string
	Type             clientpb.CrackFileType
	UncompressedSize int64
	SHA256           string
	CreatedAt        time.Time
	LastModified     time.Time
}

// FileInventorySnapshot is the last completely downloaded and verified
// inventory for a single Sliver server. Obsolete files may be pruned after the
// snapshot is published.
type FileInventorySnapshot struct {
	Server    string
	Files     []SyncedFileSnapshot
	UpdatedAt time.Time
}

type serverFileInventory struct {
	retained map[string]struct{}
	snapshot FileInventorySnapshot
}

// FileInventories returns independent, deterministically ordered copies of the
// last completely downloaded and verified per-server inventories.
func (c *Crackstation) FileInventories() []FileInventorySnapshot {
	if c == nil {
		return nil
	}
	c.inventoryLock.RLock()
	defer c.inventoryLock.RUnlock()

	snapshots := make([]FileInventorySnapshot, 0, len(c.inventories))
	for _, inventory := range c.inventories {
		snapshots = append(snapshots, cloneFileInventorySnapshot(inventory.snapshot))
	}
	sort.Slice(snapshots, func(i, j int) bool {
		return fileInventorySnapshotLess(snapshots[i], snapshots[j])
	})
	return snapshots
}

func newFileInventorySnapshot(server *SliverServer, files []*clientpb.CrackFile, updatedAt time.Time) FileInventorySnapshot {
	snapshot := FileInventorySnapshot{
		Server:    fileInventoryServerLabel(server),
		Files:     make([]SyncedFileSnapshot, 0, len(files)),
		UpdatedAt: updatedAt,
	}
	for _, file := range files {
		if file == nil {
			continue
		}
		snapshot.Files = append(snapshot.Files, SyncedFileSnapshot{
			Name:             file.GetName(),
			Type:             file.GetType(),
			UncompressedSize: file.GetUncompressedSize(),
			SHA256:           file.GetSha2_256(),
			CreatedAt:        crackFileTimestamp(file.GetCreatedAt()),
			LastModified:     crackFileTimestamp(file.GetLastModified()),
		})
	}
	sort.Slice(snapshot.Files, func(i, j int) bool {
		return syncedFileSnapshotLess(snapshot.Files[i], snapshot.Files[j])
	})
	return snapshot
}

func cloneFileInventorySnapshot(snapshot FileInventorySnapshot) FileInventorySnapshot {
	clone := snapshot
	clone.Files = append([]SyncedFileSnapshot(nil), snapshot.Files...)
	return clone
}

func fileInventoryServerLabel(server *SliverServer) string {
	if server == nil || server.Config == nil {
		return "server"
	}
	operator := strings.TrimSpace(server.Config.Operator)
	host := strings.TrimSpace(server.Config.LHost)
	address := host
	if host != "" && server.Config.LPort > 0 {
		address = net.JoinHostPort(host, strconv.Itoa(server.Config.LPort))
	}
	switch {
	case operator != "" && address != "":
		return operator + "@" + address
	case operator != "":
		return operator
	case address != "":
		return address
	default:
		return "server"
	}
}

func crackFileTimestamp(unixSeconds int64) time.Time {
	if unixSeconds <= 0 {
		return time.Time{}
	}
	return time.Unix(unixSeconds, 0).UTC()
}

func syncedFileSnapshotLess(left, right SyncedFileSnapshot) bool {
	if left.Type != right.Type {
		return left.Type < right.Type
	}
	if left.Name != right.Name {
		return left.Name < right.Name
	}
	if left.SHA256 != right.SHA256 {
		return left.SHA256 < right.SHA256
	}
	if left.UncompressedSize != right.UncompressedSize {
		return left.UncompressedSize < right.UncompressedSize
	}
	if !left.CreatedAt.Equal(right.CreatedAt) {
		return left.CreatedAt.Before(right.CreatedAt)
	}
	return left.LastModified.Before(right.LastModified)
}

func fileInventorySnapshotLess(left, right FileInventorySnapshot) bool {
	if left.Server != right.Server {
		return left.Server < right.Server
	}
	for index := 0; index < len(left.Files) && index < len(right.Files); index++ {
		if syncedFileSnapshotLess(left.Files[index], right.Files[index]) {
			return true
		}
		if syncedFileSnapshotLess(right.Files[index], left.Files[index]) {
			return false
		}
	}
	if len(left.Files) != len(right.Files) {
		return len(left.Files) < len(right.Files)
	}
	if !left.UpdatedAt.Equal(right.UpdatedAt) {
		return left.UpdatedAt.Before(right.UpdatedAt)
	}
	return false
}
