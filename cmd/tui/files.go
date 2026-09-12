package tui

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/sliverarmory/sliver-crackstation/pkg/crackstation"
)

const fileDigestDisplayLength = 12

type fileViewData struct {
	files          []crackstation.SyncedFileSnapshot
	totalSize      int64
	wordlists      int
	rules          int
	hcstat2        int
	ready          bool
	inventoryCount int
}

type syncedFileKey struct {
	typeID clientpb.CrackFileType
	digest string
}

func (m crackstationModel) renderFileLines() []string {
	data := m.fileData
	bodyHeight := m.bodyContentHeight()
	syncedServers, totalServers := m.fileServerCounts()
	if !data.ready {
		message := "waiting for the initial successful synchronization"
		if totalServers > 0 {
			message = fmt.Sprintf("waiting for initial synchronization (0/%d servers)", totalServers)
		}
		return fitFileStatusLines(bodyHeight, message)
	}

	if len(data.files) == 0 {
		message := "none synchronized"
		if syncedServers < totalServers {
			message = fmt.Sprintf(
				"none yet; waiting for %d server%s (%d/%d synchronized)",
				totalServers-syncedServers,
				pluralSuffix(totalServers-syncedServers),
				syncedServers,
				totalServers,
			)
		}
		return fitEmptyFileLines(bodyHeight, message)
	}

	pageSize := m.filePageSize(len(data.files))
	pageCount := pageCount(len(data.files), pageSize)
	page := m.filePage
	if page < 0 || page >= pageCount {
		page = 0
	}
	start := page * pageSize
	end := start + pageSize
	if end > len(data.files) {
		end = len(data.files)
	}

	if bodyHeight == 1 {
		file := data.files[start]
		return []string{formatLine(
			fmt.Sprintf("File %d/%d", start+1, len(data.files)),
			fmt.Sprintf("%s | %s | %s", syncedFileTypeLabel(file.Type), emptyFallback(file.Name, "unnamed"), humanizeByteCount(file.UncompressedSize)),
		)}
	}

	summaryParts := []string{
		fmt.Sprintf("page %d/%d", page+1, pageCount),
		fmt.Sprintf("%d files", len(data.files)),
		humanizeByteCount(data.totalSize) + " synchronized",
	}
	if totalServers > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("servers %d/%d", syncedServers, totalServers))
	}
	summaryParts = append(summaryParts,
		fmt.Sprintf("%d wordlists", data.wordlists),
		fmt.Sprintf("%d rules", data.rules),
		fmt.Sprintf("%d hcstat2", data.hcstat2),
	)
	summary := strings.Join(summaryParts, " | ")
	lines := []string{formatLine("Files", summary)}
	if bodyHeight == 0 || bodyHeight >= 3 {
		lines = append([]string{titleStyle.Render("Synchronized Files")}, lines...)
	}
	for _, file := range data.files[start:end] {
		lines = append(lines, renderSyncedFileLine(file))
	}
	return lines
}

func (m crackstationModel) filePageCount() int {
	fileCount := len(m.fileData.files)
	if fileCount == 0 {
		return 0
	}
	return pageCount(fileCount, m.filePageSize(fileCount))
}

func (m crackstationModel) filePageSize(total int) int {
	if total <= 0 {
		return 0
	}
	pageSize := total
	if height := m.bodyContentHeight(); height > 0 {
		switch height {
		case 1, 2:
			pageSize = 1
		default:
			pageSize = height - 2
		}
		if pageSize < 1 {
			pageSize = 1
		}
		if pageSize > total {
			pageSize = total
		}
	}
	return pageSize
}

func (m crackstationModel) clampFilePage(page int) int {
	pages := m.filePageCount()
	if pages == 0 || page < 0 || page >= pages {
		return 0
	}
	return page
}

func collectFileViewData(inventories []crackstation.FileInventorySnapshot) fileViewData {
	data := fileViewData{
		ready:          len(inventories) > 0,
		inventoryCount: len(inventories),
	}
	unique := make(map[syncedFileKey]crackstation.SyncedFileSnapshot)
	for _, inventory := range inventories {
		for _, file := range inventory.Files {
			file.Name = sanitizeFileDisplayName(file.Name)
			key := syncedFileKey{typeID: file.Type, digest: file.SHA256}
			current, exists := unique[key]
			if !exists || syncedFilePreferred(file, current) {
				unique[key] = file
			}
		}
	}

	data.files = make([]crackstation.SyncedFileSnapshot, 0, len(unique))
	for _, file := range unique {
		data.files = append(data.files, file)
		data.totalSize = saturatingFileSizeSum(data.totalSize, file.UncompressedSize)
		switch file.Type {
		case clientpb.CrackFileType_WORDLIST:
			data.wordlists++
		case clientpb.CrackFileType_RULES:
			data.rules++
		case clientpb.CrackFileType_MARKOV_HCSTAT2:
			data.hcstat2++
		}
	}
	sort.Slice(data.files, func(i, j int) bool {
		return syncedFileDisplayLess(data.files[i], data.files[j])
	})
	return data
}

func syncedFilePreferred(candidate, current crackstation.SyncedFileSnapshot) bool {
	if candidate.Name != "" && current.Name == "" {
		return true
	}
	if candidate.Name == "" && current.Name != "" {
		return false
	}
	if len(candidate.Name) != len(current.Name) {
		return len(candidate.Name) < len(current.Name)
	}
	candidateName := strings.ToLower(candidate.Name)
	currentName := strings.ToLower(current.Name)
	if candidateName != currentName {
		return candidateName < currentName
	}
	if candidate.Name != current.Name {
		return candidate.Name < current.Name
	}
	return candidate.UncompressedSize < current.UncompressedSize
}

func syncedFileDisplayLess(left, right crackstation.SyncedFileSnapshot) bool {
	leftType := syncedFileTypeOrder(left.Type)
	rightType := syncedFileTypeOrder(right.Type)
	if leftType != rightType {
		return leftType < rightType
	}
	leftName := strings.ToLower(left.Name)
	rightName := strings.ToLower(right.Name)
	if leftName != rightName {
		return leftName < rightName
	}
	if left.Name != right.Name {
		return left.Name < right.Name
	}
	return left.SHA256 < right.SHA256
}

func syncedFileTypeOrder(fileType clientpb.CrackFileType) int {
	switch fileType {
	case clientpb.CrackFileType_WORDLIST:
		return 0
	case clientpb.CrackFileType_RULES:
		return 1
	case clientpb.CrackFileType_MARKOV_HCSTAT2:
		return 2
	default:
		return 3
	}
}

func renderSyncedFileLine(file crackstation.SyncedFileSnapshot) string {
	name := emptyFallback(sanitizeFileDisplayName(file.Name), "unnamed")
	digest := file.SHA256
	if len(digest) > fileDigestDisplayLength {
		digest = digest[:fileDigestDisplayLength]
	}
	if digest == "" {
		digest = "unknown digest"
	}
	return formatLine(syncedFileTypeLabel(file.Type), fmt.Sprintf(
		"%s | %s | %s", name, humanizeByteCount(file.UncompressedSize), digest,
	))
}

func (m crackstationModel) fileServerCounts() (int, int) {
	synced := m.fileData.inventoryCount
	total := countServers(m.crack)
	if total < synced {
		total = synced
	}
	return synced, total
}

func fitFileStatusLines(bodyHeight int, message string) []string {
	if bodyHeight == 1 {
		return []string{formatLine("Files", message)}
	}
	return []string{
		titleStyle.Render("Synchronized Files"),
		formatLine("Files", message),
	}
}

func fitEmptyFileLines(bodyHeight int, message string) []string {
	if bodyHeight == 1 {
		return []string{formatLine("Files", message)}
	}
	if bodyHeight == 2 {
		return []string{
			titleStyle.Render("Synchronized Files"),
			formatLine("Files", message),
		}
	}
	return []string{
		titleStyle.Render("Synchronized Files"),
		formatLine("Inventory", "0 files | 0 B synchronized"),
		formatLine("Files", message),
	}
}

func sanitizeFileDisplayName(value string) string {
	value = strings.ToValidUTF8(value, "�")
	var sanitized strings.Builder
	pendingSpace := false
	for _, runeValue := range value {
		if unicode.IsSpace(runeValue) || !unicode.IsPrint(runeValue) {
			pendingSpace = sanitized.Len() > 0
			continue
		}
		if pendingSpace {
			sanitized.WriteByte(' ')
			pendingSpace = false
		}
		sanitized.WriteRune(runeValue)
	}
	return strings.TrimSpace(sanitized.String())
}

func pluralSuffix(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

func syncedFileTypeLabel(fileType clientpb.CrackFileType) string {
	switch fileType {
	case clientpb.CrackFileType_WORDLIST:
		return "Wordlist"
	case clientpb.CrackFileType_RULES:
		return "Rules"
	case clientpb.CrackFileType_MARKOV_HCSTAT2:
		return "HCStat2"
	default:
		return "File"
	}
}

func humanizeByteCount(size int64) string {
	if size <= 0 {
		return "0 B"
	}
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	}
	units := [...]string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	value := float64(size)
	unit := 0
	for value >= 1024 && unit < len(units) {
		value /= 1024
		unit++
	}
	return fmt.Sprintf("%.1f %s", value, units[unit-1])
}

func saturatingFileSizeSum(total, size int64) int64 {
	const maxInt64 = int64(1<<63 - 1)
	if size <= 0 {
		return total
	}
	if total > maxInt64-size {
		return maxInt64
	}
	return total + size
}

func pageCount(total, pageSize int) int {
	if total <= 0 || pageSize <= 0 {
		return 0
	}
	return 1 + (total-1)/pageSize
}
