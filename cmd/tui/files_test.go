package tui

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/charmbracelet/x/ansi"
	"github.com/sliverarmory/sliver-crackstation/pkg/crackstation"
)

func TestRenderFilesShowsDeduplicatedAllTypeInventory(t *testing.T) {
	model := filesTestModel(filesTestInventories())
	model.width = 160
	model.height = 30

	view := ansi.Strip(model.renderMainView())
	summaryLines := strings.Split(view, "\n")
	inventorySummary := filesLineContaining(t, summaryLines, "15.5 KiB")
	for _, want := range []string{"5", "15.5 KiB"} {
		if !strings.Contains(inventorySummary, want) {
			t.Errorf("files inventory summary missing %q: %q", want, inventorySummary)
		}
	}
	typeSummary := strings.ToLower(filesLineContaining(t, summaryLines, "wordlists"))
	for _, want := range []string{"2 wordlists", "2 rules", "1 hcstat2"} {
		if !strings.Contains(typeSummary, want) {
			t.Errorf("files type summary missing %q: %q", want, typeSummary)
		}
	}

	for _, unwanted := range []string{"Server Quota", "Server Storage", "Disk Quota"} {
		if strings.Contains(view, unwanted) {
			t.Errorf("Files view rendered out-of-scope quota data %q\n%s", unwanted, view)
		}
	}

	if got := strings.Count(view, "shared.txt"); got != 1 {
		t.Fatalf("deduplicated shared file rendered %d times, want 1\n%s", got, view)
	}
	if strings.Contains(view, "zz-alias.txt") {
		t.Fatalf("alternate metadata for a duplicate type/digest rendered as another local file\n%s", view)
	}
	for _, want := range []string{
		"Wordlist: alpha.txt | 2.0 KiB | " + filesDigestPrefix('a'),
		"Wordlist: shared.txt | 4.0 KiB | " + filesDigestPrefix('b'),
		"Rules: aardvark.rule | 512 B | " + filesDigestPrefix('a'),
		"Rules: beta.rule | 1.0 KiB | " + filesDigestPrefix('c'),
		"HCStat2: markov.hcstat2 | 8.0 KiB | " + filesDigestPrefix('d'),
	} {
		if !strings.Contains(view, want) {
			t.Errorf("Files view missing row %q\n%s", want, view)
		}
	}

	assertFilesOrdered(t, view,
		"Wordlist: alpha.txt",
		"Wordlist: shared.txt",
		"Rules: aardvark.rule",
		"Rules: beta.rule",
		"HCStat2: markov.hcstat2",
	)
}

func TestFilesViewDistinguishesInitialSyncFromEmptyInventory(t *testing.T) {
	notReady := filesTestModel(nil)
	notReadyView := strings.ToLower(ansi.Strip(notReady.renderMainView()))
	for _, want := range []string{"waiting", "successful", "synchron"} {
		if !strings.Contains(notReadyView, want) {
			t.Fatalf("not-ready Files view missing %q\n%s", want, notReadyView)
		}
	}

	readyEmpty := filesTestModel([]crackstation.FileInventorySnapshot{{
		Server:    "empty",
		Files:     []crackstation.SyncedFileSnapshot{},
		UpdatedAt: time.Unix(1_700_000_000, 0),
	}})
	readyEmptyView := strings.ToLower(ansi.Strip(readyEmpty.renderMainView()))
	for _, want := range []string{"none", "synchronized", "files"} {
		if !strings.Contains(readyEmptyView, want) {
			t.Fatalf("ready-empty Files view missing %q\n%s", want, readyEmptyView)
		}
	}
	if strings.Contains(readyEmptyView, "waiting") {
		t.Fatalf("ready-empty inventory was presented as not yet synchronized\n%s", readyEmptyView)
	}
}

func TestFilesViewReportsPartialMultiServerInventory(t *testing.T) {
	model := filesTestModel([]crackstation.FileInventorySnapshot{{
		Server:    "ready",
		UpdatedAt: time.Unix(1_700_000_000, 0),
	}})
	model.crack = &crackstation.Crackstation{Servers: &sync.Map{}}
	model.crack.Servers.Store("ready", struct{}{})
	model.crack.Servers.Store("pending", struct{}{})

	view := strings.ToLower(ansi.Strip(model.renderMainView()))
	for _, want := range []string{"waiting for 1 server", "1/2 synchronized"} {
		if !strings.Contains(view, want) {
			t.Fatalf("partial Files view missing %q\n%s", want, view)
		}
	}
}

func TestFilesViewSanitizesRemoteFileNames(t *testing.T) {
	rawName := "safe\nInjected:\t\x1b]8;;https://example.invalid\aescape\x1b[31m\r" + string([]byte{0xff}) + ".txt"
	sanitized := sanitizeFileDisplayName(rawName)
	if !utf8.ValidString(sanitized) {
		t.Fatalf("sanitized file name is not valid UTF-8: %q", sanitized)
	}
	for _, runeValue := range sanitized {
		if !unicode.IsPrint(runeValue) {
			t.Fatalf("sanitized file name contains non-printing rune %U: %q", runeValue, sanitized)
		}
	}
	if strings.ContainsAny(sanitized, "\r\n\t\x1b\a") {
		t.Fatalf("sanitized file name retained terminal controls: %q", sanitized)
	}

	model := filesTestModel([]crackstation.FileInventorySnapshot{{
		Server: "server",
		Files: []crackstation.SyncedFileSnapshot{
			filesSnapshot(rawName, clientpb.CrackFileType_WORDLIST, 1024, 'a'),
		},
	}})
	lines := model.renderFileLines()
	if len(lines) != 3 {
		t.Fatalf("one remote file rendered as %d logical lines, want 3: %#v", len(lines), lines)
	}
	if plain := ansi.Strip(strings.Join(lines, "\n")); strings.Contains(plain, "\nInjected:") {
		t.Fatalf("remote newline escaped its file row:\n%s", plain)
	}
}

func TestFilesPaginationWrapsAndTabNavigationIncludesFiles(t *testing.T) {
	files := []crackstation.SyncedFileSnapshot{
		filesSnapshot("alpha.txt", clientpb.CrackFileType_WORDLIST, 1024, '0'),
		filesSnapshot("beta.txt", clientpb.CrackFileType_WORDLIST, 1024, '1'),
		filesSnapshot("gamma.txt", clientpb.CrackFileType_WORDLIST, 1024, '2'),
		filesSnapshot("delta.txt", clientpb.CrackFileType_WORDLIST, 1024, '3'),
		filesSnapshot("epsilon.txt", clientpb.CrackFileType_WORDLIST, 1024, '4'),
		filesSnapshot("eta.txt", clientpb.CrackFileType_WORDLIST, 1024, '5'),
		filesSnapshot("theta.txt", clientpb.CrackFileType_WORDLIST, 1024, '6'),
		filesSnapshot("zeta.txt", clientpb.CrackFileType_WORDLIST, 1024, '7'),
	}
	model := filesTestModel([]crackstation.FileInventorySnapshot{{
		Server:    "server",
		Files:     files,
		UpdatedAt: time.Unix(1_700_000_000, 0),
	}})
	model.width = 40
	model.height = 12

	initialView := ansi.Strip(model.renderMainView())
	currentPage, totalPages := filesPageNumbers(t, initialView)
	if currentPage != 1 || totalPages < 2 {
		t.Fatalf("initial compact Files page = %d/%d, want multiple pages\n%s", currentPage, totalPages, initialView)
	}
	if !strings.Contains(initialView, "alpha.txt") {
		t.Fatalf("initial Files page does not contain first sorted file\n%s", initialView)
	}

	model = updateFilesModel(t, model, tea.KeyRight)
	if page, pages := filesPageNumbers(t, ansi.Strip(model.renderMainView())); page != 2 || pages != totalPages {
		t.Fatalf("right arrow selected page %d/%d, want 2/%d", page, pages, totalPages)
	}
	for range totalPages - 1 {
		model = updateFilesModel(t, model, tea.KeyRight)
	}
	wrappedView := ansi.Strip(model.renderMainView())
	if page, pages := filesPageNumbers(t, wrappedView); page != 1 || pages != totalPages {
		t.Fatalf("right arrow did not wrap to page 1/%d; got %d/%d\n%s", totalPages, page, pages, wrappedView)
	}
	if !strings.Contains(wrappedView, "alpha.txt") {
		t.Fatalf("wrapped first Files page does not contain first sorted file\n%s", wrappedView)
	}

	model = updateFilesModel(t, model, tea.KeyLeft)
	lastView := ansi.Strip(model.renderMainView())
	if page, pages := filesPageNumbers(t, lastView); page != totalPages || pages != totalPages {
		t.Fatalf("left arrow did not wrap to final page %d/%d; got %d/%d\n%s", totalPages, totalPages, page, pages, lastView)
	}
	if !strings.Contains(lastView, "zeta.txt") {
		t.Fatalf("final Files page does not contain last sorted file\n%s", lastView)
	}

	tabs := ansi.Strip(model.renderTabs())
	assertFilesOrdered(t, tabs, "Summary", "Host", "Devices", "Benchmarks", "Files")
	if got := model.viewName(); got != "files" {
		t.Fatalf("viewName() = %q, want files", got)
	}
	if footer := model.footerText(); !strings.Contains(footer, "←/→: page") {
		t.Fatalf("Files footer missing page controls: %q", footer)
	}

	model.view = viewSummary
	for step, want := range []viewMode{viewHost, viewDevices, viewBenchmarks, viewFiles, viewSummary} {
		model = updateFilesModel(t, model, tea.KeyTab)
		if model.view != want {
			t.Fatalf("tab step %d selected view %v, want %v", step+1, model.view, want)
		}
	}
}

func TestFilesViewFitsSmallAndNarrowTerminals(t *testing.T) {
	for _, size := range []struct {
		width  int
		height int
	}{
		{width: 40, height: 12},
		{width: 24, height: 12},
		{width: 60, height: 16},
	} {
		t.Run(fmt.Sprintf("%dx%d", size.width, size.height), func(t *testing.T) {
			model := filesTestModel(filesTestInventories())
			model.width = size.width
			model.height = size.height

			view := model.renderMainView()
			lines := strings.Split(view, "\n")
			if len(lines) > size.height {
				t.Fatalf("Files renderMainView(%dx%d) has %d rows\n%s", size.width, size.height, len(lines), ansi.Strip(view))
			}
			for _, line := range lines {
				if width := ansi.StringWidth(line); width > size.width {
					t.Fatalf("Files renderMainView(%dx%d) line width = %d\n%s", size.width, size.height, width, ansi.Strip(line))
				}
			}

			plain := ansi.Strip(view)
			for _, want := range []string{"Files", "q: quit"} {
				if !strings.Contains(plain, want) {
					t.Errorf("Files renderMainView(%dx%d) missing %q\n%s", size.width, size.height, want, plain)
				}
			}
			if size.width == 40 && !strings.Contains(plain, "alpha.txt") {
				t.Errorf("compact 40x12 Files view did not retain an actual file row\n%s", plain)
			}
		})
	}
}

func TestFilesPageCapacityDoesNotShrinkAsTerminalGetsTaller(t *testing.T) {
	model := filesTestModel(filesTestInventories())
	previous := 0
	for height := 9; height <= 20; height++ {
		model.height = height
		capacity := model.filePageSize(len(model.fileData.files))
		if capacity < previous {
			t.Fatalf("file page capacity shrank at terminal height %d: %d -> %d", height, previous, capacity)
		}
		previous = capacity
	}
}

func filesTestModel(inventories []crackstation.FileInventorySnapshot) crackstationModel {
	model := newModel(nil, nil)
	model.view = viewFiles
	model.fileData = collectFileViewData(inventories)
	model.width = 120
	model.height = 24
	return model
}

func filesTestInventories() []crackstation.FileInventorySnapshot {
	return []crackstation.FileInventorySnapshot{
		{
			Server: "alpha",
			Files: []crackstation.SyncedFileSnapshot{
				filesSnapshot("beta.rule", clientpb.CrackFileType_RULES, 1024, 'c'),
				filesSnapshot("shared.txt", clientpb.CrackFileType_WORDLIST, 4096, 'b'),
				filesSnapshot("markov.hcstat2", clientpb.CrackFileType_MARKOV_HCSTAT2, 8192, 'd'),
				filesSnapshot("alpha.txt", clientpb.CrackFileType_WORDLIST, 2048, 'a'),
			},
			UpdatedAt: time.Unix(1_700_000_000, 0),
		},
		{
			Server: "beta",
			Files: []crackstation.SyncedFileSnapshot{
				// Matching digests in different type namespaces are separate files.
				filesSnapshot("aardvark.rule", clientpb.CrackFileType_RULES, 512, 'a'),
				// Matching type/digest entries are one physical local file, even if
				// two servers advertise different names and sizes for the metadata.
				filesSnapshot("zz-alias.txt", clientpb.CrackFileType_WORDLIST, 5000, 'b'),
			},
			UpdatedAt: time.Unix(1_700_000_001, 0),
		},
		{
			Server:    "empty-server",
			UpdatedAt: time.Unix(1_700_000_002, 0),
		},
	}
}

func filesSnapshot(name string, fileType clientpb.CrackFileType, size int64, digestByte byte) crackstation.SyncedFileSnapshot {
	return crackstation.SyncedFileSnapshot{
		Name:             name,
		Type:             fileType,
		UncompressedSize: size,
		SHA256:           filesDigest(digestByte),
	}
}

func filesDigest(value byte) string {
	return strings.Repeat(string([]byte{value}), 64)
}

func filesDigestPrefix(value byte) string {
	return strings.Repeat(string([]byte{value}), 12)
}

func updateFilesModel(t *testing.T, model crackstationModel, code rune) crackstationModel {
	t.Helper()
	updated, _ := model.Update(tea.KeyPressMsg(tea.Key{Code: code}))
	result, ok := updated.(crackstationModel)
	if !ok {
		t.Fatalf("Update returned %T, want crackstationModel", updated)
	}
	return result
}

func assertFilesOrdered(t *testing.T, view string, values ...string) {
	t.Helper()
	previous := -1
	for _, value := range values {
		index := strings.Index(view, value)
		if index < 0 {
			t.Fatalf("missing %q\n%s", value, view)
		}
		if index <= previous {
			t.Fatalf("%q is out of order\n%s", value, view)
		}
		previous = index
	}
}

var filesPagePattern = regexp.MustCompile(`([0-9]+)/([0-9]+)`)

func filesPageNumbers(t *testing.T, view string) (int, int) {
	t.Helper()
	match := filesPagePattern.FindStringSubmatch(view)
	if len(match) != 3 {
		t.Fatalf("Files view does not include page numbers\n%s", view)
	}
	page, err := strconv.Atoi(match[1])
	if err != nil {
		t.Fatal(err)
	}
	pages, err := strconv.Atoi(match[2])
	if err != nil {
		t.Fatal(err)
	}
	return page, pages
}

func filesLineContaining(t *testing.T, lines []string, needle string) string {
	t.Helper()
	for _, line := range lines {
		if strings.Contains(line, needle) {
			return line
		}
	}
	t.Fatalf("missing line containing %q\n%s", needle, strings.Join(lines, "\n"))
	return ""
}
