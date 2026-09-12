package tui

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/charmbracelet/x/ansi"
	"github.com/sliverarmory/sliver-crackstation/pkg/crackstation"
)

func TestRenderSyncProgressBarsBeforeActivity(t *testing.T) {
	const (
		firstDigest  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		secondDigest = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	)
	model := syncProgressTestModel(map[string]float32{
		secondDigest: 0.75,
		firstDigest:  0.25,
	}, 2*1024)
	model.activity = &crackstation.ActivitySnapshot{Kind: crackstation.ActivityCracking}

	lines := strings.Split(plainLines(model.renderDetailLines()), "\n")
	wantHeading := "File Synchronization (2 files @ 2.0 KiB/s)"
	if len(lines) == 0 || lines[0] != wantHeading {
		t.Fatalf("first detail line = %q, want %q\n%s", firstLine(lines), wantHeading, strings.Join(lines, "\n"))
	}

	overall := lineContaining(t, lines, "Overall:")
	assertProgressBar(t, overall, "50%")
	first := lineContaining(t, lines, "0123456789a…:")
	assertProgressBar(t, first, "25%")
	second := lineContaining(t, lines, "fedcba98765…:")
	assertProgressBar(t, second, "75%")

	view := strings.Join(lines, "\n")
	for _, ordered := range [][2]string{
		{wantHeading, "Overall:"},
		{"Overall:", "0123456789a…:"},
		{"0123456789a…:", "fedcba98765…:"},
		{"fedcba98765…:", "Running Job"},
	} {
		if strings.Index(view, ordered[0]) >= strings.Index(view, ordered[1]) {
			t.Fatalf("%q was not rendered before %q\n%s", ordered[0], ordered[1], view)
		}
	}
}

func TestRenderSyncProgressBarsLimitsFiles(t *testing.T) {
	progress := map[string]float32{}
	for _, digest := range []string{
		"a000000000000000", "b000000000000000", "c000000000000000", "d000000000000000",
		"e000000000000000", "f000000000000000", "g000000000000000", "h000000000000000",
	} {
		progress[digest] = 0.5
	}

	lines := strings.Split(plainLines(syncProgressTestModel(progress, 1024).renderDetailLines()), "\n")
	view := strings.Join(lines, "\n")
	previous := -1
	for _, label := range []string{
		"a0000000000…:", "b0000000000…:", "c0000000000…:",
		"d0000000000…:", "e0000000000…:", "f0000000000…:",
	} {
		index := strings.Index(view, label)
		if index < 0 {
			t.Fatalf("missing sorted file progress label %q\n%s", label, view)
		}
		if index <= previous {
			t.Fatalf("file progress label %q is out of order\n%s", label, view)
		}
		previous = index
	}
	for _, omitted := range []string{"g0000000000…:", "h0000000000…:"} {
		if strings.Contains(view, omitted) {
			t.Fatalf("rendered capped file progress label %q\n%s", omitted, view)
		}
	}
	if !strings.Contains(view, "...: 2 more") {
		t.Fatalf("missing capped-file summary\n%s", view)
	}

	barLines := 0
	for _, line := range lines {
		if strings.Contains(line, "▌") && strings.Contains(line, "░") && strings.Contains(line, "50%") {
			barLines++
		}
	}
	if barLines != 7 {
		t.Fatalf("progress bar lines = %d, want overall plus six files\n%s", barLines, view)
	}
}

func TestRenderSyncProgressEmptyFallbackBeforeActivity(t *testing.T) {
	model := syncProgressTestModel(map[string]float32{}, 0)
	model.activity = &crackstation.ActivitySnapshot{Kind: crackstation.ActivityCracking}

	view := plainLines(model.renderDetailLines())
	fallback := "Sync Progress: No file progress reported"
	if !strings.Contains(view, fallback) {
		t.Fatalf("missing empty sync progress fallback\n%s", view)
	}
	if strings.Contains(view, "▌") || strings.Contains(view, "░") {
		t.Fatalf("empty sync progress rendered a progress bar\n%s", view)
	}
	if strings.Index(view, fallback) >= strings.Index(view, "Running Job") {
		t.Fatalf("empty sync progress was not rendered before activity\n%s", view)
	}
}

func TestRenderSyncProgressSummaryFitsSmallTerminal(t *testing.T) {
	for _, test := range []struct {
		name         string
		withActivity bool
	}{
		{name: "background sync"},
		{name: "job sync", withActivity: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			model := syncProgressTestModel(map[string]float32{
				"0123456789abcdef": 0.25,
				"fedcba9876543210": 0.75,
			}, 2*1024)
			if test.withActivity {
				model.activity = &crackstation.ActivitySnapshot{Kind: crackstation.ActivityCracking}
			}
			model.width = 40
			model.height = 12

			view := model.renderMainView()
			lines := strings.Split(view, "\n")
			if len(lines) > model.height {
				t.Fatalf("renderMainView(%dx%d) has %d rows\n%s", model.width, model.height, len(lines), ansi.Strip(view))
			}
			for _, line := range lines {
				if width := ansi.StringWidth(line); width > model.width {
					t.Fatalf("renderMainView(%dx%d) line width = %d\n%s", model.width, model.height, width, ansi.Strip(line))
				}
			}

			plain := ansi.Strip(view)
			if !strings.Contains(plain, "File Synchronization") {
				t.Fatalf("small Summary hid sync heading\n%s", plain)
			}
			overall := lineContaining(t, strings.Split(plain, "\n"), "Overall:")
			assertProgressBar(t, overall, "50%")
		})
	}
}

func TestSyncProgressNormalizesValuesAndFallsBackInNarrowViews(t *testing.T) {
	for _, test := range []struct {
		name  string
		value float32
		want  float64
	}{
		{name: "negative", value: -0.25, want: 0},
		{name: "valid", value: 0.25, want: 0.25},
		{name: "over one", value: 1.25, want: 1},
		{name: "NaN", value: float32(math.NaN()), want: 0},
		{name: "infinity", value: float32(math.Inf(1)), want: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := normalizedProgress(test.value); got != test.want {
				t.Fatalf("normalizedProgress(%v) = %v, want %v", test.value, got, test.want)
			}
		})
	}

	model := syncProgressTestModel(map[string]float32{"0123456789abcdef": 0.25}, 0)
	model.width = 24
	line := ansi.Strip(model.renderSyncProgressLine("0123456789abcdef", 0.25))
	if strings.ContainsAny(line, "▌░") || !strings.Contains(line, "25%") {
		t.Fatalf("narrow progress line did not fall back to a percentage: %q", line)
	}
	if width := ansi.StringWidth(line); width > model.bodyLineWidth() {
		t.Fatalf("narrow progress line width = %d, want <= %d: %q", width, model.bodyLineWidth(), line)
	}
}

func syncProgressTestModel(progress map[string]float32, speed float32) crackstationModel {
	model := newModel(nil, nil)
	model.status = &clientpb.CrackstationStatus{
		Name:      "worker",
		State:     clientpb.States_IDLE,
		IsSyncing: true,
		Syncing: &clientpb.CrackSyncStatus{
			Progress: progress,
			Speed:    speed,
		},
	}
	model.lastUpdate = time.Now()
	model.view = viewSummary
	model.width = 80
	model.height = 24
	return model
}

func assertProgressBar(t *testing.T, line, percentage string) {
	t.Helper()
	for _, want := range []string{"▌", "░", percentage} {
		if !strings.Contains(line, want) {
			t.Fatalf("progress line missing %q: %q", want, line)
		}
	}
}

func lineContaining(t *testing.T, lines []string, needle string) string {
	t.Helper()
	for _, line := range lines {
		if strings.Contains(line, needle) {
			return line
		}
	}
	t.Fatalf("missing line containing %q\n%s", needle, strings.Join(lines, "\n"))
	return ""
}

func firstLine(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return lines[0]
}
