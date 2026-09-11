package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/charmbracelet/x/ansi"
	"github.com/sliverarmory/sliver-crackstation/pkg/crackstation"
	"github.com/sliverarmory/sliver-crackstation/pkg/hashcat"
)

func TestRenderCrackingActivityShowsLiveTelemetry(t *testing.T) {
	now := time.Unix(1_789_070_400, 0)
	model := crackstationModel{activity: &crackstation.ActivitySnapshot{
		Kind:        crackstation.ActivityCracking,
		Phase:       crackstation.ActivityPhaseCracking,
		JobID:       "job-123",
		StartedAt:   now.Add(-95 * time.Second),
		Attempt:     2,
		HashMode:    1000,
		HasHashMode: true,
		AttackMode:  clientpb.CrackAttackMode_BRUTEFORCE,
		HashCount:   7,
		ShardSkip:   1_000_000,
		ShardLimit:  5_000_000,
		HashcatStatus: &hashcat.Status{
			State:           3,
			Progress:        hashcat.StatusCounter{Current: 250_000, Total: 1_000_000},
			RecoveredHashes: hashcat.StatusCounter{Current: 2, Total: 7},
			RecoveredSalts:  hashcat.StatusCounter{Current: 1, Total: 4},
			Rejected:        42,
			EstimatedStop:   uint64(now.Add(90 * time.Second).Unix()),
			Devices: []hashcat.DeviceStatus{{
				ID: 1, Name: "RTX 5090", Type: "GPU", Speed: 125_500_000_000,
				Temp: 73, Util: 99, FanSpeed: 61, CoreSpeed: 2_850,
				MemorySpeed: 14_000, BusLanes: 16, Power: 425_500,
			}},
		},
	}}

	view := plainLines(model.renderActivityLines(now))
	for _, want := range []string{
		"Running Job", "Job: Cracking | job-123 | elapsed 1m35s | attempt 2 | running Hashcat",
		"Work: NTLM (1000) | Brute force | 7 hashes",
		"Shard: skip 1.00M, limit 5.00M",
		"Hashcat: Running | 25.00% (250.00k / 1.00M)",
		"Performance: 125.50 GH/s | ETA 1m30s",
		"Results: 2/7 hashes, 1/4 salts | 42 rejected",
		"Device #1: RTX 5090 | 125.50 GH/s | 73°C | 99% util | 61% fan | 425.5 W",
		"Device #1 Clocks: core 2850 MHz | memory 14000 MHz | PCIe x16",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("renderActivityLines() missing %q\n%s", want, view)
		}
	}
}

func TestRenderCrackingActivityMarksStaleTelemetry(t *testing.T) {
	now := time.Unix(1_789_070_400, 0)
	model := crackstationModel{activity: &crackstation.ActivitySnapshot{
		Kind:        crackstation.ActivityCracking,
		TelemetryAt: now.Add(-5 * time.Second),
		HashcatStatus: &hashcat.Status{
			State:   3,
			Devices: []hashcat.DeviceStatus{{ID: 1, Speed: 100, Temp: 70}},
		},
	}}
	view := plainLines(model.renderActivityLines(now))
	if !strings.Contains(view, "Hashcat: Running | telemetry 5s old") {
		t.Fatalf("renderActivityLines() did not mark stale telemetry\n%s", view)
	}
}

func TestRenderCrackingActivityOmitsUnavailableHardwareMetrics(t *testing.T) {
	model := crackstationModel{activity: &crackstation.ActivitySnapshot{
		Kind: crackstation.ActivityCracking,
		HashcatStatus: &hashcat.Status{Devices: []hashcat.DeviceStatus{{
			ID: 2, Name: "CPU", Speed: 99,
			Temp: -1, Util: -1, FanSpeed: -1, CoreSpeed: -1,
			MemorySpeed: -1, BusLanes: -1, Power: -1,
		}}},
	}}

	view := plainLines(model.renderActivityLines(time.Now()))
	if !strings.Contains(view, "Device #2: CPU | 99 H/s") {
		t.Fatalf("renderActivityLines() missing device rate\n%s", view)
	}
	for _, unavailable := range []string{"°C", "% util", "% fan", " W", "Clocks:"} {
		if strings.Contains(view, unavailable) {
			t.Errorf("renderActivityLines() rendered unavailable metric %q\n%s", unavailable, view)
		}
	}
}

func TestRenderBenchmarkActivityShowsCurrentAndLatestModes(t *testing.T) {
	model := crackstationModel{activity: &crackstation.ActivitySnapshot{
		Kind:      crackstation.ActivityBenchmarking,
		JobID:     "benchmark",
		StartedAt: time.Now().Add(-time.Minute),
		BenchmarkProgress: &hashcat.BenchmarkProgress{
			HashMode:       22000,
			HashName:       "WPA-PBKDF2-PMKID+EAPOL",
			TotalModes:     590,
			CompletedModes: 11,
			LastHashMode:   1000,
			LastHashName:   "NTLM",
			LastSpeed:      375_000_000_000,
			LastDeviceSpeeds: []hashcat.BenchmarkDeviceSpeed{
				{Device: 1, Speed: 190_000_000_000},
				{Device: 2, Speed: 185_000_000_000},
			},
		},
	}}

	view := plainLines(model.renderActivityLines(time.Now()))
	for _, want := range []string{
		"Job: Benchmarking | benchmark | elapsed", "Current Mode: WPA-PBKDF2-PMKID+EAPOL (22000)",
		"Mode Progress: 11/590 complete", "Current Result: measuring...",
		"Latest Result: NTLM (1000) @ 375.00 GH/s", "Device #1: 190.00 GH/s",
		"Device #2: 185.00 GH/s",
		"Hardware Metrics: temperature/utilization unavailable in benchmark mode",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("renderActivityLines() missing %q\n%s", want, view)
		}
	}
}

func TestRenderBenchmarkActivityLabelsPartialDeviceRate(t *testing.T) {
	view := plainLines(renderBenchmarkActivity(&hashcat.BenchmarkProgress{
		HashMode:       1000,
		HashName:       "NTLM",
		TotalModes:     2,
		CompletedModes: 0,
		Speed:          100,
		DeviceSpeeds:   []hashcat.BenchmarkDeviceSpeed{{Device: 1, Speed: 100}},
	}))
	if !strings.Contains(view, "Current Result: 100 H/s (partial)") || strings.Contains(view, "Latest Result:") {
		t.Fatalf("partial benchmark rate was presented as final\n%s", view)
	}
}

func TestBenchmarkActivityEndedIncludesDirectJobTransition(t *testing.T) {
	benchmark := &crackstation.ActivitySnapshot{Kind: crackstation.ActivityBenchmarking}
	cracking := &crackstation.ActivitySnapshot{Kind: crackstation.ActivityCracking}
	if !benchmarkActivityEnded(benchmark, nil) || !benchmarkActivityEnded(benchmark, cracking) {
		t.Fatal("benchmark completion transition was not detected")
	}
	if benchmarkActivityEnded(cracking, nil) || benchmarkActivityEnded(benchmark, benchmark) {
		t.Fatal("non-completion transition was treated as benchmark completion")
	}
}

func TestRenderMainViewStaysWithinTerminal(t *testing.T) {
	now := time.Now()
	for _, size := range []struct{ width, height int }{{40, 12}, {60, 20}, {80, 24}} {
		model := crackstationModel{
			status:     &clientpb.CrackstationStatus{Name: "worker-with-a-long-name", State: clientpb.States_CRACKING},
			lastUpdate: now,
			view:       viewSummary,
			width:      size.width,
			height:     size.height,
			activity: &crackstation.ActivitySnapshot{
				Kind:        crackstation.ActivityCracking,
				Phase:       crackstation.ActivityPhaseCracking,
				JobID:       "job-with-a-long-identifier",
				StartedAt:   now.Add(-time.Minute),
				HashMode:    1000,
				HasHashMode: true,
				AttackMode:  clientpb.CrackAttackMode_BRUTEFORCE,
			},
		}
		view := model.renderMainView()
		lines := strings.Split(view, "\n")
		if len(lines) > size.height {
			t.Errorf("renderMainView(%dx%d) has %d rows\n%s", size.width, size.height, len(lines), ansi.Strip(view))
		}
		for _, line := range lines {
			if width := ansi.StringWidth(line); width > size.width {
				t.Errorf("renderMainView(%dx%d) line width = %d\n%s", size.width, size.height, width, ansi.Strip(line))
			}
		}
		plain := ansi.Strip(view)
		if !strings.Contains(plain, "Running Job") || !strings.Contains(plain, "Job:") || !strings.Contains(plain, "q: quit") {
			t.Errorf("renderMainView(%dx%d) hid active job or footer\n%s", size.width, size.height, plain)
		}
	}
}

func TestContentWidthHasMinimum(t *testing.T) {
	if got := (crackstationModel{width: 3}).contentWidth(); got != 1 {
		t.Fatalf("contentWidth() = %d, want 1", got)
	}
}

func plainLines(lines []string) string {
	return ansi.Strip(strings.Join(lines, "\n"))
}
