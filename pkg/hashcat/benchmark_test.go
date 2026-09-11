package hashcat

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bishopfox/sliver/protobuf/clientpb"
)

func TestParseBenchmarkUsesAggregateAndStopsAtNextMode(t *testing.T) {
	output := `* Hash-Mode 1000 (NTLM)
Speed.#1.........: 1.50 GH/s
Speed.#2.........: 2.50 GH/s
Speed.#*.........: 3.75 GH/s

* Hash-Mode 22000 (WPA-PBKDF2)
Speed.#1.........: 900.00 kH/s
Speed.#2.........: 100.00 kH/s
`
	benchmarks, err := parseBenchmark(output)
	if err != nil {
		t.Fatalf("parseBenchmark() error = %v", err)
	}
	if benchmarks[1000] != 3_750_000_000 {
		t.Fatalf("aggregate speed = %d", benchmarks[1000])
	}
	if benchmarks[22000] != 1_000_000 {
		t.Fatalf("summed device speed = %d", benchmarks[22000])
	}
}

func TestParseBenchmarkRejectsMissingAndMalformedSpeeds(t *testing.T) {
	for _, input := range []string{
		"no benchmark here",
		"* Hash-Mode 0 (MD5)\nRecovered........: 0/1",
		"* Hash-Mode 0 (MD5)\nSpeed.#1.........: nope MH/s",
		"* Hash-Mode 0 (MD5)\nSpeed.#1.........: 10 frogs/s",
	} {
		if _, err := parseBenchmark(input); err == nil {
			t.Fatalf("parseBenchmark(%q) error = nil", input)
		}
	}
}

func TestParseBenchmarkSectionsRetainsOnlyIndependentPositiveResults(t *testing.T) {
	output := `* Hash-Mode 1000 (NTLM)
Speed.#1.........: 42 H/s

* Hash-Mode 72000 (Python bridge)
Speed.#1.........: nope H/s

* Hash-Mode 74000 (Rust bridge)
Speed.#1.........: 0 H/s
`
	benchmarks, err := parseBenchmarkSections(output)
	if err == nil {
		t.Fatal("parseBenchmarkSections() error = nil; want malformed and zero-speed diagnostics")
	}
	if !reflect.DeepEqual(benchmarks, map[int32]uint64{1000: 42}) {
		t.Fatalf("parseBenchmarkSections() = %v; want only independently valid mode 1000", benchmarks)
	}
	if strict, strictErr := parseBenchmark(output); strictErr == nil || strict != nil {
		t.Fatalf("parseBenchmark() = %v, %v; strict parsing must reject partial output", strict, strictErr)
	}
}

func TestParseBenchmarkResultMarksTruncatedPrefixIncomplete(t *testing.T) {
	output := "* Hash-Mode 1000 (NTLM)\nSpeed.#1.........: 42 H/s\n"
	benchmarks, err := parseBenchmarkResult(CommandResult{
		Stdout:           []byte(output),
		StdoutTruncated:  true,
		StdoutTotalBytes: uint64(len(output) + 100),
	})
	if err == nil || !strings.Contains(err.Error(), "stdout was truncated") {
		t.Fatalf("parseBenchmarkResult() error = %v; want truncation diagnostic", err)
	}
	if !reflect.DeepEqual(benchmarks, map[int32]uint64{1000: 42}) {
		t.Fatalf("parseBenchmarkResult() = %v; want complete prefix section retained for exact recovery", benchmarks)
	}
}

func TestBenchmarkContextStreamingReportsModeAndDeviceProgress(t *testing.T) {
	h := testHashcatScript(t, `
printf '%s\n' \
  '  * Hash-Mode 1000 (NTLM)  ' \
  'Speed.#2.........: 2.00 GH/s' \
  'Speed.#1.........: 1.00 GH/s' \
  'Speed.#*.........: 2.75 GH/s' \
  '* Hash-Mode 22000 (WPA (PBKDF2)) [Iterations: 4095]' \
  'Speed.#2.........: 100.00 kH/s' \
  'Speed.#1.........: 900.00 kH/s'
`)
	writeTestHashcatModules(t, h, 1000, 22000)

	var progress []BenchmarkProgress
	benchmarks, err := h.BenchmarkContextStreaming(nil, &clientpb.CrackCommand{
		Benchmark:    true,
		BenchmarkAll: true,
	}, func(update BenchmarkProgress) {
		progress = append(progress, update)
	})
	if err != nil {
		t.Fatal(err)
	}
	wantBenchmarks := map[int32]uint64{1000: 2_750_000_000, 22000: 1_000_000}
	if !reflect.DeepEqual(benchmarks, wantBenchmarks) {
		t.Fatalf("BenchmarkContextStreaming() = %v; want %v", benchmarks, wantBenchmarks)
	}
	if len(progress) != 8 {
		t.Fatalf("progress callbacks = %#v; want two headers, five speed updates, and final completion", progress)
	}
	if first := progress[0]; first.HashMode != 1000 || first.HashName != "NTLM" || first.TotalModes != 2 || first.CompletedModes != 0 || first.Speed != 0 {
		t.Fatalf("first progress = %#v", first)
	}
	wantFirstDevice := []BenchmarkDeviceSpeed{{Device: 2, Speed: 2_000_000_000}}
	if got := progress[1]; got.CompletedModes != 0 || got.ModeComplete || got.LastSpeed != 0 || got.Speed != 2_000_000_000 || !reflect.DeepEqual(got.DeviceSpeeds, wantFirstDevice) {
		t.Fatalf("first device progress = %#v; partial device rate must remain in-progress with immutable snapshot %v", got, wantFirstDevice)
	}
	wantDevices := []BenchmarkDeviceSpeed{
		{Device: 1, Speed: 1_000_000_000},
		{Device: 2, Speed: 2_000_000_000},
	}
	if aggregate := progress[3]; !aggregate.ModeComplete || aggregate.Speed != 2_750_000_000 || !reflect.DeepEqual(aggregate.DeviceSpeeds, wantDevices) {
		t.Fatalf("aggregate progress = %#v; want aggregate with sorted devices %v", aggregate, wantDevices)
	}
	transition := progress[4]
	if transition.HashMode != 22000 || transition.HashName != "WPA (PBKDF2)" || transition.ModeComplete || transition.Speed != 0 || len(transition.DeviceSpeeds) != 0 ||
		transition.LastHashMode != 1000 || transition.LastHashName != "NTLM" || transition.LastSpeed != 2_750_000_000 || !reflect.DeepEqual(transition.LastDeviceSpeeds, wantDevices) {
		t.Fatalf("mode transition progress = %#v", transition)
	}
	final := progress[len(progress)-1]
	if final.CompletedModes != 2 || !final.ModeComplete || final.Speed != 1_000_000 || final.LastHashMode != 22000 || final.LastSpeed != 1_000_000 {
		t.Fatalf("final progress = %#v", final)
	}
}

func TestBenchmarkProgressIgnoresInvalidSpeedsAndSaturatesDeviceSum(t *testing.T) {
	var progress []BenchmarkProgress
	observer := newBenchmarkProgressObserver(3, func(update BenchmarkProgress) {
		progress = append(progress, update)
	})
	for _, line := range []string{
		"* Hash-Mode 22000 (WPA (PBKDF2)) [Iterations: 4095]",
		"Speed.#1.........: nope H/s",
		"Speed.#1.........: -1 H/s",
		"Speed.#1.........: 0 H/s",
		"Speed.#-1........: 1 H/s",
		"Speed.#2.........: 10 EH/s",
		"Speed.#1.........: 10 EH/s",
	} {
		observer.observeLine([]byte(line))
	}
	observer.finishCurrent()
	if len(progress) != 4 {
		t.Fatalf("progress callbacks = %#v; invalid and zero speeds must be ignored and completion emitted once", progress)
	}
	final := progress[len(progress)-1]
	if final.HashName != "WPA (PBKDF2)" || final.Speed != ^uint64(0) || final.CompletedModes != 1 {
		t.Fatalf("saturated progress = %#v", final)
	}
	wantDevices := []BenchmarkDeviceSpeed{
		{Device: 1, Speed: 10_000_000_000_000_000_000},
		{Device: 2, Speed: 10_000_000_000_000_000_000},
	}
	if !reflect.DeepEqual(final.DeviceSpeeds, wantDevices) {
		t.Fatalf("device speeds = %v; want sorted %v", final.DeviceSpeeds, wantDevices)
	}
}

func TestBenchmarkContextStreamingLeavesUnknownTotalWithoutExplicitMode(t *testing.T) {
	h := testHashcatScript(t, `
printf '%s\n' \
  '* Hash-Mode 0 (MD5)' \
  'Speed.#1.........: 10 H/s' \
  '' \
  '* Hash-Mode 1000 (NTLM)' \
  'Speed.#1.........: 20 H/s'
`)

	var progress []BenchmarkProgress
	_, err := h.BenchmarkContextStreaming(nil, &clientpb.CrackCommand{
		Benchmark: true,
		HashType:  clientpb.HashType_INVALID,
	}, func(update BenchmarkProgress) {
		progress = append(progress, update)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(progress) == 0 || progress[len(progress)-1].CompletedModes != 2 || progress[len(progress)-1].TotalModes != 0 {
		t.Fatalf("progress = %#v; default benchmark mode count must remain unknown", progress)
	}
}

func TestParseBenchmarkSpeedRejectsUint64Boundary(t *testing.T) {
	for _, line := range []string{
		"Speed.#1.........: 18446744073709551616 H/s",
		"Speed.#1.........: 18.446744073709552 EH/s",
	} {
		if _, err := parseBenchmarkSpeed(line); err == nil || !strings.Contains(err.Error(), "overflows") {
			t.Fatalf("parseBenchmarkSpeed(%q) error = %v; want overflow", line, err)
		}
	}
}

func TestBenchmarkAllRecoversInstalledModesAfterBridgeAbort(t *testing.T) {
	h := testHashcatScript(t, `
mode=all
for arg in "$@"; do
  case "$arg" in
    --hash-type=*) mode=${arg#--hash-type=} ;;
  esac
done
printf '%s\n' "$mode:$*" >> invocations
case "$mode" in
  all)
    printf '%s\n' '* Hash-Mode 1000 (NTLM)' 'Speed.#1.........: 42 H/s' '' '* Hash-Mode 72000 (Python bridge)'
    printf '%s\n' "Bridge initialization for hash-mode '72000' failed." >&2
    exit 255
    ;;
  72000)
    printf '%s\n' 'Unable to find suitable Python library for -m 72000.' >&2
    exit 255
    ;;
  74000)
    printf '%s\n' '* Hash-Mode 74000 (Rust bridge)' 'Speed.#1.........: 74 H/s'
    ;;
  99999)
    printf '%s\n' '* Hash-Mode 99999 (Plaintext)' 'Speed.#1.........: 99 H/s'
    exit 255
    ;;
esac
`)
	writeTestHashcatModules(t, h, 1000, 72000, 74000, 99999)

	var progress []BenchmarkProgress
	benchmarks, err := h.BenchmarkContextStreaming(nil, &clientpb.CrackCommand{
		AttackMode:     clientpb.CrackAttackMode_NO_ATTACK,
		HashType:       clientpb.HashType_INVALID,
		Benchmark:      true,
		BenchmarkAll:   true,
		LogfileDisable: true,
	}, func(update BenchmarkProgress) {
		progress = append(progress, update)
	})
	if err != nil {
		t.Fatalf("Benchmark() error = %v", err)
	}
	want := map[int32]uint64{1000: 42, 74000: 74, 99999: 99}
	if !reflect.DeepEqual(benchmarks, want) {
		t.Fatalf("Benchmark() = %v; want %v", benchmarks, want)
	}
	if len(progress) == 0 || progress[len(progress)-1].CompletedModes != 3 || progress[len(progress)-1].LastHashMode != 99999 {
		t.Fatalf("recovery progress = %#v; observer must span retries without double counting", progress)
	}

	invocations, err := os.ReadFile(filepath.Join(h.cwd, "invocations"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(invocations)), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[0], "all:") ||
		!strings.HasPrefix(lines[1], "72000:") ||
		!strings.HasPrefix(lines[2], "74000:") ||
		!strings.HasPrefix(lines[3], "99999:") {
		t.Fatalf("benchmark invocations = %q; want sorted exact recovery after bulk run", lines)
	}
	for _, line := range lines[1:] {
		if !strings.Contains(line, "--benchmark") || strings.Contains(line, "--benchmark-all") || !strings.Contains(line, "--logfile-disable") {
			t.Fatalf("exact recovery invocation has unsafe arguments: %q", line)
		}
	}
}

func TestBenchmarkNonzeroWithoutUsableOutputReturnsError(t *testing.T) {
	h := testHashcatScript(t, `printf 'run\n' >> invocations; printf '%s\n' "Bridge initialization failed" >&2; exit 255`)
	writeTestHashcatModules(t, h, 1000, 74000)
	benchmarks, err := h.Benchmark(&clientpb.CrackCommand{Benchmark: true, BenchmarkAll: true})
	if err == nil {
		t.Fatal("Benchmark() error = nil; want nonzero empty benchmark rejection")
	}
	if benchmarks != nil {
		t.Fatalf("Benchmark() = %v; want nil results", benchmarks)
	}
	if !strings.Contains(err.Error(), "no usable positive results") {
		t.Fatalf("Benchmark() error = %q; want usable-results diagnostic", err)
	}
	invocations, readErr := os.ReadFile(filepath.Join(h.cwd, "invocations"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(invocations) != "run\n" {
		t.Fatalf("benchmark invocations = %q; zero-result bulk failure must not launch exact retries", invocations)
	}
}

func TestBenchmarkMalformedOnlyOutputReturnsError(t *testing.T) {
	h := testHashcatScript(t, `
printf '%s\n' '* Hash-Mode 1000 (NTLM)' 'Speed.#1.........: nope H/s'
exit 255
`)
	benchmarks, err := h.Benchmark(&clientpb.CrackCommand{Benchmark: true, BenchmarkAll: true})
	if err == nil {
		t.Fatal("Benchmark() error = nil; want malformed benchmark rejection")
	}
	if benchmarks != nil {
		t.Fatalf("Benchmark() = %v; want nil results", benchmarks)
	}
	if !strings.Contains(err.Error(), "invalid speed") {
		t.Fatalf("Benchmark() error = %q; want malformed-speed diagnostic", err)
	}
}

func TestInstalledHashModesUsesOnlyCanonicalRegularModules(t *testing.T) {
	h := &Hashcat{cwd: t.TempDir()}
	writeTestHashcatModules(t, h, 74000, 1000, 72000)
	for name, directory := range map[string]bool{
		"module_1234.so":   false,
		"module_12345.txt": false,
		"module_abcde.so":  false,
		"module_22222.so":  true,
	} {
		path := filepath.Join(h.cwd, "modules", name)
		if directory {
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}

	modes, err := h.installedHashModes()
	if err != nil {
		t.Fatal(err)
	}
	want := []int32{1000, 72000, 74000}
	if !reflect.DeepEqual(modes, want) {
		t.Fatalf("installedHashModes() = %v; want %v", modes, want)
	}
}

func TestCanonicalModuleHashMode(t *testing.T) {
	tests := []struct {
		name string
		mode int32
		ok   bool
	}{
		{name: "module_00000.so", mode: 0, ok: true},
		{name: "module_74000.dll", mode: 74000, ok: true},
		{name: "module_1234.so"},
		{name: "module_123456.so"},
		{name: "module_abcde.so"},
		{name: "module_12345.dylib"},
		{name: "prefix_module_12345.so"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mode, ok := canonicalModuleHashMode(test.name)
			if mode != test.mode || ok != test.ok {
				t.Fatalf("canonicalModuleHashMode(%q) = %d, %v; want %d, %v", test.name, mode, ok, test.mode, test.ok)
			}
		})
	}
}

func writeTestHashcatModules(t *testing.T, h *Hashcat, modes ...int32) {
	t.Helper()
	directory := filepath.Join(h.cwd, "modules")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for _, mode := range modes {
		path := filepath.Join(directory, fmt.Sprintf("module_%05d.so", mode))
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
