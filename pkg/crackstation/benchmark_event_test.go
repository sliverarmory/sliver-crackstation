package crackstation

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/sliverarmory/sliver-crackstation/pkg/hashcat"
	"github.com/sliverarmory/sliver-crackstation/pkg/operatorconfig"
	"github.com/sliverarmory/sliver-crackstation/pkg/protocompat"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestHandleEventBenchmarkUploadsResults(t *testing.T) {
	originalHostUUID := HostUUID
	HostUUID = "host-uuid-test"
	t.Cleanup(func() {
		HostUUID = originalHostUUID
	})

	benchmarkCh := make(chan *clientpb.CrackBenchmark, 1)

	mock := &mockSliverRPC{
		CrackstationRegisterFunc: func(_ *clientpb.Crackstation, stream rpcpb.SliverRPC_CrackstationRegisterServer) error {
			event := &clientpb.Event{EventType: crackBenchmarkEvent}
			if err := stream.Send(event); err != nil {
				return status.Errorf(codes.Internal, "failed to send event: %v", err)
			}
			return nil
		},
		CrackstationBenchmarkFunc: func(_ context.Context, req *clientpb.CrackBenchmark) (*commonpb.Empty, error) {
			benchmarkCh <- req
			return &commonpb.Empty{}, nil
		},
	}

	client := newBufConnClient(t, mock)
	station := &Crackstation{
		Name:      "bench-station",
		dataDir:   t.TempDir(),
		crackLock: &sync.Mutex{},
		hashcat:   newTestHashcat(t),
	}
	server := &SliverServer{
		Crackstation: station,
		rpc:          client,
		Config:       &operatorconfig.ClientConfig{Operator: "bench-op"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	events, err := server.Events(ctx)
	if err != nil {
		t.Fatalf("failed to open event stream: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for event := range events {
			station.handleEvent(server, event)
		}
	}()

	var got *clientpb.CrackBenchmark
	select {
	case got = <-benchmarkCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for fresh benchmark upload")
	}
	wg.Wait()

	if got == nil {
		t.Fatal("expected CrackstationBenchmark to be called")
	}
	if got.Name != station.Name {
		t.Fatalf("expected Name %q, got %q", station.Name, got.Name)
	}
	if got.HostUUID != HostUUID {
		t.Fatalf("expected HostUUID %q, got %q", HostUUID, got.HostUUID)
	}
	if got.Benchmarks[1000] != 4242 {
		t.Fatalf("expected benchmark for mode 1000 to be 4242, got %d", got.Benchmarks[1000])
	}
	fields, err := protocompat.NewReader(got)
	if err != nil {
		t.Fatal(err)
	}
	schemaVersion, err := fields.Uint32(crackBenchmarkSchemaVersionField)
	if err != nil {
		t.Fatal(err)
	}
	hashcatVersion, err := fields.String(crackBenchmarkHashcatVersionField)
	if err != nil {
		t.Fatal(err)
	}
	if schemaVersion != benchmarkSchemaVersion || hashcatVersion != "test" {
		t.Fatalf("benchmark protocol marker = schema %d, Hashcat %q", schemaVersion, hashcatVersion)
	}
}

func TestUnknownHashcatVersionIsConsistentAcrossRegistrationAndBenchmark(t *testing.T) {
	station := &Crackstation{hashcat: &hashcat.Hashcat{}}
	registration := station.ToProtobuf()
	if registration.GetHashcatVersion() != "unknown" {
		t.Fatalf("registration Hashcat version = %q; want stable unknown marker", registration.GetHashcatVersion())
	}
	message, err := (&SliverServer{Crackstation: station}).benchmarkMessage("worker", map[int32]uint64{0: 1})
	if err != nil {
		t.Fatal(err)
	}
	fields, err := protocompat.NewReader(message)
	if err != nil {
		t.Fatal(err)
	}
	version, err := fields.String(crackBenchmarkHashcatVersionField)
	if err != nil {
		t.Fatal(err)
	}
	if version != registration.GetHashcatVersion() {
		t.Fatalf("benchmark Hashcat version = %q; registration reported %q", version, registration.GetHashcatVersion())
	}
}

func newTestHashcat(t *testing.T) *hashcat.Hashcat {
	t.Helper()
	return newTestHashcatWithScript(t, "#!/bin/sh\nprintf '%s\\n' '* Hash-Mode 1000 (NTLM)' 'Speed.#1.........: 4242 H/s'\n")
}

func newTestHashcatWithScript(t *testing.T, script string) *hashcat.Hashcat {
	t.Helper()
	directory := t.TempDir()
	executable := filepath.Join(directory, "hashcat-test")
	if err := os.WriteFile(executable, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	h := &hashcat.Hashcat{}
	for name, value := range map[string]string{"version": "test", "exe": executable, "cwd": directory} {
		field := reflect.ValueOf(h).Elem().FieldByName(name)
		if !field.IsValid() {
			t.Fatalf("hashcat.Hashcat missing %s field", name)
		}
		reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().SetString(value)
	}
	return h
}

func benchmarkRequestData(t *testing.T, ignoreLocalCache bool) []byte {
	t.Helper()
	command := &clientpb.CrackCommand{}
	if err := protocompat.SetBool(command, crackCommandIgnoreLocalCacheField, ignoreLocalCache); err != nil {
		t.Fatal(err)
	}
	data, err := proto.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseBenchmarkRequestAcceptsSixteenByteProtobuf(t *testing.T) {
	command := &clientpb.CrackCommand{Session: "1234567890"}
	if err := protocompat.SetBool(command, crackCommandIgnoreLocalCacheField, true); err != nil {
		t.Fatal(err)
	}
	data, err := proto.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 16 {
		t.Fatalf("test payload length = %d; want 16", len(data))
	}
	ignoreLocalCache, err := parseBenchmarkRequest(data)
	if err != nil {
		t.Fatal(err)
	}
	if !ignoreLocalCache {
		t.Fatal("valid 16-byte protobuf was mistaken for a legacy task UUID")
	}
}

func TestRequestedBenchmarkUsesLocalCacheByDefault(t *testing.T) {
	forceData, err := proto.Marshal(&clientpb.CrackCommand{Force: true})
	if err != nil {
		t.Fatal(err)
	}
	benchmarkOptionData, err := proto.Marshal(&clientpb.CrackCommand{BenchmarkMin: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "empty request"},
		{name: "hashcat force", data: forceData},
		{name: "unrecognized benchmark option", data: benchmarkOptionData},
		{name: "malformed request", data: []byte{0x80}},
		{name: "legacy task UUID", data: []byte("0123456789abcdef")},
	} {
		t.Run(test.name, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "benchmark-ran")
			h := newScriptHashcat(t, `
: > '`+marker+`'
printf '%s\n' '* Hash-Mode 1000 (NTLM)' 'Speed.#1.........: 88 H/s'
`)
			var uploaded *clientpb.CrackBenchmark
			mock := &mockSliverRPC{CrackstationBenchmarkFunc: func(_ context.Context, benchmark *clientpb.CrackBenchmark) (*commonpb.Empty, error) {
				uploaded = benchmark
				return &commonpb.Empty{}, nil
			}}
			station, err := NewCrackstation("worker", t.TempDir(), h)
			if err != nil {
				t.Fatal(err)
			}
			if err := station.saveBenchmarkResults(map[int32]uint64{1000: 41}); err != nil {
				t.Fatal(err)
			}
			server := &SliverServer{Crackstation: station, rpc: newBufConnClient(t, mock)}

			station.handleEvent(server, &clientpb.Event{EventType: crackBenchmarkEvent, Data: test.data})

			if uploaded == nil || uploaded.GetBenchmarks()[1000] != 41 {
				t.Fatalf("uploaded benchmark = %#v; want cached rate 41", uploaded)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("Hashcat benchmark unexpectedly ran; marker error = %v", err)
			}
		})
	}
}

func TestRequestedBenchmarkIgnoreLocalCacheRunsFreshWithoutHashcatForce(t *testing.T) {
	argsPath := filepath.Join(t.TempDir(), "hashcat-args")
	h := newScriptHashcat(t, `
printf '%s\n' "$@" > '`+argsPath+`'
printf '%s\n' '* Hash-Mode 1000 (NTLM)' 'Speed.#1.........: 88 H/s'
`)
	var uploaded *clientpb.CrackBenchmark
	mock := &mockSliverRPC{CrackstationBenchmarkFunc: func(_ context.Context, benchmark *clientpb.CrackBenchmark) (*commonpb.Empty, error) {
		uploaded = benchmark
		return &commonpb.Empty{}, nil
	}}
	station, err := NewCrackstation("worker", t.TempDir(), h)
	if err != nil {
		t.Fatal(err)
	}
	if err := station.saveBenchmarkResults(map[int32]uint64{1000: 41}); err != nil {
		t.Fatal(err)
	}
	server := &SliverServer{Crackstation: station, rpc: newBufConnClient(t, mock)}

	station.handleEvent(server, &clientpb.Event{
		EventType: crackBenchmarkEvent,
		Data:      benchmarkRequestData(t, true),
	})

	if uploaded == nil || uploaded.GetBenchmarks()[1000] != 88 {
		t.Fatalf("uploaded benchmark = %#v; want fresh rate 88", uploaded)
	}
	cached, err := station.LoadBenchmarkResults()
	if err != nil || cached[1000] != 88 {
		t.Fatalf("cached benchmark = %v, %v; want fresh rate 88", cached, err)
	}
	data, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Fields(string(data))
	for _, arg := range args {
		if arg == "--force" {
			t.Fatalf("IgnoreLocalCache leaked into Hashcat argv: %q", args)
		}
	}
}

func TestRequestedBenchmarkReplacesInvalidLocalCache(t *testing.T) {
	h := newScriptHashcat(t, `printf '%s\n' '* Hash-Mode 1000 (NTLM)' 'Speed.#1.........: 88 H/s'`)
	var uploaded *clientpb.CrackBenchmark
	mock := &mockSliverRPC{CrackstationBenchmarkFunc: func(_ context.Context, benchmark *clientpb.CrackBenchmark) (*commonpb.Empty, error) {
		uploaded = benchmark
		return &commonpb.Empty{}, nil
	}}
	station, err := NewCrackstation("worker", t.TempDir(), h)
	if err != nil {
		t.Fatal(err)
	}
	if err := station.saveBenchmarkResults(map[int32]uint64{1000: 0}); err != nil {
		t.Fatal(err)
	}
	server := &SliverServer{Crackstation: station, rpc: newBufConnClient(t, mock)}

	station.handleEvent(server, &clientpb.Event{EventType: crackBenchmarkEvent})

	if uploaded == nil || uploaded.GetBenchmarks()[1000] != 88 {
		t.Fatalf("uploaded benchmark = %#v; want fresh rate 88", uploaded)
	}
	cached, err := station.LoadBenchmarkResults()
	if err != nil || cached[1000] != 88 {
		t.Fatalf("cached benchmark = %v, %v; want replacement rate 88", cached, err)
	}
}

func TestBenchmarkRunsAllHashModesWithoutExplicitModes(t *testing.T) {
	argsPath := filepath.Join(t.TempDir(), "hashcat-args")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + argsPath + "'\n" +
		"printf '%s\\n' '* Hash-Mode 1000 (NTLM)' 'Speed.#1.........: 4242 H/s'\n"
	station := &Crackstation{
		dataDir: t.TempDir(),
		hashcat: newTestHashcatWithScript(t, script),
	}

	if err := station.Benchmark(); err != nil {
		t.Fatalf("Benchmark() error = %v", err)
	}
	data, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Fields(string(data))
	foundBenchmark := false
	foundBenchmarkAll := false
	foundLogfileDisable := false
	for _, arg := range args {
		if arg == "--benchmark" {
			foundBenchmark = true
		}
		if arg == "--benchmark-all" {
			foundBenchmarkAll = true
		}
		if arg == "--logfile-disable" {
			foundLogfileDisable = true
		}
		if strings.HasPrefix(arg, "--attack-mode=") || strings.HasPrefix(arg, "--hash-type=") {
			t.Fatalf("benchmark argv contains unintended mode %q: %q", arg, args)
		}
	}
	if !foundBenchmark {
		t.Fatalf("benchmark argv missing --benchmark: %q", args)
	}
	if !foundBenchmarkAll {
		t.Fatalf("benchmark argv missing --benchmark-all: %q", args)
	}
	if !foundLogfileDisable {
		t.Fatalf("benchmark argv missing --logfile-disable: %q", args)
	}
}

func TestRequestedBenchmarkRetriesFreshFailure(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "attempted")
	h := newScriptHashcat(t, `
if [ ! -f '`+marker+`' ]; then
  : > '`+marker+`'
  exit 2
fi
printf '%s\n' '* Hash-Mode 1000 (NTLM)' 'Speed.#1.........: 77 H/s'
`)
	var uploads atomic.Int32
	mock := &mockSliverRPC{CrackstationBenchmarkFunc: func(context.Context, *clientpb.CrackBenchmark) (*commonpb.Empty, error) {
		uploads.Add(1)
		return &commonpb.Empty{}, nil
	}}
	station, err := NewCrackstation("worker", t.TempDir(), h)
	if err != nil {
		t.Fatal(err)
	}
	station.runBenchmarkRequest(&SliverServer{Crackstation: station, rpc: newBufConnClient(t, mock)})
	if uploads.Load() != 1 {
		t.Fatalf("benchmark uploads = %d; want one after retry succeeds", uploads.Load())
	}
	results, err := station.LoadBenchmarkResults()
	if err != nil || results[1000] != 77 {
		t.Fatalf("benchmark results = %v, %v", results, err)
	}
}

func TestRequestedBenchmarkUploadsModesRecoveredAfterBridgeAbort(t *testing.T) {
	h := newScriptHashcat(t, `
mkdir -p modules
: > modules/module_01000.so
: > modules/module_72000.so
: > modules/module_74000.so
mode=all
for arg in "$@"; do
  case "$arg" in
    --hash-type=*) mode=${arg#--hash-type=} ;;
  esac
done
case "$mode" in
  all)
    printf '%s\n' '* Hash-Mode 1000 (NTLM)' 'Speed.#1.........: 42 H/s' '' '* Hash-Mode 72000 (Python bridge)'
    exit 255
    ;;
  72000)
    printf '%s\n' 'Unable to find suitable Python library for -m 72000.' >&2
    exit 255
    ;;
  74000)
    printf '%s\n' '* Hash-Mode 74000 (Rust bridge)' 'Speed.#1.........: 74 H/s'
    ;;
esac
`)
	var uploaded *clientpb.CrackBenchmark
	mock := &mockSliverRPC{CrackstationBenchmarkFunc: func(_ context.Context, benchmark *clientpb.CrackBenchmark) (*commonpb.Empty, error) {
		uploaded = benchmark
		return &commonpb.Empty{}, nil
	}}
	station, err := NewCrackstation("worker", t.TempDir(), h)
	if err != nil {
		t.Fatal(err)
	}
	station.runBenchmarkRequest(&SliverServer{Crackstation: station, rpc: newBufConnClient(t, mock)})

	if uploaded == nil || len(uploaded.GetBenchmarks()) == 0 {
		t.Fatalf("uploaded benchmark = %#v; want recovered nonempty results", uploaded)
	}
	if uploaded.GetBenchmarks()[1000] != 42 || uploaded.GetBenchmarks()[74000] != 74 {
		t.Fatalf("uploaded benchmarks = %v; want bulk mode 1000 and recovered mode 74000", uploaded.GetBenchmarks())
	}
	if _, found := uploaded.GetBenchmarks()[72000]; found {
		t.Fatalf("uploaded benchmarks = %v; unavailable bridge mode 72000 must not be advertised", uploaded.GetBenchmarks())
	}
}

func TestRequestedBenchmarkRetriesAgainOnReconnectEvent(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "benchmark-runs")
	h := newScriptHashcat(t, `printf 'run\n' >> '`+marker+`'; printf '%s\n' '* Hash-Mode 1000 (NTLM)' 'Speed.#1.........: 88 H/s'`)
	var uploads atomic.Int32
	mock := &mockSliverRPC{CrackstationBenchmarkFunc: func(context.Context, *clientpb.CrackBenchmark) (*commonpb.Empty, error) {
		if uploads.Add(1) <= int32(benchmarkMaxAttempts) {
			return nil, status.Error(codes.Unavailable, "temporary outage")
		}
		return &commonpb.Empty{}, nil
	}}
	station, err := NewCrackstation("worker", t.TempDir(), h)
	if err != nil {
		t.Fatal(err)
	}
	server := &SliverServer{Crackstation: station, rpc: newBufConnClient(t, mock)}
	// The first registration event runs the benchmark and exhausts its bounded
	// upload retries. The reconnect event reuses that result for another upload.
	station.runBenchmarkRequest(server)
	station.runBenchmarkRequest(server)
	if uploads.Load() != int32(benchmarkMaxAttempts+1) {
		t.Fatalf("benchmark uploads = %d; reconnect event did not retry", uploads.Load())
	}
	runs, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(runs), "run\n") != 1 {
		t.Fatalf("fresh benchmark runs = %q; reconnect should reuse the first result", runs)
	}
}

func TestBenchmarkEventsAreBoundToConnectionGeneration(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "benchmark-runs")
	firstStarted := filepath.Join(t.TempDir(), "first-started")
	h := newScriptHashcat(t, `
printf 'run\n' >> '`+marker+`'
if [ ! -f '`+firstStarted+`' ]; then
  : > '`+firstStarted+`'
  while :; do :; done
fi
printf '%s\n' '* Hash-Mode 1000 (NTLM)' 'Speed.#1.........: 91 H/s'
`)
	uploaded := make(chan *clientpb.CrackBenchmark, 2)
	mock := &mockSliverRPC{CrackstationBenchmarkFunc: func(_ context.Context, benchmark *clientpb.CrackBenchmark) (*commonpb.Empty, error) {
		uploaded <- benchmark
		return &commonpb.Empty{}, nil
	}}
	station, err := NewCrackstation("worker", t.TempDir(), h)
	if err != nil {
		t.Fatal(err)
	}
	server := &SliverServer{Crackstation: station, rpc: newBufConnClient(t, mock)}
	oldConnectionDone := make(chan struct{})
	newConnectionDone := make(chan struct{})
	go station.Start()
	t.Cleanup(station.Stop)

	station.Events <- &ServerEvent{
		Server: server, Event: &clientpb.Event{EventType: crackBenchmarkEvent}, ConnectionDone: oldConnectionDone,
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(firstStarted); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first benchmark did not start")
		}
		time.Sleep(time.Millisecond)
	}

	close(oldConnectionDone)
	// Events already queued for the disconnected stream must be discarded.
	station.Events <- &ServerEvent{
		Server: server, Event: &clientpb.Event{EventType: crackBenchmarkEvent}, ConnectionDone: oldConnectionDone,
	}
	station.Events <- &ServerEvent{
		Server: server, Event: &clientpb.Event{EventType: crackBenchmarkEvent}, ConnectionDone: oldConnectionDone,
	}
	station.Events <- &ServerEvent{
		Server: server, Event: &clientpb.Event{EventType: crackBenchmarkEvent}, ConnectionDone: newConnectionDone,
	}

	select {
	case benchmark := <-uploaded:
		if benchmark.GetBenchmarks()[1000] != 91 {
			t.Fatalf("uploaded benchmarks = %v", benchmark.GetBenchmarks())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("replacement connection benchmark did not complete")
	}
	select {
	case duplicate := <-uploaded:
		t.Fatalf("stale connection uploaded duplicate benchmark: %v", duplicate.GetBenchmarks())
	case <-time.After(100 * time.Millisecond):
	}
	runs, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(string(runs), "run\n"); count != 2 {
		t.Fatalf("benchmark runs = %d (%q); want cancelled old generation plus one replacement", count, runs)
	}
}
