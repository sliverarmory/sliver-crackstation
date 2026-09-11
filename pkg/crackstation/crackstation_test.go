package crackstation

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/sliverarmory/sliver-crackstation/pkg/hashcat"
	"github.com/sliverarmory/sliver-crackstation/pkg/protocompat"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

type fakeRPC struct {
	rpcpb.SliverRPCClient
	received *clientpb.CrackBenchmark
}

func TestToProtobufAdvertisesCrackQueryCapability(t *testing.T) {
	registration := (&Crackstation{hashcat: &hashcat.Hashcat{}}).ToProtobuf()
	wire, err := proto.Marshal(registration)
	if err != nil {
		t.Fatal(err)
	}
	decoded := &clientpb.Crackstation{}
	if err := proto.Unmarshal(wire, decoded); err != nil {
		t.Fatal(err)
	}
	reader, err := protocompat.NewReader(decoded)
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := reader.Strings(crackstationCapabilitiesField)
	if err != nil {
		t.Fatal(err)
	}
	if len(capabilities) != 1 || capabilities[0] != crackQueryCapability {
		t.Fatalf("capabilities = %q; want [%q]", capabilities, crackQueryCapability)
	}
}

func TestAddCrackstationCapabilityDeduplicatesAndPreservesUnknownFields(t *testing.T) {
	registration := &clientpb.Crackstation{}
	if err := protocompat.SetStrings(registration, crackstationCapabilitiesField, []string{"existing", crackQueryCapability, crackQueryCapability}); err != nil {
		t.Fatal(err)
	}
	const preservedField = 105
	if err := protocompat.SetString(registration, preservedField, "preserve-me"); err != nil {
		t.Fatal(err)
	}
	if err := addCrackstationCapability(registration, crackQueryCapability); err != nil {
		t.Fatal(err)
	}
	reader, err := protocompat.NewReader(registration)
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := reader.Strings(crackstationCapabilitiesField)
	if err != nil {
		t.Fatal(err)
	}
	if len(capabilities) != 2 || capabilities[0] != "existing" || capabilities[1] != crackQueryCapability {
		t.Fatalf("capabilities = %q; want existing capability followed by %q", capabilities, crackQueryCapability)
	}
	preserved, err := reader.String(preservedField)
	if err != nil || preserved != "preserve-me" {
		t.Fatalf("preserved unknown field = %q, %v", preserved, err)
	}
}

func TestLoadBenchmarkResultsRejectsEmptyCache(t *testing.T) {
	station := &Crackstation{dataDir: t.TempDir()}
	if err := os.WriteFile(filepath.Join(station.dataDir, "benchmark.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := station.LoadBenchmarkResults(); err == nil {
		t.Fatal("LoadBenchmarkResults accepted an empty benchmark cache")
	}
}

func (f *fakeRPC) CrackstationBenchmark(ctx context.Context, in *clientpb.CrackBenchmark, opts ...grpc.CallOption) (*commonpb.Empty, error) {
	f.received = in
	return &commonpb.Empty{}, nil
}

func TestUploadBenchmarkResult(t *testing.T) {
	originalHostUUID := HostUUID
	HostUUID = "host-uuid-test"
	t.Cleanup(func() {
		HostUUID = originalHostUUID
	})

	fake := &fakeRPC{}
	server := &SliverServer{
		Crackstation: &Crackstation{Name: "demo-station"},
		rpc:          fake,
	}

	benchmarks := map[int32]uint64{
		1000: 4242,
	}

	if err := server.uploadBenchmarkResult(&clientpb.CrackTask{ID: "task-1"}, benchmarks); err != nil {
		t.Fatalf("uploadBenchmarkResult returned error: %v", err)
	}

	if fake.received == nil {
		t.Fatal("expected CrackstationBenchmark to be called")
	}
	if fake.received.Name != "demo-station" {
		t.Fatalf("expected Name %q, got %q", "demo-station", fake.received.Name)
	}
	if fake.received.HostUUID != HostUUID {
		t.Fatalf("expected HostUUID %q, got %q", HostUUID, fake.received.HostUUID)
	}
	if got := fake.received.Benchmarks[1000]; got != 4242 {
		t.Fatalf("expected benchmark for mode 1000 to be 4242, got %d", got)
	}
}

func TestWatchConnCancelsOnClose(t *testing.T) {
	listener := bufconn.Listen(testBufConnSize)
	server := grpc.NewServer()
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	dialer := func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}
	conn, err := grpc.DialContext(
		ctx,
		"bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to dial bufconn: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})

	serverState := &SliverServer{ln: conn}
	watchCtx, watchCancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		serverState.watchConn(watchCtx, watchCancel)
		close(done)
	}()

	if err := conn.Close(); err != nil {
		t.Fatalf("failed to close conn: %v", err)
	}

	select {
	case <-watchCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("expected watchConn to cancel context after close")
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watchConn did not exit after cancel")
	}
}
