package crackstation

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type fakeRPC struct {
	rpcpb.SliverRPCClient
	received *clientpb.CrackBenchmark
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
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
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
	conn, err := grpc.DialContext(
		ctx,
		listener.Addr().String(),
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
