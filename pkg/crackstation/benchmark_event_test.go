package crackstation

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/gofrs/uuid"
	"github.com/sliverarmory/sliver-crackstation/pkg/hashcat"
	"github.com/sliverarmory/sliver-crackstation/pkg/operatorconfig"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestHandleEventBenchmarkUploadsResults(t *testing.T) {
	originalHostUUID := HostUUID
	HostUUID = "host-uuid-test"
	t.Cleanup(func() {
		HostUUID = originalHostUUID
	})

	taskID := uuid.Must(uuid.NewV4())
	task := &clientpb.CrackTask{ID: taskID.String()}

	updateCh := make(chan *clientpb.CrackTask, 4)
	benchmarkCh := make(chan *clientpb.CrackBenchmark, 1)

	mock := &mockSliverRPC{
		CrackstationRegisterFunc: func(_ *clientpb.Crackstation, stream rpcpb.SliverRPC_CrackstationRegisterServer) error {
			event := &clientpb.Event{EventType: crackBenchmarkEvent, Data: taskID.Bytes()}
			if err := stream.Send(event); err != nil {
				return status.Errorf(codes.Internal, "failed to send event: %v", err)
			}
			return nil
		},
		CrackTaskByIDFunc: func(_ context.Context, req *clientpb.CrackTask) (*clientpb.CrackTask, error) {
			if req.ID != taskID.String() {
				return nil, status.Errorf(codes.InvalidArgument, "unexpected task id: %s", req.ID)
			}
			return task, nil
		},
		CrackTaskUpdateFunc: func(_ context.Context, update *clientpb.CrackTask) (*commonpb.Empty, error) {
			updateCh <- update
			return &commonpb.Empty{}, nil
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

	benchmarks := map[int32]uint64{1000: 4242}
	benchmarkData, err := json.Marshal(benchmarks)
	if err != nil {
		t.Fatalf("failed to marshal benchmark data: %v", err)
	}
	if err := os.WriteFile(filepath.Join(station.dataDir, "benchmark.json"), benchmarkData, 0600); err != nil {
		t.Fatalf("failed to write benchmark.json: %v", err)
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

	var (
		got           *clientpb.CrackBenchmark
		finalUpdate   *clientpb.CrackTask
		updateCount   int
		deadline      = time.After(3 * time.Second)
		receivedBench bool
	)
	for !(receivedBench && finalUpdate != nil) {
		select {
		case update := <-updateCh:
			updateCount++
			if update.CompletedAt != 0 {
				finalUpdate = update
			}
		case bench := <-benchmarkCh:
			got = bench
			receivedBench = true
		case <-deadline:
			t.Fatal("timeout waiting for benchmark and task updates")
		}
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
	if updateCount != 2 {
		t.Fatalf("expected 2 task updates, got %d", updateCount)
	}
	if finalUpdate == nil || finalUpdate.CompletedAt == 0 {
		t.Fatal("expected final task update to include CompletedAt")
	}
	if finalUpdate.Err != "" {
		t.Fatalf("expected no task error, got %q", finalUpdate.Err)
	}
}

func newTestHashcat(t *testing.T) *hashcat.Hashcat {
	t.Helper()
	h := &hashcat.Hashcat{}
	field := reflect.ValueOf(h).Elem().FieldByName("version")
	if !field.IsValid() {
		t.Fatal("hashcat.Hashcat missing version field")
	}
	if !field.CanSet() {
		reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().SetString("test")
		return h
	}
	field.SetString("test")
	return h
}
