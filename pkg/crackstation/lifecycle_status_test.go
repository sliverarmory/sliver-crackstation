package crackstation

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/sliverarmory/sliver-crackstation/pkg/operatorconfig"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestNewCrackstationInitializesBoundedLifecycle(t *testing.T) {
	station, err := NewCrackstation("worker", t.TempDir(), newScriptHashcat(t, "exit 0"))
	if err != nil {
		t.Fatal(err)
	}
	if station.Events == nil || cap(station.Events) != eventQueueSize {
		t.Fatalf("Events = %#v cap=%d", station.Events, cap(station.Events))
	}
	if station.taskEvents == nil || cap(station.taskEvents) != eventQueueSize || station.done == nil {
		t.Fatal("task queue or lifecycle channel was not initialized")
	}
	done := make(chan struct{})
	go func() {
		station.Start()
		close(done)
	}()
	station.Stop()
	station.Stop()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Start did not stop promptly")
	}
}

func TestConnectCannotPublishConnectionAfterStopDuringDial(t *testing.T) {
	station, err := NewCrackstation("worker", t.TempDir(), newScriptHashcat(t, "exit 0"))
	if err != nil {
		t.Fatal(err)
	}
	server := station.AddServer(&operatorconfig.ClientConfig{Token: "shutdown-race"})
	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	var connection *grpc.ClientConn
	server.dial = func(*operatorconfig.ClientConfig) (rpcpb.SliverRPCClient, *grpc.ClientConn, error) {
		close(dialStarted)
		<-releaseDial
		var dialErr error
		connection, dialErr = grpc.NewClient("passthrough:///unused", grpc.WithTransportCredentials(insecure.NewCredentials()))
		if dialErr != nil {
			return nil, nil, dialErr
		}
		return rpcpb.NewSliverRPCClient(connection), connection, nil
	}
	connectDone := make(chan struct{})
	go func() {
		server.Connect()
		close(connectDone)
	}()
	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("connection dial did not start")
	}
	station.Stop()
	close(releaseDial)
	select {
	case <-connectDone:
	case <-time.After(time.Second):
		t.Fatal("connection attempt did not stop after shutdown")
	}
	if connection == nil || connection.GetState() != connectivity.Shutdown {
		t.Fatalf("post-shutdown dial connection state = %v; want Shutdown", connection)
	}
	state, rpc, liveConnection := server.connectionSnapshot()
	if state != DISCONNECTED || rpc != nil || liveConnection != nil {
		t.Fatalf("server published a connection after Stop: state=%s rpc=%v conn=%v", state, rpc != nil, liveConnection)
	}
}

func TestEventBrokerDoesNotBlockOnSlowSubscriber(t *testing.T) {
	broker := newBroker()
	slow := broker.Subscribe()
	for index := 0; index < eventBufSize*4; index++ {
		broker.Publish(&clientpb.CrackstationStatus{Name: "snapshot"})
	}
	if len(slow) != eventBufSize {
		t.Fatalf("buffered snapshots = %d; want bounded %d", len(slow), eventBufSize)
	}
	broker.Unsubscribe(slow)
	broker.Stop()
	broker.Stop()
}

func TestEventBrokerPublishesIndependentSnapshots(t *testing.T) {
	broker := newBroker()
	first := broker.Subscribe()
	second := broker.Subscribe()
	original := &clientpb.CrackstationStatus{
		Name: "worker",
		Syncing: &clientpb.CrackSyncStatus{
			Progress: map[string]float32{"digest": 0.5},
		},
	}
	broker.Publish(original)
	firstSnapshot := <-first
	secondSnapshot := <-second
	firstSnapshot.Name = "mutated"
	firstSnapshot.Syncing.Progress["digest"] = 1
	if secondSnapshot.GetName() != "worker" || secondSnapshot.GetSyncing().GetProgress()["digest"] != 0.5 {
		t.Fatalf("subscriber mutation leaked into peer snapshot: %#v", secondSnapshot)
	}
	if original.GetName() != "worker" || original.GetSyncing().GetProgress()["digest"] != 0.5 {
		t.Fatalf("subscriber mutation leaked into publisher snapshot: %#v", original)
	}
	broker.Stop()
}

func TestPublishStatusSendsEveryConnectedServer(t *testing.T) {
	station, err := NewCrackstation("worker", t.TempDir(), newScriptHashcat(t, "exit 0"))
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan *clientpb.Event, 2)
	for index := 0; index < 2; index++ {
		mock := &mockSliverRPC{CrackstationTriggerFunc: func(_ context.Context, event *clientpb.Event) (*commonpb.Empty, error) {
			received <- proto.Clone(event).(*clientpb.Event)
			return &commonpb.Empty{}, nil
		}}
		server := station.AddServer(&operatorconfig.ClientConfig{Token: string(rune('a' + index))})
		server.rpc = newBufConnClient(t, mock)
		server.State = CONNECTED
	}
	station.publishStatus()
	for range 2 {
		select {
		case event := <-received:
			if event.GetEventType() != crackStatusEvent {
				t.Fatalf("event type = %q", event.GetEventType())
			}
			status := &clientpb.CrackstationStatus{}
			if err := proto.Unmarshal(event.GetData(), status); err != nil {
				t.Fatal(err)
			}
			if status.GetName() != "worker" || status.GetHostUUID() != HostUUID {
				t.Fatalf("status = %#v", status)
			}
		case <-time.After(time.Second):
			t.Fatal("connected server did not receive status")
		}
	}
}

func TestServerConnectionSnapshotsAreRaceSafe(t *testing.T) {
	rpc := newBufConnClient(t, &mockSliverRPC{})
	server := &SliverServer{}
	done := make(chan struct{})
	server.setConnectionDone(done)
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			for iteration := 0; iteration < 500; iteration++ {
				if index%2 == 0 {
					server.setConnectionState([]string{CONNECTED, CONNECTING, DISCONNECTED}[iteration%3])
					server.setConnectionDone(done)
				} else {
					_ = server.ConnectionState()
					_ = server.rpcClient()
					_ = server.connectionDoneSnapshot()
				}
			}
		}(worker)
	}
	server.setConnection(CONNECTED, rpc, nil)
	workers.Wait()
	if server.rpcClient() == nil {
		t.Fatal("connection snapshot lost the RPC client")
	}
}

func TestAfterRegistrationSyncsButOnlyUploadsForcedBenchmark(t *testing.T) {
	station, err := NewCrackstation("worker", t.TempDir(), newScriptHashcat(t, "exit 0"))
	if err != nil {
		t.Fatal(err)
	}
	benchmarkData, _ := json.Marshal(map[int32]uint64{1000: 99})
	if err := os.WriteFile(filepath.Join(station.dataDir, "benchmark.json"), benchmarkData, 0600); err != nil {
		t.Fatal(err)
	}
	var lists atomic.Int32
	var benchmarks atomic.Int32
	mock := &mockSliverRPC{
		CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
			lists.Add(1)
			return &clientpb.CrackFiles{}, nil
		},
		CrackstationBenchmarkFunc: func(context.Context, *clientpb.CrackBenchmark) (*commonpb.Empty, error) {
			if benchmarks.Add(1) == 1 {
				return nil, status.Error(codes.FailedPrecondition, "registration not ready")
			}
			return &commonpb.Empty{}, nil
		},
	}
	server := &SliverServer{Crackstation: station, rpc: newBufConnClient(t, mock)}
	go station.Start()
	t.Cleanup(station.Stop)
	server.afterRegistration()
	waitForCount(t, &lists, 1)
	waitForSyncRequest(t, station, server)
	if benchmarks.Load() != 0 {
		t.Fatal("normal registration uploaded a benchmark before server request")
	}
	station.SetUploadBenchmarkOnConnect(true)
	server.afterRegistration()
	waitForCount(t, &lists, 2)
	waitForSyncRequest(t, station, server)
	waitForCount(t, &benchmarks, 2)
	if benchmarks.Load() != 2 {
		t.Fatalf("forced registration benchmark attempts = %d; want one readiness retry", benchmarks.Load())
	}
	server.afterRegistration()
	waitForCount(t, &lists, 3)
	if benchmarks.Load() != 2 {
		t.Fatalf("forced benchmark uploaded more than once: %d", benchmarks.Load())
	}
}

func waitForSyncRequest(t *testing.T, station *Crackstation, server *SliverServer) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		station.syncPendingLock.Lock()
		_, pending := station.syncPending[server]
		station.syncPendingLock.Unlock()
		if !pending {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("sync request remained pending")
}

func waitForCount(t *testing.T, value *atomic.Int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if value.Load() >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("counter = %d; want at least %d", value.Load(), want)
}

func TestTaskEventsPreserveArrivalOrder(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "order")
	h := newScriptHashcat(t, `
mode=crack
outfile=''
for arg in "$@"; do
  case "$arg" in
    --keyspace) mode=keyspace ;;
    --outfile=*) outfile=${arg#--outfile=} ;;
  esac
done
printf '%s\n' "$mode" >> '`+logPath+`'
if [ "$mode" = keyspace ]; then
  sleep 0.2
  printf '100\n'
else
  : > "$outfile"
fi
`)
	keyspaceTask, _ := leasedTask(t, &clientpb.CrackCommand{AttackMode: clientpb.CrackAttackMode_BRUTEFORCE, Identify: "?d"}, crackTaskKindKeyspace, 0, 0)
	crackTask, _ := leasedTask(t, &clientpb.CrackCommand{AttackMode: clientpb.CrackAttackMode_BRUTEFORCE, Identify: "?d"}, crackTaskKindCrack, 0, 1)
	tasks := map[string]*clientpb.CrackTask{keyspaceTask.GetID(): keyspaceTask, crackTask.GetID(): crackTask}
	completed := make(chan struct{}, 2)
	mock := &mockSliverRPC{
		CrackTaskByIDFunc: func(_ context.Context, request *clientpb.CrackTask) (*clientpb.CrackTask, error) {
			return proto.Clone(tasks[request.GetID()]).(*clientpb.CrackTask), nil
		},
		CrackTaskUpdateFunc: func(_ context.Context, update *clientpb.CrackTask) (*commonpb.Empty, error) {
			if update.GetCompletedAt() != 0 {
				select {
				case completed <- struct{}{}:
				default:
				}
			}
			return &commonpb.Empty{}, nil
		},
		CrackstationTriggerFunc: func(context.Context, *clientpb.Event) (*commonpb.Empty, error) {
			return &commonpb.Empty{}, nil
		},
		CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
			return &clientpb.CrackFiles{}, nil
		},
	}
	station, err := NewCrackstation("worker", t.TempDir(), h)
	if err != nil {
		t.Fatal(err)
	}
	server := &SliverServer{Crackstation: station, rpc: newBufConnClient(t, mock)}
	go station.Start()
	t.Cleanup(station.Stop)
	station.Events <- &ServerEvent{Server: server, Event: &clientpb.Event{EventType: crackKeyspaceEvent, Data: assignmentData(t, keyspaceTask)}}
	station.Events <- &ServerEvent{Server: server, Event: &clientpb.Event{EventType: crackEvent, Data: assignmentData(t, crackTask)}}
	for range 2 {
		select {
		case <-completed:
		case <-time.After(3 * time.Second):
			t.Fatal("serialized task did not complete")
		}
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Fields(string(data)); len(got) != 2 || got[0] != "keyspace" || got[1] != "crack" {
		t.Fatalf("hashcat execution order = %q", got)
	}
}

func TestCrackFileUpdatedEventRequestsSync(t *testing.T) {
	station, err := NewCrackstation("worker", t.TempDir(), newScriptHashcat(t, "exit 0"))
	if err != nil {
		t.Fatal(err)
	}
	var lists atomic.Int32
	mock := &mockSliverRPC{CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
		lists.Add(1)
		return &clientpb.CrackFiles{}, nil
	}}
	server := &SliverServer{Crackstation: station, rpc: newBufConnClient(t, mock)}
	go station.Start()
	t.Cleanup(station.Stop)
	station.Events <- &ServerEvent{Server: server, Event: &clientpb.Event{EventType: crackFileUpdateEvent}}
	waitForCount(t, &lists, 1)
}

func TestSyncRequestDuringInflightSyncQueuesOneRerun(t *testing.T) {
	station, err := NewCrackstation("worker", t.TempDir(), newScriptHashcat(t, "exit 0"))
	if err != nil {
		t.Fatal(err)
	}
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var lists atomic.Int32
	mock := &mockSliverRPC{CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
		if lists.Add(1) == 1 {
			close(firstStarted)
			<-releaseFirst
		}
		return &clientpb.CrackFiles{}, nil
	}}
	server := &SliverServer{Crackstation: station, rpc: newBufConnClient(t, mock)}
	go station.Start()
	t.Cleanup(station.Stop)
	station.requestSync(server)
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("initial sync did not begin")
	}
	for range 20 {
		station.requestSync(server)
	}
	close(releaseFirst)
	waitForCount(t, &lists, 2)
	waitForSyncRequest(t, station, server)
	time.Sleep(50 * time.Millisecond)
	if lists.Load() != 2 {
		t.Fatalf("manifest fetches = %d; want one in-flight sync and one dirty rerun", lists.Load())
	}
}

func TestInitialSyncRetriesTransientFailureWithoutAnotherEvent(t *testing.T) {
	station, err := NewCrackstation("worker", t.TempDir(), newScriptHashcat(t, "exit 0"))
	if err != nil {
		t.Fatal(err)
	}
	station.syncRetryBaseDelay = 5 * time.Millisecond
	station.syncRetryMaxDelay = 10 * time.Millisecond
	var lists atomic.Int32
	synchronized := make(chan struct{})
	var synchronizedOnce sync.Once
	mock := &mockSliverRPC{CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
		if lists.Add(1) == 1 {
			return nil, status.Error(codes.Unavailable, "transient manifest outage")
		}
		synchronizedOnce.Do(func() { close(synchronized) })
		return &clientpb.CrackFiles{}, nil
	}}
	server := &SliverServer{Crackstation: station, rpc: newBufConnClient(t, mock)}
	generation := make(chan struct{})
	server.setConnectionDone(generation)
	server.setConnectionState(CONNECTED)
	go station.syncEventWorker()
	t.Cleanup(station.Stop)

	station.requestSync(server)
	select {
	case <-synchronized:
	case <-time.After(time.Second):
		t.Fatalf("initial sync was not retried after a transient failure; list calls = %d", lists.Load())
	}
	waitForSyncRequest(t, station, server)
	if got := lists.Load(); got != 2 {
		t.Fatalf("manifest fetches = %d; want one failed attempt and one automatic retry", got)
	}
}

func TestInitialSyncRetryStopsWithConnectionGeneration(t *testing.T) {
	station, err := NewCrackstation("worker", t.TempDir(), newScriptHashcat(t, "exit 0"))
	if err != nil {
		t.Fatal(err)
	}
	station.syncRetryBaseDelay = 100 * time.Millisecond
	station.syncRetryMaxDelay = 100 * time.Millisecond
	firstAttempt := make(chan struct{})
	var firstAttemptOnce sync.Once
	var lists atomic.Int32
	mock := &mockSliverRPC{CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
		lists.Add(1)
		firstAttemptOnce.Do(func() { close(firstAttempt) })
		return nil, status.Error(codes.Unavailable, "connection lost")
	}}
	server := &SliverServer{Crackstation: station, rpc: newBufConnClient(t, mock)}
	generation := make(chan struct{})
	server.setConnectionDone(generation)
	server.setConnectionState(CONNECTED)
	go station.syncEventWorker()
	t.Cleanup(station.Stop)

	station.requestSync(server)
	select {
	case <-firstAttempt:
	case <-time.After(time.Second):
		t.Fatal("initial sync did not run")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		station.syncPendingLock.Lock()
		waiting := station.syncPending[server] == syncRequestRetryWaiting
		station.syncPendingLock.Unlock()
		if waiting {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(generation)
	server.setConnectionState(DISCONNECTED)
	waitForSyncRequest(t, station, server)
	time.Sleep(150 * time.Millisecond)
	if got := lists.Load(); got != 1 {
		t.Fatalf("manifest fetches after disconnect = %d; want retry canceled with old connection", got)
	}
}

func TestInitialSyncRetryWaitsForReadyInSameConnectionGeneration(t *testing.T) {
	station, err := NewCrackstation("worker", t.TempDir(), newScriptHashcat(t, "exit 0"))
	if err != nil {
		t.Fatal(err)
	}
	station.syncRetryBaseDelay = 5 * time.Millisecond
	station.syncRetryMaxDelay = 10 * time.Millisecond
	var lists atomic.Int32
	synchronized := make(chan struct{})
	var synchronizedOnce sync.Once
	mock := &mockSliverRPC{CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
		if lists.Add(1) == 1 {
			return nil, status.Error(codes.Unavailable, "transport temporarily connecting")
		}
		synchronizedOnce.Do(func() { close(synchronized) })
		return &clientpb.CrackFiles{}, nil
	}}
	server := &SliverServer{Crackstation: station, rpc: newBufConnClient(t, mock)}
	generation := make(chan struct{})
	server.setConnectionDone(generation)
	server.setConnectionState(CONNECTING)
	go station.syncEventWorker()
	t.Cleanup(station.Stop)

	station.requestSync(server)
	waitForCount(t, &lists, 1)
	time.Sleep(25 * time.Millisecond)
	if got := lists.Load(); got != 1 {
		t.Fatalf("manifest fetches while connecting = %d; retry should wait for Ready", got)
	}
	server.setConnectionState(CONNECTED)
	select {
	case <-synchronized:
	case <-time.After(time.Second):
		t.Fatalf("sync did not resume when connection became Ready; list calls = %d", lists.Load())
	}
	waitForSyncRequest(t, station, server)
}

func TestDirtySyncRerunDoesNotDeadlockSaturatedQueue(t *testing.T) {
	station, err := NewCrackstation("worker", t.TempDir(), newScriptHashcat(t, "exit 0"))
	if err != nil {
		t.Fatal(err)
	}
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	var activeLists atomic.Int32
	activeMock := &mockSliverRPC{CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
		if activeLists.Add(1) == 1 {
			close(firstStarted)
			<-releaseFirst
		}
		return &clientpb.CrackFiles{}, nil
	}}
	var queuedLists atomic.Int32
	queuedMock := &mockSliverRPC{CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
		queuedLists.Add(1)
		return &clientpb.CrackFiles{}, nil
	}}
	activeServer := &SliverServer{Crackstation: station, rpc: newBufConnClient(t, activeMock)}
	queuedRPC := newBufConnClient(t, queuedMock)
	go station.syncEventWorker()
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseFirst) })
		station.Stop()
	})

	station.requestSync(activeServer)
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("initial synchronization did not begin")
	}
	station.requestSync(activeServer)
	for range cap(station.syncEvents) {
		station.requestSync(&SliverServer{Crackstation: station, rpc: queuedRPC})
	}
	if got := len(station.syncEvents); got != cap(station.syncEvents) {
		t.Fatalf("sync queue length = %d, want saturated capacity %d", got, cap(station.syncEvents))
	}

	releaseOnce.Do(func() { close(releaseFirst) })
	waitForCount(t, &queuedLists, 1)
	waitForCount(t, &activeLists, 2)
}

func TestInitialSyncRequestsSurviveSaturatedQueue(t *testing.T) {
	station, err := NewCrackstation("worker", t.TempDir(), newScriptHashcat(t, "exit 0"))
	if err != nil {
		t.Fatal(err)
	}
	activeStarted := make(chan struct{})
	releaseActive := make(chan struct{})
	var releaseOnce sync.Once
	activeMock := &mockSliverRPC{CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
		close(activeStarted)
		<-releaseActive
		return &clientpb.CrackFiles{}, nil
	}}
	requestCount := cap(station.syncEvents) + 1
	allProcessed := make(chan struct{})
	var processedOnce sync.Once
	var queuedLists atomic.Int32
	queuedMock := &mockSliverRPC{CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
		if queuedLists.Add(1) == int32(requestCount) {
			processedOnce.Do(func() { close(allProcessed) })
		}
		return &clientpb.CrackFiles{}, nil
	}}
	activeServer := &SliverServer{Crackstation: station, rpc: newBufConnClient(t, activeMock)}
	queuedRPC := newBufConnClient(t, queuedMock)
	go station.syncEventWorker()
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseActive) })
		station.Stop()
	})

	station.requestSync(activeServer)
	select {
	case <-activeStarted:
	case <-time.After(time.Second):
		t.Fatal("active synchronization did not begin")
	}
	enqueued := make(chan struct{})
	go func() {
		for range requestCount {
			station.requestSync(&SliverServer{Crackstation: station, rpc: queuedRPC})
		}
		close(enqueued)
	}()
	deadline := time.Now().Add(time.Second)
	for len(station.syncEvents) != cap(station.syncEvents) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := len(station.syncEvents); got != cap(station.syncEvents) {
		t.Fatalf("sync queue length = %d, want saturated capacity %d", got, cap(station.syncEvents))
	}

	releaseOnce.Do(func() { close(releaseActive) })
	select {
	case <-enqueued:
	case <-time.After(time.Second):
		t.Fatal("overflowing initial sync request did not enqueue after capacity became available")
	}
	select {
	case <-allProcessed:
	case <-time.After(3 * time.Second):
		t.Fatalf("processed initial sync requests = %d, want %d", queuedLists.Load(), requestCount)
	}
}

func TestEventsWaitsForRegistrationHeader(t *testing.T) {
	station, err := NewCrackstation("worker", t.TempDir(), newScriptHashcat(t, "exit 0"))
	if err != nil {
		t.Fatal(err)
	}
	benchmarkData, _ := json.Marshal(map[int32]uint64{1000: 99})
	if err := os.WriteFile(filepath.Join(station.dataDir, "benchmark.json"), benchmarkData, 0600); err != nil {
		t.Fatal(err)
	}
	registrationEntered := make(chan struct{})
	releaseRegistration := make(chan struct{})
	var ready atomic.Bool
	mock := &mockSliverRPC{
		CrackstationRegisterFunc: func(_ *clientpb.Crackstation, stream rpcpb.SliverRPC_CrackstationRegisterServer) error {
			close(registrationEntered)
			<-releaseRegistration
			ready.Store(true)
			if err := stream.SendHeader(metadata.MD{}); err != nil {
				return err
			}
			<-stream.Context().Done()
			return stream.Context().Err()
		},
		CrackstationBenchmarkFunc: func(context.Context, *clientpb.CrackBenchmark) (*commonpb.Empty, error) {
			if !ready.Load() {
				return nil, status.Error(codes.FailedPrecondition, "not registered")
			}
			return &commonpb.Empty{}, nil
		},
	}
	server := &SliverServer{
		Crackstation: station,
		Config:       &operatorconfig.ClientConfig{Operator: "operator"},
		rpc:          newBufConnClient(t, mock),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type eventsResult struct {
		events <-chan *clientpb.Event
		err    error
	}
	result := make(chan eventsResult, 1)
	go func() {
		events, eventsErr := server.Events(ctx)
		result <- eventsResult{events: events, err: eventsErr}
	}()
	select {
	case <-registrationEntered:
	case <-time.After(time.Second):
		t.Fatal("register handler was not entered")
	}
	select {
	case early := <-result:
		t.Fatalf("Events returned before registration readiness header: %v", early.err)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseRegistration)
	select {
	case registered := <-result:
		if registered.err != nil {
			t.Fatal(registered.err)
		}
		if registered.events == nil {
			t.Fatal("Events returned a nil event channel")
		}
	case <-time.After(time.Second):
		t.Fatal("Events did not return after readiness header")
	}
	if err := server.sendBenchmarkOnConnect(); err != nil {
		t.Fatalf("unary RPC raced registration: %v", err)
	}
}

func TestQueuedTaskUsesOriginalConnectionGeneration(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "executions")
	h := newScriptHashcat(t, `
mode=crack
outfile=''
for arg in "$@"; do
  case "$arg" in
    --keyspace) mode=keyspace ;;
    --outfile=*) outfile=${arg#--outfile=} ;;
  esac
done
printf '%s\n' "$mode" >> '`+logPath+`'
if [ "$mode" = keyspace ]; then printf '1\n'; else : > "$outfile"; fi
`)
	oldTask, _ := leasedTask(t, &clientpb.CrackCommand{AttackMode: clientpb.CrackAttackMode_BRUTEFORCE, Identify: "?d"}, crackTaskKindCrack, 0, 1)
	newTask, _ := leasedTask(t, &clientpb.CrackCommand{AttackMode: clientpb.CrackAttackMode_BRUTEFORCE, Identify: "?d"}, crackTaskKindKeyspace, 0, 0)
	tasks := map[string]*clientpb.CrackTask{oldTask.GetID(): oldTask, newTask.GetID(): newTask}
	var fetches atomic.Int32
	completed := make(chan struct{}, 1)
	mock := &mockSliverRPC{
		CrackTaskByIDFunc: func(_ context.Context, request *clientpb.CrackTask) (*clientpb.CrackTask, error) {
			fetches.Add(1)
			return proto.Clone(tasks[request.GetID()]).(*clientpb.CrackTask), nil
		},
		CrackTaskUpdateFunc: func(_ context.Context, update *clientpb.CrackTask) (*commonpb.Empty, error) {
			if update.GetID() == newTask.GetID() && update.GetCompletedAt() != 0 {
				select {
				case completed <- struct{}{}:
				default:
				}
			}
			return &commonpb.Empty{}, nil
		},
		CrackstationTriggerFunc: func(context.Context, *clientpb.Event) (*commonpb.Empty, error) {
			return &commonpb.Empty{}, nil
		},
		CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
			return &clientpb.CrackFiles{}, nil
		},
	}
	station, err := NewCrackstation("worker", t.TempDir(), h)
	if err != nil {
		t.Fatal(err)
	}
	server := &SliverServer{Crackstation: station, rpc: newBufConnClient(t, mock)}
	oldConnectionDone := make(chan struct{})
	close(oldConnectionDone)
	newConnectionDone := make(chan struct{})
	server.setConnectionDone(newConnectionDone)
	go station.Start()
	t.Cleanup(station.Stop)
	station.Events <- &ServerEvent{
		Server: server, Event: &clientpb.Event{EventType: crackEvent, Data: assignmentData(t, oldTask)},
		ConnectionDone: oldConnectionDone,
	}
	station.Events <- &ServerEvent{
		Server: server, Event: &clientpb.Event{EventType: crackKeyspaceEvent, Data: assignmentData(t, newTask)},
		ConnectionDone: newConnectionDone,
	}
	select {
	case <-completed:
	case <-time.After(2 * time.Second):
		t.Fatal("new connection task did not complete")
	}
	if fetches.Load() != 1 {
		t.Fatalf("task fetches = %d; stale queued generation should not fetch or execute", fetches.Load())
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Fields(string(data)); len(got) != 1 || got[0] != "keyspace" {
		t.Fatalf("executions = %q; stale connection task ran after reconnect", got)
	}
}

func TestInflightFileSyncDoesNotBlockTaskHeartbeat(t *testing.T) {
	h := newScriptHashcat(t, `
outfile=''
for arg in "$@"; do case "$arg" in --outfile=*) outfile=${arg#--outfile=} ;; esac; done
: > "$outfile"
`)
	task, _ := leasedTask(t, &clientpb.CrackCommand{AttackMode: clientpb.CrackAttackMode_BRUTEFORCE, Identify: "?d"}, crackTaskKindCrack, 0, 1)
	firstSyncStarted := make(chan struct{})
	releaseFirstSync := make(chan struct{})
	heartbeat := make(chan struct{}, 1)
	completed := make(chan struct{}, 1)
	var lists atomic.Int32
	mock := &mockSliverRPC{
		CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
			if lists.Add(1) == 1 {
				close(firstSyncStarted)
				<-releaseFirstSync
			}
			return &clientpb.CrackFiles{}, nil
		},
		CrackTaskByIDFunc: func(context.Context, *clientpb.CrackTask) (*clientpb.CrackTask, error) {
			return proto.Clone(task).(*clientpb.CrackTask), nil
		},
		CrackTaskUpdateFunc: func(_ context.Context, update *clientpb.CrackTask) (*commonpb.Empty, error) {
			if update.GetCompletedAt() != 0 {
				select {
				case completed <- struct{}{}:
				default:
				}
			}
			return &commonpb.Empty{}, nil
		},
		CrackstationTriggerFunc: func(_ context.Context, event *clientpb.Event) (*commonpb.Empty, error) {
			if event.GetEventType() == crackTaskStatusEvent {
				select {
				case heartbeat <- struct{}{}:
				default:
				}
			}
			return &commonpb.Empty{}, nil
		},
	}
	station, err := NewCrackstation("worker", t.TempDir(), h)
	if err != nil {
		t.Fatal(err)
	}
	server := &SliverServer{Crackstation: station, rpc: newBufConnClient(t, mock)}
	go station.Start()
	t.Cleanup(station.Stop)
	station.Events <- &ServerEvent{Server: server, Event: &clientpb.Event{EventType: crackFileUpdateEvent}}
	select {
	case <-firstSyncStarted:
	case <-time.After(time.Second):
		t.Fatal("background sync did not begin")
	}
	station.Events <- &ServerEvent{Server: server, Event: &clientpb.Event{EventType: crackEvent, Data: assignmentData(t, task)}}
	select {
	case <-heartbeat:
		// The task is waiting for the verified cache, but its lease is alive.
	case <-time.After(time.Second):
		t.Fatal("blocked file sync also blocked the task heartbeat")
	}
	for range 10 {
		station.Events <- &ServerEvent{Server: server, Event: &clientpb.Event{EventType: crackFileUpdateEvent}}
	}
	close(releaseFirstSync)
	select {
	case <-completed:
	case <-time.After(2 * time.Second):
		t.Fatal("task did not complete after sync released")
	}
	waitForCount(t, &lists, 3)
}
