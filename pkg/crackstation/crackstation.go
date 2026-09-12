package crackstation

/*
	Sliver Implant Framework
	Copyright (C) 2022  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/sliverarmory/sliver-crackstation/assets"
	"github.com/sliverarmory/sliver-crackstation/pkg/hashcat"
	"github.com/sliverarmory/sliver-crackstation/pkg/hostuuid"
	"github.com/sliverarmory/sliver-crackstation/pkg/operatorconfig"
	"github.com/sliverarmory/sliver-crackstation/pkg/protocompat"
	"github.com/sliverarmory/sliver-crackstation/pkg/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/protobuf/proto"
)

var HostUUID string

// crackKeyspaceEvent is emitted by the server when it wants the crackstation to
// calculate hashcat's `--keyspace` for a given CrackTask's CrackCommand.
//
// Note: This constant lives here (vs. upstream sliver constants) because the
// server-side API is still evolving.
const crackKeyspaceEvent = "crack-keyspace"

const (
	crackEvent                        = "crack"
	crackBenchmarkEvent               = "crack-benchmark"
	crackQueryEvent                   = "crack-query"
	crackFileUpdateEvent              = "crack-file-updated"
	crackStatusEvent                  = "crack-status"
	crackTaskStatusEvent              = "crack-task-status"
	eventQueueSize                    = 64
	benchmarkMaxAttempts              = 3
	benchmarkRetryDelay               = 250 * time.Millisecond
	benchmarkSchemaVersion            = uint32(1)
	defaultSyncRetryBaseDelay         = 250 * time.Millisecond
	defaultSyncRetryMaxDelay          = 30 * time.Second
	crackBenchmarkSchemaVersionField  = 4
	crackBenchmarkHashcatVersionField = 5
	crackstationCapabilitiesField     = 104
	crackQueryCapability              = "crack-query-v1"
)

type syncRequestState uint8

const (
	syncRequestQueued syncRequestState = iota + 1
	syncRequestDirty
	syncRequestRetryWaiting
)

func init() {
	HostUUID = hostuuid.GetUUID()
}

func NewCrackstation(name string, dataDir string, hashcatInstance *hashcat.Hashcat) (*Crackstation, error) {
	if hashcatInstance == nil {
		return nil, errors.New("missing hashcat instance")
	}
	crackstation := &Crackstation{
		Name:                name,
		StatusBroker:        newBroker(),
		Servers:             &sync.Map{},
		hashcat:             hashcatInstance,
		dataDir:             dataDir,
		crackLock:           &sync.Mutex{},
		syncLock:            &sync.Mutex{},
		Events:              make(chan *ServerEvent, eventQueueSize),
		done:                make(chan struct{}),
		taskEvents:          make(chan *ServerEvent, eventQueueSize),
		syncEvents:          make(chan *SliverServer, eventQueueSize),
		syncPending:         make(map[*SliverServer]syncRequestState),
		syncRetries:         make(map[*SliverServer]uint),
		syncRetryGeneration: make(map[*SliverServer]<-chan struct{}),
		inventories:         make(map[*SliverServer]serverFileInventory),
		syncRetryBaseDelay:  defaultSyncRetryBaseDelay,
		syncRetryMaxDelay:   defaultSyncRetryMaxDelay,
	}
	if err := crackstation.CleanupStaleTaskMaterializations(assets.GetAppTmpDir()); err != nil {
		return nil, fmt.Errorf("clean stale crack task files: %w", err)
	}
	hashcatInstance.SetFileResolver(crackstation.ResolveCrackFile)
	return crackstation, nil
}

// ServerEvent - Correlate Events & Sliver Servers
type ServerEvent struct {
	Server         *SliverServer
	Event          *clientpb.Event
	ConnectionDone <-chan struct{}
}

// Crackstation - This represents the Crackstation, there should only be one of these
// per machine. It manages locks around the hardware so we don't execute multiple
// hashcat jobs on a single machine at the same time. It can accept tasks for n number
// of sliver servers
type Crackstation struct {
	Name         string
	StatusBroker *eventBroker
	Servers      *sync.Map

	// servers []chan *ServerEvent
	Events              chan *ServerEvent
	taskEvents          chan *ServerEvent
	syncEvents          chan *SliverServer
	syncPendingLock     sync.Mutex
	syncPending         map[*SliverServer]syncRequestState
	syncRetries         map[*SliverServer]uint
	syncRetryGeneration map[*SliverServer]<-chan struct{}
	syncRetryBaseDelay  time.Duration
	syncRetryMaxDelay   time.Duration
	inventoryLock       sync.RWMutex
	inventories         map[*SliverServer]serverFileInventory
	done                chan struct{}

	hashcat *hashcat.Hashcat
	dataDir string

	currentCrackJobID string
	crackLock         *sync.Mutex
	activityLock      sync.RWMutex
	isCracking        bool
	activity          *ActivitySnapshot

	SyncStatus     *clientpb.CrackSyncStatus
	syncStart      time.Time
	syncBytes      int
	syncLock       *sync.Mutex
	syncGateOnce   sync.Once
	syncGate       chan struct{}
	syncStatusLock sync.RWMutex
	syncing        bool

	stopOnce                 sync.Once
	uploadBenchmarkOnConnect bool
}

// HIPBackendInfo returns a snapshot of the locally detected HIP devices. HIP
// is encoded into the wire-compatible Crackstation protobuf by ToProtobuf.
func (c *Crackstation) HIPBackendInfo() []*hashcat.HIPBackendInfo {
	return append([]*hashcat.HIPBackendInfo(nil), c.hashcat.HIPBackend...)
}

func (c *Crackstation) hashcatVersion() string {
	if c == nil || c.hashcat == nil {
		return "unknown"
	}
	version := strings.TrimSpace(c.hashcat.Version())
	if version == "" {
		return "unknown"
	}
	return version
}

// RoundRobinConnect - Round robin the crackstation across all servers
func (c *Crackstation) roundRobinConnect(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			now := time.Now()
			c.Servers.Range(func(_, value interface{}) bool {
				server := value.(*SliverServer)
				server.refreshState(now)
				if server.ConnectionState() == DISCONNECTED && server.readyToDial(now) {
					go server.Connect()
				}
				return true
			})
		}
	}
}

func (c *Crackstation) ToProtobuf() *clientpb.Crackstation {
	station := &clientpb.Crackstation{
		Name:           c.Name,
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		HashcatVersion: c.hashcatVersion(),
		CUDA:           c.hashcat.CUDABackend,
		Metal:          c.hashcat.MetalBackend,
		OpenCL:         c.hashcat.OpenCLBackend,
		HostUUID:       HostUUID,
	}
	if err := protocompat.SetMessageBytesList(station, 103, c.hashcat.HIPBackendWire()); err != nil {
		slog.Error("Failed to encode HIP backend information", "err", err)
	}
	if err := addCrackstationCapability(station, crackQueryCapability); err != nil {
		slog.Error("Failed to encode crackstation capability", "capability", crackQueryCapability, "err", err)
	}
	return station
}

func addCrackstationCapability(station *clientpb.Crackstation, capability string) error {
	reader, err := protocompat.NewReader(station)
	if err != nil {
		return err
	}
	capabilities, err := reader.Strings(crackstationCapabilitiesField)
	if err != nil {
		return err
	}
	deduplicated := make([]string, 0, len(capabilities)+1)
	seen := make(map[string]struct{}, len(capabilities)+1)
	for _, existing := range append(capabilities, capability) {
		if existing == "" {
			continue
		}
		if _, duplicate := seen[existing]; duplicate {
			continue
		}
		seen[existing] = struct{}{}
		deduplicated = append(deduplicated, existing)
	}
	return protocompat.SetStrings(station, crackstationCapabilitiesField, deduplicated)
}

func (c *Crackstation) Status() *clientpb.CrackstationStatus {
	status := &clientpb.CrackstationStatus{
		Name:     c.Name,
		HostUUID: HostUUID,
	}

	c.activityLock.RLock()
	if c.isCracking {
		status.State = clientpb.States_CRACKING
		status.CurrentCrackJobID = c.currentCrackJobID
	} else {
		status.State = clientpb.States_IDLE
		status.CurrentCrackJobID = ""
	}
	c.activityLock.RUnlock()

	status.IsSyncing, status.Syncing = c.syncSnapshot()

	return status
}

func (c *Crackstation) publishStatus() {
	status := c.Status()
	c.StatusBroker.Publish(status)
	c.Servers.Range(func(_, value interface{}) bool {
		server, ok := value.(*SliverServer)
		if !ok || server.ConnectionState() != CONNECTED {
			return true
		}
		server.sendStatus(proto.Clone(status).(*clientpb.CrackstationStatus))
		return true
	})
}

func (s *SliverServer) sendStatus(status *clientpb.CrackstationStatus) {
	if s == nil {
		return
	}
	rpc := s.rpcClient()
	if rpc == nil || s.statusSendLock == nil || !s.statusSendLock.TryLock() {
		return
	}
	go func() {
		defer s.statusSendLock.Unlock()
		data, err := proto.Marshal(status)
		if err != nil {
			slog.Error("Failed to marshal crackstation status", "err", err)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := rpc.CrackstationTrigger(ctx, &clientpb.Event{EventType: crackStatusEvent, Data: data}); err != nil {
			slog.Debug("Failed to send crackstation status", "err", err)
		}
	}()
}

// Start - Main entrypoint for the crackstation, if this function returns the
// entire program should exit
func (c *Crackstation) Start() {
	go c.roundRobinConnect(1 * time.Second)
	go c.taskEventWorker()
	go c.syncEventWorker()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {

		// Handle events from the server(s)
		case serverEvent := <-c.Events:
			if serverEvent != nil && serverEvent.Server != nil && serverEvent.Event != nil {
				if serverEvent.Event.GetEventType() == crackFileUpdateEvent {
					c.requestSync(serverEvent.Server)
				} else {
					select {
					case c.taskEvents <- serverEvent:
					case <-c.done:
						return
					}
				}
			}

		// Publish status on 1 second interval
		case <-ticker.C:
			c.publishStatus()

		case <-c.done:
			return
		}
	}
}

func (c *Crackstation) requestSync(server *SliverServer) {
	if server == nil {
		return
	}
	enqueue := false
	c.syncPendingLock.Lock()
	if c.syncPending == nil {
		c.syncPending = make(map[*SliverServer]syncRequestState)
	}
	switch c.syncPending[server] {
	case syncRequestQueued, syncRequestDirty:
		c.syncPending[server] = syncRequestDirty
	case syncRequestRetryWaiting:
		// A new server event or registration supersedes the backoff timer.
		// Queue immediately and let the timer observe that it no longer owns
		// the pending state.
		c.syncPending[server] = syncRequestQueued
		delete(c.syncRetries, server)
		delete(c.syncRetryGeneration, server)
		enqueue = true
	default:
		c.syncPending[server] = syncRequestQueued
		enqueue = true
	}
	c.syncPendingLock.Unlock()
	if !enqueue {
		return
	}
	c.enqueueSync(server)
}

func (c *Crackstation) enqueueSync(server *SliverServer) {
	select {
	case c.syncEvents <- server:
	case <-c.done:
		c.syncPendingLock.Lock()
		delete(c.syncPending, server)
		delete(c.syncRetries, server)
		delete(c.syncRetryGeneration, server)
		c.syncPendingLock.Unlock()
	}
}

func (c *Crackstation) syncRetryDelay(attempt uint) time.Duration {
	base := c.syncRetryBaseDelay
	if base <= 0 {
		base = defaultSyncRetryBaseDelay
	}
	maximum := c.syncRetryMaxDelay
	if maximum <= 0 {
		maximum = defaultSyncRetryMaxDelay
	}
	if base >= maximum {
		return maximum
	}
	delay := base
	for current := uint(1); current < attempt && delay < maximum; current++ {
		if delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}

func (c *Crackstation) waitForSyncRetry(server *SliverServer, generation <-chan struct{}, attempt uint) {
	timer := time.NewTimer(c.syncRetryDelay(attempt))
	defer timer.Stop()
	select {
	case <-timer.C:
		state, currentGeneration := server.connectionGenerationSnapshot()
		if currentGeneration == nil || currentGeneration != generation {
			c.clearSyncRetry(server, generation)
			return
		}
		select {
		case <-currentGeneration:
			c.clearSyncRetry(server, generation)
			return
		default:
		}
		if state != CONNECTED {
			c.syncPendingLock.Lock()
			if c.syncPending[server] != syncRequestRetryWaiting || c.syncRetryGeneration[server] != generation {
				c.syncPendingLock.Unlock()
				return
			}
			attempt++
			c.syncRetries[server] = attempt
			c.syncPendingLock.Unlock()
			go c.waitForSyncRetry(server, generation, attempt)
			return
		}
		c.syncPendingLock.Lock()
		if c.syncPending[server] != syncRequestRetryWaiting || c.syncRetryGeneration[server] != generation {
			c.syncPendingLock.Unlock()
			return
		}
		c.syncPending[server] = syncRequestQueued
		delete(c.syncRetryGeneration, server)
		c.syncPendingLock.Unlock()
		c.enqueueSync(server)
	case <-generation:
		c.clearSyncRetry(server, generation)
	case <-c.done:
		c.clearSyncRetry(server, generation)
	}
}

func (c *Crackstation) clearSyncRetry(server *SliverServer, generation <-chan struct{}) {
	c.syncPendingLock.Lock()
	defer c.syncPendingLock.Unlock()
	if c.syncPending[server] != syncRequestRetryWaiting || c.syncRetryGeneration[server] != generation {
		return
	}
	delete(c.syncPending, server)
	delete(c.syncRetries, server)
	delete(c.syncRetryGeneration, server)
}

func (c *Crackstation) syncEventWorker() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-c.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	reruns := make([]*SliverServer, 0, 1)
	preferRerun := false
	for {
		if ctx.Err() != nil {
			return
		}
		var server *SliverServer
		if len(reruns) != 0 && preferRerun {
			server = reruns[0]
			reruns = reruns[1:]
			preferRerun = false
		} else if len(reruns) != 0 {
			select {
			case server = <-c.syncEvents:
				preferRerun = true
			case <-c.done:
				return
			default:
				server = reruns[0]
				reruns = reruns[1:]
				preferRerun = false
			}
		} else {
			select {
			case server = <-c.syncEvents:
			case <-c.done:
				return
			}
		}
		syncErr := c.SyncFilesContext(ctx, server)
		if syncErr != nil && ctx.Err() == nil {
			slog.Error("Failed to synchronize crack files", "err", syncErr)
		}
		var retryGeneration <-chan struct{}
		var retryAttempt uint
		c.syncPendingLock.Lock()
		state := c.syncPending[server]
		if state == syncRequestDirty {
			c.syncPending[server] = syncRequestQueued
			delete(c.syncRetryGeneration, server)
			if syncErr == nil {
				delete(c.syncRetries, server)
			} else {
				if c.syncRetries == nil {
					c.syncRetries = make(map[*SliverServer]uint)
				}
				c.syncRetries[server]++
			}
		} else if syncErr != nil && ctx.Err() == nil {
			_, generation := server.connectionGenerationSnapshot()
			if generation != nil {
				select {
				case <-generation:
					delete(c.syncPending, server)
					delete(c.syncRetries, server)
					delete(c.syncRetryGeneration, server)
				default:
					if c.syncRetries == nil {
						c.syncRetries = make(map[*SliverServer]uint)
					}
					if c.syncRetryGeneration == nil {
						c.syncRetryGeneration = make(map[*SliverServer]<-chan struct{})
					}
					c.syncRetries[server]++
					retryAttempt = c.syncRetries[server]
					retryGeneration = generation
					c.syncRetryGeneration[server] = generation
					c.syncPending[server] = syncRequestRetryWaiting
				}
			} else {
				delete(c.syncPending, server)
				delete(c.syncRetries, server)
				delete(c.syncRetryGeneration, server)
			}
		} else {
			delete(c.syncPending, server)
			delete(c.syncRetries, server)
			delete(c.syncRetryGeneration, server)
		}
		c.syncPendingLock.Unlock()
		if state == syncRequestDirty {
			reruns = append(reruns, server)
		} else if retryGeneration != nil {
			go c.waitForSyncRetry(server, retryGeneration, retryAttempt)
		}
	}
}

func (c *Crackstation) taskEventWorker() {
	for {
		select {
		case serverEvent := <-c.taskEvents:
			if serverEvent != nil && serverEvent.Server != nil && serverEvent.Event != nil {
				c.handleEventForConnection(serverEvent.Server, serverEvent.Event, serverEvent.ConnectionDone)
			}
		case <-c.done:
			return
		}
	}
}

func (c *Crackstation) Stop() {
	c.stopOnce.Do(func() {
		close(c.done)
		if c.Servers != nil {
			c.Servers.Range(func(_, value interface{}) bool {
				server, ok := value.(*SliverServer)
				if ok {
					if err := server.Close(); err != nil {
						slog.Debug("Failed to close Sliver server connection during shutdown", "err", err)
					}
				}
				return true
			})
		}
		// Every crack, keyspace, and benchmark execution owns crackLock for its
		// full lifetime. Closing done cancels its CommandContext; this barrier
		// guarantees the child has been killed and reaped before Stop returns
		// and the process hosting the crackstation can exit.
		if c.crackLock != nil {
			c.crackLock.Lock()
			c.crackLock.Unlock()
		}
		if c.syncLock != nil {
			c.syncLock.Lock()
			c.syncLock.Unlock()
		}
		if c.StatusBroker != nil {
			c.StatusBroker.Stop()
		}
	})
}

func (c *Crackstation) isActive() bool {
	c.activityLock.RLock()
	defer c.activityLock.RUnlock()
	return c.isCracking
}

// SetUploadBenchmarkOnConnect requests upload of a locally forced benchmark
// after registration. Normal connects wait for the server's benchmark event.
func (c *Crackstation) SetUploadBenchmarkOnConnect(enabled bool) {
	c.uploadBenchmarkOnConnect = enabled
}

// Benchmark - Execute hashcat benchmark and save results to disk
func (c *Crackstation) Benchmark() error {
	return c.benchmarkContext(context.Background())
}

func (c *Crackstation) benchmarkContext(ctx context.Context) error {
	benchmarkResults, err := c.hashcat.BenchmarkContextStreaming(ctx, &clientpb.CrackCommand{
		AttackMode:     clientpb.CrackAttackMode_NO_ATTACK,
		HashType:       clientpb.HashType_INVALID,
		Benchmark:      true,
		BenchmarkAll:   true,
		LogfileDisable: true,
	}, c.observeBenchmarkProgress)
	if err != nil {
		slog.Error("Error running benchmark", "err", err)
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	err = c.saveBenchmarkResults(benchmarkResults)
	if err != nil {
		slog.Error("Failed to save benchmark results", "err", err)
		return err
	}
	return nil
}

func (c *Crackstation) saveBenchmarkResults(benchmarkResults map[int32]uint64) error {
	benchmarkData, err := json.Marshal(benchmarkResults)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.dataDir, 0700); err != nil {
		return err
	}
	err = os.WriteFile(filepath.Join(c.dataDir, "benchmark.json"), benchmarkData, 0600)
	if err != nil {
		return err
	}
	return nil
}

func (c *Crackstation) EnsureBenchmark(force bool) error {
	if !force {
		if _, err := c.LoadBenchmarkResults(); err == nil {
			return nil
		}
	}
	return c.Benchmark()
}

// LoadBenchmarkResults - Load benchmark results from disk
func (c *Crackstation) LoadBenchmarkResults() (map[int32]uint64, error) {
	if _, err := os.Stat(filepath.Join(c.dataDir, "benchmark.json")); os.IsNotExist(err) {
		return nil, errors.New("benchmark.json does not exist")
	}
	data, err := os.ReadFile(filepath.Join(c.dataDir, "benchmark.json"))
	if err != nil {
		return nil, err
	}
	results := map[int32]uint64{}
	err = json.Unmarshal(data, &results)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, errors.New("benchmark.json contains no benchmark results")
	}
	return results, nil
}

func (c *Crackstation) handleEvent(server *SliverServer, event *clientpb.Event) {
	var connectionDone <-chan struct{}
	if server != nil {
		connectionDone = server.connectionDoneSnapshot()
	}
	c.handleEventForConnection(server, event, connectionDone)
}

func (c *Crackstation) handleEventForConnection(server *SliverServer, event *clientpb.Event, connectionDone <-chan struct{}) {
	slog.Info("Crackstation event", "type", event.EventType)
	switch event.EventType {
	case crackEvent:
		c.runCrackTaskForConnection(server, event.Data, connectionDone)
	case crackBenchmarkEvent:
		c.runBenchmarkRequestForConnection(server, connectionDone)
	case crackKeyspaceEvent:
		c.runKeyspaceTaskForConnection(server, event.Data, connectionDone)
	case crackQueryEvent:
		c.runQueryTaskForConnection(server, event.Data, connectionDone)
	case crackFileUpdateEvent:
		c.requestSync(server)
	}
}

func parseHashcatKeyspace(stdout []byte) (string, error) {
	// Hashcat `--keyspace` is expected to write the keyspace as a decimal integer
	// to stdout.
	out := strings.TrimSpace(string(stdout))
	if out == "" {
		return "", errors.New("hashcat returned empty keyspace output")
	}

	// Be robust to extra newlines; use the last non-empty line.
	lines := strings.Split(out, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		value, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return "", fmt.Errorf("unexpected keyspace output %q: %w", fields[0], err)
		}
		return strconv.FormatUint(value, 10), nil
	}
	return "", errors.New("hashcat returned keyspace output without a value")
}

func (c *Crackstation) AddServer(config *operatorconfig.ClientConfig) *SliverServer {
	server, _ := c.Servers.LoadOrStore(config.Token, &SliverServer{
		Config:       config,
		State:        DISCONNECTED,
		Crackstation: c,

		connectLock:       &sync.Mutex{},
		reconnectInterval: defaultReconnectInterval,
		reconnectLock:     &sync.Mutex{},
		statusSendLock:    &sync.Mutex{},
	})
	return server.(*SliverServer)
}

const (
	DISCONNECTED = "DISCONNECTED"
	CONNECTED    = "CONNECTED"
	CONNECTING   = "CONNECTING"
)

const defaultReconnectInterval = 30 * time.Second

// SliverServer - A single sliver server, this manages the connection to the
// to the server and events going to/from the server
type SliverServer struct {
	Crackstation *Crackstation
	rpc          rpcpb.SliverRPCClient
	Config       *operatorconfig.ClientConfig
	State        string
	ln           *grpc.ClientConn

	connectLock *sync.Mutex
	dial        func(*operatorconfig.ClientConfig) (rpcpb.SliverRPCClient, *grpc.ClientConn, error)

	reconnectInterval   time.Duration
	reconnectAt         time.Time
	reconnectLock       *sync.Mutex
	statusSendLock      *sync.Mutex
	benchmarkUploadLock sync.Mutex
	benchmarkUploaded   bool
	connectionLock      sync.RWMutex
	connectionDone      <-chan struct{}
}

// ConnectionState returns a race-free snapshot for the status UI and the
// reconnect/status loops.
func (s *SliverServer) ConnectionState() string {
	state, _, _ := s.connectionSnapshot()
	return state
}

func (s *SliverServer) connectionSnapshot() (string, rpcpb.SliverRPCClient, *grpc.ClientConn) {
	if s == nil {
		return DISCONNECTED, nil, nil
	}
	s.connectionLock.RLock()
	defer s.connectionLock.RUnlock()
	return s.State, s.rpc, s.ln
}

func (s *SliverServer) rpcClient() rpcpb.SliverRPCClient {
	_, rpc, _ := s.connectionSnapshot()
	return rpc
}

func (s *SliverServer) connectionDoneSnapshot() <-chan struct{} {
	if s == nil {
		return nil
	}
	s.connectionLock.RLock()
	defer s.connectionLock.RUnlock()
	return s.connectionDone
}

func (s *SliverServer) connectionGenerationSnapshot() (string, <-chan struct{}) {
	if s == nil {
		return DISCONNECTED, nil
	}
	s.connectionLock.RLock()
	defer s.connectionLock.RUnlock()
	return s.State, s.connectionDone
}

func (s *SliverServer) setConnectionDone(done <-chan struct{}) {
	s.connectionLock.Lock()
	s.connectionDone = done
	s.connectionLock.Unlock()
}

func (s *SliverServer) clearConnectionDone(done <-chan struct{}) {
	s.connectionLock.Lock()
	if s.connectionDone == done {
		s.connectionDone = nil
	}
	s.connectionLock.Unlock()
}

func (s *SliverServer) setConnection(state string, rpc rpcpb.SliverRPCClient, connection *grpc.ClientConn) {
	s.connectionLock.Lock()
	s.State = state
	s.rpc = rpc
	s.ln = connection
	s.connectionLock.Unlock()
}

func (s *SliverServer) setConnectionState(state string) {
	s.connectionLock.Lock()
	s.State = state
	s.connectionLock.Unlock()
}

func (s *SliverServer) Connect() {
	if s == nil || s.Crackstation == nil {
		return
	}
	select {
	case <-s.Crackstation.done:
		return
	default:
	}
	gotLock := s.connectLock.TryLock()
	if !gotLock {
		return
	}
	defer s.connectLock.Unlock()
	select {
	case <-s.Crackstation.done:
		return
	default:
	}
	defer s.setConnectionState(DISCONNECTED)

	s.setConnectionState(CONNECTING)
	slog.Info("Connecting to server", "operator", s.Config.Operator, "host", s.Config.LHost, "port", s.Config.LPort)
	dial := s.dial
	if dial == nil {
		dial = transport.MTLSConnect
	}
	rpc, connection, err := dial(s.Config)
	if err != nil {
		s.scheduleReconnect()
		slog.Error("Connection to server failed", "err", err)
		return
	}
	s.connectionLock.Lock()
	select {
	case <-s.Crackstation.done:
		s.connectionLock.Unlock()
		_ = transport.CloseConnection(connection)
		return
	default:
		s.State = CONNECTING
		s.rpc = rpc
		s.ln = connection
		s.connectionLock.Unlock()
	}
	s.clearReconnectSchedule()
	ctx, cancel := context.WithCancel(context.Background())
	connectionDone := ctx.Done()
	s.setConnectionDone(connectionDone)
	defer func() {
		s.setConnectionState(DISCONNECTED)
		cancel()
		s.clearConnectionDone(connectionDone)
		_ = transport.CloseConnection(connection)
		s.setConnection(DISCONNECTED, nil, nil)
	}()

	// Feed events into crackstation event channel
	events, err := s.Events(ctx)
	if err != nil {
		s.scheduleReconnect()
		slog.Error("Error establishing events channel", "err", err)
		return
	}
	s.setConnectionState(CONNECTED)
	s.afterRegistration()

	go s.watchConn(ctx, cancel)

	for event := range events {
		select {
		case s.Crackstation.Events <- &ServerEvent{Server: s, Event: event, ConnectionDone: connectionDone}:
		case <-connectionDone:
			return
		case <-s.Crackstation.done:
			return
		}
	}

	s.scheduleReconnect()
}

func (s *SliverServer) sendBenchmarkOnConnect() error {
	if s.Crackstation == nil {
		return errors.New("missing crackstation")
	}
	benchmarks, err := s.Crackstation.LoadBenchmarkResults()
	if err != nil {
		return err
	}
	name := s.Crackstation.Name
	slog.Info("Uploading cached benchmarks", "entries", len(benchmarks))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rpc := s.rpcClient()
	if rpc == nil {
		return errors.New("missing sliver server RPC client")
	}
	benchmark, err := s.benchmarkMessage(name, benchmarks)
	if err != nil {
		return err
	}
	_, err = rpc.CrackstationBenchmark(ctx, benchmark)
	if err != nil {
		return err
	}
	slog.Info("Uploaded cached benchmarks", "entries", len(benchmarks))
	return nil
}

func (s *SliverServer) afterRegistration() {
	if s.Crackstation == nil {
		return
	}
	if s.Crackstation.uploadBenchmarkOnConnect {
		// Registration is ready, but event consumption must not wait behind a
		// slow unary upload or its retries.
		go s.uploadForcedBenchmarkOnce()
	}
	s.Crackstation.requestSync(s)
}

func (s *SliverServer) uploadForcedBenchmarkOnce() {
	s.benchmarkUploadLock.Lock()
	defer s.benchmarkUploadLock.Unlock()
	if s.benchmarkUploaded {
		return
	}
	var err error
	for attempt := 1; attempt <= benchmarkMaxAttempts; attempt++ {
		err = s.sendBenchmarkOnConnect()
		if err == nil {
			s.benchmarkUploaded = true
			return
		}
		slog.Warn("Forced benchmark upload attempt failed", "attempt", attempt, "err", err)
		if attempt < benchmarkMaxAttempts && !s.Crackstation.waitBenchmarkRetry(attempt) {
			return
		}
	}
	slog.Error("Failed to upload forced benchmark after retries", "err", err)
}

func (s *SliverServer) Events(ctx context.Context) (<-chan *clientpb.Event, error) {
	crackstation := s.Crackstation.ToProtobuf()
	crackstation.OperatorName = s.Config.Operator // Insert server config specific values
	rpc := s.rpcClient()
	if rpc == nil {
		return nil, errors.New("missing sliver server RPC client")
	}
	eventStream, err := rpc.CrackstationRegister(ctx, crackstation)
	if err != nil {
		return nil, err
	}
	// The server sends initial headers only after the host has been installed
	// in its authorization registry. This is the readiness barrier for the
	// benchmark and file-sync unary RPCs issued after Events returns.
	if _, err := eventStream.Header(); err != nil {
		return nil, fmt.Errorf("wait for crackstation registration readiness: %w", err)
	}
	events := make(chan *clientpb.Event)
	go func() {
		defer close(events)
		for {
			event, err := eventStream.Recv()
			if err == io.EOF || event == nil {
				slog.Info("Crackstation event stream closed", "err", err)
				return
			}
			if err != nil {
				slog.Error("Error receiving cracking event", "err", err)
				return
			}
			select {
			case events <- event:
			case <-ctx.Done():
				return
			}
		}
	}()
	return events, nil
}

func (s *SliverServer) refreshState(now time.Time) {
	state, _, connection := s.connectionSnapshot()
	if state != CONNECTED || connection == nil {
		return
	}
	switch connection.GetState() {
	case connectivity.Ready:
		s.setConnectionState(CONNECTED)
	case connectivity.Connecting, connectivity.Idle:
		s.setConnectionState(CONNECTING)
	case connectivity.TransientFailure, connectivity.Shutdown:
		s.setConnectionState(DISCONNECTED)
		s.scheduleReconnectAt(now)
		_ = transport.CloseConnection(connection)
	}
}

func (s *SliverServer) watchConn(ctx context.Context, cancel context.CancelFunc) {
	_, _, connection := s.connectionSnapshot()
	if connection == nil {
		return
	}
	for {
		state := connection.GetState()
		switch state {
		case connectivity.Ready:
			s.setConnectionState(CONNECTED)
		case connectivity.Connecting, connectivity.Idle:
			s.setConnectionState(CONNECTING)
		case connectivity.TransientFailure, connectivity.Shutdown:
			s.setConnectionState(DISCONNECTED)
			s.scheduleReconnect()
			cancel()
			_ = transport.CloseConnection(connection)
			return
		}
		if !connection.WaitForStateChange(ctx, state) {
			return
		}
	}
}

func (s *SliverServer) Close() error {
	_, _, connection := s.connectionSnapshot()
	return transport.CloseConnection(connection)
}

func (s *SliverServer) fetchTask(assignment crackTaskAssignment) (*clientpb.CrackTask, error) {
	slog.Info("Fetching task", "task_id", assignment.TaskID)
	ctx, cancel := context.WithTimeout(context.Background(), taskRPCTimeout)
	defer cancel()
	rpc := s.rpcClient()
	if rpc == nil {
		return nil, errors.New("missing sliver server RPC client")
	}
	request := &clientpb.CrackTask{ID: assignment.TaskID, HostUUID: assignment.HostUUID}
	if err := protocompat.SetUint32(request, crackTaskAttemptField, assignment.Attempt); err != nil {
		return nil, err
	}
	if err := protocompat.SetString(request, crackTaskLeaseTokenField, assignment.LeaseToken); err != nil {
		return nil, err
	}
	return rpc.CrackTaskByID(ctx, request)
}

func (s *SliverServer) saveTask(task *clientpb.CrackTask) error {
	ctx, cancel := context.WithTimeout(context.Background(), taskRPCTimeout)
	defer cancel()
	rpc := s.rpcClient()
	if rpc == nil {
		return errors.New("missing sliver server RPC client")
	}
	// Crack commands are immutable, server-owned task input. Do not echo a
	// potentially large hash list and option payload on lifecycle updates.
	update := proto.Clone(task).(*clientpb.CrackTask)
	update.Command = nil
	_, err := rpc.CrackTaskUpdate(ctx, update)
	return err
}

func (s *SliverServer) uploadBenchmarkResult(_ *clientpb.CrackTask, benchmark map[int32]uint64) error {
	return s.uploadBenchmarkResultContext(context.Background(), nil, benchmark)
}

func (s *SliverServer) uploadBenchmarkResultContext(parent context.Context, _ *clientpb.CrackTask, benchmark map[int32]uint64) error {
	name := ""
	if s.Crackstation != nil {
		name = s.Crackstation.Name
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	rpc := s.rpcClient()
	if rpc == nil {
		return errors.New("missing sliver server RPC client")
	}
	message, err := s.benchmarkMessage(name, benchmark)
	if err != nil {
		return err
	}
	_, err = rpc.CrackstationBenchmark(ctx, message)
	return err
}

func (s *SliverServer) benchmarkMessage(name string, benchmarks map[int32]uint64) (*clientpb.CrackBenchmark, error) {
	message := &clientpb.CrackBenchmark{Name: name, HostUUID: HostUUID, Benchmarks: benchmarks}
	if err := protocompat.SetUint32(message, crackBenchmarkSchemaVersionField, benchmarkSchemaVersion); err != nil {
		return nil, fmt.Errorf("encode benchmark schema version: %w", err)
	}
	hashcatVersion := "unknown"
	if s != nil && s.Crackstation != nil && s.Crackstation.hashcat != nil {
		hashcatVersion = s.Crackstation.hashcatVersion()
	}
	if err := protocompat.SetString(message, crackBenchmarkHashcatVersionField, hashcatVersion); err != nil {
		return nil, fmt.Errorf("encode benchmark Hashcat version: %w", err)
	}
	return message, nil
}

func (s *SliverServer) readyToDial(now time.Time) bool {
	if s.reconnectLock == nil {
		return true
	}
	s.reconnectLock.Lock()
	defer s.reconnectLock.Unlock()
	if s.reconnectAt.IsZero() {
		return true
	}
	return !now.Before(s.reconnectAt)
}

func (s *SliverServer) ReconnectIn(now time.Time) time.Duration {
	if s.reconnectLock == nil {
		return 0
	}
	s.reconnectLock.Lock()
	defer s.reconnectLock.Unlock()
	if s.reconnectAt.IsZero() {
		return 0
	}
	remaining := s.reconnectAt.Sub(now)
	if remaining < 0 {
		return 0
	}
	return remaining
}

func (s *SliverServer) scheduleReconnect() {
	s.scheduleReconnectAt(time.Now())
}

func (s *SliverServer) scheduleReconnectAt(now time.Time) {
	if s.reconnectLock == nil {
		return
	}
	s.reconnectLock.Lock()
	defer s.reconnectLock.Unlock()
	interval := s.reconnectInterval
	if interval <= 0 {
		interval = defaultReconnectInterval
	}
	s.reconnectAt = now.Add(interval)
}

func (s *SliverServer) clearReconnectSchedule() {
	if s.reconnectLock == nil {
		return
	}
	s.reconnectLock.Lock()
	s.reconnectAt = time.Time{}
	s.reconnectLock.Unlock()
}
