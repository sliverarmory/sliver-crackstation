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
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	sliverClientAssets "github.com/bishopfox/sliver/client/assets"
	consts "github.com/bishopfox/sliver/client/constants"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/implant/sliver/hostuuid"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/gofrs/uuid"
	"github.com/sliverarmory/sliver-crackstation/pkg/hashcat"
	"google.golang.org/grpc"
)

var HostUUID string

func init() {
	HostUUID = hostuuid.GetUUID()
}

func NewCrackstation(name string, dataDir string, hashcatInstance *hashcat.Hashcat) (*Crackstation, error) {
	crackstation := &Crackstation{
		Name:         name,
		StatusBroker: newBroker(),
		Servers:      &sync.Map{},
		hashcat:      hashcatInstance,
		dataDir:      dataDir,
		crackLock:    &sync.Mutex{},
		syncLock:     &sync.Mutex{},
	}
	return crackstation, nil
}

// ServerEvent - Correlate Events & Sliver Servers
type ServerEvent struct {
	Server *SliverServer
	Event  *clientpb.Event
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
	Events chan *ServerEvent
	done   chan struct{}

	hashcat *hashcat.Hashcat
	dataDir string

	currentCrackJobID string
	crackLock         *sync.Mutex

	SyncStatus *clientpb.CrackSyncStatus
	syncStart  time.Time
	syncBytes  int
	syncLock   *sync.Mutex

	roundRobinStop chan struct{}
}

// RoundRobinConnect - Round robin the crackstation across all servers
func (c *Crackstation) roundRobinConnect(interval time.Duration) {
	c.roundRobinStop = make(chan struct{})
	for {
		select {
		case <-c.roundRobinStop:
			close(c.roundRobinStop)
			return
		case <-time.After(interval):
			c.Servers.Range(func(_, value interface{}) bool {
				server := value.(*SliverServer)
				go server.Connect()
				return true
			})
		}
	}
}

func (c *Crackstation) ToProtobuf() *clientpb.Crackstation {
	return &clientpb.Crackstation{
		Name:           c.Name,
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		HashcatVersion: c.hashcat.Version(),
		CUDA:           c.hashcat.CUDABackend,
		Metal:          c.hashcat.MetalBackend,
		OpenCL:         c.hashcat.OpenCLBackend,
		HostUUID:       HostUUID,
	}
}

func (c *Crackstation) Status() *clientpb.CrackstationStatus {
	status := &clientpb.CrackstationStatus{
		Name:     c.Name,
		HostUUID: HostUUID,
	}

	// Crack status
	acquiredLock := c.crackLock.TryLock()
	if acquiredLock {
		c.crackLock.Unlock()
		status.State = clientpb.States_IDLE
		status.CurrentCrackJobID = ""
	} else {
		status.State = clientpb.States_CRACKING
		status.CurrentCrackJobID = c.currentCrackJobID
	}

	// Sync status
	acquiredLock = c.syncLock.TryLock()
	if acquiredLock {
		c.syncLock.Unlock()
		status.IsSyncing = false
		status.Syncing = nil
	} else {
		status.IsSyncing = true
		status.Syncing = c.SyncStatus
	}

	return status
}

// Start - Main entrypoint for the crackstation, if this function returns the
// entire program should exit
func (c *Crackstation) Start() {
	c.done = make(chan struct{})
	defer close(c.done)

	go c.roundRobinConnect(5 * time.Second)
	defer func() { c.roundRobinStop <- struct{}{} }()

	for {
		select {

		// Handle events from the server(s)
		case serverEvent := <-c.Events:
			go c.handleEvent(serverEvent.Server, serverEvent.Event)

		// Publish status on 1 second interval
		case <-time.After(1 * time.Second):
			go c.StatusBroker.Publish(c.Status()) // Publish status

		case <-c.done:
			return
		}
	}
}

func (c *Crackstation) Stop() {
	c.done <- struct{}{}
}

// Benchmark - Execute hashcat benchmark and save results to disk
func (c *Crackstation) Benchmark() error {
	benchmarkResults, err := c.hashcat.Benchmark(&clientpb.CrackCommand{
		AttackMode: clientpb.CrackAttackMode_NO_ATTACK,
		HashType:   clientpb.HashType_INVALID,
		Benchmark:  true,
	})
	if err != nil {
		log.Printf("Error running benchmark: %s", err)
		return err
	}
	err = c.saveBenchmarkResults(benchmarkResults)
	if err != nil {
		log.Printf("Failed to save benchmark results: %s", err)
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
	return results, nil
}

func (c *Crackstation) handleEvent(server *SliverServer, event *clientpb.Event) {
	log.Printf("[event] %s", event.EventType)
	switch event.EventType {

	case consts.CrackStr:

	case consts.CrackBenchmark:
		c.crackLock.Lock()
		defer c.crackLock.Unlock()
		var err error
		task, err := server.fetchTask(event.Data)
		if err != nil {
			log.Printf("Error fetching task: %v", err)
			return
		}
		log.Printf("Benchmarking crackstation ...")
		c.currentCrackJobID = task.ID
		defer func() { c.currentCrackJobID = "" }()
		task.StartedAt = time.Now().Unix()
		server.saveTask(task)

		// Make sure here after we do not return on error without cleaning up
		// the server-side task!
		var results map[int32]uint64
		results, err = c.LoadBenchmarkResults()
		if err != nil {
			err = c.Benchmark()
			if err != nil {
				log.Printf("Error running benchmark: %v", err)
			}
			results, err = c.LoadBenchmarkResults()
		}
		if err == nil {
			err = server.uploadBenchmarkResult(task, results)
			if err != nil {
				log.Printf("Error uploading benchmark result: %v", err)
			}
		}
		if err != nil {
			task.Err = err.Error()
		}
		task.CompletedAt = time.Now().Unix()
		err = server.saveTask(task)
		if err != nil {
			log.Printf("Error finalizing task: %v", err)
		}
	}
}

func (c *Crackstation) AddServer(config *sliverClientAssets.ClientConfig) *SliverServer {
	server, _ := c.Servers.LoadOrStore(config.Token, &SliverServer{
		Config:       config,
		State:        DISCONNECTED,
		Crackstation: c,

		connectLock: &sync.Mutex{},
	})
	return server.(*SliverServer)
}

const (
	DISCONNECTED = "DISCONNECTED"
	CONNECTED    = "CONNECTED"
	CONNECTING   = "CONNECTING"
)

// SliverServer - A single sliver server, this manages the connection to the
// to the server and events going to/from the server
type SliverServer struct {
	Crackstation *Crackstation
	rpc          rpcpb.SliverRPCClient
	Config       *sliverClientAssets.ClientConfig
	State        string
	ln           *grpc.ClientConn

	connectLock *sync.Mutex
}

func (s *SliverServer) Connect() {
	gotLock := s.connectLock.TryLock()
	if !gotLock {
		return
	}
	defer s.connectLock.Unlock()
	defer func() { s.State = DISCONNECTED }()

	s.State = CONNECTING
	log.Printf("Connecting to server %s@%s:%d", s.Config.Operator, s.Config.LHost, s.Config.LPort)
	var err error
	s.rpc, s.ln, err = transport.MTLSConnect(s.Config)
	if err != nil {
		log.Printf("Connection to server failed: %s", err)
		return
	}
	s.State = CONNECTED

	// Feed events into crackstation event channel
	events, err := s.Events()
	if err != nil {
		log.Printf("Error establishing events channel: %v", err)
		return
	}

	for event := range events {
		s.Crackstation.Events <- &ServerEvent{Server: s, Event: event}
	}
}

func (s *SliverServer) Events() (<-chan *clientpb.Event, error) {
	crackstation := s.Crackstation.ToProtobuf()
	crackstation.OperatorName = s.Config.Operator // Insert server config specific values
	eventStream, err := s.rpc.CrackstationRegister(context.Background(), crackstation)
	if err != nil {
		return nil, err
	}
	events := make(chan *clientpb.Event)
	go func() {
		defer close(events)
		for {
			event, err := eventStream.Recv()
			if err == io.EOF || event == nil {
				log.Printf("Crackstation event stream closed: %v", err)
				return
			}
			if err != nil {
				log.Printf("Error receiving cracking event: %v", err)
				return
			}
			events <- event
		}
	}()
	return events, nil
}

func (s *SliverServer) Close() error {
	return s.ln.Close()
}

func (s *SliverServer) fetchTask(taskID []byte) (*clientpb.CrackTask, error) {
	parsedTaskID := uuid.FromBytesOrNil(taskID)
	if parsedTaskID == uuid.Nil {
		return nil, fmt.Errorf("invalid task ID '%v'", taskID)
	}
	log.Printf("Fetching task: %s", parsedTaskID.String())
	return s.rpc.CrackTaskByID(context.Background(), &clientpb.CrackTask{ID: parsedTaskID.String()})
}

func (s *SliverServer) saveTask(task *clientpb.CrackTask) error {
	_, err := s.rpc.CrackTaskUpdate(context.Background(), task)
	return err
}

func (s *SliverServer) uploadBenchmarkResult(task *clientpb.CrackTask, benchmark map[int32]uint64) error {
	_, err := s.rpc.CrackstationBenchmark(context.Background(), &clientpb.CrackBenchmark{
		HostUUID:   HostUUID,
		Benchmarks: benchmark,
	})
	return err
}
