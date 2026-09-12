package crackstation

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/gofrs/uuid"
	"github.com/sliverarmory/sliver-crackstation/pkg/hashcat"
	"github.com/sliverarmory/sliver-crackstation/pkg/protocompat"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	taskHeartbeatInterval   = time.Second
	taskRPCTimeout          = 10 * time.Second
	defaultHashcatSeparator = ":"
	maxTaskLeaseDuration    = 10 * time.Minute
	maxRecoveredUpdateBytes = 8 << 20
	maxRecoveredRecordBytes = 16 << 20
	maxTaskStatusBytes      = 1 << 20

	crackCommandOutfileField             protoreflect.FieldNumber = 28
	crackCommandOutfileJSONField         protoreflect.FieldNumber = 118
	crackCommandHashCopyField            protoreflect.FieldNumber = 140
	crackCommandStatusTimerV7Field       protoreflect.FieldNumber = 160
	crackCommandOutfileCheckTimerV7Field protoreflect.FieldNumber = 162
	// crackCommandIgnoreLocalCacheField is a control-plane field used only by
	// CrackCommand payloads attached to crack-benchmark events. It must never be
	// forwarded to Hashcat.
	crackCommandIgnoreLocalCacheField protoreflect.FieldNumber = 174
)

type recoveredCredential struct {
	Hash      string `json:"hash"`
	Plaintext []byte `json:"plaintext"`
}

type taskStatusEnvelope struct {
	TaskID     string          `json:"task_id"`
	HostUUID   string          `json:"host_uuid"`
	Attempt    uint32          `json:"attempt"`
	LeaseToken string          `json:"lease_token"`
	ObservedAt int64           `json:"observed_at"`
	Status     json.RawMessage `json:"status"`
}

type crackTaskAssignment struct {
	TaskID     string `json:"task_id"`
	HostUUID   string `json:"host_uuid"`
	Attempt    uint32 `json:"attempt"`
	LeaseToken string `json:"lease_token"`
}

func parseCrackTaskAssignment(data []byte) (crackTaskAssignment, error) {
	assignment := crackTaskAssignment{}
	if err := json.Unmarshal(data, &assignment); err != nil {
		return assignment, fmt.Errorf("decode crack task assignment: %w", err)
	}
	parsedID, err := uuid.FromString(assignment.TaskID)
	if err != nil || parsedID == uuid.Nil {
		return assignment, fmt.Errorf("invalid crack task assignment ID %q", assignment.TaskID)
	}
	if assignment.HostUUID != HostUUID {
		return assignment, fmt.Errorf("crack task assignment host %q does not match local host", assignment.HostUUID)
	}
	if assignment.Attempt == 0 {
		return assignment, errors.New("crack task assignment has invalid attempt 0")
	}
	if assignment.LeaseToken == "" {
		return assignment, errors.New("crack task assignment is missing lease token")
	}
	return assignment, nil
}

func (c *Crackstation) runBenchmarkRequest(server *SliverServer) {
	var connectionDone <-chan struct{}
	if server != nil {
		connectionDone = server.connectionDoneSnapshot()
	}
	c.runBenchmarkRequestForConnection(server, connectionDone, false)
}

func parseBenchmarkRequest(data []byte) (bool, error) {
	if len(data) == 0 {
		return false, nil
	}
	command := &clientpb.CrackCommand{}
	if err := proto.Unmarshal(data, command); err != nil {
		if len(data) == 16 {
			// Older Sliver servers sent a raw 16-byte task UUID here.
			return false, nil
		}
		return false, fmt.Errorf("decode benchmark request: %w", err)
	}
	fields, err := protocompat.NewReader(command)
	if err != nil {
		return false, fmt.Errorf("read benchmark request: %w", err)
	}
	ignoreLocalCache, err := fields.Bool(crackCommandIgnoreLocalCacheField)
	if err != nil {
		return false, fmt.Errorf("read benchmark cache policy: %w", err)
	}
	return ignoreLocalCache, nil
}

func (c *Crackstation) runBenchmarkRequestForConnection(server *SliverServer, connectionDone <-chan struct{}, ignoreLocalCache bool) {
	taskContext, cancelTask, connectionLost := taskContextForConnection(connectionDone, c.done)
	defer cancelTask()
	if taskConnectionLost(connectionDone, c.done, connectionLost, cancelTask) {
		return
	}
	c.crackLock.Lock()
	defer c.crackLock.Unlock()
	if taskConnectionLost(connectionDone, c.done, connectionLost, cancelTask) {
		return
	}
	c.beginActivity(ActivitySnapshot{Kind: ActivityBenchmarking, Phase: ActivityPhasePreparing, JobID: "benchmark"})
	defer c.endActivity()

	var results map[int32]uint64
	var err error
	if !ignoreLocalCache {
		results, err = c.LoadBenchmarkResults()
		if err == nil {
			slog.Info("Using cached benchmark results for server request", "modes", len(results))
		}
	}
	if ignoreLocalCache || err != nil {
		if ignoreLocalCache {
			slog.Info("Server requested a fresh benchmark; ignoring local cache")
		} else {
			slog.Info("No usable cached benchmark results; running benchmark", "err", err)
		}
		for attempt := 1; attempt <= benchmarkMaxAttempts; attempt++ {
			c.setActivityAttempt(uint32(attempt))
			c.setActivityPhase(ActivityPhaseBenchmarking)
			err = c.benchmarkContext(taskContext)
			if err == nil {
				results, err = c.LoadBenchmarkResults()
			}
			if err == nil {
				break
			}
			if taskConnectionLost(connectionDone, c.done, connectionLost, cancelTask) {
				return
			}
			slog.Warn("Requested benchmark attempt failed", "attempt", attempt, "err", err)
			if attempt < benchmarkMaxAttempts {
				c.setActivityPhase(ActivityPhaseRetrying)
				if !waitBenchmarkRetryContext(taskContext, attempt) {
					return
				}
			}
		}
		if err != nil {
			slog.Error("Requested benchmark failed after retries", "err", err)
			return
		}
	}
	c.setActivityPhase(ActivityPhaseUploading)
	for attempt := 1; attempt <= benchmarkMaxAttempts; attempt++ {
		if taskConnectionLost(connectionDone, c.done, connectionLost, cancelTask) {
			return
		}
		err = server.uploadBenchmarkResultContext(taskContext, nil, results)
		if err == nil {
			return
		}
		if taskConnectionLost(connectionDone, c.done, connectionLost, cancelTask) {
			return
		}
		slog.Warn("Requested benchmark upload failed", "attempt", attempt, "err", err)
		if attempt < benchmarkMaxAttempts {
			c.setActivityPhase(ActivityPhaseRetrying)
			if !waitBenchmarkRetryContext(taskContext, attempt) {
				return
			}
			c.setActivityPhase(ActivityPhaseUploading)
		}
	}
	slog.Error("Requested benchmark upload failed after retries", "err", err)
}

func (c *Crackstation) waitBenchmarkRetry(attempt int) bool {
	timer := time.NewTimer(time.Duration(attempt) * benchmarkRetryDelay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-c.done:
		return false
	}
}

func waitBenchmarkRetryContext(ctx context.Context, attempt int) bool {
	timer := time.NewTimer(time.Duration(attempt) * benchmarkRetryDelay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (c *Crackstation) runCrackTask(server *SliverServer, taskID []byte) {
	var connectionDone <-chan struct{}
	if server != nil {
		connectionDone = server.connectionDoneSnapshot()
	}
	c.runCrackTaskForConnection(server, taskID, connectionDone)
}

func (c *Crackstation) runCrackTaskForConnection(server *SliverServer, taskID []byte, connectionDone <-chan struct{}) {
	c.crackLock.Lock()
	defer c.crackLock.Unlock()
	taskContext, cancelTask, connectionLost := taskContextForConnection(connectionDone, c.done)
	defer cancelTask()
	if taskConnectionLost(connectionDone, c.done, connectionLost, cancelTask) {
		return
	}
	task, metadata, err := c.beginTask(server, taskID, crackTaskKindCrack)
	if err != nil {
		slog.Error("Unable to begin crack task", "err", err)
		return
	}
	activity := activityForTask(ActivityCracking, task, metadata)
	activity.Phase = ActivityPhaseSynchronizing
	c.beginActivity(activity)
	defer c.endActivity()
	if taskConnectionLost(connectionDone, c.done, connectionLost, cancelTask) {
		return
	}
	heartbeat := newTaskHeartbeat(server, task, metadata, cancelTask)
	heartbeat.Start()
	defer heartbeat.Stop()
	syncErr := c.syncFilesForTask(taskContext, server)
	c.setActivityPhase(ActivityPhasePreparing)
	if syncErr != nil {
		slog.Warn("Crack task file synchronization failed; trying verified cache", "task_id", task.GetID(), "err", syncErr)
	}
	if heartbeat.LeaseLost() || taskConnectionLost(connectionDone, c.done, connectionLost, cancelTask) {
		heartbeat.Stop()
		return
	}

	command, outfilePath, err := c.prepareCrackCommand(task.Command, metadata)
	if err != nil && syncErr != nil && errors.Is(err, errManagedCrackFileUnavailable) {
		slog.Warn("Relinquishing crack task until managed files are available", "task_id", task.GetID(), "err", errors.Join(syncErr, err))
		heartbeat.Stop()
		return
	}
	if outfilePath != "" {
		defer os.Remove(outfilePath)
	}
	var resultErr error
	if err == nil {
		var result = emptyCommandResult()
		c.setActivityPhase(ActivityPhaseCracking)
		result, resultErr = c.hashcat.CrackManagedWithResultStreamingContext(taskContext, command, func(statusJSON []byte) {
			heartbeat.Observe(statusJSON)
			c.observeHashcatStatus(statusJSON)
		})
		if taskConnectionLost(connectionDone, c.done, connectionLost, cancelTask) {
			heartbeat.Stop()
			return
		}
		if encodeErr := setCrackTaskResult(task, result); encodeErr != nil {
			resultErr = errors.Join(resultErr, encodeErr)
		}
	} else {
		resultErr = err
	}
	c.setActivityPhase(ActivityPhaseFinalizing)
	if outfilePath != "" {
		recoveryErr := c.uploadRecoveredCredentials(
			taskContext,
			server,
			task,
			outfilePath,
			task.Command.GetHashes(),
			effectiveHashcatSeparator(task.Command),
		)
		resultErr = errors.Join(resultErr, recoveryErr)
	}
	if latestErr := setCrackTaskLatestStatus(task, heartbeat.status(), time.Now()); latestErr != nil {
		resultErr = errors.Join(resultErr, latestErr)
	}
	heartbeat.Stop()
	if heartbeat.LeaseLost() || taskConnectionLost(connectionDone, c.done, connectionLost, cancelTask) {
		slog.Debug("Discarding stale crack task result", "task_id", task.GetID())
		return
	}
	c.finishTask(server, task, resultErr)
}

func (c *Crackstation) runKeyspaceTask(server *SliverServer, taskID []byte) {
	var connectionDone <-chan struct{}
	if server != nil {
		connectionDone = server.connectionDoneSnapshot()
	}
	c.runKeyspaceTaskForConnection(server, taskID, connectionDone)
}

func (c *Crackstation) runKeyspaceTaskForConnection(server *SliverServer, taskID []byte, connectionDone <-chan struct{}) {
	c.crackLock.Lock()
	defer c.crackLock.Unlock()
	taskContext, cancelTask, connectionLost := taskContextForConnection(connectionDone, c.done)
	defer cancelTask()
	if taskConnectionLost(connectionDone, c.done, connectionLost, cancelTask) {
		return
	}
	task, metadata, err := c.beginTask(server, taskID, crackTaskKindKeyspace)
	if err != nil {
		slog.Error("Unable to begin keyspace task", "err", err)
		return
	}
	activity := activityForTask(ActivityKeyspace, task, metadata)
	activity.Phase = ActivityPhaseSynchronizing
	c.beginActivity(activity)
	defer c.endActivity()
	if taskConnectionLost(connectionDone, c.done, connectionLost, cancelTask) {
		return
	}
	heartbeat := newTaskHeartbeat(server, task, metadata, cancelTask)
	heartbeat.Start()
	defer heartbeat.Stop()
	syncErr := c.syncFilesForTask(taskContext, server)
	c.setActivityPhase(ActivityPhasePreparing)
	if syncErr != nil {
		slog.Warn("Keyspace task file synchronization failed; trying verified cache", "task_id", task.GetID(), "err", syncErr)
	}
	if heartbeat.LeaseLost() || taskConnectionLost(connectionDone, c.done, connectionLost, cancelTask) {
		heartbeat.Stop()
		return
	}

	var resultErr error
	if task.Command == nil {
		resultErr = errors.New("missing crack command")
	} else {
		command := proto.Clone(task.Command).(*clientpb.CrackCommand)
		command.Hashes = nil
		command.Skip = 0
		command.Limit = 0
		command.Keyspace = true
		command.Quiet = true
		command.Status = false
		command.StatusJSON = false
		command.MachineReadable = false
		command.LogfileDisable = true
		command.RestoreDisable = true
		command.HwmonDisable = false
		// A keyspace probe has no recovered output to persist. Strip every
		// caller-controlled local output/potfile setting just as crack shards do,
		// so the probe cannot read or write an arbitrary crackstation path.
		command.Potfile = nil
		command.PotfileDisable = true
		command.OutfileFormat = nil
		command.OutfileAutohexDisable = false
		command.OutfileCheckTimer = 0
		if clearErr := protocompat.Clear(command, crackCommandOutfileField); clearErr != nil {
			resultErr = clearErr
		} else if clearErr := protocompat.SetBool(command, crackCommandOutfileJSONField, false); clearErr != nil {
			resultErr = clearErr
		} else if clearErr := protocompat.SetUint32(command, crackCommandOutfileCheckTimerV7Field, 0); clearErr != nil {
			resultErr = clearErr
		} else if validateErr := c.hashcat.ValidateManagedTaskCommand(command); validateErr != nil {
			if syncErr != nil && errors.Is(validateErr, errManagedCrackFileUnavailable) {
				validateErr = errors.Join(syncErr, validateErr)
			}
			resultErr = validateErr
		} else {
			c.setActivityPhase(ActivityPhaseKeyspace)
			result, runErr := c.hashcat.CrackManagedWithResultStreamingContext(taskContext, command, nil)
			if taskConnectionLost(connectionDone, c.done, connectionLost, cancelTask) {
				heartbeat.Stop()
				return
			}
			if runErr != nil {
				if heartbeat.LeaseLost() || taskConnectionLost(connectionDone, c.done, connectionLost, cancelTask) {
					heartbeat.Stop()
					return
				}
				if syncErr := c.syncFilesForTask(taskContext, server); syncErr != nil {
					slog.Error("Keyspace file synchronization failed", "task_id", task.ID, "err", syncErr)
				}
				if heartbeat.LeaseLost() || taskConnectionLost(connectionDone, c.done, connectionLost, cancelTask) {
					heartbeat.Stop()
					return
				}
				result, runErr = c.hashcat.CrackManagedWithResultStreamingContext(taskContext, command, nil)
			}
			resultValidationErr := hashcat.ValidateManagedKeyspaceResult(result)
			runErr = errors.Join(runErr, resultValidationErr)
			encodeErr := setCrackTaskResult(task, result)
			runErr = errors.Join(runErr, encodeErr)
			if runErr == nil {
				keyspace, parseErr := parseHashcatKeyspace(result.Stdout)
				if parseErr != nil {
					runErr = parseErr
				} else if setErr := setCrackTaskKeyspace(task, keyspace); setErr != nil {
					runErr = setErr
				}
			}
			if encodeErr == nil && hashcat.IsManagedQueryResultError(runErr) {
				// Preserve the captured result for the server's compatibility-path
				// validator, which reports malformed keyspace output as DataLoss.
				runErr = nil
			}
			resultErr = runErr
		}
	}
	c.setActivityPhase(ActivityPhaseFinalizing)
	if latestErr := setCrackTaskLatestStatus(task, heartbeat.status(), time.Now()); latestErr != nil {
		resultErr = errors.Join(resultErr, latestErr)
	}
	heartbeat.Stop()
	if heartbeat.LeaseLost() || taskConnectionLost(connectionDone, c.done, connectionLost, cancelTask) {
		slog.Debug("Discarding stale keyspace task result", "task_id", task.GetID())
		return
	}
	c.finishTask(server, task, resultErr)
}

func (c *Crackstation) syncFilesForTask(ctx context.Context, server *SliverServer) error {
	var syncErr error
	for attempt := 1; attempt <= benchmarkMaxAttempts; attempt++ {
		syncErr = c.SyncFilesContext(ctx, server)
		if syncErr == nil {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return errors.Join(syncErr, err)
		}
		if attempt < benchmarkMaxAttempts && !waitBenchmarkRetryContext(ctx, attempt) {
			return errors.Join(syncErr, ctx.Err())
		}
	}
	return syncErr
}

func emptyCommandResult() hashcatCommandResult {
	return hashcatCommandResult{ExitCode: -1}
}

// hashcatCommandResult aliases the exact result shape without making task
// flow helpers depend on Hashcat internals beyond its public result contract.
type hashcatCommandResult = hashcat.CommandResult

func (c *Crackstation) beginTask(server *SliverServer, taskID []byte, expectedKind crackTaskKind) (*clientpb.CrackTask, crackTaskMetadata, error) {
	assignment, err := parseCrackTaskAssignment(taskID)
	if err != nil {
		return nil, crackTaskMetadata{}, err
	}
	task, err := server.fetchTask(assignment)
	if err != nil {
		return nil, crackTaskMetadata{}, err
	}
	if task == nil {
		return nil, crackTaskMetadata{}, errors.New("server returned nil crack task")
	}
	metadata, err := readCrackTaskMetadata(task)
	if err != nil {
		return nil, crackTaskMetadata{}, fmt.Errorf("decode crack task metadata: %w", err)
	}
	if task.GetID() != assignment.TaskID || task.GetHostUUID() != assignment.HostUUID || metadata.Attempt != assignment.Attempt || metadata.LeaseToken != assignment.LeaseToken {
		return nil, crackTaskMetadata{}, errors.New("fetched crack task does not match dispatched lease assignment")
	}
	if metadata.Kind != expectedKind {
		return nil, crackTaskMetadata{}, fmt.Errorf("fetched crack task kind %d does not match dispatched event kind %d", metadata.Kind, expectedKind)
	}
	if metadata.State != crackTaskStateLeased {
		return nil, crackTaskMetadata{}, fmt.Errorf("fetched crack task is not leased (state %d)", metadata.State)
	}
	if _, err := taskLeaseDuration(metadata); err != nil {
		return nil, crackTaskMetadata{}, err
	}
	now := time.Now()
	task.HostUUID = HostUUID
	if task.StartedAt == 0 {
		task.StartedAt = now.Unix()
	}
	task.Err = ""
	if err := setCrackTaskState(task, crackTaskStateRunning, now); err != nil {
		return nil, crackTaskMetadata{}, err
	}
	leaseObservedAt, err := c.saveTaskWithRetryStartedAt(server, task)
	if err != nil {
		return nil, crackTaskMetadata{}, fmt.Errorf("save running crack task: %w", err)
	}
	metadata.LeaseObservedAt = leaseObservedAt
	return task, metadata, nil
}

func (c *Crackstation) finishTask(server *SliverServer, task *clientpb.CrackTask, taskErr error) {
	now := time.Now()
	task.CompletedAt = now.Unix()
	state := crackTaskStateCompleted
	if taskErr != nil {
		state = crackTaskStateFailed
		task.Err = taskErr.Error()
		slog.Error("Crack task failed", "task_id", task.GetID(), "err", taskErr)
	} else {
		task.Err = ""
	}
	if err := setCrackTaskState(task, state, now); err != nil {
		task.Err = errors.Join(taskErr, err).Error()
	}
	saveErr := c.saveTaskWithRetry(server, task)
	if saveErr == nil {
		return
	}
	if isLeaseRejection(saveErr) {
		slog.Debug("Crack task lease was lost before final update", "task_id", task.GetID())
		return
	}
	slog.Error("Error finalizing crack task after retries", "task_id", task.GetID(), "err", saveErr)
}

func (c *Crackstation) saveTaskWithRetry(server *SliverServer, task *clientpb.CrackTask) error {
	_, err := c.saveTaskWithRetryStartedAt(server, task)
	return err
}

func (c *Crackstation) saveTaskWithRetryStartedAt(server *SliverServer, task *clientpb.CrackTask) (time.Time, error) {
	var saveErr error
	var requestStartedAt time.Time
	for attempt := 1; attempt <= benchmarkMaxAttempts; attempt++ {
		requestStartedAt = time.Now()
		saveErr = server.saveTask(task)
		if saveErr == nil || isLeaseRejection(saveErr) {
			return requestStartedAt, saveErr
		}
		if attempt < benchmarkMaxAttempts && !c.waitBenchmarkRetry(attempt) {
			return requestStartedAt, saveErr
		}
	}
	return requestStartedAt, saveErr
}

func isLeaseRejection(err error) bool {
	return status.Code(err) == codes.Aborted || status.Code(err) == codes.PermissionDenied
}

func taskContextForConnection(connectionDone <-chan struct{}, stationDone <-chan struct{}) (context.Context, context.CancelFunc, *atomic.Bool) {
	ctx, cancel := context.WithCancel(context.Background())
	connectionLost := &atomic.Bool{}
	if connectionDone == nil && stationDone == nil {
		return ctx, cancel, connectionLost
	}
	go func() {
		select {
		case <-connectionDone:
			connectionLost.Store(true)
			cancel()
		case <-stationDone:
			connectionLost.Store(true)
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel, connectionLost
}

func taskConnectionLost(connectionDone <-chan struct{}, stationDone <-chan struct{}, lost *atomic.Bool, cancel context.CancelFunc) bool {
	if lost.Load() {
		return true
	}
	select {
	case <-connectionDone:
		lost.Store(true)
		cancel()
		return true
	default:
	}
	select {
	case <-stationDone:
		lost.Store(true)
		cancel()
		return true
	default:
		return false
	}
}

func taskDisplayID(task *clientpb.CrackTask, metadata crackTaskMetadata) string {
	if metadata.CrackJobID != "" {
		return metadata.CrackJobID
	}
	return task.GetID()
}

func activityForTask(kind ActivityKind, task *clientpb.CrackTask, metadata crackTaskMetadata) ActivitySnapshot {
	activity := ActivitySnapshot{
		Kind:       kind,
		JobID:      taskDisplayID(task, metadata),
		Attempt:    metadata.Attempt,
		ShardSkip:  metadata.ShardSkip,
		ShardLimit: metadata.ShardLimit,
	}
	if task == nil || task.Command == nil {
		return activity
	}
	activity.AttackMode = task.Command.GetAttackMode()
	activity.HashCount = len(task.Command.GetHashes())
	if hashMode, ok, err := hashcat.EffectiveHashMode(task.Command); err == nil && ok {
		activity.HashMode = hashMode
		activity.HasHashMode = true
	}
	return activity
}

func (c *Crackstation) prepareCrackCommand(command *clientpb.CrackCommand, metadata crackTaskMetadata) (*clientpb.CrackCommand, string, error) {
	if command == nil {
		return nil, "", errors.New("missing crack command")
	}
	copyCommand := proto.Clone(command).(*clientpb.CrackCommand)
	copyCommand.Skip = metadata.ShardSkip
	copyCommand.Limit = metadata.ShardLimit
	copyCommand.Status = true
	copyCommand.MachineReadable = false
	copyCommand.HwmonDisable = false
	copyCommand.StatusJSON = true
	copyCommand.StatusTimer = 1
	copyCommand.LogfileDisable = true
	copyCommand.RestoreDisable = true
	copyCommand.Keyspace = false
	// Queue tasks must not share Hashcat's local potfile across jobs or Sliver
	// servers. A potfile hit can suppress the controlled outfile record that is
	// required to return recovered plaintext to the owning server.
	copyCommand.Potfile = nil
	copyCommand.PotfileDisable = true
	copyCommand.OutfileAutohexDisable = false
	copyCommand.OutfileCheckTimer = 0
	if err := protocompat.SetUint32(copyCommand, crackCommandStatusTimerV7Field, 1); err != nil {
		return nil, "", err
	}
	if err := protocompat.SetBool(copyCommand, crackCommandHashCopyField, true); err != nil {
		return nil, "", err
	}
	if err := protocompat.SetUint32(copyCommand, crackCommandOutfileCheckTimerV7Field, 0); err != nil {
		return nil, "", err
	}
	if err := c.hashcat.ValidateManagedTaskCommand(copyCommand); err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(filepath.Join(c.dataDir, "tasks"), 0700); err != nil {
		return nil, "", err
	}
	outfile, err := os.CreateTemp(filepath.Join(c.dataDir, "tasks"), ".recovered-*")
	if err != nil {
		return nil, "", err
	}
	outfilePath := outfile.Name()
	if err := outfile.Close(); err != nil {
		os.Remove(outfilePath)
		return nil, "", err
	}
	if err := protocompat.SetString(copyCommand, crackCommandOutfileField, outfilePath); err != nil {
		os.Remove(outfilePath)
		return nil, "", err
	}
	if err := protocompat.SetBool(copyCommand, crackCommandOutfileJSONField, false); err != nil {
		os.Remove(outfilePath)
		return nil, "", err
	}
	copyCommand.OutfileFormat = []clientpb.CrackOutfileFormat{
		clientpb.CrackOutfileFormat_HASH_SALT,
		clientpb.CrackOutfileFormat_HEX_PLAIN,
	}
	return copyCommand, outfilePath, nil
}

func effectiveHashcatSeparator(command *clientpb.CrackCommand) string {
	if command != nil && command.GetSeparator() != "" {
		return command.GetSeparator()
	}
	return defaultHashcatSeparator
}

func readRecoveredCredentials(path string, submittedHashes []string, separator string) ([]recoveredCredential, error) {
	credentials := make([]recoveredCredential, 0)
	err := visitRecoveredCredentials(context.Background(), path, submittedHashes, separator, func(credential recoveredCredential) error {
		credentials = append(credentials, credential)
		return nil
	})
	return credentials, err
}

func visitRecoveredCredentials(ctx context.Context, path string, submittedHashes []string, separator string, visit func(recoveredCredential) error) error {
	if separator == "" {
		return errors.New("empty hashcat outfile separator")
	}
	if visit == nil {
		return errors.New("missing recovered credential visitor")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	hashIndex := newRecoveredHashIndex(submittedHashes)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), maxRecoveredRecordBytes)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := scanner.Bytes()
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if len(line) != 0 {
			hash, hexPlaintext, splitErr := splitRecoveredCredentialIndexed(line, hashIndex, separator)
			if splitErr != nil {
				return splitErr
			}
			plaintext, err := hex.DecodeString(string(hexPlaintext))
			if err != nil {
				return fmt.Errorf("decode recovered credential hex plaintext: %w", err)
			}
			if err := visit(recoveredCredential{Hash: string(hash), Plaintext: plaintext}); err != nil {
				return err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return scanner.Err()
}

func (c *Crackstation) uploadRecoveredCredentials(ctx context.Context, server *SliverServer, task *clientpb.CrackTask, path string, submittedHashes []string, separator string) error {
	return c.uploadRecoveredCredentialsWithLimit(ctx, server, task, path, submittedHashes, separator, maxRecoveredUpdateBytes)
}

func (c *Crackstation) uploadRecoveredCredentialsWithLimit(ctx context.Context, server *SliverServer, task *clientpb.CrackTask, path string, submittedHashes []string, separator string, maxBytes int) error {
	if maxBytes < 2 {
		return errors.New("recovered credential update limit is too small")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	batch := make([]recoveredCredential, 0)
	batchBytes := 2 // JSON array brackets.
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		encoded, err := json.Marshal(batch)
		if err != nil {
			return err
		}
		if len(encoded) > maxBytes {
			return fmt.Errorf("recovered credential batch is %d bytes, limit is %d", len(encoded), maxBytes)
		}
		if err := setCrackTaskRecovered(task, encoded); err != nil {
			return err
		}
		saveErr := c.saveTaskWithRetry(server, task)
		batch = batch[:0]
		batchBytes = 2
		clearErr := setCrackTaskRecovered(task, nil)
		if saveErr != nil {
			// Never carry a rejected batch into the terminal update: a permanent
			// validation failure would otherwise make completion impossible and
			// cause the lease reaper to recompute the same shard forever.
			return errors.Join(fmt.Errorf("save recovered credential batch: %w", saveErr), clearErr)
		}
		return clearErr
	}
	readErr := visitRecoveredCredentials(ctx, path, submittedHashes, separator, func(credential recoveredCredential) error {
		encoded, err := json.Marshal(credential)
		if err != nil {
			return err
		}
		recordBytes := len(encoded)
		if len(batch) != 0 {
			recordBytes++ // comma
		}
		if recordBytes+2 > maxBytes {
			return fmt.Errorf("single recovered credential is %d bytes, update limit is %d", recordBytes+2, maxBytes)
		}
		if batchBytes+recordBytes > maxBytes {
			if err := flush(); err != nil {
				return err
			}
			recordBytes = len(encoded)
		}
		batch = append(batch, credential)
		batchBytes += recordBytes
		return nil
	})
	if err := ctx.Err(); err != nil {
		return errors.Join(readErr, err)
	}
	flushErr := flush()
	return errors.Join(readErr, flushErr)
}

func splitRecoveredCredential(line []byte, submittedHashes []string, separator string) ([]byte, []byte, error) {
	return splitRecoveredCredentialIndexed(line, newRecoveredHashIndex(submittedHashes), separator)
}

const (
	fnv64Offset = uint64(14695981039346656037)
	fnv64Prime  = uint64(1099511628211)
)

type recoveredHashIndex struct {
	count   int
	buckets map[uint64][]string
}

func newRecoveredHashIndex(submittedHashes []string) recoveredHashIndex {
	index := recoveredHashIndex{buckets: make(map[uint64][]string, len(submittedHashes))}
	seen := make(map[string]struct{}, len(submittedHashes))
	for _, hash := range submittedHashes {
		if hash == "" {
			continue
		}
		if _, duplicate := seen[hash]; duplicate {
			continue
		}
		seen[hash] = struct{}{}
		value := fnv64Offset
		for position := 0; position < len(hash); position++ {
			value ^= uint64(hash[position])
			value *= fnv64Prime
		}
		index.buckets[value] = append(index.buckets[value], hash)
		index.count++
	}
	return index
}

func splitRecoveredCredentialIndexed(line []byte, submittedHashes recoveredHashIndex, separator string) ([]byte, []byte, error) {
	separatorBytes := []byte(separator)
	if len(separatorBytes) == 0 {
		return nil, nil, errors.New("empty hashcat outfile separator")
	}
	bestHashLength := -1
	prefixHash := fnv64Offset
	for position := 0; position+len(separatorBytes) <= len(line); position++ {
		if position > bestHashLength && bytes.Equal(line[position:position+len(separatorBytes)], separatorBytes) {
			for _, submittedHash := range submittedHashes.buckets[prefixHash] {
				if len(submittedHash) == position && bytes.Equal(line[:position], []byte(submittedHash)) {
					bestHashLength = position
					break
				}
			}
		}
		prefixHash ^= uint64(line[position])
		prefixHash *= fnv64Prime
	}
	if bestHashLength >= 0 {
		return line[:bestHashLength], line[bestHashLength+len(separatorBytes):], nil
	}
	if submittedHashes.count != 0 {
		return nil, nil, errors.New("recovered credential does not match any submitted hash")
	}
	if separatorCanAppearInHex(separatorBytes) {
		return nil, nil, fmt.Errorf("cannot safely parse recovered credential without submitted hashes using separator %q", separator)
	}
	separatorIndex := bytes.LastIndex(line, separatorBytes)
	if separatorIndex <= 0 {
		return nil, nil, errors.New("malformed recovered credential record")
	}
	return line[:separatorIndex], line[separatorIndex+len(separatorBytes):], nil
}

func separatorCanAppearInHex(separator []byte) bool {
	if len(separator) == 0 {
		return true
	}
	for _, value := range separator {
		if !((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') || (value >= 'A' && value <= 'F')) {
			return false
		}
	}
	return true
}

type taskHeartbeat struct {
	server   *SliverServer
	taskID   string
	metadata crackTaskMetadata

	latestMu  sync.RWMutex
	latest    []byte
	stop      chan struct{}
	event     chan struct{}
	wg        sync.WaitGroup
	stopOnce  sync.Once
	cancel    context.CancelFunc
	leaseLost atomic.Bool
	// leaseDeadline is extended only after the server acknowledges a canonical
	// task-status event. A short unary outage is tolerated; an outage lasting
	// through the confirmed lease stops work before it can be duplicated.
	leaseDuration time.Duration
	deadlineMu    sync.RWMutex
	leaseDeadline time.Time
}

func newTaskHeartbeat(server *SliverServer, task *clientpb.CrackTask, metadata crackTaskMetadata, cancel context.CancelFunc) *taskHeartbeat {
	heartbeat := &taskHeartbeat{
		server: server, taskID: task.GetID(), metadata: metadata,
		latest: []byte("{}"), stop: make(chan struct{}), event: make(chan struct{}, 1), cancel: cancel,
	}
	if duration, err := taskLeaseDuration(metadata); err == nil {
		heartbeat.leaseDuration = duration
		observedAt := metadata.LeaseObservedAt
		if observedAt.IsZero() {
			observedAt = time.Now()
		}
		heartbeat.leaseDeadline = observedAt.Add(duration)
		if !time.Now().Before(heartbeat.leaseDeadline) {
			heartbeat.loseLease()
		}
	}
	return heartbeat
}

func taskLeaseDuration(metadata crackTaskMetadata) (time.Duration, error) {
	if metadata.UpdatedAt <= 0 || metadata.LeaseExpiresAt <= metadata.UpdatedAt {
		return 0, errors.New("fetched crack task has an invalid lease duration")
	}
	seconds := metadata.LeaseExpiresAt - metadata.UpdatedAt
	maxSeconds := int64(maxTaskLeaseDuration / time.Second)
	if seconds > maxSeconds {
		seconds = maxSeconds
	}
	return time.Duration(seconds) * time.Second, nil
}

func (heartbeat *taskHeartbeat) Start() {
	heartbeat.wg.Add(2)
	go func() {
		defer heartbeat.wg.Done()
		ticker := time.NewTicker(taskHeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				heartbeat.tick()
			case <-heartbeat.stop:
				return
			}
		}
	}()
	go func() {
		defer heartbeat.wg.Done()
		for {
			select {
			case <-heartbeat.event:
				heartbeat.sendEvent(time.Now(), heartbeat.status())
			case <-heartbeat.stop:
				return
			}
		}
	}()
	heartbeat.signalEvent()
}

func (heartbeat *taskHeartbeat) Stop() {
	heartbeat.stopOnce.Do(func() { close(heartbeat.stop) })
	heartbeat.wg.Wait()
}

func (heartbeat *taskHeartbeat) LeaseLost() bool {
	return heartbeat.leaseLost.Load()
}

func (heartbeat *taskHeartbeat) handleLeaseError(err error) {
	if err == nil {
		return
	}
	switch status.Code(err) {
	case codes.Aborted, codes.PermissionDenied:
		heartbeat.loseLease()
	}
}

func (heartbeat *taskHeartbeat) loseLease() {
	if heartbeat.leaseLost.CompareAndSwap(false, true) && heartbeat.cancel != nil {
		heartbeat.cancel()
	}
}

func (heartbeat *taskHeartbeat) renewLease(now time.Time) {
	if heartbeat.leaseDuration > 0 {
		heartbeat.deadlineMu.Lock()
		heartbeat.leaseDeadline = now.Add(heartbeat.leaseDuration)
		heartbeat.deadlineMu.Unlock()
	}
}

func (heartbeat *taskHeartbeat) Observe(statusJSON []byte) {
	if len(statusJSON) == 0 || len(statusJSON) > maxTaskStatusBytes || !json.Valid(statusJSON) {
		return
	}
	heartbeat.latestMu.Lock()
	heartbeat.latest = append(heartbeat.latest[:0], statusJSON...)
	heartbeat.latestMu.Unlock()
	heartbeat.signalEvent()
}

func (heartbeat *taskHeartbeat) status() []byte {
	heartbeat.latestMu.RLock()
	defer heartbeat.latestMu.RUnlock()
	return append([]byte(nil), heartbeat.latest...)
}

func (heartbeat *taskHeartbeat) tick() {
	heartbeat.deadlineMu.RLock()
	deadline := heartbeat.leaseDeadline
	heartbeat.deadlineMu.RUnlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		heartbeat.loseLease()
		return
	}
	heartbeat.signalEvent()
}

func (heartbeat *taskHeartbeat) signalEvent() {
	select {
	case heartbeat.event <- struct{}{}:
	default:
	}
}

func (heartbeat *taskHeartbeat) sendEvent(observedAt time.Time, statusJSON []byte) {
	if heartbeat.server == nil {
		return
	}
	rpc := heartbeat.server.rpcClient()
	if rpc == nil {
		return
	}
	envelope, err := json.Marshal(taskStatusEnvelope{
		TaskID: heartbeat.taskID, HostUUID: HostUUID,
		Attempt: heartbeat.metadata.Attempt, LeaseToken: heartbeat.metadata.LeaseToken,
		ObservedAt: observedAt.Unix(), Status: json.RawMessage(statusJSON),
	})
	if err != nil {
		return
	}
	requestStartedAt := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := rpc.CrackstationTrigger(ctx, &clientpb.Event{EventType: crackTaskStatusEvent, Data: envelope}); err != nil {
		heartbeat.handleLeaseError(err)
		slog.Debug("Failed to send crack task status", "task_id", heartbeat.taskID, "err", err)
	} else {
		// The server starts the renewed lease while processing this request.
		// Anchoring at request start is conservative across response latency.
		heartbeat.renewLease(requestStartedAt)
	}
}
