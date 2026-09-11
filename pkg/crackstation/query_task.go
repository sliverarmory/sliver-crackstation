package crackstation

import (
	"errors"
	"log/slog"
	"time"

	"github.com/sliverarmory/sliver-crackstation/pkg/hashcat"
)

func (c *Crackstation) runQueryTask(server *SliverServer, taskID []byte) {
	var connectionDone <-chan struct{}
	if server != nil {
		connectionDone = server.connectionDoneSnapshot()
	}
	c.runQueryTaskForConnection(server, taskID, connectionDone)
}

// runQueryTaskForConnection executes an output-only Hashcat query under the
// same lease, heartbeat, connection-cancellation, file synchronization, and
// single-process lock used by durable crack tasks. Query results are returned
// through the existing CrackTask stdout/stderr/exit/truncation fields.
func (c *Crackstation) runQueryTaskForConnection(server *SliverServer, taskID []byte, connectionDone <-chan struct{}) {
	c.crackLock.Lock()
	defer c.crackLock.Unlock()
	taskContext, cancelTask, connectionLost := taskContextForConnection(connectionDone, c.done)
	defer cancelTask()
	if taskConnectionLost(connectionDone, c.done, connectionLost, cancelTask) {
		return
	}
	task, metadata, err := c.beginTask(server, taskID, crackTaskKindQuery)
	if err != nil {
		slog.Error("Unable to begin crack query task", "err", err)
		return
	}
	activity := activityForTask(ActivityQuery, task, metadata)
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
		slog.Warn("Crack query file synchronization failed; trying verified cache", "task_id", task.GetID(), "err", syncErr)
	}
	if heartbeat.LeaseLost() || taskConnectionLost(connectionDone, c.done, connectionLost, cancelTask) {
		heartbeat.Stop()
		return
	}

	var resultErr error
	if task.Command == nil {
		resultErr = errors.New("missing crack command")
	} else if mode, validateErr := c.hashcat.ValidateManagedQueryCommand(task.Command); validateErr != nil || mode == hashcat.ManagedQueryKeyspace {
		if validateErr == nil {
			validateErr = errors.New("keyspace tasks must use the crack-keyspace compatibility event")
		}
		if syncErr != nil && errors.Is(validateErr, errManagedCrackFileUnavailable) {
			validateErr = errors.Join(syncErr, validateErr)
		}
		resultErr = validateErr
	} else {
		c.setActivityPhase(ActivityPhaseQuery)
		result, _, runErr := c.hashcat.CrackManagedQueryWithResultContext(taskContext, task.Command)
		if taskConnectionLost(connectionDone, c.done, connectionLost, cancelTask) {
			heartbeat.Stop()
			return
		}
		resultInvalid := hashcat.IsManagedQueryResultError(runErr)
		if encodeErr := setCrackTaskResult(task, result); encodeErr != nil {
			runErr = errors.Join(runErr, encodeErr)
		} else if resultInvalid {
			// The process completed and its bounded result is available. Let the
			// authoritative server validator classify malformed output as DataLoss.
			runErr = nil
		}
		resultErr = runErr
	}

	c.setActivityPhase(ActivityPhaseFinalizing)
	if latestErr := setCrackTaskLatestStatus(task, heartbeat.status(), time.Now()); latestErr != nil {
		resultErr = errors.Join(resultErr, latestErr)
	}
	heartbeat.Stop()
	if heartbeat.LeaseLost() || taskConnectionLost(connectionDone, c.done, connectionLost, cancelTask) {
		slog.Debug("Discarding stale crack query result", "task_id", task.GetID())
		return
	}
	c.finishTask(server, task, resultErr)
}
