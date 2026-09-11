package crackstation

import (
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/sliverarmory/sliver-crackstation/pkg/hashcat"
)

// ActivityKind identifies the work currently holding the crackstation's
// Hashcat execution lock.
type ActivityKind uint8

const (
	ActivityUnknown ActivityKind = iota
	ActivityCracking
	ActivityBenchmarking
	ActivityKeyspace
	ActivityQuery
)

func (kind ActivityKind) String() string {
	switch kind {
	case ActivityCracking:
		return "Cracking"
	case ActivityBenchmarking:
		return "Benchmarking"
	case ActivityKeyspace:
		return "Keyspace"
	case ActivityQuery:
		return "Query"
	default:
		return "Unknown"
	}
}

// ActivityPhase describes the stage of the active job without retaining any
// submitted target, candidate, mask, or wordlist data.
type ActivityPhase uint8

const (
	ActivityPhaseUnknown ActivityPhase = iota
	ActivityPhaseSynchronizing
	ActivityPhasePreparing
	ActivityPhaseCracking
	ActivityPhaseBenchmarking
	ActivityPhaseRetrying
	ActivityPhaseUploading
	ActivityPhaseFinalizing
	ActivityPhaseKeyspace
	ActivityPhaseQuery
)

func (phase ActivityPhase) String() string {
	switch phase {
	case ActivityPhaseSynchronizing:
		return "syncing files"
	case ActivityPhasePreparing:
		return "preparing Hashcat"
	case ActivityPhaseCracking:
		return "running Hashcat"
	case ActivityPhaseBenchmarking:
		return "measuring hash modes"
	case ActivityPhaseRetrying:
		return "waiting to retry"
	case ActivityPhaseUploading:
		return "uploading results"
	case ActivityPhaseFinalizing:
		return "finalizing results"
	case ActivityPhaseKeyspace:
		return "calculating keyspace"
	case ActivityPhaseQuery:
		return "running Hashcat query"
	default:
		return ""
	}
}

// ActivitySnapshot is a local, safe-to-display view of the job currently
// running on this crackstation. It intentionally excludes submitted hashes,
// Hashcat targets, candidates, and wordlist paths.
type ActivitySnapshot struct {
	Kind        ActivityKind
	Phase       ActivityPhase
	JobID       string
	StartedAt   time.Time
	UpdatedAt   time.Time
	TelemetryAt time.Time
	Attempt     uint32
	HashMode    int32
	HasHashMode bool
	AttackMode  clientpb.CrackAttackMode
	HashCount   int
	ShardSkip   uint64
	ShardLimit  uint64

	HashcatStatus     *hashcat.Status
	BenchmarkProgress *hashcat.BenchmarkProgress
}

// Activity returns an immutable copy of the currently running local job.
func (c *Crackstation) Activity() *ActivitySnapshot {
	if c == nil {
		return nil
	}
	c.activityLock.RLock()
	defer c.activityLock.RUnlock()
	if !c.isCracking || c.activity == nil {
		return nil
	}
	return cloneActivity(c.activity)
}

func cloneActivity(activity *ActivitySnapshot) *ActivitySnapshot {
	if activity == nil {
		return nil
	}
	clone := *activity
	if activity.HashcatStatus != nil {
		status := *activity.HashcatStatus
		status.Devices = append([]hashcat.DeviceStatus(nil), activity.HashcatStatus.Devices...)
		clone.HashcatStatus = &status
	}
	if activity.BenchmarkProgress != nil {
		progress := *activity.BenchmarkProgress
		progress.DeviceSpeeds = append([]hashcat.BenchmarkDeviceSpeed(nil), activity.BenchmarkProgress.DeviceSpeeds...)
		progress.LastDeviceSpeeds = append([]hashcat.BenchmarkDeviceSpeed(nil), activity.BenchmarkProgress.LastDeviceSpeeds...)
		clone.BenchmarkProgress = &progress
	}
	return &clone
}

func (c *Crackstation) beginActivity(activity ActivitySnapshot) {
	now := time.Now()
	if activity.StartedAt.IsZero() {
		activity.StartedAt = now
	}
	activity.UpdatedAt = now

	c.activityLock.Lock()
	c.isCracking = true
	c.currentCrackJobID = activity.JobID
	c.activity = cloneActivity(&activity)
	c.activityLock.Unlock()
}

func (c *Crackstation) endActivity() {
	c.activityLock.Lock()
	c.isCracking = false
	c.currentCrackJobID = ""
	c.activity = nil
	c.activityLock.Unlock()
}

func (c *Crackstation) setActivityAttempt(attempt uint32) {
	c.activityLock.Lock()
	if c.activity != nil {
		if c.activity.Kind == ActivityBenchmarking && c.activity.Attempt != attempt {
			c.activity.BenchmarkProgress = nil
		}
		c.activity.Attempt = attempt
		c.activity.UpdatedAt = time.Now()
	}
	c.activityLock.Unlock()
}

func (c *Crackstation) setActivityPhase(phase ActivityPhase) {
	c.activityLock.Lock()
	if c.activity != nil {
		c.activity.Phase = phase
		c.activity.UpdatedAt = time.Now()
	}
	c.activityLock.Unlock()
}

func (c *Crackstation) observeHashcatStatus(statusJSON []byte) {
	status, err := hashcat.ParseStatusJSON(statusJSON)
	if err != nil {
		return
	}
	now := time.Now()
	c.activityLock.Lock()
	if c.activity != nil && (c.activity.Kind == ActivityCracking || c.activity.Kind == ActivityKeyspace) {
		statusCopy := status
		statusCopy.Devices = append([]hashcat.DeviceStatus(nil), status.Devices...)
		c.activity.HashcatStatus = &statusCopy
		c.activity.UpdatedAt = now
		c.activity.TelemetryAt = now
	}
	c.activityLock.Unlock()
}

func (c *Crackstation) observeBenchmarkProgress(progress hashcat.BenchmarkProgress) {
	now := time.Now()
	c.activityLock.Lock()
	if c.activity != nil && c.activity.Kind == ActivityBenchmarking {
		progressCopy := progress
		progressCopy.DeviceSpeeds = append([]hashcat.BenchmarkDeviceSpeed(nil), progress.DeviceSpeeds...)
		progressCopy.LastDeviceSpeeds = append([]hashcat.BenchmarkDeviceSpeed(nil), progress.LastDeviceSpeeds...)
		c.activity.BenchmarkProgress = &progressCopy
		c.activity.UpdatedAt = now
		c.activity.TelemetryAt = now
	}
	c.activityLock.Unlock()
}
