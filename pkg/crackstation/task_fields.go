package crackstation

import (
	"fmt"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/sliverarmory/sliver-crackstation/pkg/protocompat"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// These field numbers are part of Sliver's additive durable crack-task schema.
// Keeping them here lets this independently released worker interoperate with a
// newer server while it remains pinned to an older generated protobuf module.
const (
	crackTaskCrackJobIDField       protoreflect.FieldNumber = 16
	crackTaskKindField             protoreflect.FieldNumber = 17
	crackTaskStateField            protoreflect.FieldNumber = 18
	crackTaskAttemptField          protoreflect.FieldNumber = 19
	crackTaskLeaseTokenField       protoreflect.FieldNumber = 20
	crackTaskLeaseExpiresAtField   protoreflect.FieldNumber = 21
	crackTaskUpdatedAtField        protoreflect.FieldNumber = 22
	crackTaskLastHeartbeatAtField  protoreflect.FieldNumber = 23
	crackTaskKeyspaceField         protoreflect.FieldNumber = 24
	crackTaskLatestStatusJSONField protoreflect.FieldNumber = 25
	crackTaskRecoveredJSONField    protoreflect.FieldNumber = 26
	crackTaskShardSkipField        protoreflect.FieldNumber = 27
	crackTaskShardLimitField       protoreflect.FieldNumber = 28
)

type crackTaskKind int32

const (
	crackTaskKindUnspecified crackTaskKind = iota
	crackTaskKindCrack
	crackTaskKindKeyspace
	crackTaskKindBenchmark
	crackTaskKindQuery
)

type crackTaskState int32

const (
	crackTaskStateQueued crackTaskState = iota
	crackTaskStateLeased
	crackTaskStateRunning
	crackTaskStateCompleted
	crackTaskStateFailed
	crackTaskStateCancelled
)

type crackTaskMetadata struct {
	CrackJobID     string
	Kind           crackTaskKind
	State          crackTaskState
	Attempt        uint32
	LeaseToken     string
	LeaseExpiresAt int64
	UpdatedAt      int64
	// LeaseObservedAt is a local monotonic timestamp captured immediately
	// before the RPC which most recently established the lease. It is never
	// serialized and avoids comparing clocks across hosts.
	LeaseObservedAt time.Time
	ShardSkip       uint64
	ShardLimit      uint64
}

func readCrackTaskMetadata(task *clientpb.CrackTask) (crackTaskMetadata, error) {
	fields, err := protocompat.NewReader(task)
	if err != nil {
		return crackTaskMetadata{}, err
	}
	jobID, err := fields.String(crackTaskCrackJobIDField)
	if err != nil {
		return crackTaskMetadata{}, err
	}
	kind, err := fields.Enum(crackTaskKindField)
	if err != nil {
		return crackTaskMetadata{}, err
	}
	state, err := fields.Enum(crackTaskStateField)
	if err != nil {
		return crackTaskMetadata{}, err
	}
	attempt, err := fields.Uint32(crackTaskAttemptField)
	if err != nil {
		return crackTaskMetadata{}, err
	}
	leaseToken, err := fields.String(crackTaskLeaseTokenField)
	if err != nil {
		return crackTaskMetadata{}, err
	}
	leaseExpiresAt, err := fields.Int64(crackTaskLeaseExpiresAtField)
	if err != nil {
		return crackTaskMetadata{}, err
	}
	updatedAt, err := fields.Int64(crackTaskUpdatedAtField)
	if err != nil {
		return crackTaskMetadata{}, err
	}
	shardSkip, err := fields.Uint64(crackTaskShardSkipField)
	if err != nil {
		return crackTaskMetadata{}, err
	}
	shardLimit, err := fields.Uint64(crackTaskShardLimitField)
	if err != nil {
		return crackTaskMetadata{}, err
	}
	return crackTaskMetadata{
		CrackJobID:     jobID,
		Kind:           crackTaskKind(kind),
		State:          crackTaskState(state),
		Attempt:        attempt,
		LeaseToken:     leaseToken,
		LeaseExpiresAt: leaseExpiresAt,
		UpdatedAt:      updatedAt,
		ShardSkip:      shardSkip,
		ShardLimit:     shardLimit,
	}, nil
}

func setCrackTaskState(task *clientpb.CrackTask, state crackTaskState, now time.Time) error {
	if err := protocompat.SetEnum(task, crackTaskStateField, int32(state)); err != nil {
		return fmt.Errorf("set crack task state: %w", err)
	}
	if err := protocompat.SetInt64(task, crackTaskUpdatedAtField, now.Unix()); err != nil {
		return fmt.Errorf("set crack task update time: %w", err)
	}
	if state == crackTaskStateRunning {
		if err := protocompat.SetInt64(task, crackTaskLastHeartbeatAtField, now.Unix()); err != nil {
			return fmt.Errorf("set crack task heartbeat time: %w", err)
		}
	}
	return nil
}

func setCrackTaskKeyspace(task *clientpb.CrackTask, keyspace string) error {
	return protocompat.SetString(task, crackTaskKeyspaceField, keyspace)
}

func setCrackTaskLatestStatus(task *clientpb.CrackTask, statusJSON []byte, observedAt time.Time) error {
	if err := protocompat.SetBytes(task, crackTaskLatestStatusJSONField, statusJSON); err != nil {
		return err
	}
	return protocompat.SetInt64(task, crackTaskLastHeartbeatAtField, observedAt.Unix())
}

func setCrackTaskRecovered(task *clientpb.CrackTask, recoveredJSON []byte) error {
	return protocompat.SetBytes(task, crackTaskRecoveredJSONField, recoveredJSON)
}
