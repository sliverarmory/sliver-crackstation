package crackstation

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/gofrs/uuid"
	"github.com/sliverarmory/sliver-crackstation/pkg/hashcat"
	"github.com/sliverarmory/sliver-crackstation/pkg/protocompat"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func newScriptHashcat(t *testing.T, script string) *hashcat.Hashcat {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX helper script")
	}
	directory := t.TempDir()
	executable := filepath.Join(directory, "hashcat")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\n"+script+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	h := &hashcat.Hashcat{}
	for name, value := range map[string]string{"exe": executable, "cwd": directory, "version": "test"} {
		field := reflect.ValueOf(h).Elem().FieldByName(name)
		reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().SetString(value)
	}
	return h
}

func leasedTask(t *testing.T, command *clientpb.CrackCommand, kind crackTaskKind, skip, limit uint64) (*clientpb.CrackTask, uuid.UUID) {
	t.Helper()
	id := uuid.Must(uuid.NewV4())
	task := &clientpb.CrackTask{ID: id.String(), HostUUID: HostUUID, Command: command}
	setters := []error{
		protocompat.SetString(task, crackTaskCrackJobIDField, "job-1"),
		protocompat.SetEnum(task, crackTaskKindField, int32(kind)),
		protocompat.SetEnum(task, crackTaskStateField, int32(crackTaskStateLeased)),
		protocompat.SetUint32(task, crackTaskAttemptField, 7),
		protocompat.SetString(task, crackTaskLeaseTokenField, "lease-secret"),
		protocompat.SetInt64(task, crackTaskUpdatedAtField, time.Now().Unix()),
		protocompat.SetInt64(task, crackTaskLeaseExpiresAtField, time.Now().Add(time.Minute).Unix()),
		protocompat.SetUint64(task, crackTaskShardSkipField, skip),
		protocompat.SetUint64(task, crackTaskShardLimitField, limit),
	}
	for _, err := range setters {
		if err != nil {
			t.Fatal(err)
		}
	}
	return task, id
}

func assignmentData(t *testing.T, task *clientpb.CrackTask) []byte {
	t.Helper()
	metadata, err := readCrackTaskMetadata(task)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(crackTaskAssignment{
		TaskID: task.GetID(), HostUUID: task.GetHostUUID(),
		Attempt: metadata.Attempt, LeaseToken: metadata.LeaseToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

type taskCapture struct {
	mu       sync.Mutex
	updates  []*clientpb.CrackTask
	triggers []*clientpb.Event
}

func (capture *taskCapture) addUpdate(task *clientpb.CrackTask) {
	capture.mu.Lock()
	capture.updates = append(capture.updates, proto.Clone(task).(*clientpb.CrackTask))
	capture.mu.Unlock()
}

func (capture *taskCapture) addTrigger(event *clientpb.Event) {
	capture.mu.Lock()
	capture.triggers = append(capture.triggers, proto.Clone(event).(*clientpb.Event))
	capture.mu.Unlock()
}

func (capture *taskCapture) snapshot() ([]*clientpb.CrackTask, []*clientpb.Event) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]*clientpb.CrackTask(nil), capture.updates...), append([]*clientpb.Event(nil), capture.triggers...)
}

func taskServer(t *testing.T, task *clientpb.CrackTask, capture *taskCapture) *SliverServer {
	t.Helper()
	mock := &mockSliverRPC{
		CrackTaskByIDFunc: func(_ context.Context, request *clientpb.CrackTask) (*clientpb.CrackTask, error) {
			if request.GetHostUUID() != HostUUID {
				t.Errorf("fetch HostUUID = %q; want %q", request.GetHostUUID(), HostUUID)
			}
			reader, err := protocompat.NewReader(request)
			if err != nil {
				t.Errorf("fetch metadata: %v", err)
			} else {
				attempt, _ := reader.Uint32(crackTaskAttemptField)
				token, _ := reader.String(crackTaskLeaseTokenField)
				if attempt != 7 || token != "lease-secret" {
					t.Errorf("fetch lease metadata = %d, %q", attempt, token)
				}
			}
			return proto.Clone(task).(*clientpb.CrackTask), nil
		},
		CrackTaskUpdateFunc: func(_ context.Context, update *clientpb.CrackTask) (*commonpb.Empty, error) {
			capture.addUpdate(update)
			return &commonpb.Empty{}, nil
		},
		CrackstationTriggerFunc: func(_ context.Context, event *clientpb.Event) (*commonpb.Empty, error) {
			capture.addTrigger(event)
			return &commonpb.Empty{}, nil
		},
		CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
			return &clientpb.CrackFiles{}, nil
		},
	}
	return &SliverServer{rpc: newBufConnClient(t, mock)}
}

func TestRunCrackTaskStreamsHeartbeatsAndCapturesRecovery(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())
	argsPath := filepath.Join(t.TempDir(), "args")
	h := newScriptHashcat(t, `
printf '%s\n' "$@" > '`+argsPath+`'
outfile=''
for arg in "$@"; do
  case "$arg" in --outfile=*) outfile=${arg#--outfile=} ;; esac
done
sleep 1.2
printf '%s\n' '{"session":"job-1","status":3,"progress":[5,10],"devices":[{"temp":73}]}'
sleep 0.2
printf 'ABCDEF0123456789:salt:70613a7373\n' > "$outfile"
printf 'warning\n' >&2
`)
	task, _ := leasedTask(t, &clientpb.CrackCommand{
		AttackMode:            clientpb.CrackAttackMode_BRUTEFORCE,
		Hashes:                []string{"ABCDEF0123456789:salt"},
		Identify:              "?d?d",
		Potfile:               []byte("shared.pot"),
		MachineReadable:       true,
		OutfileAutohexDisable: true,
		OutfileCheckTimer:     99,
	}, crackTaskKindCrack, 10, 25)
	capture := &taskCapture{}
	server := taskServer(t, task, capture)
	station, err := NewCrackstation("worker", t.TempDir(), h)
	if err != nil {
		t.Fatal(err)
	}
	station.runCrackTask(server, assignmentData(t, task))

	updates, triggers := capture.snapshot()
	if len(updates) != 3 {
		t.Fatalf("task updates = %d; want running, recovered-result batch, and final lifecycle updates", len(updates))
	}
	for index, update := range updates {
		if update.GetCommand() != nil {
			t.Fatalf("lifecycle update %d echoed the server-owned command", index)
		}
	}
	final := updates[len(updates)-1]
	metadata, err := readCrackTaskMetadata(final)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.State != crackTaskStateCompleted || metadata.Attempt != 7 || metadata.LeaseToken != "lease-secret" {
		t.Fatalf("final metadata = %#v", metadata)
	}
	reader, err := protocompat.NewReader(final)
	if err != nil {
		t.Fatal(err)
	}
	latest, _ := reader.Bytes(crackTaskLatestStatusJSONField)
	if !strings.Contains(string(latest), `"temp":73`) {
		t.Fatalf("final latest status = %s", latest)
	}
	var recoveredJSON []byte
	for _, update := range updates {
		updateReader, err := protocompat.NewReader(update)
		if err != nil {
			t.Fatal(err)
		}
		if candidate, _ := updateReader.Bytes(crackTaskRecoveredJSONField); len(candidate) != 0 {
			recoveredJSON = candidate
		}
	}
	var recovered []recoveredCredential
	if err := json.Unmarshal(recoveredJSON, &recovered); err != nil {
		t.Fatalf("recovered JSON %q: %v", recoveredJSON, err)
	}
	if len(recovered) != 1 || recovered[0].Hash != "ABCDEF0123456789:salt" || string(recovered[0].Plaintext) != "pa:ss" {
		t.Fatalf("recovered = %#v", recovered)
	}
	stderr, _ := reader.Bytes(crackTaskStderrField)
	if string(stderr) != "warning\n" {
		t.Fatalf("stderr = %q", stderr)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{
		"--skip=10", "--limit=25", "--status", "--status-json", "--status-timer=1",
		"--outfile-format=1,3", "--outfile-check-timer=0", "--potfile-disable", "--hash-copy",
		"--logfile-disable",
	} {
		if !strings.Contains(string(args), flag) {
			t.Fatalf("args missing %q: %q", flag, args)
		}
	}
	for _, forbidden := range []string{"shared.pot", "--machine-readable", "--outfile-autohex-disable", "--separator="} {
		if strings.Contains(string(args), forbidden) {
			t.Fatalf("queue execution emitted forbidden argument %q: %q", forbidden, args)
		}
	}
	foundStatus := false
	foundHeartbeatOnly := false
	for _, event := range triggers {
		if event.GetEventType() != crackTaskStatusEvent {
			continue
		}
		var envelope taskStatusEnvelope
		if json.Unmarshal(event.GetData(), &envelope) == nil && envelope.TaskID == task.ID && envelope.Attempt == 7 && envelope.LeaseToken == "lease-secret" {
			if string(envelope.Status) == "{}" {
				foundHeartbeatOnly = true
			}
			if strings.Contains(string(envelope.Status), `"temp":73`) {
				foundStatus = true
			}
		}
	}
	if !foundHeartbeatOnly || !foundStatus {
		t.Fatalf("canonical task-status heartbeats missing empty=%v telemetry=%v: %#v", foundHeartbeatOnly, foundStatus, triggers)
	}
}

func TestRunFailedCrackTaskPreservesValidRecoveryBeforeMalformedTail(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())
	h := newScriptHashcat(t, `
outfile=''
for arg in "$@"; do
  case "$arg" in --outfile=*) outfile=${arg#--outfile=} ;; esac
done
printf 'good-hash:7061\nbad-hash:7' > "$outfile"
exit 2
`)
	task, _ := leasedTask(t, &clientpb.CrackCommand{
		AttackMode: clientpb.CrackAttackMode_BRUTEFORCE,
		Hashes:     []string{"good-hash", "bad-hash"},
		Identify:   "?d",
	}, crackTaskKindCrack, 0, 10)
	capture := &taskCapture{}
	station, err := NewCrackstation("worker", t.TempDir(), h)
	if err != nil {
		t.Fatal(err)
	}
	station.runCrackTask(taskServer(t, task, capture), assignmentData(t, task))

	updates, _ := capture.snapshot()
	if len(updates) != 3 {
		t.Fatalf("task updates = %d; want running, partial recovery batch, and failed", len(updates))
	}
	final := updates[len(updates)-1]
	metadata, err := readCrackTaskMetadata(final)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.State != crackTaskStateFailed || !strings.Contains(final.GetErr(), "exit status 2") || !strings.Contains(final.GetErr(), "odd length") {
		t.Fatalf("failed task metadata/error = %#v, %q", metadata, final.GetErr())
	}
	var encoded []byte
	for _, update := range updates {
		reader, err := protocompat.NewReader(update)
		if err != nil {
			t.Fatal(err)
		}
		if candidate, err := reader.Bytes(crackTaskRecoveredJSONField); err != nil {
			t.Fatal(err)
		} else if len(candidate) != 0 {
			encoded = candidate
		}
	}
	var recovered []recoveredCredential
	if err := json.Unmarshal(encoded, &recovered); err != nil {
		t.Fatalf("decode partial recovered JSON %q: %v", encoded, err)
	}
	if len(recovered) != 1 || recovered[0].Hash != "good-hash" || string(recovered[0].Plaintext) != "pa" {
		t.Fatalf("partial recovered results = %#v", recovered)
	}
}

func TestUploadRecoveredCredentialsUsesBoundedBatches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recovered")
	if err := os.WriteFile(path, []byte("hash-one:706c61696e31\nhash-two:706c61696e32\nhash-three:706c61696e33\n"), 0600); err != nil {
		t.Fatal(err)
	}
	task, _ := leasedTask(t, &clientpb.CrackCommand{}, crackTaskKindCrack, 0, 1)
	task.StartedAt = time.Now().Unix()
	if err := setCrackTaskState(task, crackTaskStateRunning, time.Now()); err != nil {
		t.Fatal(err)
	}
	capture := &taskCapture{}
	station, err := NewCrackstation("worker", t.TempDir(), newScriptHashcat(t, "exit 0"))
	if err != nil {
		t.Fatal(err)
	}
	const tinyBatchLimit = 90
	if err := station.uploadRecoveredCredentialsWithLimit(
		context.Background(), taskServer(t, task, capture), task, path,
		[]string{"hash-one", "hash-two", "hash-three"}, ":", tinyBatchLimit,
	); err != nil {
		t.Fatal(err)
	}
	updates, _ := capture.snapshot()
	if len(updates) < 2 {
		t.Fatalf("recovered batch updates = %d; want multiple bounded updates", len(updates))
	}
	var recovered []recoveredCredential
	for _, update := range updates {
		reader, err := protocompat.NewReader(update)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := reader.Bytes(crackTaskRecoveredJSONField)
		if err != nil {
			t.Fatal(err)
		}
		if len(encoded) > tinyBatchLimit {
			t.Fatalf("recovered batch bytes = %d; limit is %d", len(encoded), tinyBatchLimit)
		}
		var batch []recoveredCredential
		if err := json.Unmarshal(encoded, &batch); err != nil {
			t.Fatal(err)
		}
		recovered = append(recovered, batch...)
	}
	if len(recovered) != 3 || recovered[0].Hash != "hash-one" || recovered[1].Hash != "hash-two" || recovered[2].Hash != "hash-three" {
		t.Fatalf("recovered batches = %#v", recovered)
	}
	reader, err := protocompat.NewReader(task)
	if err != nil {
		t.Fatal(err)
	}
	if remaining, err := reader.Bytes(crackTaskRecoveredJSONField); err != nil || len(remaining) != 0 {
		t.Fatalf("acknowledged batch remained on task: %q, %v", remaining, err)
	}
}

func TestRejectedRecoveryBatchDoesNotPoisonFailedTerminalUpdate(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())
	h := newScriptHashcat(t, `
outfile=''
for arg in "$@"; do case "$arg" in --outfile=*) outfile=${arg#--outfile=} ;; esac; done
printf 'rejected-hash:706c61696e\n' > "$outfile"
`)
	task, _ := leasedTask(t, &clientpb.CrackCommand{
		AttackMode: clientpb.CrackAttackMode_BRUTEFORCE,
		Hashes:     []string{"rejected-hash"},
		Identify:   "?d",
	}, crackTaskKindCrack, 0, 1)
	var rejectedCalls atomic.Int32
	var terminal *clientpb.CrackTask
	mock := &mockSliverRPC{
		CrackTaskByIDFunc: func(context.Context, *clientpb.CrackTask) (*clientpb.CrackTask, error) {
			return proto.Clone(task).(*clientpb.CrackTask), nil
		},
		CrackTaskUpdateFunc: func(_ context.Context, update *clientpb.CrackTask) (*commonpb.Empty, error) {
			reader, err := protocompat.NewReader(update)
			if err != nil {
				return nil, err
			}
			recovered, err := reader.Bytes(crackTaskRecoveredJSONField)
			if err != nil {
				return nil, err
			}
			if len(recovered) != 0 {
				rejectedCalls.Add(1)
				return nil, status.Error(codes.InvalidArgument, "recovery budget exceeded")
			}
			if update.GetCompletedAt() != 0 {
				terminal = proto.Clone(update).(*clientpb.CrackTask)
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
	station.runCrackTask(&SliverServer{rpc: newBufConnClient(t, mock)}, assignmentData(t, task))
	if rejectedCalls.Load() != benchmarkMaxAttempts {
		t.Fatalf("rejected batch attempts = %d; want bounded retry count %d", rejectedCalls.Load(), benchmarkMaxAttempts)
	}
	if terminal == nil {
		t.Fatal("rejected recovery batch prevented terminal failed update")
	}
	metadata, err := readCrackTaskMetadata(terminal)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.State != crackTaskStateFailed || !strings.Contains(terminal.GetErr(), "recovery budget exceeded") {
		t.Fatalf("terminal state/error = %#v, %q", metadata, terminal.GetErr())
	}
	reader, err := protocompat.NewReader(terminal)
	if err != nil {
		t.Fatal(err)
	}
	if recovered, err := reader.Bytes(crackTaskRecoveredJSONField); err != nil || len(recovered) != 0 {
		t.Fatalf("terminal update retained rejected recovery batch: %q, %v", recovered, err)
	}
}

func TestRunKeyspaceTaskStoresUint64ValueAndClearsRange(t *testing.T) {
	argsPath := filepath.Join(t.TempDir(), "args")
	forbiddenOutputPath := filepath.Join(t.TempDir(), "caller-output")
	forbiddenPotfilePath := filepath.Join(t.TempDir(), "caller-potfile")
	if err := os.WriteFile(forbiddenPotfilePath, []byte("local-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	h := newScriptHashcat(t, `printf '%s\n' "$@" > '`+argsPath+`'; printf '18446744073709551615\n'`)
	command := &clientpb.CrackCommand{
		AttackMode: clientpb.CrackAttackMode_BRUTEFORCE,
		Hashes:     []string{"secret-hash"},
		Identify:   "?d",
		Skip:       8,
		Limit:      9,
		Status:     true,
		StatusJSON: true,
		Potfile:    []byte(forbiddenPotfilePath),
	}
	if err := protocompat.SetString(command, crackCommandOutfileField, forbiddenOutputPath); err != nil {
		t.Fatal(err)
	}
	task, _ := leasedTask(t, command, crackTaskKindKeyspace, 100, 200)
	capture := &taskCapture{}
	server := taskServer(t, task, capture)
	station, err := NewCrackstation("worker", t.TempDir(), h)
	if err != nil {
		t.Fatal(err)
	}
	station.runKeyspaceTask(server, assignmentData(t, task))

	updates, _ := capture.snapshot()
	final := updates[len(updates)-1]
	reader, err := protocompat.NewReader(final)
	if err != nil {
		t.Fatal(err)
	}
	keyspace, _ := reader.String(crackTaskKeyspaceField)
	if keyspace != "18446744073709551615" {
		t.Fatalf("keyspace = %q", keyspace)
	}
	state, _ := reader.Enum(crackTaskStateField)
	if crackTaskState(state) != crackTaskStateCompleted {
		t.Fatalf("state = %d, error = %q", state, final.GetErr())
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(args), "--keyspace") || !strings.Contains(string(args), "--logfile-disable") || !strings.Contains(string(args), "--potfile-disable") || strings.Contains(string(args), "--skip=") || strings.Contains(string(args), "--limit=") || strings.Contains(string(args), "secret-hash") || strings.Contains(string(args), "--status") || strings.Contains(string(args), "--outfile=") || strings.Contains(string(args), "--potfile-path=") || strings.Contains(string(args), forbiddenOutputPath) || strings.Contains(string(args), forbiddenPotfilePath) {
		t.Fatalf("unexpected keyspace args: %q", args)
	}
}

func TestRunKeyspaceTaskCompletesInvalidProcessResultForServerValidation(t *testing.T) {
	h := newScriptHashcat(t, "printf '42\\n'; exit 1")
	task, _ := leasedTask(t, &clientpb.CrackCommand{
		AttackMode: clientpb.CrackAttackMode_BRUTEFORCE,
		Identify:   "?d",
	}, crackTaskKindKeyspace, 0, 0)
	capture := &taskCapture{}
	server := taskServer(t, task, capture)
	station, err := NewCrackstation("worker", t.TempDir(), h)
	if err != nil {
		t.Fatal(err)
	}
	station.runKeyspaceTask(server, assignmentData(t, task))

	updates, _ := capture.snapshot()
	final := updates[len(updates)-1]
	metadata, err := readCrackTaskMetadata(final)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.State != crackTaskStateCompleted || final.GetErr() != "" {
		t.Fatalf("state=%v error=%q; want completed result for authoritative server validation", metadata.State, final.GetErr())
	}
	reader, err := protocompat.NewReader(final)
	if err != nil {
		t.Fatal(err)
	}
	keyspace, _ := reader.String(crackTaskKeyspaceField)
	stdout, _ := reader.Bytes(crackTaskStdoutField)
	exitCode, _ := reader.Int32(crackTaskExitCodeField)
	if keyspace != "" || string(stdout) != "42\n" || exitCode != 1 {
		t.Fatalf("keyspace=%q stdout=%q exit=%d; want empty keyspace and preserved process result", keyspace, stdout, exitCode)
	}
}

func TestReadRecoveredCredentialsPreservesSaltedHashesAndPlaintextBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outfile")
	data := []byte("hash:salt:70613a73733a1f\nempty:\nbinary:000a1fff\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	credentials, err := readRecoveredCredentials(path, []string{"hash", "hash:salt", "empty", "binary"}, ":")
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 3 {
		t.Fatalf("credentials = %#v", credentials)
	}
	if credentials[0].Hash != "hash:salt" || string(credentials[0].Plaintext) != "pa:ss:\x1f" {
		t.Fatalf("salted credential = %#v", credentials[0])
	}
	if credentials[1].Hash != "empty" || len(credentials[1].Plaintext) != 0 {
		t.Fatalf("empty credential = %#v", credentials[1])
	}
	if credentials[2].Hash != "binary" || !reflect.DeepEqual(credentials[2].Plaintext, []byte{0, '\n', 0x1f, 0xff}) {
		t.Fatalf("credentials = %#v", credentials)
	}
	encoded, err := json.Marshal(credentials)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"hash":"binary","plaintext":"AAof/w=="`) {
		t.Fatalf("plaintext was not canonical base64 JSON: %s", encoded)
	}
}

func TestReadRecoveredCredentialsSeparatorParsing(t *testing.T) {
	t.Run("hex digit separator uses exact submitted hash", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "outfile")
		if err := os.WriteFile(path, []byte("hasha3a\n"), 0600); err != nil {
			t.Fatal(err)
		}
		credentials, err := readRecoveredCredentials(path, []string{"hash"}, "a")
		if err != nil {
			t.Fatal(err)
		}
		if len(credentials) != 1 || credentials[0].Hash != "hash" || string(credentials[0].Plaintext) != ":" {
			t.Fatalf("credentials = %#v", credentials)
		}
	})

	t.Run("safe fallback uses last separator", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "outfile")
		if err := os.WriteFile(path, []byte("hash:salt:7061\n"), 0600); err != nil {
			t.Fatal(err)
		}
		credentials, err := readRecoveredCredentials(path, nil, ":")
		if err != nil {
			t.Fatal(err)
		}
		if len(credentials) != 1 || credentials[0].Hash != "hash:salt" || string(credentials[0].Plaintext) != "pa" {
			t.Fatalf("credentials = %#v", credentials)
		}
	})

	t.Run("unsafe fallback is rejected", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "outfile")
		if err := os.WriteFile(path, []byte("hasha3a\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readRecoveredCredentials(path, nil, "a"); err == nil {
			t.Fatal("accepted ambiguous hex-digit separator without submitted hashes")
		}
	})
}

func TestReadRecoveredCredentialsRejectsMalformedHex(t *testing.T) {
	for name, record := range map[string]string{
		"odd length": "hash:abc\n",
		"non hex":    "hash:zz\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "outfile")
			if err := os.WriteFile(path, []byte(record), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := readRecoveredCredentials(path, []string{"hash"}, ":"); err == nil {
				t.Fatal("accepted malformed HEX_PLAIN output")
			}
		})
	}
}

func TestReadRecoveredCredentialsReturnsValidPrefixWithError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outfile")
	if err := os.WriteFile(path, []byte("first:7061\nsecond:7"), 0600); err != nil {
		t.Fatal(err)
	}
	recovered, err := readRecoveredCredentials(path, []string{"first", "second"}, ":")
	if err == nil || !strings.Contains(err.Error(), "odd length") {
		t.Fatalf("readRecoveredCredentials() error = %v; want malformed-tail diagnostic", err)
	}
	if len(recovered) != 1 || recovered[0].Hash != "first" || string(recovered[0].Plaintext) != "pa" {
		t.Fatalf("valid recovery prefix = %#v", recovered)
	}
}

func TestRecoveredHashIndexScalesAcrossLargeSubmittedSet(t *testing.T) {
	hashes := make([]string, 0, 100_002)
	for index := 0; index < 100_000; index++ {
		hashes = append(hashes, fmt.Sprintf("%032x", index))
	}
	hashes = append(hashes, "salted", "salted:hash")
	index := newRecoveredHashIndex(hashes)
	if index.count != len(hashes) {
		t.Fatalf("indexed hashes = %d; want %d", index.count, len(hashes))
	}
	line := []byte("salted:hash:706c61696e")
	for iteration := 0; iteration < 2_000; iteration++ {
		hash, plaintext, err := splitRecoveredCredentialIndexed(line, index, ":")
		if err != nil {
			t.Fatal(err)
		}
		if string(hash) != "salted:hash" || string(plaintext) != "706c61696e" {
			t.Fatalf("indexed split = %q, %q", hash, plaintext)
		}
	}
}

func TestPrepareCrackCommandPreservesSeparatorAndForcesControlledOutput(t *testing.T) {
	station, err := NewCrackstation("worker", t.TempDir(), newScriptHashcat(t, "exit 0"))
	if err != nil {
		t.Fatal(err)
	}
	command := &clientpb.CrackCommand{
		AttackMode:            clientpb.CrackAttackMode_BRUTEFORCE,
		Identify:              "?d",
		Separator:             "|",
		MachineReadable:       true,
		HwmonDisable:          true,
		LogfileDisable:        false,
		OutfileAutohexDisable: true,
		OutfileCheckTimer:     99,
	}
	prepared, outfile, err := station.prepareCrackCommand(command, crackTaskMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(outfile) })
	if prepared.GetSeparator() != "|" {
		t.Fatalf("separator = %q; want preserved custom separator", prepared.GetSeparator())
	}
	if prepared.GetMachineReadable() || prepared.GetHwmonDisable() || prepared.GetOutfileAutohexDisable() {
		t.Fatalf("incompatible controlled flags were retained: %#v", prepared)
	}
	if !prepared.GetLogfileDisable() {
		t.Fatal("managed crack command did not disable Hashcat's persistent logfile")
	}
	if prepared.GetOutfileCheckTimer() != 0 {
		t.Fatalf("legacy outfile check timer = %d; want 0", prepared.GetOutfileCheckTimer())
	}
	if !reflect.DeepEqual(prepared.GetOutfileFormat(), []clientpb.CrackOutfileFormat{
		clientpb.CrackOutfileFormat_HASH_SALT,
		clientpb.CrackOutfileFormat_HEX_PLAIN,
	}) {
		t.Fatalf("outfile format = %v", prepared.GetOutfileFormat())
	}
	reader, err := protocompat.NewReader(prepared)
	if err != nil {
		t.Fatal(err)
	}
	if value, err := reader.Bool(crackCommandHashCopyField); err != nil || !value {
		t.Fatalf("hash copy = %v, %v; want true", value, err)
	}
	if value, err := reader.Uint32(crackCommandOutfileCheckTimerV7Field); err != nil || value != 0 || !reader.HasVarint(crackCommandOutfileCheckTimerV7Field) {
		t.Fatalf("v7 outfile check timer = %d, present=%v, err=%v; want explicit 0", value, reader.HasVarint(crackCommandOutfileCheckTimerV7Field), err)
	}
}

func TestParseHashcatKeyspaceRejectsUint64Overflow(t *testing.T) {
	if _, err := parseHashcatKeyspace([]byte("18446744073709551616\n")); err == nil {
		t.Fatal("parseHashcatKeyspace accepted a value that cannot be sharded with uint64 fields")
	}
}

func TestParseCrackTaskAssignmentRejectsUntrustedDispatch(t *testing.T) {
	id := uuid.Must(uuid.NewV4()).String()
	for name, assignment := range map[string]crackTaskAssignment{
		"wrong host":   {TaskID: id, HostUUID: "another-host", Attempt: 1, LeaseToken: "token"},
		"zero attempt": {TaskID: id, HostUUID: HostUUID, LeaseToken: "token"},
		"empty token":  {TaskID: id, HostUUID: HostUUID, Attempt: 1},
		"invalid id":   {TaskID: "not-a-uuid", HostUUID: HostUUID, Attempt: 1, LeaseToken: "token"},
	} {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(assignment)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseCrackTaskAssignment(data); err == nil {
				t.Fatal("untrusted assignment was accepted")
			}
		})
	}
}

func TestBeginTaskRejectsMismatchedKindAndState(t *testing.T) {
	for name, mutate := range map[string]func(*clientpb.CrackTask) error{
		"kind": func(task *clientpb.CrackTask) error {
			return protocompat.SetEnum(task, crackTaskKindField, int32(crackTaskKindKeyspace))
		},
		"state": func(task *clientpb.CrackTask) error {
			return protocompat.SetEnum(task, crackTaskStateField, int32(crackTaskStateRunning))
		},
	} {
		t.Run(name, func(t *testing.T) {
			task, _ := leasedTask(t, &clientpb.CrackCommand{}, crackTaskKindCrack, 0, 1)
			if err := mutate(task); err != nil {
				t.Fatal(err)
			}
			var updates atomic.Int32
			mock := &mockSliverRPC{
				CrackTaskByIDFunc: func(context.Context, *clientpb.CrackTask) (*clientpb.CrackTask, error) {
					return proto.Clone(task).(*clientpb.CrackTask), nil
				},
				CrackTaskUpdateFunc: func(context.Context, *clientpb.CrackTask) (*commonpb.Empty, error) {
					updates.Add(1)
					return &commonpb.Empty{}, nil
				},
			}
			station, err := NewCrackstation("worker", t.TempDir(), newScriptHashcat(t, "exit 0"))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := station.beginTask(&SliverServer{rpc: newBufConnClient(t, mock)}, assignmentData(t, task), crackTaskKindCrack); err == nil {
				t.Fatal("beginTask accepted a mismatched durable assignment")
			}
			if updates.Load() != 0 {
				t.Fatalf("updates = %d; rejected assignment must not transition", updates.Load())
			}
		})
	}
}

func TestLeaseLossCancelsTaskWaitingForFileSync(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "hashcat-started")
	h := newScriptHashcat(t, `: > '`+marker+`'`)
	task, _ := leasedTask(t, &clientpb.CrackCommand{AttackMode: clientpb.CrackAttackMode_BRUTEFORCE, Identify: "?d"}, crackTaskKindCrack, 0, 1)
	firstListStarted := make(chan struct{})
	releaseFirstList := make(chan struct{})
	leaseRejected := make(chan struct{})
	var releaseOnce sync.Once
	var rejectOnce sync.Once
	var lists atomic.Int32
	var finalCalls atomic.Int32
	mock := &mockSliverRPC{
		CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
			if lists.Add(1) == 1 {
				close(firstListStarted)
				<-releaseFirstList
			}
			return &clientpb.CrackFiles{}, nil
		},
		CrackTaskByIDFunc: func(context.Context, *clientpb.CrackTask) (*clientpb.CrackTask, error) {
			return proto.Clone(task).(*clientpb.CrackTask), nil
		},
		CrackTaskUpdateFunc: func(_ context.Context, update *clientpb.CrackTask) (*commonpb.Empty, error) {
			if update.GetCompletedAt() != 0 {
				finalCalls.Add(1)
			}
			return &commonpb.Empty{}, nil
		},
		CrackstationTriggerFunc: func(context.Context, *clientpb.Event) (*commonpb.Empty, error) {
			rejectOnce.Do(func() { close(leaseRejected) })
			return nil, status.Error(codes.Aborted, "lease reassigned")
		},
	}
	station, err := NewCrackstation("worker", t.TempDir(), h)
	if err != nil {
		t.Fatal(err)
	}
	server := &SliverServer{rpc: newBufConnClient(t, mock)}
	backgroundDone := make(chan error, 1)
	go func() { backgroundDone <- station.SyncFiles(server) }()
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseFirstList) }) })
	select {
	case <-firstListStarted:
	case <-time.After(time.Second):
		t.Fatal("background synchronization did not acquire the gate")
	}

	taskDone := make(chan struct{})
	dispatch := assignmentData(t, task)
	go func() {
		station.runCrackTask(server, dispatch)
		close(taskDone)
	}()
	select {
	case <-leaseRejected:
	case <-time.After(time.Second):
		t.Fatal("task heartbeat did not detect lease loss")
	}
	select {
	case <-taskDone:
	case <-time.After(time.Second):
		t.Fatal("task remained blocked in file synchronization after lease loss")
	}
	if got := lists.Load(); got != 1 {
		t.Fatalf("crack file list calls = %d; canceled task reached reconciliation", got)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("hashcat started after the task lost its lease: %v", err)
	}
	if got := finalCalls.Load(); got != 0 {
		t.Fatalf("terminal task updates = %d; canceled lease must not publish a stale final", got)
	}

	releaseOnce.Do(func() { close(releaseFirstList) })
	select {
	case err := <-backgroundDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("background synchronization did not finish")
	}
}

func TestLeaseLossCancelsRunningHashcatWithoutStaleFinal(t *testing.T) {
	h := newScriptHashcat(t, `while :; do :; done`)
	task, _ := leasedTask(t, &clientpb.CrackCommand{AttackMode: clientpb.CrackAttackMode_BRUTEFORCE, Identify: "?d"}, crackTaskKindCrack, 0, 1)
	var updateCalls atomic.Int32
	var triggerCalls atomic.Int32
	var finalCalls atomic.Int32
	mock := &mockSliverRPC{
		CrackTaskByIDFunc: func(context.Context, *clientpb.CrackTask) (*clientpb.CrackTask, error) {
			return proto.Clone(task).(*clientpb.CrackTask), nil
		},
		CrackTaskUpdateFunc: func(_ context.Context, update *clientpb.CrackTask) (*commonpb.Empty, error) {
			updateCalls.Add(1)
			if update.GetCompletedAt() != 0 {
				finalCalls.Add(1)
			}
			return &commonpb.Empty{}, nil
		},
		CrackstationTriggerFunc: func(context.Context, *clientpb.Event) (*commonpb.Empty, error) {
			if triggerCalls.Add(1) >= 2 {
				return nil, status.Error(codes.Aborted, "lease reassigned")
			}
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
	server := &SliverServer{rpc: newBufConnClient(t, mock)}
	dispatch := assignmentData(t, task)
	done := make(chan struct{})
	go func() {
		station.runCrackTask(server, dispatch)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("hashcat did not stop after lease loss")
	}
	if updateCalls.Load() != 1 || triggerCalls.Load() < 2 || finalCalls.Load() != 0 {
		t.Fatalf("updates=%d triggers=%d final=%d; stale completion must not be sent", updateCalls.Load(), triggerCalls.Load(), finalCalls.Load())
	}
}

func TestFinishTaskRetriesTransientTerminalSave(t *testing.T) {
	task, _ := leasedTask(t, &clientpb.CrackCommand{}, crackTaskKindCrack, 0, 1)
	// The initial lease timestamp can be stale after periodic renewals. A
	// transient terminal update must still retry until the server explicitly
	// rejects the lease.
	if err := protocompat.SetInt64(task, crackTaskLeaseExpiresAtField, time.Now().Add(-time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	mock := &mockSliverRPC{CrackTaskUpdateFunc: func(context.Context, *clientpb.CrackTask) (*commonpb.Empty, error) {
		if calls.Add(1) == 1 {
			return nil, status.Error(codes.Unavailable, "temporary")
		}
		return &commonpb.Empty{}, nil
	}}
	station, err := NewCrackstation("worker", t.TempDir(), newScriptHashcat(t, "exit 0"))
	if err != nil {
		t.Fatal(err)
	}
	station.finishTask(&SliverServer{rpc: newBufConnClient(t, mock)}, task, nil)
	if calls.Load() != 2 {
		t.Fatalf("terminal save attempts = %d; want retry then success", calls.Load())
	}
}

func TestBeginTaskRetriesTransientRunningSave(t *testing.T) {
	task, _ := leasedTask(t, &clientpb.CrackCommand{Hashes: []string{"large-server-owned-input"}}, crackTaskKindCrack, 0, 1)
	var calls atomic.Int32
	mock := &mockSliverRPC{
		CrackTaskByIDFunc: func(context.Context, *clientpb.CrackTask) (*clientpb.CrackTask, error) {
			return proto.Clone(task).(*clientpb.CrackTask), nil
		},
		CrackTaskUpdateFunc: func(_ context.Context, update *clientpb.CrackTask) (*commonpb.Empty, error) {
			if update.GetCommand() != nil {
				t.Error("running transition echoed server-owned command")
			}
			if calls.Add(1) == 1 {
				return nil, status.Error(codes.Unavailable, "timeout after commit")
			}
			return &commonpb.Empty{}, nil
		},
	}
	station, err := NewCrackstation("worker", t.TempDir(), newScriptHashcat(t, "exit 0"))
	if err != nil {
		t.Fatal(err)
	}
	started, _, err := station.beginTask(&SliverServer{rpc: newBufConnClient(t, mock)}, assignmentData(t, task), crackTaskKindCrack)
	if err != nil {
		t.Fatal(err)
	}
	if started == nil || calls.Load() != 2 {
		t.Fatalf("started=%v update attempts=%d; want idempotent retry", started != nil, calls.Load())
	}
}

func TestConnectionLossAfterRunningSavePreventsHashcatStart(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "hashcat-started")
	h := newScriptHashcat(t, `: > '`+marker+`'`)
	task, _ := leasedTask(t, &clientpb.CrackCommand{AttackMode: clientpb.CrackAttackMode_BRUTEFORCE, Identify: "?d"}, crackTaskKindCrack, 0, 1)
	connectionDone := make(chan struct{})
	var closeOnce sync.Once
	var updates atomic.Int32
	mock := &mockSliverRPC{
		CrackTaskByIDFunc: func(context.Context, *clientpb.CrackTask) (*clientpb.CrackTask, error) {
			return proto.Clone(task).(*clientpb.CrackTask), nil
		},
		CrackTaskUpdateFunc: func(context.Context, *clientpb.CrackTask) (*commonpb.Empty, error) {
			updates.Add(1)
			closeOnce.Do(func() { close(connectionDone) })
			return &commonpb.Empty{}, nil
		},
	}
	station, err := NewCrackstation("worker", t.TempDir(), h)
	if err != nil {
		t.Fatal(err)
	}
	station.runCrackTaskForConnection(&SliverServer{rpc: newBufConnClient(t, mock)}, assignmentData(t, task), connectionDone)
	if updates.Load() != 1 {
		t.Fatalf("updates = %d; want only confirmed running transition", updates.Load())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("hashcat started after its connection generation closed: %v", err)
	}
}

func TestConnectionLossCancelsRunningHashcatWithoutStaleFinal(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "hashcat-started")
	h := newScriptHashcat(t, `: > '`+marker+`'; while :; do :; done`)
	task, _ := leasedTask(t, &clientpb.CrackCommand{AttackMode: clientpb.CrackAttackMode_BRUTEFORCE, Identify: "?d"}, crackTaskKindCrack, 0, 1)
	connectionDone := make(chan struct{})
	var updateCalls atomic.Int32
	var finalCalls atomic.Int32
	mock := &mockSliverRPC{
		CrackTaskByIDFunc: func(context.Context, *clientpb.CrackTask) (*clientpb.CrackTask, error) {
			return proto.Clone(task).(*clientpb.CrackTask), nil
		},
		CrackTaskUpdateFunc: func(_ context.Context, update *clientpb.CrackTask) (*commonpb.Empty, error) {
			updateCalls.Add(1)
			if update.GetCompletedAt() != 0 {
				finalCalls.Add(1)
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
	server := &SliverServer{rpc: newBufConnClient(t, mock)}
	done := make(chan struct{})
	go func() {
		station.runCrackTaskForConnection(server, assignmentData(t, task), connectionDone)
		close(done)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("hashcat did not start")
		}
		time.Sleep(time.Millisecond)
	}
	close(connectionDone)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("hashcat did not stop after connection stream closed")
	}
	if updateCalls.Load() != 1 || finalCalls.Load() != 0 {
		t.Fatalf("updates=%d final=%d; disconnected task must not send stale completion", updateCalls.Load(), finalCalls.Load())
	}
}

func TestStopCancelsRunningHashcatWithoutStaleFinal(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "hashcat-started")
	h := newScriptHashcat(t, `printf '%s' "$$" > '`+marker+`'; while :; do :; done`)
	task, _ := leasedTask(t, &clientpb.CrackCommand{AttackMode: clientpb.CrackAttackMode_BRUTEFORCE, Identify: "?d"}, crackTaskKindCrack, 0, 1)
	var updateCalls atomic.Int32
	var finalCalls atomic.Int32
	mock := &mockSliverRPC{
		CrackTaskByIDFunc: func(context.Context, *clientpb.CrackTask) (*clientpb.CrackTask, error) {
			return proto.Clone(task).(*clientpb.CrackTask), nil
		},
		CrackTaskUpdateFunc: func(_ context.Context, update *clientpb.CrackTask) (*commonpb.Empty, error) {
			updateCalls.Add(1)
			if update.GetCompletedAt() != 0 {
				finalCalls.Add(1)
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
	server := &SliverServer{rpc: newBufConnClient(t, mock)}
	done := make(chan struct{})
	connectionDone := make(chan struct{})
	go func() {
		station.runCrackTaskForConnection(server, assignmentData(t, task), connectionDone)
		close(done)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("hashcat did not start")
		}
		time.Sleep(time.Millisecond)
	}
	station.Stop()
	pidData, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
	if err != nil {
		t.Fatalf("parse Hashcat test PID: %v", err)
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Signal(syscall.Signal(0)); err == nil {
		t.Fatalf("Hashcat process %d is still alive after Stop returned", pid)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("hashcat did not stop after crackstation shutdown")
	}
	if updateCalls.Load() != 1 || finalCalls.Load() != 0 {
		t.Fatalf("updates=%d final=%d; shutdown task must not send stale completion", updateCalls.Load(), finalCalls.Load())
	}
}

func TestManagedFileSyncRetriesTransientFailureForCrackAndKeyspace(t *testing.T) {
	for _, test := range []struct {
		name     string
		kind     crackTaskKind
		failList bool
	}{
		{name: "crack list retry", kind: crackTaskKindCrack, failList: true},
		{name: "keyspace chunk retry", kind: crackTaskKindKeyspace, failList: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := []byte("password\n")
			managedFile, digest := crackFileFixture(payload, clientpb.CrackFileType_WORDLIST)
			compressed := compressedPayload(t, payload)
			setCrackFileTransferSize(t, managedFile, int64(len(compressed)))
			command := &clientpb.CrackCommand{
				AttackMode: clientpb.CrackAttackMode_STRAIGHT,
				Hashes:     []string{"hash"},
				Identify:   "crackfile://wordlist/" + digest,
			}
			task, _ := leasedTask(t, command, test.kind, 0, 1)
			marker := filepath.Join(t.TempDir(), "hashcat-ran")
			h := newScriptHashcat(t, `
outfile=''
keyspace=false
for arg in "$@"; do
  case "$arg" in
    --outfile=*) outfile=${arg#--outfile=} ;;
    --keyspace) keyspace=true ;;
  esac
done
printf 'run\n' >> '`+marker+`'
if [ "$keyspace" = true ]; then printf '1\n'; else : > "$outfile"; fi
`)
			var listCalls atomic.Int32
			var chunkCalls atomic.Int32
			var final *clientpb.CrackTask
			mock := &mockSliverRPC{
				CrackTaskByIDFunc: func(context.Context, *clientpb.CrackTask) (*clientpb.CrackTask, error) {
					return proto.Clone(task).(*clientpb.CrackTask), nil
				},
				CrackTaskUpdateFunc: func(_ context.Context, update *clientpb.CrackTask) (*commonpb.Empty, error) {
					if update.GetCompletedAt() != 0 {
						final = proto.Clone(update).(*clientpb.CrackTask)
					}
					return &commonpb.Empty{}, nil
				},
				CrackstationTriggerFunc: func(context.Context, *clientpb.Event) (*commonpb.Empty, error) {
					return &commonpb.Empty{}, nil
				},
				CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
					call := listCalls.Add(1)
					if test.failList && call == 1 {
						return nil, status.Error(codes.Unavailable, "transient list outage")
					}
					return &clientpb.CrackFiles{Files: []*clientpb.CrackFile{managedFile}}, nil
				},
				CrackFileChunkDownloadFunc: func(_ context.Context, request *clientpb.CrackFileChunk) (*clientpb.CrackFileChunk, error) {
					call := chunkCalls.Add(1)
					if !test.failList && call == 1 {
						return nil, status.Error(codes.Unavailable, "transient chunk outage")
					}
					return &clientpb.CrackFileChunk{
						ID: request.GetID(), CrackFileID: request.GetCrackFileID(), N: request.GetN(), Data: compressed,
					}, nil
				},
			}
			station, err := NewCrackstation("worker", t.TempDir(), h)
			if err != nil {
				t.Fatal(err)
			}
			server := &SliverServer{rpc: newBufConnClient(t, mock)}
			if test.kind == crackTaskKindCrack {
				station.runCrackTask(server, assignmentData(t, task))
			} else {
				station.runKeyspaceTask(server, assignmentData(t, task))
			}
			if final == nil {
				t.Fatal("task did not complete after transient file sync recovered")
			}
			metadata, err := readCrackTaskMetadata(final)
			if err != nil {
				t.Fatal(err)
			}
			if metadata.State != crackTaskStateCompleted || final.GetErr() != "" {
				t.Fatalf("final task = state %d, err %q", metadata.State, final.GetErr())
			}
			if listCalls.Load() < 2 {
				t.Fatalf("list calls = %d; transient sync was not retried", listCalls.Load())
			}
			if runs, err := os.ReadFile(marker); err != nil || strings.Count(string(runs), "run\n") != 1 {
				t.Fatalf("hashcat runs = %q, %v", runs, err)
			}
		})
	}
}

func TestMissingManagedFileAfterSyncOutageHandlesTaskLifecycle(t *testing.T) {
	for _, test := range []struct {
		name         string
		kind         crackTaskKind
		wantTerminal bool
	}{
		{name: "durable crack relinquishes", kind: crackTaskKindCrack},
		{name: "standalone keyspace fails", kind: crackTaskKindKeyspace, wantTerminal: true},
		{name: "standalone query fails", kind: crackTaskKindQuery, wantTerminal: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			digest := strings.Repeat("a", 64)
			command := &clientpb.CrackCommand{
				AttackMode: clientpb.CrackAttackMode_STRAIGHT,
				Identify:   "crackfile://wordlist/" + digest,
			}
			if test.kind == crackTaskKindCrack {
				command.Hashes = []string{"hash"}
			}
			if test.kind == crackTaskKindQuery {
				if err := protocompat.SetBool(command, queryTotalCandidatesField, true); err != nil {
					t.Fatal(err)
				}
			}
			task, _ := leasedTask(t, command, test.kind, 0, 1)
			var updateCalls atomic.Int32
			var listCalls atomic.Int32
			var final *clientpb.CrackTask
			mock := &mockSliverRPC{
				CrackTaskByIDFunc: func(context.Context, *clientpb.CrackTask) (*clientpb.CrackTask, error) {
					return proto.Clone(task).(*clientpb.CrackTask), nil
				},
				CrackTaskUpdateFunc: func(_ context.Context, update *clientpb.CrackTask) (*commonpb.Empty, error) {
					updateCalls.Add(1)
					if update.GetCompletedAt() != 0 {
						final = proto.Clone(update).(*clientpb.CrackTask)
					}
					return &commonpb.Empty{}, nil
				},
				CrackstationTriggerFunc: func(context.Context, *clientpb.Event) (*commonpb.Empty, error) {
					return &commonpb.Empty{}, nil
				},
				CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
					listCalls.Add(1)
					return nil, status.Error(codes.Unavailable, "persistent sync outage")
				},
			}
			station, err := NewCrackstation("worker", t.TempDir(), newScriptHashcat(t, "exit 99"))
			if err != nil {
				t.Fatal(err)
			}
			server := &SliverServer{rpc: newBufConnClient(t, mock)}
			switch test.kind {
			case crackTaskKindCrack:
				station.runCrackTask(server, assignmentData(t, task))
			case crackTaskKindKeyspace:
				station.runKeyspaceTask(server, assignmentData(t, task))
			case crackTaskKindQuery:
				station.runQueryTask(server, assignmentData(t, task))
			}
			if listCalls.Load() != benchmarkMaxAttempts {
				t.Fatalf("sync attempts = %d; want %d", listCalls.Load(), benchmarkMaxAttempts)
			}
			if !test.wantTerminal {
				if updateCalls.Load() != 1 || final != nil {
					t.Fatalf("updates=%d final=%v; durable task must leave its running lease to requeue", updateCalls.Load(), final != nil)
				}
				return
			}
			if updateCalls.Load() != 2 || final == nil {
				t.Fatalf("updates=%d final=%v; standalone task must report terminal failure", updateCalls.Load(), final != nil)
			}
			metadata, err := readCrackTaskMetadata(final)
			if err != nil {
				t.Fatal(err)
			}
			if metadata.State != crackTaskStateFailed || !strings.Contains(final.GetErr(), "persistent sync outage") || !strings.Contains(final.GetErr(), errManagedCrackFileUnavailable.Error()) {
				t.Fatalf("state=%v error=%q; want joined synchronization and managed-file failure", metadata.State, final.GetErr())
			}
		})
	}
}

func TestHeartbeatCancelsAfterLastConfirmedLeaseExpires(t *testing.T) {
	task := &clientpb.CrackTask{ID: uuid.Must(uuid.NewV4()).String()}
	metadata := crackTaskMetadata{
		Attempt: 1, LeaseToken: "lease", UpdatedAt: 100, LeaseExpiresAt: 101,
	}
	mock := &mockSliverRPC{CrackstationTriggerFunc: func(context.Context, *clientpb.Event) (*commonpb.Empty, error) {
		return nil, status.Error(codes.Unavailable, "isolated unary outage")
	}}
	cancelled := make(chan struct{})
	var cancelOnce sync.Once
	heartbeat := newTaskHeartbeat(&SliverServer{rpc: newBufConnClient(t, mock)}, task, metadata, func() {
		cancelOnce.Do(func() { close(cancelled) })
	})
	heartbeat.Start()
	defer heartbeat.Stop()
	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("heartbeat kept work alive beyond its last confirmed lease")
	}
	if !heartbeat.LeaseLost() {
		t.Fatal("expired confirmed lease was not marked lost")
	}
}

func TestHeartbeatObserveIgnoresOversizedStatus(t *testing.T) {
	heartbeat := newTaskHeartbeat(nil, &clientpb.CrackTask{ID: "task"}, crackTaskMetadata{}, func() {})
	oversized := []byte(`{"status":3,"padding":"` + strings.Repeat("x", maxTaskStatusBytes) + `"}`)
	heartbeat.Observe(oversized)
	if got := string(heartbeat.status()); got != "{}" {
		t.Fatalf("oversized status replaced bounded snapshot: %q", got)
	}
	valid := []byte(`{"status":3,"devices":[{"temp":71}]}`)
	heartbeat.Observe(valid)
	if got := string(heartbeat.status()); got != string(valid) {
		t.Fatalf("valid status = %q, want %q", got, valid)
	}
}

func TestBeginTaskAndHeartbeatUseLeaseDurationAcrossClockSkew(t *testing.T) {
	for _, skew := range []time.Duration{-5 * time.Minute, 5 * time.Minute} {
		t.Run(skew.String(), func(t *testing.T) {
			task, _ := leasedTask(t, &clientpb.CrackCommand{}, crackTaskKindCrack, 0, 1)
			serverNow := time.Now().Add(skew).Unix()
			if err := protocompat.SetInt64(task, crackTaskUpdatedAtField, serverNow); err != nil {
				t.Fatal(err)
			}
			if err := protocompat.SetInt64(task, crackTaskLeaseExpiresAtField, serverNow+45); err != nil {
				t.Fatal(err)
			}
			mock := &mockSliverRPC{
				CrackTaskByIDFunc: func(context.Context, *clientpb.CrackTask) (*clientpb.CrackTask, error) {
					return proto.Clone(task).(*clientpb.CrackTask), nil
				},
				CrackTaskUpdateFunc: func(context.Context, *clientpb.CrackTask) (*commonpb.Empty, error) {
					return &commonpb.Empty{}, nil
				},
			}
			station, err := NewCrackstation("worker", t.TempDir(), newScriptHashcat(t, "exit 0"))
			if err != nil {
				t.Fatal(err)
			}
			started, metadata, err := station.beginTask(&SliverServer{rpc: newBufConnClient(t, mock)}, assignmentData(t, task), crackTaskKindCrack)
			if err != nil {
				t.Fatalf("beginTask with server clock skew %s: %v", skew, err)
			}
			before := time.Now()
			heartbeat := newTaskHeartbeat(nil, started, metadata, func() {})
			if heartbeat.leaseDuration != 45*time.Second {
				t.Fatalf("lease duration = %s; want 45s", heartbeat.leaseDuration)
			}
			heartbeat.deadlineMu.RLock()
			deadline := heartbeat.leaseDeadline
			heartbeat.deadlineMu.RUnlock()
			if deadline.Before(before.Add(44*time.Second)) || deadline.After(time.Now().Add(46*time.Second)) {
				t.Fatalf("local deadline = %s; want approximately now+45s", deadline)
			}
		})
	}

	metadata := crackTaskMetadata{UpdatedAt: 1, LeaseExpiresAt: 1 + int64((24*time.Hour)/time.Second)}
	if duration, err := taskLeaseDuration(metadata); err != nil || duration != maxTaskLeaseDuration {
		t.Fatalf("clamped lease duration = %s, %v; want %s", duration, err, maxTaskLeaseDuration)
	}
}

func TestHeartbeatRenewalDeadlineIncludesRPCResponseLatency(t *testing.T) {
	task := &clientpb.CrackTask{ID: uuid.Must(uuid.NewV4()).String()}
	metadata := crackTaskMetadata{
		Attempt: 1, LeaseToken: "lease", UpdatedAt: 100, LeaseExpiresAt: 101,
	}
	mock := &mockSliverRPC{CrackstationTriggerFunc: func(context.Context, *clientpb.Event) (*commonpb.Empty, error) {
		time.Sleep(1100 * time.Millisecond)
		return &commonpb.Empty{}, nil
	}}
	cancelled := make(chan struct{})
	var cancelOnce sync.Once
	heartbeat := newTaskHeartbeat(&SliverServer{rpc: newBufConnClient(t, mock)}, task, metadata, func() {
		cancelOnce.Do(func() { close(cancelled) })
	})
	heartbeat.sendEvent(time.Now(), []byte("{}"))
	heartbeat.tick()
	select {
	case <-cancelled:
	default:
		t.Fatal("delayed successful lease response incorrectly started a fresh full lease at response time")
	}
}

func TestInitialRunningLeaseDeadlineIncludesRPCResponseLatency(t *testing.T) {
	task, _ := leasedTask(t, &clientpb.CrackCommand{}, crackTaskKindCrack, 0, 1)
	if err := protocompat.SetInt64(task, crackTaskUpdatedAtField, 100); err != nil {
		t.Fatal(err)
	}
	if err := protocompat.SetInt64(task, crackTaskLeaseExpiresAtField, 101); err != nil {
		t.Fatal(err)
	}
	mock := &mockSliverRPC{
		CrackTaskByIDFunc: func(context.Context, *clientpb.CrackTask) (*clientpb.CrackTask, error) {
			return proto.Clone(task).(*clientpb.CrackTask), nil
		},
		CrackTaskUpdateFunc: func(context.Context, *clientpb.CrackTask) (*commonpb.Empty, error) {
			time.Sleep(1100 * time.Millisecond)
			return &commonpb.Empty{}, nil
		},
	}
	station, err := NewCrackstation("worker", t.TempDir(), newScriptHashcat(t, "exit 0"))
	if err != nil {
		t.Fatal(err)
	}
	started, metadata, err := station.beginTask(&SliverServer{rpc: newBufConnClient(t, mock)}, assignmentData(t, task), crackTaskKindCrack)
	if err != nil {
		t.Fatal(err)
	}
	cancelled := make(chan struct{})
	heartbeat := newTaskHeartbeat(nil, started, metadata, func() { close(cancelled) })
	if !heartbeat.LeaseLost() {
		t.Fatal("running transition response consumed the lease but local deadline was restarted after the response")
	}
	select {
	case <-cancelled:
	default:
		t.Fatal("expired initial local lease did not cancel task context")
	}
}
