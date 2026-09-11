package crackstation

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/sliverarmory/sliver-crackstation/pkg/hashcat"
	"github.com/sliverarmory/sliver-crackstation/pkg/protocompat"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	queryTotalCandidatesField = 129
	queryLookupField          = 130
	queryIdentifyModeField    = 142
	queryHashInfoLevelField   = 146
	queryCrackstationField    = 173
)

func crackQueryTaskCommand(t *testing.T, mode hashcat.ManagedQueryMode) *clientpb.CrackCommand {
	t.Helper()
	command := &clientpb.CrackCommand{
		HashType:       clientpb.HashType_INVALID,
		Quiet:          true,
		MarkovDisable:  true,
		RestoreDisable: true,
		PotfileDisable: true,
		LogfileDisable: true,
	}
	for _, setterErr := range []error{
		protocompat.SetBool(command, crackCommandHashCopyField, true),
		protocompat.SetUint32(command, crackCommandOutfileCheckTimerV7Field, 0),
		protocompat.SetString(command, queryCrackstationField, "selected-worker"),
	} {
		if setterErr != nil {
			t.Fatal(setterErr)
		}
	}
	switch mode {
	case hashcat.ManagedQueryKeyspace:
		command.AttackMode = clientpb.CrackAttackMode_BRUTEFORCE
		command.Identify = "?d?d"
		command.Keyspace = true
	case hashcat.ManagedQueryTotalCandidates:
		command.AttackMode = clientpb.CrackAttackMode_BRUTEFORCE
		command.Identify = "?d?d"
		if err := protocompat.SetBool(command, queryTotalCandidatesField, true); err != nil {
			t.Fatal(err)
		}
	case hashcat.ManagedQueryLookup:
		command.AttackMode = clientpb.CrackAttackMode_BRUTEFORCE
		command.Identify = "?d?d"
		command.Skip = 3
		command.Limit = 7
		if err := protocompat.SetString(command, queryLookupField, "candidate"); err != nil {
			t.Fatal(err)
		}
	case hashcat.ManagedQueryIdentify:
		command.Hashes = []string{"5f4dcc3b5aa765d61d8327deb882cf99"}
		if err := protocompat.SetBool(command, queryIdentifyModeField, true); err != nil {
			t.Fatal(err)
		}
	case hashcat.ManagedQueryHashInfo:
		command.HashType = clientpb.HashType_NTLM
		if err := protocompat.SetUint32(command, queryHashInfoLevelField, 2); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unsupported test query mode %d", mode)
	}
	return command
}

func TestCrackQueryEventCompletesEveryModeThroughTaskResultFields(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())
	tests := []struct {
		mode       hashcat.ManagedQueryMode
		wantOutput string
		wantFlag   string
	}{
		{hashcat.ManagedQueryTotalCandidates, "84\n", "--total-candidates"},
		{hashcat.ManagedQueryLookup, "candidate -> 17\n", "--lookup=candidate"},
		{hashcat.ManagedQueryIdentify, "Mode 0: MD5\n", "--identify"},
		{hashcat.ManagedQueryHashInfo, "Hash mode details\n", "--hash-info"},
	}
	for _, test := range tests {
		t.Run(test.mode.String(), func(t *testing.T) {
			argumentsPath := filepath.Join(t.TempDir(), "arguments")
			script := fmt.Sprintf(`
printf '%%s\n' "$@" > %q
output=''
for arg in "$@"; do
  case "$arg" in
    --keyspace) output='42' ;;
    --total-candidates) output='84' ;;
    --lookup=candidate) output='candidate -> 17' ;;
    --identify) output='Mode 0: MD5' ;;
    --hash-info) output='Hash mode details' ;;
  esac
done
printf '%%s\n' "$output"
`, argumentsPath)
			task, _ := leasedTask(t, crackQueryTaskCommand(t, test.mode), crackTaskKindQuery, 0, 0)
			capture := &taskCapture{}
			server := taskServer(t, task, capture)
			station, err := NewCrackstation("worker", t.TempDir(), newScriptHashcat(t, script))
			if err != nil {
				t.Fatal(err)
			}
			station.handleEvent(server, &clientpb.Event{EventType: crackQueryEvent, Data: assignmentData(t, task)})

			updates, _ := capture.snapshot()
			if len(updates) != 2 {
				t.Fatalf("task updates = %d; want running and terminal", len(updates))
			}
			for index, update := range updates {
				if update.GetCommand() != nil {
					t.Fatalf("task update %d echoed server-owned command", index)
				}
			}
			final := updates[len(updates)-1]
			metadata, err := readCrackTaskMetadata(final)
			if err != nil {
				t.Fatal(err)
			}
			if metadata.Kind != crackTaskKindQuery || metadata.State != crackTaskStateCompleted || final.GetErr() != "" {
				t.Fatalf("final task metadata=%#v error=%q", metadata, final.GetErr())
			}
			reader, err := protocompat.NewReader(final)
			if err != nil {
				t.Fatal(err)
			}
			stdout, _ := reader.Bytes(crackTaskStdoutField)
			exitCode, _ := reader.Int32(crackTaskExitCodeField)
			if string(stdout) != test.wantOutput || exitCode != 0 {
				t.Fatalf("stdout=%q exit=%d; want %q, 0", stdout, exitCode, test.wantOutput)
			}
			legacyKeyspace, _ := reader.String(crackTaskKeyspaceField)
			if legacyKeyspace != "" {
				t.Fatalf("generic query populated legacy keyspace field: %q", legacyKeyspace)
			}
			arguments, err := os.ReadFile(argumentsPath)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(arguments), test.wantFlag) {
				t.Fatalf("arguments %q do not contain %q", arguments, test.wantFlag)
			}
			if station.Activity() != nil {
				t.Fatal("query activity remained set after task completion")
			}
		})
	}
}

func TestCrackQueryInvalidResultCompletesForServerValidation(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())
	task, _ := leasedTask(t, crackQueryTaskCommand(t, hashcat.ManagedQueryTotalCandidates), crackTaskKindQuery, 0, 0)
	capture := &taskCapture{}
	server := taskServer(t, task, capture)
	station, err := NewCrackstation("worker", t.TempDir(), newScriptHashcat(t, "printf '42\\n'; printf 'diagnostic\\n' >&2; exit 1"))
	if err != nil {
		t.Fatal(err)
	}
	station.runQueryTask(server, assignmentData(t, task))

	updates, _ := capture.snapshot()
	final := updates[len(updates)-1]
	metadata, err := readCrackTaskMetadata(final)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := protocompat.NewReader(final)
	if err != nil {
		t.Fatal(err)
	}
	stdout, _ := reader.Bytes(crackTaskStdoutField)
	stderr, _ := reader.Bytes(crackTaskStderrField)
	exitCode, _ := reader.Int32(crackTaskExitCodeField)
	if metadata.State != crackTaskStateCompleted || final.GetErr() != "" {
		t.Fatalf("state=%v error=%q; want completed result for authoritative server validation", metadata.State, final.GetErr())
	}
	if string(stdout) != "42\n" || string(stderr) != "diagnostic\n" || exitCode != 1 {
		t.Fatalf("stdout=%q stderr=%q exit=%d; process result was not retained", stdout, stderr, exitCode)
	}
}

func TestCrackQueryEventRejectsLegacyKeyspaceKind(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())
	marker := filepath.Join(t.TempDir(), "hashcat-started")
	task, _ := leasedTask(t, crackQueryTaskCommand(t, hashcat.ManagedQueryKeyspace), crackTaskKindQuery, 0, 0)
	capture := &taskCapture{}
	server := taskServer(t, task, capture)
	station, err := NewCrackstation("worker", t.TempDir(), newScriptHashcat(t, fmt.Sprintf(": > %q", marker)))
	if err != nil {
		t.Fatal(err)
	}
	station.runQueryTask(server, assignmentData(t, task))

	updates, _ := capture.snapshot()
	final := updates[len(updates)-1]
	metadata, err := readCrackTaskMetadata(final)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.State != crackTaskStateFailed || !strings.Contains(final.GetErr(), "crack-keyspace compatibility event") {
		t.Fatalf("state=%v error=%q; query event must reject keyspace", metadata.State, final.GetErr())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("hashcat ran for keyspace on generic query event: %v", err)
	}
}

func TestLeaseLossCancelsRunningCrackQueryWithoutStaleFinal(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())
	h := newScriptHashcat(t, `while :; do :; done`)
	task, _ := leasedTask(t, crackQueryTaskCommand(t, hashcat.ManagedQueryTotalCandidates), crackTaskKindQuery, 0, 0)
	var updateCalls atomic.Int32
	var triggerCalls atomic.Int32
	var finalCalls atomic.Int32
	mock := &mockSliverRPC{
		CrackTaskByIDFunc: func(context.Context, *clientpb.CrackTask) (*clientpb.CrackTask, error) {
			return task, nil
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
	done := make(chan struct{})
	go func() {
		station.runQueryTask(server, assignmentData(t, task))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("hashcat query did not stop after lease loss")
	}
	if updateCalls.Load() != 1 || triggerCalls.Load() < 2 || finalCalls.Load() != 0 {
		t.Fatalf("updates=%d triggers=%d final=%d; stale query completion must not be sent", updateCalls.Load(), triggerCalls.Load(), finalCalls.Load())
	}
}
