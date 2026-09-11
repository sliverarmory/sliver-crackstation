package hashcat

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/sliverarmory/sliver-crackstation/pkg/protocompat"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func managedQueryCommand(t *testing.T, mode ManagedQueryMode) *clientpb.CrackCommand {
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
		protocompat.SetBool(command, crackFieldHashCopy, true),
		protocompat.SetUint32(command, crackFieldOutfileCheckTimerV7, 0),
		protocompat.SetString(command, crackQueryCrackstationSelectorField, "selected-worker"),
	} {
		if setterErr != nil {
			t.Fatal(setterErr)
		}
	}

	switch mode {
	case ManagedQueryKeyspace:
		command.AttackMode = clientpb.CrackAttackMode_BRUTEFORCE
		command.Identify = "?d?d"
		command.Keyspace = true
	case ManagedQueryTotalCandidates:
		command.AttackMode = clientpb.CrackAttackMode_BRUTEFORCE
		command.Identify = "?d?d"
		if err := protocompat.SetBool(command, crackFieldTotalCandidates, true); err != nil {
			t.Fatal(err)
		}
	case ManagedQueryLookup:
		command.AttackMode = clientpb.CrackAttackMode_BRUTEFORCE
		command.Identify = "?d?d"
		command.Skip = 2
		command.Limit = 8
		if err := protocompat.SetString(command, crackFieldLookup, "candidate"); err != nil {
			t.Fatal(err)
		}
	case ManagedQueryIdentify:
		command.Hashes = []string{"5f4dcc3b5aa765d61d8327deb882cf99"}
		if err := protocompat.SetBool(command, crackFieldIdentifyMode, true); err != nil {
			t.Fatal(err)
		}
	case ManagedQueryHashInfo:
		command.HashType = clientpb.HashType_NTLM
		if err := protocompat.SetUint32(command, crackFieldHashInfoLevel, 2); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unsupported test query mode %d", mode)
	}
	return command
}

func TestCrackManagedQueryRunsEveryModeInIsolatedDirectory(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())
	tests := []struct {
		mode       ManagedQueryMode
		wantFlag   string
		wantOutput string
	}{
		{ManagedQueryKeyspace, "--keyspace", "42\n"},
		{ManagedQueryTotalCandidates, "--total-candidates", "84\n"},
		{ManagedQueryLookup, "--lookup=candidate", "candidate -> 17\n"},
		{ManagedQueryIdentify, "--identify", "Mode 0: MD5\n"},
		{ManagedQueryHashInfo, "--hash-info", "Hash mode details\n"},
	}
	for _, test := range tests {
		t.Run(test.mode.String(), func(t *testing.T) {
			argumentsPath := filepath.Join(t.TempDir(), "arguments")
			workingDirectoryPath := filepath.Join(t.TempDir(), "working-directory")
			script := fmt.Sprintf(`
printf '%%s\n' "$@" > %q
pwd > %q
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
`, argumentsPath, workingDirectoryPath)
			h := testHashcatScript(t, script)
			result, gotMode, err := h.CrackManagedQueryWithResultContext(context.Background(), managedQueryCommand(t, test.mode))
			if err != nil {
				t.Fatalf("CrackManagedQueryWithResultContext() error = %v", err)
			}
			if gotMode != test.mode || string(result.Stdout) != test.wantOutput || result.ExitCode != 0 {
				t.Fatalf("mode=%v result=%#v; want mode=%v stdout=%q", gotMode, result, test.mode, test.wantOutput)
			}
			arguments, err := os.ReadFile(argumentsPath)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(arguments), test.wantFlag) {
				t.Fatalf("arguments %q do not contain %q", arguments, test.wantFlag)
			}
			for _, forbidden := range []string{"--status", "selected-worker"} {
				if strings.Contains(string(arguments), forbidden) {
					t.Fatalf("server-only or streaming argument %q leaked into %q", forbidden, arguments)
				}
			}
			workingDirectoryRaw, err := os.ReadFile(workingDirectoryPath)
			if err != nil {
				t.Fatal(err)
			}
			workingDirectory := strings.TrimSpace(string(workingDirectoryRaw))
			if !strings.HasPrefix(filepath.Base(workingDirectory), ManagedWorkDirPrefix) {
				t.Fatalf("query working directory = %q; want isolated %q prefix", workingDirectory, ManagedWorkDirPrefix)
			}
			if _, err := os.Stat(workingDirectory); !os.IsNotExist(err) {
				t.Fatalf("query working directory was not removed: %v", err)
			}
		})
	}
}

func TestCrackManagedLookupRedactsResolvedManagedPaths(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())
	const (
		firstReference  = "crackfile://wordlist/first"
		secondReference = "crackfile://wordlist/second"
		firstPath       = "/worker/private/cache/wordlists/first"
		secondPath      = "/worker/private/cache/wordlists/first-secondary"
	)
	h := testHashcatScript(t, `printf 'stdout: %s\n' "$@"; printf 'stderr: %s\n' "$@" >&2`)
	h.SetFileResolver(func(reference string) (string, error) {
		switch reference {
		case firstReference:
			return firstPath, nil
		case secondReference:
			return secondPath, nil
		default:
			return "", fmt.Errorf("unexpected managed reference %q", reference)
		}
	})
	command := managedQueryCommand(t, ManagedQueryLookup)
	command.AttackMode = clientpb.CrackAttackMode_COMBINATION
	command.Identify = ""
	if err := protocompat.SetStrings(command, crackFieldPositionalArguments, []string{firstReference, secondReference}); err != nil {
		t.Fatal(err)
	}
	result, mode, err := h.CrackManagedQueryWithResultContext(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if mode != ManagedQueryLookup {
		t.Fatalf("mode = %v; want lookup", mode)
	}
	for streamName, output := range map[string][]byte{"stdout": result.Stdout, "stderr": result.Stderr} {
		for _, path := range []string{firstPath, secondPath} {
			if strings.Contains(string(output), path) {
				t.Fatalf("%s exposed managed cache path %q in %q", streamName, path, output)
			}
		}
		for _, reference := range []string{firstReference, secondReference} {
			if !strings.Contains(string(output), reference) {
				t.Fatalf("%s did not replace managed cache path with %q in %q", streamName, reference, output)
			}
		}
	}
}

func TestValidateManagedLookupStraightRequiresExactlyOneWordlist(t *testing.T) {
	h := &Hashcat{}
	h.SetFileResolver(func(reference string) (string, error) {
		return "/worker/cache/" + strings.TrimPrefix(reference, "crackfile://wordlist/"), nil
	})
	for _, test := range []struct {
		name       string
		operands   []string
		wantAccept bool
	}{
		{name: "none"},
		{name: "one", operands: []string{"crackfile://wordlist/first"}, wantAccept: true},
		{name: "two", operands: []string{"crackfile://wordlist/first", "crackfile://wordlist/second"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := managedQueryCommand(t, ManagedQueryLookup)
			command.AttackMode = clientpb.CrackAttackMode_STRAIGHT
			command.Identify = ""
			if err := protocompat.SetStrings(command, crackFieldPositionalArguments, test.operands); err != nil {
				t.Fatal(err)
			}
			_, err := h.ValidateManagedQueryCommand(command)
			if test.wantAccept && err != nil {
				t.Fatalf("single managed wordlist rejected: %v", err)
			}
			if !test.wantAccept && (err == nil || !strings.Contains(err.Error(), "exactly one managed wordlist operand")) {
				t.Fatalf("validation error = %v; want exact single-wordlist requirement", err)
			}
		})
	}
}

func TestValidateManagedQueryCommandRejectsInvalidCombinations(t *testing.T) {
	h := &Hashcat{}
	tests := []struct {
		name  string
		build func(*testing.T) *clientpb.CrackCommand
	}{
		{
			name: "missing mode",
			build: func(t *testing.T) *clientpb.CrackCommand {
				return &clientpb.CrackCommand{HashType: clientpb.HashType_INVALID}
			},
		},
		{
			name: "conflicting modes",
			build: func(t *testing.T) *clientpb.CrackCommand {
				command := managedQueryCommand(t, ManagedQueryKeyspace)
				if err := protocompat.SetBool(command, crackFieldTotalCandidates, true); err != nil {
					t.Fatal(err)
				}
				return command
			},
		},
		{
			name: "keyspace range",
			build: func(t *testing.T) *clientpb.CrackCommand {
				command := managedQueryCommand(t, ManagedQueryKeyspace)
				command.Limit = 1
				return command
			},
		},
		{
			name: "candidate hashes",
			build: func(t *testing.T) *clientpb.CrackCommand {
				command := managedQueryCommand(t, ManagedQueryTotalCandidates)
				command.Hashes = []string{"hash"}
				return command
			},
		},
		{
			name: "empty lookup",
			build: func(t *testing.T) *clientpb.CrackCommand {
				command := managedQueryCommand(t, ManagedQueryLookup)
				if err := protocompat.SetString(command, crackFieldLookup, ""); err != nil {
					t.Fatal(err)
				}
				return command
			},
		},
		{
			name: "oversized lookup",
			build: func(t *testing.T) *clientpb.CrackCommand {
				command := managedQueryCommand(t, ManagedQueryLookup)
				if err := protocompat.SetString(command, crackFieldLookup, strings.Repeat("x", maxManagedLookupBytes+1)); err != nil {
					t.Fatal(err)
				}
				return command
			},
		},
		{
			name: "lookup line break",
			build: func(t *testing.T) *clientpb.CrackCommand {
				command := managedQueryCommand(t, ManagedQueryLookup)
				if err := protocompat.SetString(command, crackFieldLookup, "candidate\nother"); err != nil {
					t.Fatal(err)
				}
				return command
			},
		},
		{
			name: "identify without hashes",
			build: func(t *testing.T) *clientpb.CrackCommand {
				command := managedQueryCommand(t, ManagedQueryIdentify)
				command.Hashes = nil
				return command
			},
		},
		{
			name: "identify hash mode",
			build: func(t *testing.T) *clientpb.CrackCommand {
				command := managedQueryCommand(t, ManagedQueryIdentify)
				if err := protocompat.SetUint32(command, crackFieldHashMode, 0); err != nil {
					t.Fatal(err)
				}
				return command
			},
		},
		{
			name: "too many identify hashes",
			build: func(t *testing.T) *clientpb.CrackCommand {
				command := managedQueryCommand(t, ManagedQueryIdentify)
				command.Hashes = make([]string, maxManagedIdentifyHashes+1)
				for index := range command.Hashes {
					command.Hashes[index] = "a"
				}
				return command
			},
		},
		{
			name: "oversized identify input",
			build: func(t *testing.T) *clientpb.CrackCommand {
				command := managedQueryCommand(t, ManagedQueryIdentify)
				command.Hashes = []string{strings.Repeat("a", maxManagedIdentifyBytes+1)}
				return command
			},
		},
		{
			name: "identify unrelated flag",
			build: func(t *testing.T) *clientpb.CrackCommand {
				command := managedQueryCommand(t, ManagedQueryIdentify)
				command.Force = true
				return command
			},
		},
		{
			name: "hash info attack operand",
			build: func(t *testing.T) *clientpb.CrackCommand {
				command := managedQueryCommand(t, ManagedQueryHashInfo)
				if err := protocompat.SetStrings(command, crackFieldPositionalArguments, []string{"?d"}); err != nil {
					t.Fatal(err)
				}
				return command
			},
		},
		{
			name: "hash info excessive level",
			build: func(t *testing.T) *clientpb.CrackCommand {
				command := managedQueryCommand(t, ManagedQueryHashInfo)
				if err := protocompat.SetUint32(command, crackFieldHashInfoLevel, 3); err != nil {
					t.Fatal(err)
				}
				return command
			},
		},
		{
			name: "credential selector",
			build: func(t *testing.T) *clientpb.CrackCommand {
				command := managedQueryCommand(t, ManagedQueryKeyspace)
				if err := protocompat.SetStrings(command, crackQueryCredentialIDsField, []string{"credential-id"}); err != nil {
					t.Fatal(err)
				}
				return command
			},
		},
		{
			name: "future command field",
			build: func(t *testing.T) *clientpb.CrackCommand {
				command := managedQueryCommand(t, ManagedQueryKeyspace)
				if err := protocompat.SetBool(command, protoreflect.FieldNumber(174), true); err != nil {
					t.Fatal(err)
				}
				return command
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := h.ValidateManagedQueryCommand(test.build(t)); err == nil {
				t.Fatal("ValidateManagedQueryCommand() accepted invalid query")
			}
		})
	}
}

func TestValidateManagedQueryResultRejectsIncompleteOrInvalidOutput(t *testing.T) {
	tests := []struct {
		name   string
		mode   ManagedQueryMode
		result CommandResult
	}{
		{"stdout truncated", ManagedQueryLookup, CommandResult{ExitCode: 0, Stdout: []byte("value"), StdoutTruncated: true}},
		{"stderr truncated", ManagedQueryLookup, CommandResult{ExitCode: 0, Stdout: []byte("value"), StderrTruncated: true}},
		{"nonzero exit", ManagedQueryLookup, CommandResult{ExitCode: 1, Stdout: []byte("value")}},
		{"invalid UTF-8", ManagedQueryIdentify, CommandResult{ExitCode: 0, Stdout: []byte{0xff}}},
		{"invalid stderr UTF-8", ManagedQueryIdentify, CommandResult{ExitCode: 0, Stdout: []byte("value"), Stderr: []byte{0xff}}},
		{"empty", ManagedQueryHashInfo, CommandResult{ExitCode: 0}},
		{"non-decimal", ManagedQueryKeyspace, CommandResult{ExitCode: 0, Stdout: []byte("forty-two\n")}},
		{"non-canonical decimal", ManagedQueryTotalCandidates, CommandResult{ExitCode: 0, Stdout: []byte("042\n")}},
		{"overflow", ManagedQueryKeyspace, CommandResult{ExitCode: 0, Stdout: []byte("18446744073709551616\n")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateManagedQueryResult(test.mode, test.result); err == nil {
				t.Fatal("validateManagedQueryResult() accepted invalid output")
			}
		})
	}
}

func TestValidateManagedKeyspaceResultRejectsIncompleteOrInvalidOutput(t *testing.T) {
	tests := []struct {
		name   string
		result CommandResult
	}{
		{"stdout truncated", CommandResult{ExitCode: 0, Stdout: []byte("42\n"), StdoutTruncated: true}},
		{"stderr truncated", CommandResult{ExitCode: 0, Stdout: []byte("42\n"), StderrTruncated: true}},
		{"nonzero exit", CommandResult{ExitCode: 1, Stdout: []byte("42\n")}},
		{"invalid stdout UTF-8", CommandResult{ExitCode: 0, Stdout: []byte{'n', 'o', 't', 'e', 0xff, '\n', '4', '2', '\n'}}},
		{"invalid stderr UTF-8", CommandResult{ExitCode: 0, Stdout: []byte("42\n"), Stderr: []byte{0xff}}},
		{"non-canonical decimal", CommandResult{ExitCode: 0, Stdout: []byte("042\n")}},
		{"trailing text", CommandResult{ExitCode: 0, Stdout: []byte("42 candidates\n")}},
		{"prefixed line", CommandResult{ExitCode: 0, Stdout: []byte("notice\n42\n")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateManagedKeyspaceResult(test.result); err == nil {
				t.Fatal("ValidateManagedKeyspaceResult() accepted invalid output")
			}
		})
	}
}

func TestCrackManagedQueryTreatsHashcatExitOneAsFailure(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())
	h := testHashcatScript(t, "printf '42\\n'; exit 1")
	result, mode, err := h.CrackManagedQueryWithResultContext(context.Background(), managedQueryCommand(t, ManagedQueryKeyspace))
	if err == nil || !IsManagedQueryResultError(err) || result.ExitCode != 1 || mode != ManagedQueryKeyspace {
		t.Fatalf("result=%#v mode=%v err=%v; want query failure preserving exit 1", result, mode, err)
	}
}

func TestCrackManagedQueryKeepsProcessStartFailureOperational(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())
	h := testHashcatScript(t, "printf '42\\n'")
	if err := os.Remove(h.exe); err != nil {
		t.Fatal(err)
	}
	result, mode, err := h.CrackManagedQueryWithResultContext(context.Background(), managedQueryCommand(t, ManagedQueryKeyspace))
	if err == nil || IsManagedQueryResultError(err) || result.ExitCode != -1 || mode != ManagedQueryKeyspace {
		t.Fatalf("result=%#v mode=%v err=%v; want operational process-start failure", result, mode, err)
	}
}
