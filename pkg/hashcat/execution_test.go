package hashcat

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/sliverarmory/sliver-crackstation/pkg/protocompat"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func testHashcatScript(t *testing.T, body string) *Hashcat {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX helper script")
	}
	directory := t.TempDir()
	executable := filepath.Join(directory, "hashcat")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	return &Hashcat{exe: executable, cwd: directory}
}

func TestRunHashcatStreamingPreservesOutputAndForwardsStatus(t *testing.T) {
	h := testHashcatScript(t, `
printf '%s\n' 'starting' '{"session":"job","status":3,"progress":[1,10],"devices":[{"temp":71}]}' 'finished'
printf '%s\n' '{"status":4,"devices":[{"temp":72}]}' 'diagnostic' >&2
`)
	var statuses []string
	result, err := h.CrackWithResultStreaming(&clientpb.CrackCommand{}, func(status []byte) {
		statuses = append(statuses, string(status))
	})
	if err != nil {
		t.Fatalf("CrackWithResultStreaming() error = %v", err)
	}
	if result.ExitCode != 0 || !strings.Contains(string(result.Stdout), "starting") || !strings.Contains(string(result.Stderr), "diagnostic") {
		t.Fatalf("unexpected result: %#v", result)
	}
	if len(statuses) != 2 {
		t.Fatalf("status callbacks = %q; want two JSON frames", statuses)
	}
	for _, status := range statuses {
		if !strings.HasPrefix(status, "{") {
			t.Fatalf("callback was not JSON: %q", status)
		}
	}
}

func TestCaptureHashcatStreamBoundsStatusFramesAndKeepsDraining(t *testing.T) {
	ordinary := []byte(`* Hash-Mode 1000 (NTLM)`)
	oversized := []byte(`{"status":3,"padding":"` + strings.Repeat("x", maxHashcatStatusBytes) + `"}`)
	valid := []byte(`{"status":4,"devices":[{"temp":72}]}`)
	trailing := []byte(`Speed.#1.........: 42 H/s`)
	input := append(append([]byte(nil), ordinary...), '\n')
	input = append(input, oversized...)
	input = append(input, '\n')
	input = append(input, valid...)
	input = append(input, '\n')
	input = append(input, trailing...)
	var output bytes.Buffer
	var statuses [][]byte
	var lines [][]byte
	if err := captureHashcatStreamObserved(bytes.NewReader(input), &output, func(status []byte) {
		statuses = append(statuses, append([]byte(nil), status...))
	}, func(line []byte) {
		lines = append(lines, append([]byte(nil), line...))
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), input) {
		t.Fatal("bounded status parsing stopped draining process output")
	}
	if len(statuses) != 1 || !bytes.Equal(statuses[0], valid) {
		t.Fatalf("status callbacks = %q; want only the bounded trailing frame", statuses)
	}
	wantLines := [][]byte{ordinary, valid, trailing}
	if !slices.EqualFunc(lines, wantLines, bytes.Equal) {
		t.Fatalf("line callbacks = %q; want bounded complete lines %q", lines, wantLines)
	}
}

func TestRunHashcatStreamingObservesOnlyStdoutLines(t *testing.T) {
	h := testHashcatScript(t, `
printf '%s\n' '* Hash-Mode 1000 (NTLM)'
printf '%s\n' '* Hash-Mode 99999 (stderr decoy)' '{"status":3,"devices":[{"temp":73}]}' >&2
`)
	var statuses []string
	var lines []string
	_, err := h.runHashcatStreamingObserved(context.Background(), nil, nil, func(status []byte) {
		statuses = append(statuses, string(status))
	}, func(line []byte) {
		lines = append(lines, string(line))
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || !strings.Contains(statuses[0], `"temp":73`) {
		t.Fatalf("status callbacks = %q; stderr JSON status must still be forwarded", statuses)
	}
	wantLines := []string{"* Hash-Mode 1000 (NTLM)"}
	if !slices.Equal(lines, wantLines) {
		t.Fatalf("line callbacks = %q; want stdout only %q", lines, wantLines)
	}
}

func TestRunHashcatExitOneIsSuccessfulExhaustion(t *testing.T) {
	h := testHashcatScript(t, `printf 'exhausted\n'; printf 'not recovered\n' >&2; exit 1`)
	result, err := h.CrackWithResult(&clientpb.CrackCommand{})
	if err != nil {
		t.Fatalf("CrackWithResult() error = %v; exit 1 must be exhaustion", err)
	}
	if result.ExitCode != 1 || string(result.Stdout) != "exhausted\n" || string(result.Stderr) != "not recovered\n" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestManagedFileReferencesResolveForAllSupportedFields(t *testing.T) {
	h := &Hashcat{}
	var references []string
	h.SetFileResolver(func(reference string) (string, error) {
		references = append(references, reference)
		return "/cache/" + filepath.Base(reference), nil
	})
	command := &clientpb.CrackCommand{
		MarkovHcstat2: []byte("crackfile://hcstat2/markov"),
		RulesFile:     []byte("crackfile://rules/legacy"),
	}
	if err := protocompat.SetStrings(command, crackFieldPositionalArguments, []string{"hashes.txt", "crackfile://wordlist/words"}); err != nil {
		t.Fatal(err)
	}
	if err := protocompat.SetBytesList(command, crackFieldRulesFilesV7, [][]byte{[]byte("crackfile://rules/one"), []byte("crackfile://rules/two")}); err != nil {
		t.Fatal(err)
	}
	args, cleanup, err := h.parseUserTaskArgs(command)
	defer func() {
		for _, path := range cleanup {
			_ = os.Remove(path)
		}
	}()
	if err != nil {
		t.Fatalf("parseUserTaskArgs() error = %v", err)
	}
	wantReferences := []string{
		"crackfile://hcstat2/markov",
		"crackfile://rules/one",
		"crackfile://rules/two",
		"crackfile://wordlist/words",
	}
	if !slices.Equal(references, wantReferences) {
		t.Fatalf("resolver references = %q; want %q", references, wantReferences)
	}
	joined := strings.Join(args, "\n")
	for _, suffix := range []string{"markov", "one", "two", "words"} {
		if !strings.Contains(joined, "/cache/"+suffix) {
			t.Fatalf("args %q do not contain resolved %q", args, suffix)
		}
	}
	if strings.Contains(joined, "crackfile://") {
		t.Fatalf("managed URI leaked into Hashcat args: %q", args)
	}
}

func TestManagedFileReferenceRequiresResolver(t *testing.T) {
	command := &clientpb.CrackCommand{MarkovHcstat2: []byte("crackfile://hcstat2/missing")}
	if _, _, err := (&Hashcat{}).parseUserTaskArgs(command); err == nil {
		t.Fatal("managed reference without resolver was accepted")
	}
}

func TestWriteHashLinesAndClosePropagatesFailures(t *testing.T) {
	writeFailure := errors.New("write failed")
	closeFailure := errors.New("close failed")
	tests := []struct {
		name      string
		writer    *testHashWriteCloser
		wantError error
	}{
		{
			name:      "write error",
			writer:    &testHashWriteCloser{writeErr: writeFailure},
			wantError: writeFailure,
		},
		{
			name:      "short write",
			writer:    &testHashWriteCloser{shortWrite: true},
			wantError: io.ErrShortWrite,
		},
		{
			name:      "close error",
			writer:    &testHashWriteCloser{closeErr: closeFailure},
			wantError: closeFailure,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := writeHashLinesAndClose(test.writer, []string{"first", "second"})
			if !errors.Is(err, test.wantError) {
				t.Fatalf("error = %v, want %v", err, test.wantError)
			}
			if test.writer.closeCalls != 1 {
				t.Fatalf("close calls = %d, want 1", test.writer.closeCalls)
			}
		})
	}

	written := &testHashWriteCloser{}
	if err := writeHashLinesAndClose(written, []string{"first", "second"}); err != nil {
		t.Fatal(err)
	}
	if got, want := written.buffer.String(), "first\nsecond\n"; got != want {
		t.Fatalf("written hashes = %q, want %q", got, want)
	}
}

type testHashWriteCloser struct {
	buffer     bytes.Buffer
	writeErr   error
	closeErr   error
	shortWrite bool
	closeCalls int
}

func (writer *testHashWriteCloser) Write(data []byte) (int, error) {
	if writer.writeErr != nil {
		return 0, writer.writeErr
	}
	if writer.shortWrite {
		return len(data) - 1, nil
	}
	return writer.buffer.Write(data)
}

func (writer *testHashWriteCloser) Close() error {
	writer.closeCalls++
	return writer.closeErr
}

func TestLegacyManagedRulesReferenceResolves(t *testing.T) {
	h := &Hashcat{}
	h.SetFileResolver(func(reference string) (string, error) {
		if reference != "crackfile://rules/legacy" {
			t.Fatalf("reference = %q", reference)
		}
		return "/cache/legacy.rule", nil
	})
	args, cleanup, err := h.parseUserTaskArgs(&clientpb.CrackCommand{RulesFile: []byte("crackfile://rules/legacy")})
	defer func() {
		for _, path := range cleanup {
			_ = os.Remove(path)
		}
	}()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(args, "--rules-file=/cache/legacy.rule") {
		t.Fatalf("args = %q", args)
	}
}

func TestKeyboardLayoutMappingIsMaterializedByteForByte(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())
	payload := []byte{0x00, 0xff, '\n', ':', 0x1f, 0x80}
	args, cleanup, err := (&Hashcat{}).parseUserTaskArgs(&clientpb.CrackCommand{KeyboardLayoutMapping: payload})
	defer func() {
		for _, path := range cleanup {
			_ = os.Remove(path)
		}
	}()
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "--keyboard-layout-mapping="
	var mappingPath string
	for _, arg := range args {
		if strings.HasPrefix(arg, prefix) {
			mappingPath = strings.TrimPrefix(arg, prefix)
			break
		}
	}
	if mappingPath == "" {
		t.Fatalf("args = %q; missing keyboard layout mapping", args)
	}
	materialized, err := os.ReadFile(mappingPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(materialized, payload) {
		t.Fatalf("materialized mapping = %x; want %x", materialized, payload)
	}
}

func TestParseUserTaskArgsKeepsSafeRelativeMasksInline(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())
	cwd := t.TempDir()
	localMask := filepath.Join(cwd, "local.hcmask")
	if err := os.WriteFile(localMask, []byte("?d?d"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(cwd, "local-mask-dir"), 0700); err != nil {
		t.Fatal(err)
	}
	h := &Hashcat{cwd: cwd}
	h.SetFileResolver(func(reference string) (string, error) {
		return "/cache/" + filepath.Base(reference), nil
	})

	tests := []struct {
		name       string
		mode       clientpb.CrackAttackMode
		operands   []string
		wantReject bool
	}{
		{name: "bruteforce relative collision", mode: clientpb.CrackAttackMode_BRUTEFORCE, operands: []string{"local.hcmask"}},
		{name: "bruteforce absolute file", mode: clientpb.CrackAttackMode_BRUTEFORCE, operands: []string{localMask}, wantReject: true},
		{name: "bruteforce relative directory collision", mode: clientpb.CrackAttackMode_BRUTEFORCE, operands: []string{"local-mask-dir"}},
		{name: "hybrid wordlist mask collision", mode: clientpb.CrackAttackMode_HYBRID_WORDLIST_MASK, operands: []string{"crackfile://wordlist/words", "local.hcmask"}},
		{name: "hybrid mask wordlist collision", mode: clientpb.CrackAttackMode_HYBRID_MASK_WORDLIST, operands: []string{"local.hcmask", "crackfile://wordlist/words"}},
		{name: "inline mask", mode: clientpb.CrackAttackMode_BRUTEFORCE, operands: []string{"?d?d"}},
		{name: "managed hcmask", mode: clientpb.CrackAttackMode_BRUTEFORCE, operands: []string{"crackfile://wordlist/mask"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := managedTaskTestCommand(t, test.mode, test.operands)
			args, cleanup, err := h.parseUserTaskArgs(command)
			defer func() {
				for _, path := range cleanup {
					_ = os.Remove(path)
				}
			}()
			if test.wantReject {
				if err == nil || !strings.Contains(err.Error(), "crackstation-local") {
					t.Fatalf("parseUserTaskArgs error = %v; want station-local path rejection", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			joined := strings.Join(args, "\n")
			if strings.Contains(joined, "crackfile://") {
				t.Fatalf("managed URI leaked into args: %q", args)
			}
		})
	}
}

func TestParseUserTaskArgsKeepsSafeRelativeCustomCharsetsInline(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())
	cwd := t.TempDir()
	localCharset := filepath.Join(cwd, "local.hcchr")
	if err := os.WriteFile(localCharset, []byte("abcdef"), 0600); err != nil {
		t.Fatal(err)
	}
	h := &Hashcat{cwd: cwd}

	for name, command := range map[string]*clientpb.CrackCommand{
		"legacy absolute":   {CustomCharset1: localCharset},
		"managed untracked": {CustomCharset1: "crackfile://wordlist/charset"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := h.parseUserTaskArgs(command)
			if err == nil {
				t.Fatal("station-local or untracked managed custom charset was accepted")
			}
		})
	}

	v7Local := &clientpb.CrackCommand{}
	if err := protocompat.SetString(v7Local, crackFieldCustomCharset8, "/tmp/local.hcchr"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.parseUserTaskArgs(v7Local); err == nil || !strings.Contains(err.Error(), "crackstation-local") {
		t.Fatalf("v7 station-local custom charset error = %v", err)
	}

	inline := &clientpb.CrackCommand{CustomCharset1: "?l?d"}
	if err := protocompat.SetString(inline, crackFieldCustomCharset8, "local.hcchr"); err != nil {
		t.Fatal(err)
	}
	args, _, err := h.parseUserTaskArgs(inline)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--custom-charset1=?l?d", "--custom-charset8=local.hcchr"} {
		if !slices.Contains(args, want) {
			t.Fatalf("args = %q; want %q", args, want)
		}
	}
}

func TestManagedExecutionUsesIsolatedWorkingDirectory(t *testing.T) {
	rootParent := t.TempDir()
	t.Chdir(rootParent)
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", "relative-root")
	h := testHashcatScript(t, `
if [ -e hashcat.hcstat2 ]; then
  printf 'installation file leaked into managed cwd\n' >&2
  exit 90
fi
printf '%s\n' "$PWD"
printf '%s\n' "$@"
`)
	if err := os.WriteFile(filepath.Join(h.cwd, "hashcat.hcstat2"), []byte("station-local sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	command := managedTaskTestCommand(t, clientpb.CrackAttackMode_BRUTEFORCE, []string{"hashcat.hcstat2"})
	command.CustomCharset1 = "hashcat.hcstat2"
	result, err := h.CrackManagedWithResultStreamingContext(context.Background(), command, nil)
	if err != nil {
		t.Fatalf("managed execution failed: %v, stderr=%q", err, result.Stderr)
	}
	lines := strings.Split(strings.TrimSpace(string(result.Stdout)), "\n")
	if len(lines) < 2 {
		t.Fatalf("managed execution output = %q", result.Stdout)
	}
	workingDirectory := lines[0]
	if workingDirectory == h.cwd {
		t.Fatalf("managed task ran in Hashcat installation directory %q", h.cwd)
	}
	if _, err := os.Stat(workingDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("managed working directory was not cleaned: %v", err)
	}
	joined := strings.Join(lines[1:], "\n")
	if !strings.Contains(joined, "--custom-charset1=hashcat.hcstat2") || !strings.Contains(joined, "hashcat.hcstat2") {
		t.Fatalf("colliding inline values were not preserved in argv: %q", lines[1:])
	}
}

func TestManagedTaskRejectsWindowsNetworkVolumeAndDevicePathsLexically(t *testing.T) {
	h := &Hashcat{cwd: t.TempDir()}
	unsafeValues := []string{
		`\\attacker\share\mask.hcmask`,
		`//attacker/share/mask.hcmask`,
		`C:\masks\mask.hcmask`,
		`C:mask.hcmask`,
		`\Device\Mup\attacker\share`,
		`\\?\UNC\attacker\share\mask.hcmask`,
		`\\.\pipe\remote`,
		`NUL`,
		`COM1.txt`,
		`../../etc/passwd`,
		`masks/../secret.hcmask`,
		`masks\\COM1`,
		`masks/aux.txt`,
		`charsets\\NUL:stream`,
		"abc\x00def",
		"abc\rdef",
		"abc\ndef",
	}
	for _, value := range unsafeValues {
		t.Run("mask "+value, func(t *testing.T) {
			command := managedTaskTestCommand(t, clientpb.CrackAttackMode_BRUTEFORCE, []string{value})
			if err := h.ValidateManagedTaskCommand(command); err == nil {
				t.Fatalf("ValidateManagedTaskCommand(%q) unexpectedly accepted an unsafe value", value)
			}
		})
		t.Run("charset "+value, func(t *testing.T) {
			if _, _, err := h.parseUserTaskArgs(&clientpb.CrackCommand{CustomCharset1: value}); err == nil || !strings.Contains(err.Error(), "network, or device path") {
				t.Fatalf("parseUserTaskArgs charset %q error = %v; want lexical path rejection", value, err)
			}
		})
	}
}

func TestValidateManagedTaskCommandPositionalContract(t *testing.T) {
	cwd := t.TempDir()
	localMask := filepath.Join(cwd, "local.hcmask")
	if err := os.WriteFile(localMask, []byte("?d"), 0600); err != nil {
		t.Fatal(err)
	}
	h := &Hashcat{cwd: cwd}
	h.SetFileResolver(func(reference string) (string, error) {
		return "/cache/" + filepath.Base(reference), nil
	})
	wordlist := "crackfile://wordlist/words"

	valid := []struct {
		name     string
		mode     clientpb.CrackAttackMode
		operands []string
	}{
		{name: "straight", mode: clientpb.CrackAttackMode_STRAIGHT, operands: []string{wordlist, wordlist}},
		{name: "combination", mode: clientpb.CrackAttackMode_COMBINATION, operands: []string{wordlist, wordlist}},
		{name: "bruteforce inline", mode: clientpb.CrackAttackMode_BRUTEFORCE, operands: []string{"?d?d"}},
		{name: "bruteforce local-name collision remains inline", mode: clientpb.CrackAttackMode_BRUTEFORCE, operands: []string{"local.hcmask"}},
		{name: "bruteforce managed hcmask", mode: clientpb.CrackAttackMode_BRUTEFORCE, operands: []string{wordlist}},
		{name: "hybrid wordlist mask", mode: clientpb.CrackAttackMode_HYBRID_WORDLIST_MASK, operands: []string{wordlist, "?d"}},
		{name: "hybrid mask wordlist", mode: clientpb.CrackAttackMode_HYBRID_MASK_WORDLIST, operands: []string{"?d", wordlist}},
	}
	for _, test := range valid {
		t.Run("valid "+test.name, func(t *testing.T) {
			if err := h.ValidateManagedTaskCommand(managedTaskTestCommand(t, test.mode, test.operands)); err != nil {
				t.Fatal(err)
			}
		})
	}

	invalid := []struct {
		name     string
		mode     clientpb.CrackAttackMode
		operands []string
	}{
		{name: "straight local wordlist", mode: clientpb.CrackAttackMode_STRAIGHT, operands: []string{"words.txt"}},
		{name: "combination count", mode: clientpb.CrackAttackMode_COMBINATION, operands: []string{wordlist}},
		{name: "bruteforce count", mode: clientpb.CrackAttackMode_BRUTEFORCE, operands: []string{"?d", "?l"}},
		{name: "hybrid wordlist missing", mode: clientpb.CrackAttackMode_HYBRID_WORDLIST_MASK, operands: []string{"?d"}},
		{name: "hybrid mask missing", mode: clientpb.CrackAttackMode_HYBRID_MASK_WORDLIST, operands: []string{"?d"}},
		{name: "hybrid wordlist extra", mode: clientpb.CrackAttackMode_HYBRID_WORDLIST_MASK, operands: []string{wordlist, wordlist, "?d"}},
		{name: "hybrid mask extra", mode: clientpb.CrackAttackMode_HYBRID_MASK_WORDLIST, operands: []string{"?d", wordlist, wordlist}},
		{name: "unsupported pcfg", mode: clientpb.CrackAttackMode(4), operands: []string{wordlist}},
		{name: "unsupported generic", mode: clientpb.CrackAttackMode(8), operands: []string{wordlist}},
		{name: "unsupported association", mode: clientpb.CrackAttackMode(9), operands: []string{wordlist}},
		{name: "unsupported no attack", mode: clientpb.CrackAttackMode(10), operands: []string{wordlist}},
		{name: "unsupported hybrid", mode: clientpb.CrackAttackMode(12), operands: []string{wordlist}},
	}
	for _, test := range invalid {
		t.Run("invalid "+test.name, func(t *testing.T) {
			if err := h.ValidateManagedTaskCommand(managedTaskTestCommand(t, test.mode, test.operands)); err == nil {
				t.Fatal("invalid distributed positional contract was accepted")
			}
		})
	}
}

func TestValidateManagedTaskCommandRejectsStationLocalControlPaths(t *testing.T) {
	h := &Hashcat{}
	h.SetFileResolver(func(reference string) (string, error) {
		return "/cache/words", nil
	})
	wordlist := "crackfile://wordlist/words"

	debugMode := managedTaskTestCommand(t, clientpb.CrackAttackMode_STRAIGHT, []string{wordlist})
	debugMode.DebugMode = 2
	if err := h.ValidateManagedTaskCommand(debugMode); err == nil || !strings.Contains(err.Error(), "debug output") {
		t.Fatalf("debug mode error = %v, want managed-task rejection", err)
	}

	debugFile := managedTaskTestCommand(t, clientpb.CrackAttackMode_STRAIGHT, []string{wordlist})
	if err := protocompat.SetString(debugFile, crackFieldDebugFile, "/tmp/hashcat-debug"); err != nil {
		t.Fatal(err)
	}
	if err := h.ValidateManagedTaskCommand(debugFile); err == nil || !strings.Contains(err.Error(), "debug output") {
		t.Fatalf("debug file error = %v, want managed-task rejection", err)
	}

	seekDB := managedTaskTestCommand(t, clientpb.CrackAttackMode_STRAIGHT, []string{wordlist})
	if err := protocompat.SetString(seekDB, crackFieldSeekDBPath, "/tmp/seekdb"); err != nil {
		t.Fatal(err)
	}
	if err := h.ValidateManagedTaskCommand(seekDB); err == nil || !strings.Contains(err.Error(), "seek database") {
		t.Fatalf("seek database error = %v, want managed-task rejection", err)
	}

	for index, field := range []protoreflect.FieldNumber{
		crackFieldBridgeParameter1,
		crackFieldBridgeParameter2,
		crackFieldBridgeParameter3,
		crackFieldBridgeParameter4,
	} {
		bridge := managedTaskTestCommand(t, clientpb.CrackAttackMode_STRAIGHT, []string{wordlist})
		if err := protocompat.SetString(bridge, field, "/tmp/bridge-payload"); err != nil {
			t.Fatal(err)
		}
		if err := h.ValidateManagedTaskCommand(bridge); err == nil || !strings.Contains(err.Error(), "bridge parameters") {
			t.Fatalf("bridge parameter %d error = %v, want managed-task rejection", index+1, err)
		}
	}
}

func TestValidateManagedTaskCommandRejectsDistributedControlModes(t *testing.T) {
	h := &Hashcat{cwd: t.TempDir()}
	h.SetFileResolver(func(reference string) (string, error) {
		return filepath.Join(t.TempDir(), filepath.Base(reference)), nil
	})
	type mutation func(*clientpb.CrackCommand) error
	direct := func(set func(*clientpb.CrackCommand)) mutation {
		return func(command *clientpb.CrackCommand) error {
			set(command)
			return nil
		}
	}
	setBool := func(field protoreflect.FieldNumber) mutation {
		return func(command *clientpb.CrackCommand) error { return protocompat.SetBool(command, field, true) }
	}
	setUint32 := func(field protoreflect.FieldNumber, value uint32) mutation {
		return func(command *clientpb.CrackCommand) error { return protocompat.SetUint32(command, field, value) }
	}
	setString := func(field protoreflect.FieldNumber, value string) mutation {
		return func(command *clientpb.CrackCommand) error { return protocompat.SetString(command, field, value) }
	}

	tests := []struct {
		name   string
		mutate mutation
	}{
		{name: "debug mode", mutate: direct(func(command *clientpb.CrackCommand) { command.DebugMode = 1 })},
		{name: "debug file", mutate: setString(crackFieldDebugFile, "/tmp/debug")},
		{name: "hash mode outside int32", mutate: setUint32(crackFieldHashMode, ^uint32(0))},
		{name: "multi-byte separator", mutate: direct(func(command *clientpb.CrackCommand) { command.Separator = "::" })},
		{name: "segment size", mutate: direct(func(command *clientpb.CrackCommand) { command.SegmentSize = 32 })},
		{name: "negative legacy generated-rules seed", mutate: direct(func(command *clientpb.CrackCommand) { command.GenerateRulesSeed = -1 })},
		{name: "hash containing newline", mutate: direct(func(command *clientpb.CrackCommand) { command.Hashes = []string{"hash\nnext"} })},
		{name: "rule-left NUL", mutate: setString(crackFieldRuleLeft, "l\x00rule")},
		{name: "rule-right NUL", mutate: setString(crackFieldRuleRight, "r\x00rule")},
		{name: "generate-rules selection NUL", mutate: direct(func(command *clientpb.CrackCommand) { command.GenerateRulesFuncSel = "sel\x00ect" })},
		{name: "encoding-from NUL", mutate: setString(crackFieldEncodingFromName, "utf\x008")},
		{name: "encoding-to NUL", mutate: setString(crackFieldEncodingToName, "utf\x0016")},
		{name: "username", mutate: direct(func(command *clientpb.CrackCommand) { command.Username = true })},
		{name: "loopback", mutate: direct(func(command *clientpb.CrackCommand) { command.Loopback = true })},
		{name: "remove", mutate: direct(func(command *clientpb.CrackCommand) { command.Remove = true })},
		{name: "remove timer", mutate: direct(func(command *clientpb.CrackCommand) { command.RemoveTimer = 1 })},
		{name: "runtime", mutate: direct(func(command *clientpb.CrackCommand) { command.Runtime = 1 })},
		{name: "session", mutate: direct(func(command *clientpb.CrackCommand) { command.Session = "local-session" })},
		{name: "keep guessing", mutate: direct(func(command *clientpb.CrackCommand) { command.KeepGuessing = true })},
		{name: "machine readable", mutate: direct(func(command *clientpb.CrackCommand) { command.MachineReadable = true })},
		{name: "hardware monitoring disabled", mutate: direct(func(command *clientpb.CrackCommand) { command.HwmonDisable = true })},
		{name: "induction directory", mutate: setString(crackFieldInductionDir, "/tmp/induction")},
		{name: "outfile check directory", mutate: setString(crackFieldOutfileCheckDir, "/tmp/outfiles")},
		{name: "legacy outfile check timer", mutate: direct(func(command *clientpb.CrackCommand) { command.OutfileCheckTimer = 1 })},
		{name: "v7 outfile check timer", mutate: setUint32(crackFieldOutfileCheckTimerV7, 1)},
		{name: "truecrypt keyfiles", mutate: setString(crackFieldTruecryptKeyfiles, "/tmp/truecrypt.key")},
		{name: "veracrypt keyfiles", mutate: setString(crackFieldVeracryptKeyfiles, "/tmp/veracrypt.key")},
		{name: "benchmark", mutate: direct(func(command *clientpb.CrackCommand) { command.Benchmark = true })},
		{name: "benchmark all", mutate: direct(func(command *clientpb.CrackCommand) { command.BenchmarkAll = true })},
		{name: "benchmark min", mutate: setUint32(crackFieldBenchmarkMin, 1)},
		{name: "benchmark max presence", mutate: setUint32(crackFieldBenchmarkMax, 0)},
		{name: "speed only", mutate: direct(func(command *clientpb.CrackCommand) { command.SpeedOnly = true })},
		{name: "progress only", mutate: direct(func(command *clientpb.CrackCommand) { command.ProgressOnly = true })},
		{name: "stdout", mutate: direct(func(command *clientpb.CrackCommand) { command.Stdout = true })},
		{name: "show", mutate: direct(func(command *clientpb.CrackCommand) { command.Show = true })},
		{name: "left", mutate: direct(func(command *clientpb.CrackCommand) { command.Left = true })},
		{name: "hash info", mutate: direct(func(command *clientpb.CrackCommand) { command.HashInfo = true })},
		{name: "hash info level", mutate: setUint32(crackFieldHashInfoLevel, 1)},
		{name: "backend info", mutate: direct(func(command *clientpb.CrackCommand) { command.BackendInfo = true })},
		{name: "backend info level", mutate: setUint32(crackFieldBackendInfoLevel, 1)},
		{name: "total candidates", mutate: setBool(crackFieldTotalCandidates)},
		{name: "lookup", mutate: setString(crackFieldLookup, "candidate")},
		{name: "identify mode", mutate: setBool(crackFieldIdentifyMode)},
		{name: "restore", mutate: direct(func(command *clientpb.CrackCommand) { command.Restore = true })},
		{name: "restore file", mutate: direct(func(command *clientpb.CrackCommand) { command.RestoreFile = []byte("restore") })},
		{name: "restore position", mutate: setBool(crackFieldRestorePosition)},
		{name: "restore show command", mutate: setBool(crackFieldRestoreShowCommand)},
		{name: "stdin", mutate: func(command *clientpb.CrackCommand) error {
			return protocompat.SetBytes(command, crackFieldStdin, []byte("candidate"))
		}},
		{name: "brain server", mutate: direct(func(command *clientpb.CrackCommand) { command.BrainServer = true })},
		{name: "brain client", mutate: direct(func(command *clientpb.CrackCommand) { command.BrainClient = true })},
		{name: "brain server timer", mutate: direct(func(command *clientpb.CrackCommand) { command.BrainServerTimer = 1 })},
		{name: "brain client features", mutate: direct(func(command *clientpb.CrackCommand) { command.BrainClientFeatures = "1" })},
		{name: "brain host", mutate: direct(func(command *clientpb.CrackCommand) { command.BrainHost = "127.0.0.1" })},
		{name: "brain port", mutate: direct(func(command *clientpb.CrackCommand) { command.BrainPort = 1337 })},
		{name: "brain password", mutate: direct(func(command *clientpb.CrackCommand) { command.BrainPassword = "secret" })},
		{name: "brain session", mutate: direct(func(command *clientpb.CrackCommand) { command.BrainSession = "1" })},
		{name: "brain session whitelist", mutate: direct(func(command *clientpb.CrackCommand) { command.BrainSessionWhitelist = "1" })},
		{name: "brain feed", mutate: setBool(crackFieldBrainFeed)},
		{name: "v7 brain server timer presence", mutate: setUint32(crackFieldBrainServerTimerV7, 0)},
		{name: "v7 brain client features", mutate: setUint32(crackFieldBrainClientFeaturesV7, 1)},
		{name: "v7 brain session presence", mutate: setUint32(crackFieldBrainSessionV7, 0)},
		{name: "v7 brain whitelist", mutate: direct(func(command *clientpb.CrackCommand) {
			command.BrainSessionWhitelistV7 = []uint32{1}
		})},
		{name: "v7 brain password", mutate: setString(crackFieldBrainPasswordV7, "secret")},
		{name: "encrypted output", mutate: setString(crackFieldEncryptWithPubkey, "public-key")},
		{name: "seek database", mutate: setString(crackFieldSeekDBPath, "/tmp/seekdb")},
		{name: "bridge parameter 1", mutate: setString(crackFieldBridgeParameter1, "payload")},
		{name: "bridge parameter 2", mutate: setString(crackFieldBridgeParameter2, "payload")},
		{name: "bridge parameter 3", mutate: setString(crackFieldBridgeParameter3, "payload")},
		{name: "bridge parameter 4", mutate: setString(crackFieldBridgeParameter4, "payload")},
		{name: "unmanaged markov file", mutate: direct(func(command *clientpb.CrackCommand) { command.MarkovHcstat2 = []byte("/tmp/markov.hcstat2") })},
		{name: "unmanaged legacy rules file", mutate: direct(func(command *clientpb.CrackCommand) { command.RulesFile = []byte("/tmp/rules") })},
		{name: "unmanaged v7 rules file", mutate: func(command *clientpb.CrackCommand) error {
			return protocompat.SetBytesList(command, crackFieldRulesFilesV7, [][]byte{[]byte("/tmp/rules")})
		}},
		{name: "station local custom charset", mutate: direct(func(command *clientpb.CrackCommand) { command.CustomCharset1 = "/tmp/charset" })},
		{name: "station local v7 custom charset", mutate: setString(crackFieldCustomCharset5, "/tmp/charset")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := managedTaskTestCommand(t, clientpb.CrackAttackMode_BRUTEFORCE, []string{"?d"})
			if err := test.mutate(command); err != nil {
				t.Fatalf("mutate command: %v", err)
			}
			if err := h.ValidateManagedTaskCommand(command); err == nil {
				t.Fatal("distributed control mode was accepted")
			}
		})
	}
}

func TestValidateManagedTaskCommandAcceptsResolvedAuxiliaryFiles(t *testing.T) {
	h := &Hashcat{}
	h.SetFileResolver(func(reference string) (string, error) {
		return filepath.Join("/cache", filepath.Base(reference)), nil
	})
	command := managedTaskTestCommand(t, clientpb.CrackAttackMode_STRAIGHT, []string{"crackfile://wordlist/words"})
	command.MarkovHcstat2 = []byte("crackfile://hcstat2/markov")
	command.RulesFile = []byte("crackfile://rules/legacy")
	if err := protocompat.SetBytesList(command, crackFieldRulesFilesV7, [][]byte{[]byte("crackfile://rules/v7")}); err != nil {
		t.Fatal(err)
	}
	command.GenerateRulesSeed = -1
	if err := protocompat.SetUint32(command, crackFieldGenerateRulesSeedV7, 0); err != nil {
		t.Fatal(err)
	}
	command.OutfileCheckTimer = 5
	if err := protocompat.SetUint32(command, crackFieldOutfileCheckTimerV7, 0); err != nil {
		t.Fatal(err)
	}
	if err := h.ValidateManagedTaskCommand(command); err != nil {
		t.Fatalf("managed auxiliary files rejected: %v", err)
	}
}

func managedTaskTestCommand(t *testing.T, mode clientpb.CrackAttackMode, operands []string) *clientpb.CrackCommand {
	t.Helper()
	command := &clientpb.CrackCommand{AttackMode: mode}
	if err := protocompat.SetStrings(command, crackFieldPositionalArguments, operands); err != nil {
		t.Fatal(err)
	}
	return command
}
