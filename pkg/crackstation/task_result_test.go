package crackstation

import (
	"testing"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/sliverarmory/sliver-crackstation/pkg/hashcat"
	"github.com/sliverarmory/sliver-crackstation/pkg/protocompat"
)

func TestSetCrackTaskResult(t *testing.T) {
	task := &clientpb.CrackTask{}
	result := hashcat.CommandResult{
		Stdout:           []byte("out"),
		Stderr:           []byte("err"),
		ExitCode:         23,
		StdoutTruncated:  true,
		StderrTruncated:  true,
		StdoutTotalBytes: 30,
		StderrTotalBytes: 40,
	}
	if err := setCrackTaskResult(task, result); err != nil {
		t.Fatalf("setCrackTaskResult() error = %v", err)
	}

	reader, err := protocompat.NewReader(task)
	if err != nil {
		t.Fatalf("NewReader() error = %v", err)
	}
	stdout, err := reader.Bytes(crackTaskStdoutField)
	if err != nil || string(stdout) != "out" {
		t.Fatalf("stdout = %q, %v; want out, nil", stdout, err)
	}
	stderr, err := reader.Bytes(crackTaskStderrField)
	if err != nil || string(stderr) != "err" {
		t.Fatalf("stderr = %q, %v; want err, nil", stderr, err)
	}
	exitCode, err := reader.Int32(crackTaskExitCodeField)
	if err != nil || exitCode != 23 {
		t.Fatalf("exit code = %d, %v; want 23, nil", exitCode, err)
	}
	stdoutTruncated, err := reader.Bool(crackTaskStdoutTruncatedField)
	if err != nil || !stdoutTruncated {
		t.Fatalf("stdout truncated = %v, %v; want true, nil", stdoutTruncated, err)
	}
	stderrTruncated, err := reader.Bool(crackTaskStderrTruncatedField)
	if err != nil || !stderrTruncated {
		t.Fatalf("stderr truncated = %v, %v; want true, nil", stderrTruncated, err)
	}
	stdoutTotal, err := reader.Uint64(crackTaskStdoutTotalBytesField)
	if err != nil || stdoutTotal != 30 {
		t.Fatalf("stdout total = %d, %v; want 30, nil", stdoutTotal, err)
	}
	stderrTotal, err := reader.Uint64(crackTaskStderrTotalBytesField)
	if err != nil || stderrTotal != 40 {
		t.Fatalf("stderr total = %d, %v; want 40, nil", stderrTotal, err)
	}
}
