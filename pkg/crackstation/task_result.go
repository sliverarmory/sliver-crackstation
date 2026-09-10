package crackstation

import (
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/sliverarmory/sliver-crackstation/pkg/hashcat"
	"github.com/sliverarmory/sliver-crackstation/pkg/protocompat"
)

const (
	crackTaskStdoutField           = 8
	crackTaskStderrField           = 10
	crackTaskExitCodeField         = 11
	crackTaskStdoutTruncatedField  = 12
	crackTaskStderrTruncatedField  = 13
	crackTaskStdoutTotalBytesField = 14
	crackTaskStderrTotalBytesField = 15
)

// setCrackTaskResult writes fields introduced after the currently pinned
// upstream Sliver master. protocompat stores them as unknown protobuf fields
// until a release containing the canonical schema is available.
func setCrackTaskResult(task *clientpb.CrackTask, result hashcat.CommandResult) error {
	if err := protocompat.SetBytes(task, crackTaskStdoutField, result.Stdout); err != nil {
		return err
	}
	if err := protocompat.SetBytes(task, crackTaskStderrField, result.Stderr); err != nil {
		return err
	}
	if err := protocompat.SetInt32(task, crackTaskExitCodeField, result.ExitCode); err != nil {
		return err
	}
	if err := protocompat.SetBool(task, crackTaskStdoutTruncatedField, result.StdoutTruncated); err != nil {
		return err
	}
	if err := protocompat.SetBool(task, crackTaskStderrTruncatedField, result.StderrTruncated); err != nil {
		return err
	}
	if err := protocompat.SetUint64(task, crackTaskStdoutTotalBytesField, result.StdoutTotalBytes); err != nil {
		return err
	}
	return protocompat.SetUint64(task, crackTaskStderrTotalBytesField, result.StderrTotalBytes)
}
