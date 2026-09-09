package hashcat

import (
	"os"
	"strings"
	"testing"

	"github.com/bishopfox/sliver/protobuf/clientpb"
)

func TestParseUserTaskArgsHashcatV7Options(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())

	h := &Hashcat{}
	args, cleanup, err := h.parseUserTaskArgs(&clientpb.CrackCommand{
		MultiplyAccelDisabled: true,
		Restore:               true,
		RestoreFile:           []byte("restore"),
		RulesFile:             []byte(":"),
	})
	for _, path := range cleanup {
		t.Cleanup(func() { _ = os.Remove(path) })
	}
	if err != nil {
		t.Fatalf("parseUserTaskArgs returned an error: %v", err)
	}

	joined := strings.Join(args, " ")
	for _, option := range []string{
		"--multiply-accel-disable",
		"--restore-position",
		"--restore-file-path=",
		"--rules-file=",
	} {
		if !strings.Contains(joined, option) {
			t.Errorf("expected %q in %q", option, joined)
		}
	}
	for _, obsolete := range []string{
		"--multiply-accel-disabled",
	} {
		if strings.Contains(joined, obsolete) {
			t.Errorf("did not expect obsolete option %q in %q", obsolete, joined)
		}
	}
	for _, arg := range args {
		if arg == "--restore" || strings.HasPrefix(arg, "--restore-file=") || strings.HasPrefix(arg, "--rules=") {
			t.Errorf("did not expect obsolete option %q in %q", arg, joined)
		}
	}
}

func TestParseUserTaskArgsRejectsSegmentSize(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())

	h := &Hashcat{}
	_, _, err := h.parseUserTaskArgs(&clientpb.CrackCommand{SegmentSize: 32})
	if err == nil {
		t.Fatal("expected an error for the removed --segment-size option")
	}
	if !strings.Contains(err.Error(), "does not support --segment-size") {
		t.Fatalf("unexpected error: %v", err)
	}
}
