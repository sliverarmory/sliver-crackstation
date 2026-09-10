package crackstation

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	testRoot, err := os.MkdirTemp("", "sliver-crackstation-tests-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create isolated crackstation test root: %v\n", err)
		os.Exit(1)
	}
	previousRoot, hadPreviousRoot := os.LookupEnv("SLIVER_CRACKSTATION_ROOT_DIR")
	if err := os.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", testRoot); err != nil {
		fmt.Fprintf(os.Stderr, "set isolated crackstation test root: %v\n", err)
		_ = os.RemoveAll(testRoot)
		os.Exit(1)
	}

	code := m.Run()
	if hadPreviousRoot {
		_ = os.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", previousRoot)
	} else {
		_ = os.Unsetenv("SLIVER_CRACKSTATION_ROOT_DIR")
	}
	_ = os.RemoveAll(testRoot)
	os.Exit(code)
}
