package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/sliverarmory/sliver-crackstation/pkg/crackstation"
	"github.com/sliverarmory/sliver-crackstation/pkg/hashcat"
)

func newLifecycleTestCrackstation(t *testing.T) *crackstation.Crackstation {
	t.Helper()
	station, err := crackstation.NewCrackstation("test", t.TempDir(), &hashcat.Hashcat{})
	if err != nil {
		t.Fatal(err)
	}
	return station
}

func assertStationStopped(t *testing.T, station *crackstation.Crackstation) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		station.Start()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("crackstation was not stopped before lifecycle function returned")
	}
}

func TestStartLogOnlyContextStopsOnCancellation(t *testing.T) {
	station := newLifecycleTestCrackstation(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		startLogOnlyContext(ctx, station, io.Discard)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("log-only mode did not return after cancellation")
	}
	assertStationStopped(t, station)
}

func TestStartTUIContextStopsOnCancellation(t *testing.T) {
	station := newLifecycleTestCrackstation(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := startTUIContext(ctx, station, tea.WithInput(nil), tea.WithOutput(io.Discard), tea.WithoutRenderer())
	if !errors.Is(err, tea.ErrProgramKilled) || !errors.Is(err, context.Canceled) {
		t.Fatalf("TUI cancellation error = %v; want killed and context canceled", err)
	}
	if err := normalizeTUIShutdownError(ctx, err); err != nil {
		t.Fatalf("normalized TUI cancellation error = %v", err)
	}
	assertStationStopped(t, station)
}

func TestNormalizeTUIShutdownErrorPreservesUnrelatedFailure(t *testing.T) {
	internalFailure := fmt.Errorf("%w: renderer failed", tea.ErrProgramKilled)
	if got := normalizeTUIShutdownError(context.Background(), internalFailure); !errors.Is(got, tea.ErrProgramKilled) {
		t.Fatalf("normalizeTUIShutdownError() = %v; want internal failure", got)
	}
}
