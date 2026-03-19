package crackstation

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/gofrs/uuid"
	"github.com/sliverarmory/sliver-crackstation/assets"
	"github.com/sliverarmory/sliver-crackstation/pkg/hashcat"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCrackstationCrackTaskE2E(t *testing.T) {
	if os.Getenv("SLIVER_HASHCAT_E2E") == "" {
		t.Skip("set SLIVER_HASHCAT_E2E=1 to enable hashcat end-to-end test")
	}
	if testing.Short() {
		t.Skip("skipping hashcat end-to-end test in short mode")
	}

	rootDir := t.TempDir()
	oldRoot := os.Getenv("SLIVER_CRACKSTATION_ROOT_DIR")
	if err := os.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", rootDir); err != nil {
		t.Fatalf("failed to set SLIVER_CRACKSTATION_ROOT_DIR: %v", err)
	}
	if oldRoot == "" {
		t.Cleanup(func() { _ = os.Unsetenv("SLIVER_CRACKSTATION_ROOT_DIR") })
	} else {
		t.Cleanup(func() { _ = os.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", oldRoot) })
	}

	assets.Setup(true, false)
	hashcatInstance := hashcat.NewHashcat(assets.GetHashcatDir())

	plaintext, err := randomLowerString(3)
	if err != nil {
		t.Fatalf("failed to generate plaintext: %v", err)
	}
	hash := md5.Sum([]byte(plaintext))
	hashHex := hex.EncodeToString(hash[:])

	potfilePath := filepath.Join(rootDir, "hashcat.potfile")
	potfile, err := os.Create(potfilePath)
	if err != nil {
		t.Fatalf("failed to create potfile: %v", err)
	}
	if err := potfile.Close(); err != nil {
		t.Fatalf("failed to close potfile: %v", err)
	}

	taskID := uuid.Must(uuid.NewV4())
	crackCmd := &clientpb.CrackCommand{
		AttackMode: clientpb.CrackAttackMode_BRUTEFORCE,
		HashType:   clientpb.HashType_MD5,
		Hashes:     []string{hashHex},
		Identify:   "?l?l?l",
		Potfile:    []byte(potfilePath),
		Force:      true,
		Quiet:      true,
	}
	task := &clientpb.CrackTask{ID: taskID.String(), Command: crackCmd}

	updateCh := make(chan *clientpb.CrackTask, 2)

	mock := &mockSliverRPC{
		CrackstationRegisterFunc: func(_ *clientpb.Crackstation, stream rpcpb.SliverRPC_CrackstationRegisterServer) error {
			event := &clientpb.Event{EventType: crackEvent, Data: taskID.Bytes()}
			if err := stream.Send(event); err != nil {
				return status.Errorf(codes.Internal, "failed to send event: %v", err)
			}
			return nil
		},
		CrackTaskByIDFunc: func(context.Context, *clientpb.CrackTask) (*clientpb.CrackTask, error) {
			return task, nil
		},
		CrackTaskUpdateFunc: func(_ context.Context, update *clientpb.CrackTask) (*commonpb.Empty, error) {
			updateCh <- update
			return &commonpb.Empty{}, nil
		},
	}

	client := newBufConnClient(t, mock)
	station, err := NewCrackstation("e2e", t.TempDir(), hashcatInstance)
	if err != nil {
		t.Fatalf("failed to create crackstation: %v", err)
	}
	server := &SliverServer{Crackstation: station, rpc: client}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	events, err := server.Events(ctx)
	if err != nil {
		t.Fatalf("failed to open event stream: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for event := range events {
			station.handleEvent(server, event)
		}
	}()

	var finalUpdate *clientpb.CrackTask
	deadline := time.After(90 * time.Second)
	for {
		select {
		case update := <-updateCh:
			if update.CompletedAt != 0 {
				finalUpdate = update
				goto done
			}
		case <-deadline:
			t.Fatal("timeout waiting for crack task completion")
		}
	}

done:
	wg.Wait()
	if finalUpdate == nil {
		t.Fatal("no crack task update received")
	}
	if finalUpdate.Err != "" {
		t.Fatalf("crack task failed: %s", finalUpdate.Err)
	}

	potfileData, err := os.ReadFile(potfilePath)
	if err != nil {
		t.Fatalf("failed to read potfile: %v", err)
	}
	if !strings.Contains(string(potfileData), hashHex+":"+plaintext) {
		t.Fatalf("potfile did not contain cracked value for %s", hashHex)
	}
}

func randomLowerString(length int) (string, error) {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i := range buf {
		buf[i] = letters[int(buf[i])%len(letters)]
	}
	return string(buf), nil
}
