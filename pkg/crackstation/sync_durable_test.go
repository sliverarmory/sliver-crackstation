package crackstation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/klauspost/compress/zstd"
	"github.com/sliverarmory/sliver-crackstation/pkg/operatorconfig"
	"github.com/sliverarmory/sliver-crackstation/pkg/protocompat"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func compressedPayload(t *testing.T, payload []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	writer, err := zstd.NewWriter(&compressed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func crackFileFixture(payload []byte, fileType clientpb.CrackFileType) (*clientpb.CrackFile, string) {
	digest := sha256.Sum256(payload)
	digestString := hex.EncodeToString(digest[:])
	return &clientpb.CrackFile{
		ID: "file-id", Name: "managed", Sha2_256: digestString,
		UncompressedSize: int64(len(payload)), Type: fileType,
		IsCompressed: true,
		Chunks:       []*clientpb.CrackFileChunk{{ID: "chunk", N: 0}},
	}, digestString
}

func setCrackFileTransferSize(t *testing.T, file *clientpb.CrackFile, size int64) {
	t.Helper()
	if err := protocompat.SetInt64(file, crackFileCompressedSize, size); err != nil {
		t.Fatal(err)
	}
}

func TestResolveCrackFileVerifiesContentAndURI(t *testing.T) {
	payload := []byte("passwords\n")
	_, digest := crackFileFixture(payload, clientpb.CrackFileType_WORDLIST)
	station := &Crackstation{dataDir: t.TempDir()}
	directory := station.dataDirForType(clientpb.CrackFileType_WORDLIST)
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, digest)
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	resolved, err := station.ResolveCrackFile("crackfile://wordlist/" + digest)
	if err != nil || resolved != path {
		t.Fatalf("ResolveCrackFile() = %q, %v; want %q", resolved, err, path)
	}

	for _, reference := range []string{
		"crackfile://wordlists/" + digest,
		"crackfile://wordlist/" + strings.ToUpper(digest),
		"crackfile://wordlist/../" + digest,
		"crackfile://wordlist/" + digest + "?unsafe=1",
		"file://wordlist/" + digest,
	} {
		if _, err := station.ResolveCrackFile(reference); err == nil {
			t.Fatalf("ResolveCrackFile(%q) accepted invalid reference", reference)
		} else if errors.Is(err, errManagedCrackFileUnavailable) {
			t.Fatalf("ResolveCrackFile(%q) classified invalid syntax as unavailable cache", reference)
		}
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	reference := "crackfile://wordlist/" + digest
	if _, err := station.ResolveCrackFile(reference); !errors.Is(err, errManagedCrackFileUnavailable) {
		t.Fatalf("ResolveCrackFile() corrupt cache error = %v, want unavailable sentinel", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := station.ResolveCrackFile(reference); !errors.Is(err, errManagedCrackFileUnavailable) {
		t.Fatalf("ResolveCrackFile() missing cache error = %v, want unavailable sentinel", err)
	}
}

func TestSyncFilesPropagatesFailureAndLeavesFinalUntouched(t *testing.T) {
	payload := []byte("correct payload")
	file, digest := crackFileFixture(payload, clientpb.CrackFileType_RULES)
	mock := &mockSliverRPC{
		CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
			return &clientpb.CrackFiles{Files: []*clientpb.CrackFile{file}}, nil
		},
		CrackFileChunkDownloadFunc: func(context.Context, *clientpb.CrackFileChunk) (*clientpb.CrackFileChunk, error) {
			return nil, status.Error(codes.Unavailable, "download unavailable")
		},
	}
	station := &Crackstation{dataDir: t.TempDir(), syncLock: &sync.Mutex{}}
	directory := station.dataDirForType(clientpb.CrackFileType_RULES)
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	finalPath := filepath.Join(directory, digest)
	if err := os.WriteFile(finalPath, []byte("old corrupt content"), 0600); err != nil {
		t.Fatal(err)
	}
	err := station.SyncFiles(&SliverServer{rpc: newBufConnClient(t, mock)})
	if err == nil || !strings.Contains(err.Error(), "download unavailable") {
		t.Fatalf("SyncFiles() error = %v", err)
	}
	content, readErr := os.ReadFile(finalPath)
	if readErr != nil || string(content) != "old corrupt content" {
		t.Fatalf("failed sync changed visible final: %q, %v", content, readErr)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".crackfile-") {
			t.Fatalf("temporary file leaked after failure: %s", entry.Name())
		}
	}
}

func TestSyncStagingFileName(t *testing.T) {
	tests := map[string]bool{
		".crackfile-compressed-123456789": true,
		".crackfile-compressed-orphan":    true,
		".crackfile-uncompressed-987654":  true,
		".crackfile-uncompressed-orphan":  true,
		".crackfile-compressed-":          false,
		".crackfile-uncompressed-":        false,
		".crackfile-compressed":           false,
		".crackfile-uncompressed":         false,
		".crackfile-other-123":            false,
		".env":                            false,
		"crackfile-compressed-123":        false,
	}
	for name, want := range tests {
		t.Run(name, func(t *testing.T) {
			if got := isSyncStagingFileName(name); got != want {
				t.Fatalf("isSyncStagingFileName(%q) = %t, want %t", name, got, want)
			}
		})
	}
}

func TestSyncFilesCleansStaleStagingBeforeFailedReconciliation(t *testing.T) {
	mock := &mockSliverRPC{
		CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
			return nil, status.Error(codes.Unavailable, "list unavailable")
		},
	}
	station := &Crackstation{dataDir: t.TempDir(), syncLock: &sync.Mutex{}}
	staleNames := []string{
		".crackfile-compressed-123456789",
		".crackfile-compressed-orphan",
		".crackfile-uncompressed-987654",
		".crackfile-uncompressed-orphan",
	}
	preservedNames := []string{
		".env",
		".keep",
		".crackfile-compressed-",
		".crackfile-uncompressed-",
		".crackfile-other-123",
	}
	for _, fileType := range []clientpb.CrackFileType{
		clientpb.CrackFileType_WORDLIST,
		clientpb.CrackFileType_RULES,
		clientpb.CrackFileType_MARKOV_HCSTAT2,
	} {
		directory := station.dataDirForType(fileType)
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
		for _, name := range append(append([]string{}, staleNames...), preservedNames...) {
			if err := os.WriteFile(filepath.Join(directory, name), []byte("sentinel"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		stagingDirectory := filepath.Join(directory, ".crackfile-compressed-directory")
		if err := os.Mkdir(stagingDirectory, 0700); err != nil {
			t.Fatal(err)
		}
	}

	err := station.SyncFiles(&SliverServer{rpc: newBufConnClient(t, mock)})
	if err == nil || !strings.Contains(err.Error(), "list unavailable") {
		t.Fatalf("SyncFiles() error = %v, want list failure", err)
	}
	for _, fileType := range []clientpb.CrackFileType{
		clientpb.CrackFileType_WORDLIST,
		clientpb.CrackFileType_RULES,
		clientpb.CrackFileType_MARKOV_HCSTAT2,
	} {
		directory := station.dataDirForType(fileType)
		for _, name := range staleNames {
			if _, err := os.Stat(filepath.Join(directory, name)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("stale staging file %q was not removed: %v", filepath.Join(directory, name), err)
			}
		}
		for _, name := range preservedNames {
			if _, err := os.Stat(filepath.Join(directory, name)); err != nil {
				t.Errorf("unrelated dotfile %q was removed: %v", filepath.Join(directory, name), err)
			}
		}
		stagingDirectory := filepath.Join(directory, ".crackfile-compressed-directory")
		if info, err := os.Stat(stagingDirectory); err != nil || !info.IsDir() {
			t.Errorf("matching directory %q was removed: %v", stagingDirectory, err)
		}
	}
}

func TestSyncFilesContextCancelsWhileWaitingForSyncGate(t *testing.T) {
	firstListStarted := make(chan struct{})
	releaseFirstList := make(chan struct{})
	var lists atomic.Int32
	mock := &mockSliverRPC{
		CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
			if lists.Add(1) == 1 {
				close(firstListStarted)
				<-releaseFirstList
			}
			return &clientpb.CrackFiles{}, nil
		},
	}
	station := &Crackstation{dataDir: t.TempDir(), syncLock: &sync.Mutex{}}
	server := &SliverServer{rpc: newBufConnClient(t, mock)}
	firstDone := make(chan error, 1)
	go func() { firstDone <- station.SyncFiles(server) }()
	select {
	case <-firstListStarted:
	case <-time.After(time.Second):
		t.Fatal("first synchronization did not acquire the gate")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := station.SyncFilesContext(ctx, server); !errors.Is(err, context.Canceled) {
		t.Fatalf("blocked SyncFilesContext() error = %v, want context cancellation", err)
	}
	if got := lists.Load(); got != 1 {
		t.Fatalf("crack file list calls = %d; canceled waiter reached reconciliation", got)
	}

	close(releaseFirstList)
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("first synchronization did not finish")
	}
}

func TestSyncFilesContextCancelsActiveChunkDownload(t *testing.T) {
	payload := []byte("cancellable transfer")
	file, digest := crackFileFixture(payload, clientpb.CrackFileType_WORDLIST)
	chunkStarted := make(chan struct{})
	mock := &mockSliverRPC{
		CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
			return &clientpb.CrackFiles{Files: []*clientpb.CrackFile{file}}, nil
		},
		CrackFileChunkDownloadFunc: func(ctx context.Context, _ *clientpb.CrackFileChunk) (*clientpb.CrackFileChunk, error) {
			close(chunkStarted)
			<-ctx.Done()
			return nil, status.FromContextError(ctx.Err()).Err()
		},
	}
	station := &Crackstation{dataDir: t.TempDir(), syncLock: &sync.Mutex{}}
	server := &SliverServer{rpc: newBufConnClient(t, mock)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- station.SyncFilesContext(ctx, server) }()
	select {
	case <-chunkStarted:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("chunk download did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("SyncFilesContext() error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("active chunk download ignored context cancellation")
	}

	directory := station.dataDirForType(file.GetType())
	if _, err := os.Stat(filepath.Join(directory, digest)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled download published a final file: %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if isSyncStagingFileName(entry.Name()) {
			t.Fatalf("canceled download leaked staging file %q", entry.Name())
		}
	}
}

func TestSyncEventWorkerCancelsActiveRPCOnStop(t *testing.T) {
	listStarted := make(chan struct{})
	listCanceled := make(chan struct{})
	mock := &mockSliverRPC{
		CrackFilesListFunc: func(ctx context.Context, _ *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
			close(listStarted)
			<-ctx.Done()
			close(listCanceled)
			return nil, status.FromContextError(ctx.Err()).Err()
		},
	}
	station := &Crackstation{
		dataDir:     t.TempDir(),
		syncLock:    &sync.Mutex{},
		syncEvents:  make(chan *SliverServer, 1),
		syncPending: make(map[*SliverServer]syncRequestState),
		done:        make(chan struct{}),
	}
	server := &SliverServer{rpc: newBufConnClient(t, mock)}
	go station.syncEventWorker()
	station.requestSync(server)
	select {
	case <-listStarted:
	case <-time.After(time.Second):
		close(station.done)
		t.Fatal("background synchronization did not start")
	}
	close(station.done)
	select {
	case <-listCanceled:
	case <-time.After(time.Second):
		t.Fatal("crackstation shutdown did not cancel the active sync RPC")
	}
}

func TestSyncFilesReplacesCorruptDeduplicatesAndPrunesOnlyManaged(t *testing.T) {
	payload := []byte("one\ntwo\n")
	file, digest := crackFileFixture(payload, clientpb.CrackFileType_WORDLIST)
	compressed := compressedPayload(t, payload)
	duplicate := proto.Clone(file).(*clientpb.CrackFile)
	var downloads atomic.Int32
	mock := &mockSliverRPC{
		CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
			return &clientpb.CrackFiles{Files: []*clientpb.CrackFile{file, duplicate}}, nil
		},
		CrackFileChunkDownloadFunc: func(_ context.Context, request *clientpb.CrackFileChunk) (*clientpb.CrackFileChunk, error) {
			downloads.Add(1)
			return &clientpb.CrackFileChunk{ID: request.GetID(), CrackFileID: request.GetCrackFileID(), N: request.GetN(), Data: compressed}, nil
		},
	}
	station := &Crackstation{dataDir: t.TempDir(), syncLock: &sync.Mutex{}}
	directory := station.dataDirForType(clientpb.CrackFileType_WORDLIST)
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	finalPath := filepath.Join(directory, digest)
	if err := os.WriteFile(finalPath, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	stale := strings.Repeat("a", 64)
	shortHex := strings.Repeat("b", 63)
	for name, content := range map[string]string{stale: "stale", "notes.txt": "keep", shortHex: "keep short hex"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := station.SyncFiles(&SliverServer{rpc: newBufConnClient(t, mock)}); err != nil {
		t.Fatal(err)
	}
	if downloads.Load() != 1 {
		t.Fatalf("chunk downloads = %d; duplicate inventory should download once", downloads.Load())
	}
	content, err := os.ReadFile(finalPath)
	if err != nil || !bytes.Equal(content, payload) {
		t.Fatalf("published content = %q, %v", content, err)
	}
	if _, err := os.Stat(filepath.Join(directory, stale)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale managed file was not pruned: %v", err)
	}
	for _, name := range []string{"notes.txt", shortHex} {
		if _, err := os.Stat(filepath.Join(directory, name)); err != nil {
			t.Fatalf("unmanaged file %q was pruned: %v", name, err)
		}
	}
}

func TestStatusSnapshotsAreIndependentDuringSync(t *testing.T) {
	payload := []byte("race-safe")
	file, _ := crackFileFixture(payload, clientpb.CrackFileType_MARKOV_HCSTAT2)
	compressed := compressedPayload(t, payload)
	release := make(chan struct{})
	mock := &mockSliverRPC{
		CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
			return &clientpb.CrackFiles{Files: []*clientpb.CrackFile{file}}, nil
		},
		CrackFileChunkDownloadFunc: func(_ context.Context, request *clientpb.CrackFileChunk) (*clientpb.CrackFileChunk, error) {
			<-release
			return &clientpb.CrackFileChunk{ID: request.GetID(), CrackFileID: request.GetCrackFileID(), N: request.GetN(), Data: compressed}, nil
		},
	}
	station := &Crackstation{Name: "worker", dataDir: t.TempDir(), syncLock: &sync.Mutex{}}
	done := make(chan error, 1)
	go func() { done <- station.SyncFiles(&SliverServer{rpc: newBufConnClient(t, mock)}) }()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		status := station.Status()
		if status.GetIsSyncing() {
			if status.GetSyncing() == nil {
				t.Fatal("syncing status omitted snapshot")
			}
			status.Syncing.Progress["caller-mutation"] = 1
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if station.Status().GetIsSyncing() {
		t.Fatal("station remained syncing after reconciliation")
	}
}

func TestSyncFilesSupportsUncompressedTransfer(t *testing.T) {
	payload := []byte("raw-transfer")
	file, digest := crackFileFixture(payload, clientpb.CrackFileType_RULES)
	file.IsCompressed = false
	mock := &mockSliverRPC{
		CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
			return &clientpb.CrackFiles{Files: []*clientpb.CrackFile{file}}, nil
		},
		CrackFileChunkDownloadFunc: func(_ context.Context, request *clientpb.CrackFileChunk) (*clientpb.CrackFileChunk, error) {
			return &clientpb.CrackFileChunk{CrackFileID: request.GetCrackFileID(), N: request.GetN(), Data: payload}, nil
		},
	}
	station := &Crackstation{dataDir: t.TempDir(), syncLock: &sync.Mutex{}}
	if err := station.SyncFiles(&SliverServer{rpc: newBufConnClient(t, mock)}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(station.dataDirForType(file.GetType()), digest))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("raw transfer = %q, %v", got, err)
	}
}

func TestDownloadCrackFileRejectsMismatchedAndEmptyChunkResponses(t *testing.T) {
	payload := []byte("payload")
	for name, response := range map[string]*clientpb.CrackFileChunk{
		"wrong file":     {CrackFileID: "other", N: 0, Data: payload},
		"wrong sequence": {CrackFileID: "file-id", N: 2, Data: payload},
		"empty data":     {CrackFileID: "file-id", N: 0},
	} {
		t.Run(name, func(t *testing.T) {
			file, _ := crackFileFixture(payload, clientpb.CrackFileType_WORDLIST)
			file.IsCompressed = false
			mock := &mockSliverRPC{CrackFileChunkDownloadFunc: func(context.Context, *clientpb.CrackFileChunk) (*clientpb.CrackFileChunk, error) {
				return response, nil
			}}
			station := &Crackstation{dataDir: t.TempDir(), syncLock: &sync.Mutex{}}
			station.beginSync([]*clientpb.CrackFile{file})
			defer station.endSync()
			if err := station.downloadCrackFile(&SliverServer{rpc: newBufConnClient(t, mock)}, file); err == nil {
				t.Fatal("downloadCrackFile() accepted invalid chunk response")
			}
		})
	}
}

func TestDownloadCrackFileEnforcesDeclaredTransferSize(t *testing.T) {
	payload := []byte("raw-payload")
	for name, declaredSize := range map[string]int64{
		"oversized response": int64(len(payload) - 1),
		"truncated response": int64(len(payload) + 1),
	} {
		t.Run(name, func(t *testing.T) {
			file, digest := crackFileFixture(payload, clientpb.CrackFileType_RULES)
			file.IsCompressed = false
			setCrackFileTransferSize(t, file, declaredSize)
			mock := &mockSliverRPC{CrackFileChunkDownloadFunc: func(_ context.Context, request *clientpb.CrackFileChunk) (*clientpb.CrackFileChunk, error) {
				return &clientpb.CrackFileChunk{CrackFileID: request.GetCrackFileID(), N: request.GetN(), Data: payload}, nil
			}}
			station := &Crackstation{dataDir: t.TempDir(), syncLock: &sync.Mutex{}}
			station.beginSync([]*clientpb.CrackFile{file})
			defer station.endSync()
			err := station.downloadCrackFile(&SliverServer{rpc: newBufConnClient(t, mock)}, file)
			if err == nil || !strings.Contains(err.Error(), "compressed") {
				t.Fatalf("downloadCrackFile() error = %v; want declared transfer-size failure", err)
			}
			if _, statErr := os.Stat(filepath.Join(station.dataDirForType(file.GetType()), digest)); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("invalid transfer published a final file: %v", statErr)
			}
		})
	}
}

func TestDownloadCrackFileBoundsLegacyInventoryWithoutTransferSize(t *testing.T) {
	payload := []byte("x")
	file, digest := crackFileFixture(payload, clientpb.CrackFileType_WORDLIST)
	file.IsCompressed = false
	if err := validateCrackFiles([]*clientpb.CrackFile{file}); err != nil {
		t.Fatalf("legacy inventory should remain readable: %v", err)
	}
	limit := crackFileTransferLimit(file.GetUncompressedSize(), 0)
	if limit != file.GetUncompressedSize()+legacyTransferMinimumOverhead {
		t.Fatalf("legacy transfer limit = %d", limit)
	}
	oversized := make([]byte, limit+1)
	mock := &mockSliverRPC{CrackFileChunkDownloadFunc: func(_ context.Context, request *clientpb.CrackFileChunk) (*clientpb.CrackFileChunk, error) {
		return &clientpb.CrackFileChunk{CrackFileID: request.GetCrackFileID(), N: request.GetN(), Data: oversized}, nil
	}}
	station := &Crackstation{dataDir: t.TempDir(), syncLock: &sync.Mutex{}}
	station.beginSync([]*clientpb.CrackFile{file})
	defer station.endSync()
	err := station.downloadCrackFile(&SliverServer{rpc: newBufConnClient(t, mock)}, file)
	if err == nil || !strings.Contains(err.Error(), "legacy transfer limit") {
		t.Fatalf("downloadCrackFile() error = %v; want legacy transfer bound", err)
	}
	if _, statErr := os.Stat(filepath.Join(station.dataDirForType(file.GetType()), digest)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("oversized legacy transfer published a final file: %v", statErr)
	}
}

func TestDownloadCrackFileBoundsUncompressedOutput(t *testing.T) {
	payload := []byte("decompression-overrun")
	compressed := compressedPayload(t, payload)
	file, digest := crackFileFixture(payload, clientpb.CrackFileType_WORDLIST)
	file.UncompressedSize = int64(len(payload) - 1)
	setCrackFileTransferSize(t, file, int64(len(compressed)))
	mock := &mockSliverRPC{CrackFileChunkDownloadFunc: func(_ context.Context, request *clientpb.CrackFileChunk) (*clientpb.CrackFileChunk, error) {
		return &clientpb.CrackFileChunk{CrackFileID: request.GetCrackFileID(), N: request.GetN(), Data: compressed}, nil
	}}
	station := &Crackstation{dataDir: t.TempDir(), syncLock: &sync.Mutex{}}
	station.beginSync([]*clientpb.CrackFile{file})
	defer station.endSync()
	err := station.downloadCrackFile(&SliverServer{rpc: newBufConnClient(t, mock)}, file)
	if err == nil || !strings.Contains(err.Error(), "uncompressed data exceeds") {
		t.Fatalf("downloadCrackFile() error = %v; want bounded decompression failure", err)
	}
	if _, statErr := os.Stat(filepath.Join(station.dataDirForType(file.GetType()), digest)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("decompression overrun published a final file: %v", statErr)
	}
}

func TestSyncFilesKeepsUnionOfMultipleServerInventories(t *testing.T) {
	station, err := NewCrackstation("worker", t.TempDir(), newScriptHashcat(t, "exit 0"))
	if err != nil {
		t.Fatal(err)
	}
	payloadA := []byte("server-a")
	payloadB := []byte("server-b")
	fileA, digestA := crackFileFixture(payloadA, clientpb.CrackFileType_WORDLIST)
	fileA.ID = "file-a"
	fileA.IsCompressed = false
	setCrackFileTransferSize(t, fileA, int64(len(payloadA)))
	fileB, digestB := crackFileFixture(payloadB, clientpb.CrackFileType_WORDLIST)
	fileB.ID = "file-b"
	fileB.IsCompressed = false
	setCrackFileTransferSize(t, fileB, int64(len(payloadB)))

	serverA := station.AddServer(&operatorconfig.ClientConfig{Token: "server-a"})
	serverB := station.AddServer(&operatorconfig.ClientConfig{Token: "server-b"})
	serverA.setConnection(CONNECTED, newBufConnClient(t, &mockSliverRPC{
		CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
			return &clientpb.CrackFiles{Files: []*clientpb.CrackFile{fileA}}, nil
		},
		CrackFileChunkDownloadFunc: func(_ context.Context, request *clientpb.CrackFileChunk) (*clientpb.CrackFileChunk, error) {
			return &clientpb.CrackFileChunk{CrackFileID: request.GetCrackFileID(), N: request.GetN(), Data: payloadA}, nil
		},
	}), nil)
	var includeB atomic.Bool
	includeB.Store(true)
	serverB.setConnection(CONNECTED, newBufConnClient(t, &mockSliverRPC{
		CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
			if includeB.Load() {
				return &clientpb.CrackFiles{Files: []*clientpb.CrackFile{fileB}}, nil
			}
			return &clientpb.CrackFiles{}, nil
		},
		CrackFileChunkDownloadFunc: func(_ context.Context, request *clientpb.CrackFileChunk) (*clientpb.CrackFileChunk, error) {
			return &clientpb.CrackFileChunk{CrackFileID: request.GetCrackFileID(), N: request.GetN(), Data: payloadB}, nil
		},
	}), nil)

	directory := station.dataDirForType(clientpb.CrackFileType_WORDLIST)
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	staleDigest := strings.Repeat("c", 64)
	if err := os.WriteFile(filepath.Join(directory, staleDigest), []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := station.SyncFiles(serverA); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, staleDigest)); err != nil {
		t.Fatalf("first server pruned before all inventories were known: %v", err)
	}
	if err := station.SyncFiles(serverB); err != nil {
		t.Fatal(err)
	}
	for _, digest := range []string{digestA, digestB} {
		if _, err := os.Stat(filepath.Join(directory, digest)); err != nil {
			t.Fatalf("union member %s was not retained: %v", digest, err)
		}
	}
	if _, err := os.Stat(filepath.Join(directory, staleDigest)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale file was not pruned after complete inventories: %v", err)
	}

	includeB.Store(false)
	if err := station.SyncFiles(serverB); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, digestA)); err != nil {
		t.Fatalf("server B reconciliation deleted server A content: %v", err)
	}
	if _, err := os.Stat(filepath.Join(directory, digestB)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file removed from every inventory was not pruned: %v", err)
	}
}
