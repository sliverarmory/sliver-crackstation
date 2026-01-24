package crackstation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const testBufConnSize = 1024 * 1024

type mockSliverRPC struct {
	rpcpb.UnimplementedSliverRPCServer

	CrackstationRegisterFunc   func(*clientpb.Crackstation, rpcpb.SliverRPC_CrackstationRegisterServer) error
	CrackFilesListFunc         func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error)
	CrackFileChunkDownloadFunc func(context.Context, *clientpb.CrackFileChunk) (*clientpb.CrackFileChunk, error)
	CrackTaskByIDFunc          func(context.Context, *clientpb.CrackTask) (*clientpb.CrackTask, error)
	CrackTaskUpdateFunc        func(context.Context, *clientpb.CrackTask) (*commonpb.Empty, error)
	CrackstationBenchmarkFunc  func(context.Context, *clientpb.CrackBenchmark) (*commonpb.Empty, error)
}

func (m *mockSliverRPC) CrackstationRegister(req *clientpb.Crackstation, stream rpcpb.SliverRPC_CrackstationRegisterServer) error {
	if m.CrackstationRegisterFunc != nil {
		return m.CrackstationRegisterFunc(req, stream)
	}
	return status.Error(codes.Unimplemented, "CrackstationRegister not implemented")
}

func (m *mockSliverRPC) CrackFilesList(ctx context.Context, req *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
	if m.CrackFilesListFunc != nil {
		return m.CrackFilesListFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "CrackFilesList not implemented")
}

func (m *mockSliverRPC) CrackFileChunkDownload(ctx context.Context, req *clientpb.CrackFileChunk) (*clientpb.CrackFileChunk, error) {
	if m.CrackFileChunkDownloadFunc != nil {
		return m.CrackFileChunkDownloadFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "CrackFileChunkDownload not implemented")
}

func (m *mockSliverRPC) CrackTaskByID(ctx context.Context, req *clientpb.CrackTask) (*clientpb.CrackTask, error) {
	if m.CrackTaskByIDFunc != nil {
		return m.CrackTaskByIDFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "CrackTaskByID not implemented")
}

func (m *mockSliverRPC) CrackTaskUpdate(ctx context.Context, req *clientpb.CrackTask) (*commonpb.Empty, error) {
	if m.CrackTaskUpdateFunc != nil {
		return m.CrackTaskUpdateFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "CrackTaskUpdate not implemented")
}

func (m *mockSliverRPC) CrackstationBenchmark(ctx context.Context, req *clientpb.CrackBenchmark) (*commonpb.Empty, error) {
	if m.CrackstationBenchmarkFunc != nil {
		return m.CrackstationBenchmarkFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "CrackstationBenchmark not implemented")
}

func newBufConnClient(t *testing.T, mock *mockSliverRPC) rpcpb.SliverRPCClient {
	t.Helper()

	listener := bufconn.Listen(testBufConnSize)
	server := grpc.NewServer()
	rpcpb.RegisterSliverRPCServer(server, mock)

	go func() {
		_ = server.Serve(listener)
	}()

	dialer := func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}

	conn, err := grpc.DialContext(
		context.Background(),
		"bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to dial bufconn: %v", err)
	}

	t.Cleanup(func() {
		_ = conn.Close()
		server.Stop()
		_ = listener.Close()
	})

	return rpcpb.NewSliverRPCClient(conn)
}

func TestSyncFilesDownloadsWordlist(t *testing.T) {
	payload := []byte("super-secret-passwords\n")
	payloadDigest := sha256.Sum256(payload)
	payloadSHA := hex.EncodeToString(payloadDigest[:])

	var compressed bytes.Buffer
	writer, err := zstd.NewWriter(&compressed)
	if err != nil {
		t.Fatalf("failed to create zstd writer: %v", err)
	}
	if _, err := writer.Write(payload); err != nil {
		writer.Close()
		t.Fatalf("failed to write compressed payload: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("failed to close zstd writer: %v", err)
	}

	crackFile := &clientpb.CrackFile{
		ID:               "file-1",
		Name:             "wordlist.txt",
		Sha2_256:         payloadSHA,
		UncompressedSize: int64(len(payload)),
		Type:             clientpb.CrackFileType_WORDLIST,
		Chunks: []*clientpb.CrackFileChunk{{
			ID: "chunk-1",
			N:  0,
		}},
	}

	mock := &mockSliverRPC{
		CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
			return &clientpb.CrackFiles{Files: []*clientpb.CrackFile{crackFile}}, nil
		},
		CrackFileChunkDownloadFunc: func(ctx context.Context, req *clientpb.CrackFileChunk) (*clientpb.CrackFileChunk, error) {
			if req.CrackFileID != crackFile.ID {
				return nil, status.Errorf(codes.InvalidArgument, "unexpected crack file id: %s", req.CrackFileID)
			}
			return &clientpb.CrackFileChunk{ID: req.ID, N: req.N, Data: compressed.Bytes()}, nil
		},
	}

	client := newBufConnClient(t, mock)
	station := &Crackstation{dataDir: t.TempDir(), syncLock: &sync.Mutex{}}
	server := &SliverServer{rpc: client}

	if err := station.SyncFiles(server); err != nil {
		t.Fatalf("SyncFiles returned error: %v", err)
	}

	storedPath := filepath.Join(station.dataDir, "wordlists", payloadSHA)
	stored, err := os.ReadFile(storedPath)
	if err != nil {
		t.Fatalf("expected downloaded file at %s: %v", storedPath, err)
	}
	if !bytes.Equal(stored, payload) {
		t.Fatalf("downloaded file content mismatch")
	}
}

func TestDownloadCrackFileRejectsBadSHA(t *testing.T) {
	payload := []byte("chunk-data")
	badSHA := "deadbeef"

	var compressed bytes.Buffer
	writer, err := zstd.NewWriter(&compressed)
	if err != nil {
		t.Fatalf("failed to create zstd writer: %v", err)
	}
	if _, err := writer.Write(payload); err != nil {
		writer.Close()
		t.Fatalf("failed to write compressed payload: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("failed to close zstd writer: %v", err)
	}

	crackFile := &clientpb.CrackFile{
		ID:               "file-2",
		Name:             "rules.txt",
		Sha2_256:         badSHA,
		UncompressedSize: int64(len(payload)),
		Type:             clientpb.CrackFileType_RULES,
		Chunks: []*clientpb.CrackFileChunk{{
			ID: "chunk-1",
			N:  0,
		}},
	}

	mock := &mockSliverRPC{
		CrackFileChunkDownloadFunc: func(ctx context.Context, req *clientpb.CrackFileChunk) (*clientpb.CrackFileChunk, error) {
			return &clientpb.CrackFileChunk{ID: req.ID, N: req.N, Data: compressed.Bytes()}, nil
		},
	}

	client := newBufConnClient(t, mock)
	station := &Crackstation{
		dataDir:   t.TempDir(),
		syncLock:  &sync.Mutex{},
		syncStart: time.Now(),
		SyncStatus: &clientpb.CrackSyncStatus{
			Progress: map[string]float32{badSHA: 0},
		},
	}
	server := &SliverServer{rpc: client}

	err = station.downloadCrackFile(server, crackFile)
	if err == nil {
		t.Fatal("expected sha mismatch error")
	}

	storedPath := filepath.Join(station.dataDir, "rules", badSHA)
	if _, err := os.Stat(storedPath); err == nil {
		t.Fatalf("expected file removal for bad sha at %s", storedPath)
	}
}
