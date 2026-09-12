package crackstation

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/sliverarmory/sliver-crackstation/pkg/operatorconfig"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDeduplicateCrackFilesChoosesCanonicalMetadataIndependentOfOrder(t *testing.T) {
	digest := strings.Repeat("a", 64)
	canonical := &clientpb.CrackFile{
		ID:               "z-id",
		Name:             "words.txt",
		Type:             clientpb.CrackFileType_WORDLIST,
		Sha2_256:         digest,
		UncompressedSize: 10,
	}
	alias := &clientpb.CrackFile{
		ID:               "a-id",
		Name:             "words-alternate-name.txt",
		Type:             clientpb.CrackFileType_WORDLIST,
		Sha2_256:         digest,
		UncompressedSize: 10,
	}
	for _, files := range [][]*clientpb.CrackFile{{alias, canonical}, {canonical, alias}} {
		got := deduplicateCrackFiles(files)
		if len(got) != 1 || got[0] != canonical {
			t.Fatalf("deduplicateCrackFiles(%q, %q) = %#v, want canonical metadata", files[0].GetName(), files[1].GetName(), got)
		}
	}
}

func TestFileInventoriesCaptureDeduplicatedAllTypeFilesAndReturnIndependentCopies(t *testing.T) {
	station := &Crackstation{
		Servers:  &sync.Map{},
		dataDir:  t.TempDir(),
		syncLock: &sync.Mutex{},
	}

	alphaFiles, alphaPayloads := inventoryFixtures(t, []inventoryFixture{
		{id: "rules", name: "best64.rule", payload: "rule payload", fileType: clientpb.CrackFileType_RULES, createdAt: 20, lastModified: 21},
		{id: "wordlist-z", name: "zeta.txt", payload: "zeta words", fileType: clientpb.CrackFileType_WORDLIST, createdAt: 10, lastModified: 11},
		{id: "wordlist-z-alias", name: "zeta-alias.txt", payload: "zeta words", fileType: clientpb.CrackFileType_WORDLIST, createdAt: 14, lastModified: 15},
		{id: "hcstat2", name: "english.hcstat2", payload: "markov payload", fileType: clientpb.CrackFileType_MARKOV_HCSTAT2, createdAt: 30, lastModified: 31},
		{id: "wordlist-a", name: "alpha.txt", payload: "alpha words", fileType: clientpb.CrackFileType_WORDLIST, createdAt: 12, lastModified: 13},
	})
	zetaFiles, zetaPayloads := inventoryFixtures(t, []inventoryFixture{
		{id: "zeta-rules", name: "zeta.rule", payload: "zeta rules", fileType: clientpb.CrackFileType_RULES, createdAt: 40, lastModified: 41},
	})

	alpha := station.AddServer(&operatorconfig.ClientConfig{
		Token: "alpha-token", Operator: "alice", LHost: "127.0.0.1", LPort: 31337,
	})
	alpha.rpc = inventoryRPC(t, alphaFiles, alphaPayloads)
	zeta := station.AddServer(&operatorconfig.ClientConfig{
		Token: "zeta-token", Operator: "zeta", LHost: "server.example", LPort: 31337,
	})
	zeta.rpc = inventoryRPC(t, zetaFiles, zetaPayloads)

	// Synchronize in reverse display order to ensure the accessor does not leak
	// map or completion ordering.
	if err := station.SyncFiles(zeta); err != nil {
		t.Fatal(err)
	}
	if err := station.SyncFiles(alpha); err != nil {
		t.Fatal(err)
	}

	inventories := station.FileInventories()
	if len(inventories) != 2 {
		t.Fatalf("FileInventories() returned %d inventories, want 2", len(inventories))
	}
	if inventories[0].Server != "alice@127.0.0.1:31337" || inventories[1].Server != "zeta@server.example:31337" {
		t.Fatalf("FileInventories() server order = %q, %q", inventories[0].Server, inventories[1].Server)
	}
	alphaSnapshot := inventories[0]
	if alphaSnapshot.UpdatedAt.IsZero() {
		t.Fatal("alpha inventory has a zero UpdatedAt")
	}
	wantOrder := []struct {
		name     string
		fileType clientpb.CrackFileType
	}{
		{name: "alpha.txt", fileType: clientpb.CrackFileType_WORDLIST},
		{name: "zeta.txt", fileType: clientpb.CrackFileType_WORDLIST},
		{name: "best64.rule", fileType: clientpb.CrackFileType_RULES},
		{name: "english.hcstat2", fileType: clientpb.CrackFileType_MARKOV_HCSTAT2},
	}
	if len(alphaSnapshot.Files) != len(wantOrder) {
		t.Fatalf("alpha files = %d, want %d", len(alphaSnapshot.Files), len(wantOrder))
	}
	for index, want := range wantOrder {
		file := alphaSnapshot.Files[index]
		if file.Name != want.name || file.Type != want.fileType {
			t.Fatalf("alpha file %d = %s/%s, want %s/%s", index, file.Type, file.Name, want.fileType, want.name)
		}
		if file.SHA256 == "" || file.UncompressedSize <= 0 {
			t.Fatalf("alpha file %q omitted digest or size: %#v", file.Name, file)
		}
	}
	if got := alphaSnapshot.Files[0].CreatedAt; !got.Equal(time.Unix(12, 0).UTC()) {
		t.Fatalf("alpha.txt CreatedAt = %s, want Unix 12", got)
	}
	if got := alphaSnapshot.Files[0].LastModified; !got.Equal(time.Unix(13, 0).UTC()) {
		t.Fatalf("alpha.txt LastModified = %s, want Unix 13", got)
	}

	// Mutating either the outer result or its nested file slice must not mutate
	// the crackstation's retained snapshot.
	inventories[0].Server = "mutated"
	inventories[0].Files[0].Name = "mutated"
	inventories[0].Files = append(inventories[0].Files, SyncedFileSnapshot{Name: "injected"})
	again := station.FileInventories()
	if len(again) != 2 || again[0].Server != "alice@127.0.0.1:31337" {
		t.Fatalf("mutating returned inventory changed retained server snapshot: %#v", again)
	}
	if len(again[0].Files) != len(wantOrder) || again[0].Files[0].Name != "alpha.txt" {
		t.Fatalf("mutating returned files changed retained snapshot: %#v", again[0].Files)
	}
}

func TestFileInventoriesRetainLastSuccessAfterFailedSync(t *testing.T) {
	station := &Crackstation{dataDir: t.TempDir(), syncLock: &sync.Mutex{}}
	initialFiles, initialPayloads := inventoryFixtures(t, []inventoryFixture{
		{id: "initial", name: "initial.txt", payload: "initial words", fileType: clientpb.CrackFileType_WORDLIST, createdAt: 100, lastModified: 101},
	})
	failedFiles, _ := inventoryFixtures(t, []inventoryFixture{
		{id: "failed", name: "failed.rule", payload: "failed rules", fileType: clientpb.CrackFileType_RULES, createdAt: 200, lastModified: 201},
	})
	var fail atomic.Bool
	mock := &mockSliverRPC{
		CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
			if fail.Load() {
				return &clientpb.CrackFiles{Files: failedFiles}, nil
			}
			return &clientpb.CrackFiles{Files: initialFiles}, nil
		},
		CrackFileChunkDownloadFunc: func(_ context.Context, request *clientpb.CrackFileChunk) (*clientpb.CrackFileChunk, error) {
			if fail.Load() {
				return nil, status.Error(codes.Unavailable, "download unavailable")
			}
			return &clientpb.CrackFileChunk{
				CrackFileID: request.GetCrackFileID(),
				N:           request.GetN(),
				Data:        initialPayloads[request.GetCrackFileID()],
			}, nil
		},
	}
	server := &SliverServer{
		Config: &operatorconfig.ClientConfig{Operator: "operator", LHost: "host", LPort: 1234},
		rpc:    newBufConnClient(t, mock),
	}
	if err := station.SyncFiles(server); err != nil {
		t.Fatal(err)
	}
	want := station.FileInventories()
	if len(want) != 1 {
		t.Fatalf("initial FileInventories() = %#v", want)
	}

	fail.Store(true)
	if err := station.SyncFiles(server); err == nil {
		t.Fatal("failed synchronization returned nil error")
	}
	if got := station.FileInventories(); !reflect.DeepEqual(got, want) {
		t.Fatalf("failed synchronization replaced last successful inventory\ngot:  %#v\nwant: %#v", got, want)
	}
}

func TestFileInventoriesReplaceSnapshotAfterSuccessfulEmptySync(t *testing.T) {
	station := &Crackstation{dataDir: t.TempDir(), syncLock: &sync.Mutex{}}
	files, payloads := inventoryFixtures(t, []inventoryFixture{
		{id: "initial", name: "initial.txt", payload: "initial words", fileType: clientpb.CrackFileType_WORDLIST},
	})
	var empty atomic.Bool
	mock := &mockSliverRPC{
		CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
			if empty.Load() {
				return &clientpb.CrackFiles{}, nil
			}
			return &clientpb.CrackFiles{Files: files}, nil
		},
		CrackFileChunkDownloadFunc: func(_ context.Context, request *clientpb.CrackFileChunk) (*clientpb.CrackFileChunk, error) {
			return &clientpb.CrackFileChunk{
				CrackFileID: request.GetCrackFileID(),
				N:           request.GetN(),
				Data:        payloads[request.GetCrackFileID()],
			}, nil
		},
	}
	server := &SliverServer{rpc: newBufConnClient(t, mock)}
	if err := station.SyncFiles(server); err != nil {
		t.Fatal(err)
	}
	if got := station.FileInventories(); len(got) != 1 || len(got[0].Files) != 1 {
		t.Fatalf("initial FileInventories() = %#v", got)
	}

	empty.Store(true)
	if err := station.SyncFiles(server); err != nil {
		t.Fatal(err)
	}
	got := station.FileInventories()
	if len(got) != 1 || len(got[0].Files) != 0 {
		t.Fatalf("empty successful synchronization retained stale snapshot: %#v", got)
	}
}

type inventoryFixture struct {
	id           string
	name         string
	payload      string
	fileType     clientpb.CrackFileType
	createdAt    int64
	lastModified int64
}

func inventoryFixtures(t *testing.T, fixtures []inventoryFixture) ([]*clientpb.CrackFile, map[string][]byte) {
	t.Helper()
	files := make([]*clientpb.CrackFile, 0, len(fixtures))
	payloads := make(map[string][]byte, len(fixtures))
	for _, fixture := range fixtures {
		payload := []byte(fixture.payload)
		file, _ := crackFileFixture(payload, fixture.fileType)
		file.ID = fixture.id
		file.Name = fixture.name
		file.CreatedAt = fixture.createdAt
		file.LastModified = fixture.lastModified
		file.IsCompressed = false
		setCrackFileTransferSize(t, file, int64(len(payload)))
		files = append(files, file)
		payloads[fixture.id] = payload
	}
	return files, payloads
}

func inventoryRPC(t *testing.T, files []*clientpb.CrackFile, payloads map[string][]byte) rpcpb.SliverRPCClient {
	t.Helper()
	return newBufConnClient(t, &mockSliverRPC{
		CrackFilesListFunc: func(context.Context, *clientpb.CrackFile) (*clientpb.CrackFiles, error) {
			return &clientpb.CrackFiles{Files: files}, nil
		},
		CrackFileChunkDownloadFunc: func(_ context.Context, request *clientpb.CrackFileChunk) (*clientpb.CrackFileChunk, error) {
			return &clientpb.CrackFileChunk{
				CrackFileID: request.GetCrackFileID(),
				N:           request.GetN(),
				Data:        payloads[request.GetCrackFileID()],
			}, nil
		},
	})
}
