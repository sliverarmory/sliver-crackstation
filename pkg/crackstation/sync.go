package crackstation

/*
	Sliver Implant Framework
	Copyright (C) 2022  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
*/

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/klauspost/compress/zstd"
	"github.com/sliverarmory/sliver-crackstation/pkg/protocompat"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	maxConcurrentDownloads                                      = 2
	crackFileRPCTimeout                                         = 30 * time.Second
	crackFileCompressedSize            protoreflect.FieldNumber = 11
	crackFileCompressedStagingPrefix                            = ".crackfile-compressed-"
	crackFileUncompressedStagingPrefix                          = ".crackfile-uncompressed-"
	legacyTransferMinimumOverhead                               = int64(1 << 20)
)

var errManagedCrackFileUnavailable = errors.New("managed crack file unavailable")

// SyncFiles reconciles the crackstation's content-addressed cache with the
// server. Downloads are verified before an atomic rename makes them visible.
func (c *Crackstation) SyncFiles(server *SliverServer) error {
	return c.SyncFilesContext(context.Background(), server)
}

// SyncFilesContext reconciles the crackstation's cache while allowing a task
// lease, connection, or crackstation shutdown to cancel a queued or active
// synchronization.
func (c *Crackstation) SyncFilesContext(ctx context.Context, server *SliverServer) error {
	if ctx == nil {
		return errors.New("missing crack file sync context")
	}
	if server == nil {
		return errors.New("missing sliver server RPC client")
	}
	rpc := server.rpcClient()
	if rpc == nil {
		return errors.New("missing sliver server RPC client")
	}
	if err := c.acquireSync(ctx); err != nil {
		return fmt.Errorf("wait for crack file sync: %w", err)
	}
	defer c.releaseSync()
	if err := c.cleanupStaleSyncStagingFiles(ctx); err != nil {
		return fmt.Errorf("clean stale crack file staging: %w", err)
	}

	listCtx, cancel := context.WithTimeout(ctx, crackFileRPCTimeout)
	crackFiles, err := rpc.CrackFilesList(listCtx, &clientpb.CrackFile{Type: clientpb.CrackFileType_INVALID_TYPE})
	cancel()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("list crack files: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	listedFiles := crackFiles.GetFiles()
	if err := validateCrackFiles(listedFiles); err != nil {
		return err
	}
	files := deduplicateCrackFiles(listedFiles)

	c.beginSync(files)
	defer c.endSync()

	queue := make(chan *clientpb.CrackFile, len(files))
enqueue:
	for _, crackFile := range files {
		if ctx.Err() != nil {
			break
		}
		select {
		case queue <- crackFile:
		case <-ctx.Done():
			break enqueue
		}
	}
	close(queue)

	workerCount := maxConcurrentDownloads
	if len(files) < workerCount {
		workerCount = len(files)
	}
	var workers sync.WaitGroup
	errCh := make(chan error, len(files))
	for range workerCount {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				if ctx.Err() != nil {
					return
				}
				var crackFile *clientpb.CrackFile
				var ok bool
				select {
				case <-ctx.Done():
					return
				case crackFile, ok = <-queue:
					if !ok {
						return
					}
				}
				if ctx.Err() != nil {
					return
				}
				if err := c.downloadCrackFileContext(ctx, server, crackFile); err != nil {
					errCh <- fmt.Errorf("download %q: %w", crackFile.GetName(), err)
				}
			}
		}()
	}
	workers.Wait()
	close(errCh)
	var downloadErrors []error
	for err := range errCh {
		downloadErrors = append(downloadErrors, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(downloadErrors) != 0 {
		return errors.Join(downloadErrors...)
	}
	retained, completeInventory := c.recordServerInventory(server, files)
	if completeInventory && !c.isActive() {
		if err := c.pruneManagedFiles(ctx, retained); err != nil {
			return fmt.Errorf("prune stale crack files: %w", err)
		}
	}
	return nil
}

func (c *Crackstation) acquireSync(ctx context.Context) error {
	if c.syncLock == nil {
		return errors.New("missing crack file sync lock")
	}
	c.syncGateOnce.Do(func() {
		c.syncGate = make(chan struct{}, 1)
		c.syncGate <- struct{}{}
	})
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.syncGate:
	}
	if err := ctx.Err(); err != nil {
		c.syncGate <- struct{}{}
		return err
	}
	c.syncLock.Lock()
	return nil
}

func (c *Crackstation) releaseSync() {
	c.syncLock.Unlock()
	c.syncGate <- struct{}{}
}

func deduplicateCrackFiles(files []*clientpb.CrackFile) []*clientpb.CrackFile {
	seen := map[string]struct{}{}
	unique := make([]*clientpb.CrackFile, 0, len(files))
	for _, file := range files {
		if file == nil {
			unique = append(unique, nil)
			continue
		}
		key := fmt.Sprintf("%d:%s", file.GetType(), file.GetSha2_256())
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, file)
	}
	return unique
}

func validateCrackFiles(files []*clientpb.CrackFile) error {
	for index, file := range files {
		if file == nil {
			return fmt.Errorf("crack file %d is nil", index)
		}
		if !validManagedDigest(file.GetSha2_256()) {
			return fmt.Errorf("crack file %q has invalid sha2-256 %q", file.GetName(), file.GetSha2_256())
		}
		if file.GetUncompressedSize() < 0 {
			return fmt.Errorf("crack file %q has invalid negative size", file.GetName())
		}
		if file.GetUncompressedSize() == math.MaxInt64 {
			return fmt.Errorf("crack file %q has an unsupported maximum size", file.GetName())
		}
		compressedSize, err := crackFileTransferSize(file)
		if err != nil {
			return fmt.Errorf("crack file %q compressed size: %w", file.GetName(), err)
		}
		if compressedSize < 0 {
			return fmt.Errorf("crack file %q has invalid negative compressed size", file.GetName())
		}
		// CrackFilesList is the server's completed-file inventory. A completed
		// compressed file always has at least one chunk, including an empty
		// uncompressed payload (the zstd frame itself is non-empty).
		if len(file.GetChunks()) == 0 {
			return fmt.Errorf("crack file %q is incomplete: no chunks", file.GetName())
		}
		switch file.GetType() {
		case clientpb.CrackFileType_WORDLIST, clientpb.CrackFileType_RULES, clientpb.CrackFileType_MARKOV_HCSTAT2:
		default:
			return fmt.Errorf("crack file %q has unsupported type %s", file.GetName(), file.GetType())
		}
	}
	return nil
}

func crackFileTransferSize(file *clientpb.CrackFile) (int64, error) {
	fields, err := protocompat.NewReader(file)
	if err != nil {
		return 0, err
	}
	return fields.Int64(crackFileCompressedSize)
}

// crackFileTransferLimit bounds legacy inventories created before the server
// advertised the exact compressed size. Zstd's normal overhead is far smaller
// than one percent; the one MiB floor accommodates tiny inputs without turning
// a missing additive field into an unbounded staging-file write.
func crackFileTransferLimit(uncompressedSize, compressedSize int64) int64 {
	if compressedSize > 0 {
		return compressedSize
	}
	overhead := uncompressedSize / 100
	if overhead < legacyTransferMinimumOverhead {
		overhead = legacyTransferMinimumOverhead
	}
	if uncompressedSize > math.MaxInt64-overhead {
		return math.MaxInt64
	}
	return uncompressedSize + overhead
}

func validManagedDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func (c *Crackstation) beginSync(files []*clientpb.CrackFile) {
	c.syncStatusLock.Lock()
	defer c.syncStatusLock.Unlock()
	c.syncStart = time.Now()
	c.syncBytes = 0
	c.syncing = true
	c.SyncStatus = &clientpb.CrackSyncStatus{Progress: make(map[string]float32, len(files))}
	for _, file := range files {
		c.SyncStatus.Progress[file.GetSha2_256()] = 0
	}
}

func (c *Crackstation) endSync() {
	c.syncStatusLock.Lock()
	defer c.syncStatusLock.Unlock()
	c.syncing = false
	c.SyncStatus = nil
}

func (c *Crackstation) updateSyncProgress(digest string, bytes int, progress float32) {
	c.syncStatusLock.Lock()
	defer c.syncStatusLock.Unlock()
	if c.SyncStatus == nil {
		return
	}
	c.syncBytes += bytes
	c.SyncStatus.Progress[digest] = progress
	elapsed := time.Since(c.syncStart).Seconds()
	if elapsed > 0 {
		c.SyncStatus.Speed = float32(float64(c.syncBytes) / elapsed)
	}
}

func (c *Crackstation) syncSnapshot() (bool, *clientpb.CrackSyncStatus) {
	c.syncStatusLock.RLock()
	defer c.syncStatusLock.RUnlock()
	if !c.syncing || c.SyncStatus == nil {
		return false, nil
	}
	return true, cloneSyncStatus(c.SyncStatus)
}

func cloneSyncStatus(status *clientpb.CrackSyncStatus) *clientpb.CrackSyncStatus {
	if status == nil {
		return nil
	}
	copyStatus := &clientpb.CrackSyncStatus{Speed: status.GetSpeed()}
	if status.Progress != nil {
		copyStatus.Progress = make(map[string]float32, len(status.Progress))
		for key, value := range status.Progress {
			copyStatus.Progress[key] = value
		}
	}
	return copyStatus
}

func (c *Crackstation) downloadCrackFile(server *SliverServer, crackFile *clientpb.CrackFile) error {
	return c.downloadCrackFileContext(context.Background(), server, crackFile)
}

func (c *Crackstation) downloadCrackFileContext(ctx context.Context, server *SliverServer, crackFile *clientpb.CrackFile) error {
	if ctx == nil {
		return errors.New("missing crack file download context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if server == nil || crackFile == nil {
		return errors.New("missing crack file download parameters")
	}
	if err := validateCrackFiles([]*clientpb.CrackFile{crackFile}); err != nil {
		return err
	}
	rpc := server.rpcClient()
	if rpc == nil {
		return errors.New("missing crack file download parameters")
	}
	if !validManagedDigest(crackFile.GetSha2_256()) {
		return fmt.Errorf("invalid sha2-256 %q", crackFile.GetSha2_256())
	}
	downloadDir := c.dataDirForType(crackFile.GetType())
	if err := os.MkdirAll(downloadDir, 0700); err != nil {
		return err
	}
	finalPath := filepath.Join(downloadDir, crackFile.GetSha2_256())
	if valid, err := verifyManagedFile(finalPath, crackFile.GetSha2_256(), crackFile.GetUncompressedSize()); err != nil {
		return err
	} else if valid {
		c.updateSyncProgress(crackFile.GetSha2_256(), 0, 1)
		return nil
	}

	compressed, err := os.CreateTemp(downloadDir, crackFileCompressedStagingPrefix+"*")
	if err != nil {
		return err
	}
	compressedPath := compressed.Name()
	defer os.Remove(compressedPath)

	chunks := append([]*clientpb.CrackFileChunk(nil), crackFile.GetChunks()...)
	expectedTransferSize, err := crackFileTransferSize(crackFile)
	if err != nil {
		_ = compressed.Close()
		return err
	}
	transferLimit := crackFileTransferLimit(crackFile.GetUncompressedSize(), expectedTransferSize)
	var transferred int64
	sort.SliceStable(chunks, func(i, j int) bool { return chunks[i].GetN() < chunks[j].GetN() })
	for index, chunk := range chunks {
		if err := ctx.Err(); err != nil {
			_ = compressed.Close()
			return err
		}
		if chunk == nil {
			_ = compressed.Close()
			return fmt.Errorf("chunk %d is nil", index)
		}
		request := &clientpb.CrackFileChunk{ID: chunk.GetID(), N: chunk.GetN(), CrackFileID: crackFile.GetID()}
		chunkCtx, cancel := context.WithTimeout(ctx, crackFileRPCTimeout)
		dataChunk, rpcErr := rpc.CrackFileChunkDownload(chunkCtx, request)
		cancel()
		if rpcErr != nil {
			_ = compressed.Close()
			return fmt.Errorf("download chunk %d: %w", chunk.GetN(), rpcErr)
		}
		if dataChunk == nil {
			_ = compressed.Close()
			return fmt.Errorf("download chunk %d returned nil", chunk.GetN())
		}
		if dataChunk.GetCrackFileID() != request.GetCrackFileID() || dataChunk.GetN() != request.GetN() {
			_ = compressed.Close()
			return fmt.Errorf("download chunk %d returned mismatched file or sequence", chunk.GetN())
		}
		if len(dataChunk.GetData()) == 0 {
			_ = compressed.Close()
			return fmt.Errorf("download chunk %d returned empty data", chunk.GetN())
		}
		if err := ctx.Err(); err != nil {
			_ = compressed.Close()
			return err
		}
		chunkSize := int64(len(dataChunk.GetData()))
		if chunkSize > transferLimit-transferred {
			_ = compressed.Close()
			if expectedTransferSize > 0 {
				return fmt.Errorf("compressed data exceeds declared size %d", expectedTransferSize)
			}
			return fmt.Errorf("compressed data exceeds legacy transfer limit %d", transferLimit)
		}
		if _, err := compressed.Write(dataChunk.GetData()); err != nil {
			_ = compressed.Close()
			return err
		}
		transferred += chunkSize
		progress := float32(1)
		if len(chunks) > 0 {
			progress = float32(index+1) / float32(len(chunks))
		}
		c.updateSyncProgress(crackFile.GetSha2_256(), len(dataChunk.GetData()), progress)
	}
	if expectedTransferSize > 0 && transferred != expectedTransferSize {
		_ = compressed.Close()
		return fmt.Errorf("compressed size mismatch: got %d, want %d", transferred, expectedTransferSize)
	}
	if err := compressed.Sync(); err != nil {
		_ = compressed.Close()
		return err
	}
	if _, err := compressed.Seek(0, io.SeekStart); err != nil {
		_ = compressed.Close()
		return err
	}
	if err := ctx.Err(); err != nil {
		_ = compressed.Close()
		return err
	}

	temporary, err := os.CreateTemp(downloadDir, crackFileUncompressedStagingPrefix+"*")
	if err != nil {
		_ = compressed.Close()
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	digest := sha256.New()
	var source io.Reader = compressed
	var decoder *zstd.Decoder
	if crackFile.GetIsCompressed() {
		decoder, err = zstd.NewReader(compressed)
		if err != nil {
			_ = temporary.Close()
			_ = compressed.Close()
			return fmt.Errorf("open zstd stream: %w", err)
		}
		source = decoder
	}
	boundedSource := io.LimitReader(source, crackFile.GetUncompressedSize()+1)
	written, copyErr := io.Copy(io.MultiWriter(temporary, digest), boundedSource)
	if decoder != nil {
		decoder.Close()
	}
	closeCompressedErr := compressed.Close()
	if copyErr != nil {
		_ = temporary.Close()
		return fmt.Errorf("decompress crack file: %w", copyErr)
	}
	if closeCompressedErr != nil {
		_ = temporary.Close()
		return closeCompressedErr
	}
	if written > crackFile.GetUncompressedSize() {
		_ = temporary.Close()
		return fmt.Errorf("uncompressed data exceeds declared size %d", crackFile.GetUncompressedSize())
	}
	if written != crackFile.GetUncompressedSize() {
		_ = temporary.Close()
		return fmt.Errorf("uncompressed size mismatch: got %d, want %d", written, crackFile.GetUncompressedSize())
	}
	actualDigest := hex.EncodeToString(digest.Sum(nil))
	if actualDigest != crackFile.GetSha2_256() {
		_ = temporary.Close()
		return fmt.Errorf("downloaded file sha2-256 does not match: %s != %s", actualDigest, crackFile.GetSha2_256())
	}
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := replaceFileAtomically(temporaryPath, finalPath); err != nil {
		return fmt.Errorf("publish crack file: %w", err)
	}
	slog.Info("Synced crack file", "name", crackFile.GetName(), "path", finalPath)
	return nil
}

func verifyManagedFile(path, expectedDigest string, expectedSize int64) (bool, error) {
	pathInfo, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !pathInfo.Mode().IsRegular() {
		return false, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return false, err
	}
	if expectedSize >= 0 && info.Size() != expectedSize {
		return false, nil
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return false, err
	}
	return hex.EncodeToString(digest.Sum(nil)) == expectedDigest, nil
}

// ResolveCrackFile turns an immutable crackfile URI into a verified local file.
func (c *Crackstation) ResolveCrackFile(reference string) (string, error) {
	parsed, err := url.Parse(reference)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "crackfile" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("invalid managed crack file URI %q", reference)
	}
	digest := strings.TrimPrefix(parsed.EscapedPath(), "/")
	decodedDigest, err := url.PathUnescape(digest)
	if err != nil || decodedDigest != digest || strings.Contains(decodedDigest, "/") || !validManagedDigest(decodedDigest) {
		return "", fmt.Errorf("invalid managed crack file digest %q", digest)
	}
	var fileType clientpb.CrackFileType
	switch parsed.Host {
	case "wordlist":
		fileType = clientpb.CrackFileType_WORDLIST
	case "rules":
		fileType = clientpb.CrackFileType_RULES
	case "hcstat2":
		fileType = clientpb.CrackFileType_MARKOV_HCSTAT2
	default:
		return "", fmt.Errorf("unsupported managed crack file type %q", parsed.Host)
	}
	path := filepath.Join(c.dataDirForType(fileType), decodedDigest)
	valid, err := verifyManagedFile(path, decodedDigest, -1)
	if err != nil {
		return "", err
	}
	if !valid {
		return "", fmt.Errorf("%w: %q is missing or corrupt", errManagedCrackFileUnavailable, reference)
	}
	return path, nil
}

func (c *Crackstation) recordServerInventory(server *SliverServer, files []*clientpb.CrackFile) (map[string]struct{}, bool) {
	manifest := make(map[string]struct{}, len(files))
	for _, file := range files {
		manifest[filepath.Join(c.dataDirForType(file.GetType()), file.GetSha2_256())] = struct{}{}
	}
	c.inventoryLock.Lock()
	defer c.inventoryLock.Unlock()
	if c.inventories == nil {
		c.inventories = make(map[*SliverServer]map[string]struct{})
	}
	c.inventories[server] = manifest
	keep := make(map[string]struct{})
	configured := 0
	complete := true
	if c.Servers != nil {
		c.Servers.Range(func(_, value interface{}) bool {
			configured++
			configuredServer, ok := value.(*SliverServer)
			if !ok || configuredServer == nil {
				complete = false
				return true
			}
			serverManifest, ok := c.inventories[configuredServer]
			if !ok {
				complete = false
				return true
			}
			for path := range serverManifest {
				keep[path] = struct{}{}
			}
			return true
		})
	}
	if configured == 0 {
		for path := range manifest {
			keep[path] = struct{}{}
		}
	}
	return keep, complete
}

func (c *Crackstation) pruneManagedFiles(ctx context.Context, keep map[string]struct{}) error {
	for _, directory := range []string{
		c.dataDirForType(clientpb.CrackFileType_WORDLIST),
		c.dataDirForType(clientpb.CrackFileType_RULES),
		c.dataDirForType(clientpb.CrackFileType_MARKOV_HCSTAT2),
	} {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, err := os.ReadDir(directory)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			if entry.IsDir() || !validManagedDigest(entry.Name()) {
				continue
			}
			path := filepath.Join(directory, entry.Name())
			if _, retained := keep[path]; retained {
				continue
			}
			if err := os.Remove(path); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Crackstation) cleanupStaleSyncStagingFiles(ctx context.Context) error {
	for _, directory := range []string{
		c.dataDirForType(clientpb.CrackFileType_WORDLIST),
		c.dataDirForType(clientpb.CrackFileType_RULES),
		c.dataDirForType(clientpb.CrackFileType_MARKOV_HCSTAT2),
	} {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, err := os.ReadDir(directory)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read %q: %w", directory, err)
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			if entry.IsDir() || !isSyncStagingFileName(entry.Name()) {
				continue
			}
			path := filepath.Join(directory, entry.Name())
			info, err := entry.Info()
			if err != nil {
				return fmt.Errorf("inspect %q: %w", path, err)
			}
			if !info.Mode().IsRegular() {
				continue
			}
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove %q: %w", path, err)
			}
		}
	}
	return nil
}

func isSyncStagingFileName(name string) bool {
	return (len(name) > len(crackFileCompressedStagingPrefix) && strings.HasPrefix(name, crackFileCompressedStagingPrefix)) ||
		(len(name) > len(crackFileUncompressedStagingPrefix) && strings.HasPrefix(name, crackFileUncompressedStagingPrefix))
}

func (c *Crackstation) dataDirForType(fileType clientpb.CrackFileType) string {
	switch fileType {
	case clientpb.CrackFileType_WORDLIST:
		return filepath.Join(c.dataDir, "wordlists")
	case clientpb.CrackFileType_RULES:
		return filepath.Join(c.dataDir, "rules")
	case clientpb.CrackFileType_MARKOV_HCSTAT2:
		return filepath.Join(c.dataDir, "hcstat2s")
	default:
		return c.dataDir
	}
}
