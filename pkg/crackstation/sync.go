package crackstation

/*
	Sliver Implant Framework
	Copyright (C) 2022  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/klauspost/compress/zstd"
)

const maxConcurrentDownloads = 2

func (c *Crackstation) SyncFiles(server *SliverServer) error {
	c.syncLock.Lock()
	defer c.syncLock.Unlock()
	defer func() { c.SyncStatus = &clientpb.CrackSyncStatus{} }()

	c.SyncStatus = &clientpb.CrackSyncStatus{Speed: 0, Progress: map[string]float32{}}
	crackFiles, err := server.rpc.CrackFilesList(context.Background(), &clientpb.CrackFile{Type: clientpb.CrackFileType_INVALID_TYPE})
	if err != nil {
		return err
	}
	for _, crackFile := range crackFiles.Files {
		c.SyncStatus.Progress[crackFile.Sha2_256] = 0.0 // Initialize all file id's to 0%
	}
	c.syncBytes = 0
	c.syncStart = time.Now()

	// Queue files for download
	files := make(chan *clientpb.CrackFile, len(crackFiles.Files))
	for _, crackFile := range crackFiles.Files {
		files <- crackFile
	}
	close(files)

	wg := &sync.WaitGroup{}
	for i := 0; i < maxConcurrentDownloads; i++ {
		wg.Add(1)
		go func(chan<- *clientpb.CrackFile) {
			defer wg.Done()
			for crackFile := range files {
				if err := c.downloadCrackFile(server, crackFile); err != nil {
					slog.Error("Sync failed to download file", "file", crackFile.Name, "err", err)
				}
			}
		}(files)
	}
	wg.Wait()

	return nil
}

type DataStream struct {
	stream   chan []byte
	drain    []byte
	rpc      rpcpb.SliverRPCClient
	isClosed bool
}

func (d *DataStream) Write(buf []byte) (n int, err error) {
	d.stream <- buf
	return len(buf), nil
}

func (d *DataStream) Read(buf []byte) (n int, err error) {
	if d.isClosed {
		return 0, io.EOF
	}

	if 0 < len(d.drain) {
		n = copy(buf, d.drain)
		d.drain = d.drain[n:]
		return n, nil
	}

	data := <-d.stream
	if data == nil {
		d.isClosed = true
		return 0, nil
	}
	n = copy(buf, data)
	d.drain = data[n:]
	return n, nil
}

func (d *DataStream) Close() error {
	d.stream <- nil
	return nil
}

func (c *Crackstation) downloadCrackFile(server *SliverServer, crackFile *clientpb.CrackFile) error {
	downloadToDir := c.dataDirForType(crackFile.Type)
	if err := os.MkdirAll(downloadToDir, 0700); err != nil {
		return err
	}
	downloadToFilePath := filepath.Join(downloadToDir, filepath.Base(crackFile.Sha2_256))
	if _, err := os.Stat(downloadToFilePath); err == nil {
		c.SyncStatus.Progress[crackFile.Sha2_256] = 1.0
		slog.Info("Sync file already exists, skipping", "path", downloadToFilePath)
		return nil
	}
	downloadToFile, err := os.OpenFile(downloadToFilePath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	slog.Info("Sync downloading file", "name", crackFile.Name, "bytes", crackFile.UncompressedSize, "path", downloadToFile.Name())

	// Make sure we download in order
	sort.Slice(crackFile.Chunks, func(i, j int) bool {
		return crackFile.Chunks[i].N < crackFile.Chunks[j].N
	})

	compressedStream := &DataStream{
		stream: make(chan []byte, 2),
		rpc:    server.rpc,
	}
	decompressor, err := zstd.NewReader(compressedStream)
	if err != nil {
		return err
	}
	defer decompressor.Close()
	defer downloadToFile.Close()

	// buffer some chunks in memory
	errors := []error{}
	go func() {
		defer compressedStream.Close()
		for _, chunk := range crackFile.Chunks {
			chunk.CrackFileID = crackFile.ID
			dataChunk, err := server.rpc.CrackFileChunkDownload(context.Background(), chunk)
			if err != nil {
				errors = append(errors, err)
				continue
			}
			slog.Debug("Sync downloaded chunk", "chunk_id", chunk.ID, "chunk", chunk.N+1, "total", len(crackFile.Chunks), "bytes", len(dataChunk.Data))
			compressedStream.Write(dataChunk.Data)
			c.syncBytes += len(dataChunk.Data)
			c.SyncStatus.Progress[crackFile.Sha2_256] = float32(chunk.N+1) / float32(len(crackFile.Chunks))
			c.SyncStatus.Speed = float32(c.syncBytes) / float32(time.Since(c.syncStart).Seconds())
		}
	}()

	digest := sha256.New()
	decompressorTee := io.TeeReader(decompressor, digest)
	_, err = io.Copy(downloadToFile, decompressorTee)
	if err != nil && err != io.ErrUnexpectedEOF {
		os.Remove(downloadToFile.Name())
		return err
	}
	downloadToFile.Close()

	if len(errors) > 0 {
		os.Remove(downloadToFile.Name())
		return fmt.Errorf("failed to download %d chunks: %v", len(errors), errors)
	}

	// Verify the SHA2_256
	downloadedFileSHA2_256 := hex.EncodeToString(digest.Sum(nil))
	if downloadedFileSHA2_256 != crackFile.Sha2_256 {
		os.Remove(downloadToFile.Name())
		return fmt.Errorf("downloaded file sha2-256 does not match: %s != %s", downloadedFileSHA2_256, crackFile.Sha2_256)
	}

	return nil
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
