package hashcat

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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/bishopfox/sliver/protobuf/clientpb"
)

func NewHashcat(hashcatDir string) *Hashcat {
	if _, err := os.Stat(hashcatDir); os.IsNotExist(err) {
		panic(err)
	}
	if _, err := os.Stat(filepath.Join(hashcatDir, hashcatExe)); os.IsNotExist(err) {
		panic(err)
	}
	return &Hashcat{
		exe:        filepath.Join(hashcatDir, hashcatExe),
		cwd:        hashcatDir,
		hashcatDir: hashcatDir,
	}
}

type Hashcat struct {
	exe        string
	cwd        string
	hashcatDir string
	version    string
	versionMu  sync.Mutex

	CUDABackend   []*clientpb.CUDABackendInfo
	HIPBackend    []*HIPBackendInfo
	MetalBackend  []*clientpb.MetalBackendInfo
	OpenCLBackend []*clientpb.OpenCLBackendInfo

	fileResolver func(string) (string, error)
}

// SetFileResolver installs a resolver for content-addressed file references
// such as crackfile://wordlist/<sha256>. The resolver is configured once while
// the crackstation starts, before Hashcat tasks are accepted.
func (h *Hashcat) SetFileResolver(resolver func(string) (string, error)) {
	h.fileResolver = resolver
}

// CommandResult contains the process output result of one Hashcat process. Keeping
// stderr and the exit code separate lets the crackstation return useful output
// to Sliver without placing recovered plaintexts or credentials in logs.
type CommandResult struct {
	Stdout           []byte
	Stderr           []byte
	ExitCode         int32
	StdoutTruncated  bool
	StderrTruncated  bool
	StdoutTotalBytes uint64
	StderrTotalBytes uint64
}

// Keep a task result comfortably below gRPC and database limits even for
// output-oriented modes such as --stdout, --show, and --left. Hashcat is still
// drained completely so a full pipe cannot deadlock the child process.
const (
	maxCapturedOutputBytes = 8 << 20
	maxHashcatStatusBytes  = 1 << 20
)

func (h *Hashcat) hashcatCmd(args []string) ([]byte, error) {
	result, err := h.runHashcat(args, nil)
	return result.Stdout, err
}

func (h *Hashcat) runHashcat(args []string, stdin []byte) (CommandResult, error) {
	return h.runHashcatStreaming(context.Background(), args, stdin, nil)
}

// runHashcatStreaming executes Hashcat while preserving both output streams
// and forwarding each machine-readable JSON status object as it arrives.
func (h *Hashcat) runHashcatStreaming(
	ctx context.Context,
	args []string,
	stdin []byte,
	onStatus func([]byte),
) (CommandResult, error) {
	return h.runHashcatStreamingInDirectory(ctx, args, stdin, onStatus, h.cwd)
}

func (h *Hashcat) runHashcatStreamingInDirectory(
	ctx context.Context,
	args []string,
	stdin []byte,
	onStatus func([]byte),
	workingDirectory string,
) (CommandResult, error) {
	slog.Debug("Executing hashcat", "exe", h.exe, "args", strings.Join(redactHashcatArgs(args), " "))
	cmd := exec.CommandContext(ctx, h.exe, args...)
	cmd.Dir = workingDirectory
	cmd.Env = os.Environ()
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	stdout := newLimitedBuffer(maxCapturedOutputBytes)
	stderr := newLimitedBuffer(maxCapturedOutputBytes)
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return CommandResult{ExitCode: -1}, err
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return CommandResult{ExitCode: -1}, err
	}
	if err := cmd.Start(); err != nil {
		return CommandResult{ExitCode: -1}, err
	}

	var callbackMu sync.Mutex
	forwardStatus := func(statusJSON []byte) {
		if onStatus == nil {
			return
		}
		callbackMu.Lock()
		onStatus(statusJSON)
		callbackMu.Unlock()
	}
	readErrors := make(chan error, 2)
	var readers sync.WaitGroup
	readers.Add(2)
	go func() {
		defer readers.Done()
		readErrors <- captureHashcatStream(stdoutPipe, stdout, forwardStatus)
	}()
	go func() {
		defer readers.Done()
		readErrors <- captureHashcatStream(stderrPipe, stderr, forwardStatus)
	}()

	readers.Wait()
	waitErr := cmd.Wait()
	close(readErrors)
	var readErr error
	for candidate := range readErrors {
		if candidate != nil && readErr == nil {
			readErr = candidate
		}
	}
	result := CommandResult{
		Stdout:           stdout.Bytes(),
		Stderr:           stderr.Bytes(),
		StdoutTruncated:  stdout.Truncated(),
		StderrTruncated:  stderr.Truncated(),
		StdoutTotalBytes: stdout.TotalBytes(),
		StderrTotalBytes: stderr.TotalBytes(),
	}
	if waitErr != nil {
		result.ExitCode = -1
		var exitError *exec.ExitError
		if errors.As(waitErr, &exitError) {
			result.ExitCode = int32(exitError.ExitCode())
		}
		// Hashcat exit code 1 means the candidate space was exhausted without
		// a recovery. That is a successful terminal result for a queue shard.
		if result.ExitCode != 1 {
			slog.Error("Hashcat command failed", "err", waitErr, "exit_code", result.ExitCode, "stdout_bytes", stdout.TotalBytes(), "stderr_bytes", stderr.TotalBytes(), "output_truncated", result.StdoutTruncated || result.StderrTruncated)
			return result, waitErr
		}
	}
	if readErr != nil {
		return result, readErr
	}
	return result, nil
}

func captureHashcatStream(reader io.Reader, output io.Writer, onStatus func([]byte)) error {
	buffered := bufio.NewReaderSize(reader, 64<<10)
	statusLine := make([]byte, 0, 64<<10)
	statusLineTooLarge := false
	for {
		fragment, err := buffered.ReadSlice('\n')
		if len(fragment) > 0 {
			if _, writeErr := output.Write(fragment); writeErr != nil {
				return writeErr
			}
			if !statusLineTooLarge {
				if len(statusLine)+len(fragment) <= maxHashcatStatusBytes {
					statusLine = append(statusLine, fragment...)
				} else {
					statusLine = statusLine[:0]
					statusLineTooLarge = true
				}
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if !statusLineTooLarge && len(statusLine) != 0 {
			trimmed := bytes.TrimSpace(statusLine)
			if isHashcatStatusJSON(trimmed) {
				onStatus(append([]byte(nil), trimmed...))
			}
		}
		statusLine = statusLine[:0]
		statusLineTooLarge = false
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func isHashcatStatusJSON(data []byte) bool {
	if len(data) < 2 || data[0] != '{' || data[len(data)-1] != '}' {
		return false
	}
	value := map[string]json.RawMessage{}
	if json.Unmarshal(data, &value) != nil {
		return false
	}
	for _, key := range []string{"status", "progress", "devices", "session"} {
		if _, ok := value[key]; ok {
			return true
		}
	}
	return false
}

func redactHashcatArgs(args []string) []string {
	redacted := append([]string(nil), args...)
	redactNext := false
	for index, arg := range redacted {
		if redactNext {
			redacted[index] = "<redacted>"
			redactNext = false
			continue
		}
		if strings.HasPrefix(arg, "--brain-password=") {
			redacted[index] = "--brain-password=<redacted>"
			continue
		}
		if strings.HasPrefix(arg, "--lookup=") {
			redacted[index] = "--lookup=<redacted>"
			continue
		}
		if arg == "--brain-password" || arg == "--lookup" {
			redactNext = true
		}
	}
	return redacted
}

func (h *Hashcat) BackendInfo() error {
	rawBackendInfo, err := h.hashcatCmd([]string{"--backend-info", "--machine-readable"})
	if err != nil {
		return err
	}
	cuda, hip, metal, openCL, err := parseMachineReadableBackendInfo(rawBackendInfo)
	if err != nil {
		return err
	}
	// Hashcat v7.1.2 omits Cache.Size from its JSON formatter even though the
	// human formatter reports it. Supplement only that missing datum.
	humanBackendInfo, err := h.hashcatCmd([]string{"--backend-info"})
	if err != nil {
		return err
	}
	detected := &Hashcat{
		CUDABackend:   cuda,
		HIPBackend:    hip,
		MetalBackend:  metal,
		OpenCLBackend: openCL,
	}
	if err := detected.applyBackendCacheSizes(humanBackendInfo); err != nil {
		return fmt.Errorf("decode hashcat backend cache sizes: %w", err)
	}
	// Replace every backend atomically so a failed probe or disappearing
	// runtime cannot leave a partially refreshed inventory.
	h.CUDABackend = detected.CUDABackend
	h.HIPBackend = detected.HIPBackend
	h.MetalBackend = detected.MetalBackend
	h.OpenCLBackend = detected.OpenCLBackend
	return nil
}

func (h *Hashcat) parseCUDABackendInfo(index int, lines []string) {
	h.CUDABackend = []*clientpb.CUDABackendInfo{}
	cudaVersion := ""
	for ; index < len(lines); index++ {
		{
			line := strings.TrimSpace(lines[index])
			if line == "" {
				continue
			}
			if strings.Contains(line, "CUDA.Version.:") {
				cudaVersion = strings.TrimSpace(strings.Split(line, ":")[1])
				continue
			}
			if strings.Contains(line, "Backend Device ID") {
				cuda := h.parseCudaDevice(index+1, lines)
				cuda.Version = cudaVersion
				h.CUDABackend = append(h.CUDABackend, cuda)
				continue
			}
			if strings.HasPrefix(line, "OpenCL") || strings.HasPrefix(line, "CUDA") || strings.HasPrefix(line, "Metal") {
				break
			}
		}
	}
}

func (h *Hashcat) parseCudaDevice(index int, lines []string) *clientpb.CUDABackendInfo {
	cuda := &clientpb.CUDABackendInfo{}
	for ; index < len(lines); index++ {
		if strings.Contains(strings.TrimSpace(lines[index]), "Name") {
			cuda.Name = strings.TrimSpace(strings.Split(lines[index], ":")[1])
		}
		if strings.Contains(lines[index], "Processor(s)") {
			processorCount, err := strconv.Atoi(strings.TrimSpace(strings.Split(lines[index], ":")[1]))
			if err == nil {
				cuda.Processors = int32(processorCount)
				continue
			}
		}
		if strings.Contains(lines[index], "Clock") {
			if strings.TrimSpace(strings.Split(lines[index], ":")[1]) == "N/A" {
				cuda.Clock = -1
				continue
			}
			clock, err := strconv.Atoi(strings.TrimSpace(strings.Split(lines[index], ":")[1]))
			if err == nil {
				cuda.Clock = int32(clock)
				continue
			}
		}
		if strings.Contains(lines[index], "Memory.Total") {
			cuda.MemoryTotal = strings.TrimSpace(strings.Split(lines[index], ":")[1])
			continue
		}
		if strings.Contains(lines[index], "Memory.Free") {
			cuda.MemoryFree = strings.TrimSpace(strings.Split(lines[index], ":")[1])
			continue
		}
		if strings.Contains(lines[index], "PCI.Addr.BDFe.") {
			break
		}
	}
	return cuda
}

func (h *Hashcat) parseMetalBackendInfo(index int, lines []string) {
	h.MetalBackend = []*clientpb.MetalBackendInfo{}
	metalVersion := ""
	for ; index < len(lines); index++ {
		{
			line := strings.TrimSpace(lines[index])
			if line == "" {
				continue
			}
			if strings.Contains(line, "Metal.Version.:") {
				metalVersion = strings.TrimSpace(strings.Split(line, ":")[1])
				continue
			}
			if strings.Contains(line, "Backend Device ID") {
				metal := h.parseMetalDevice(index+1, lines)
				metal.Version = metalVersion
				h.MetalBackend = append(h.MetalBackend, metal)
				continue
			}
			if strings.HasPrefix(line, "OpenCL") || strings.HasPrefix(line, "CUDA") || strings.HasPrefix(line, "Metal") {
				break
			}
		}
	}
}

func (h *Hashcat) parseMetalDevice(index int, lines []string) *clientpb.MetalBackendInfo {
	metal := &clientpb.MetalBackendInfo{}
	for ; index < len(lines); index++ {
		if strings.TrimSpace(lines[index]) == "" {
			continue
		}
		if strings.Contains(lines[index], "Type...........:") {
			metal.Type = strings.TrimSpace(strings.Split(lines[index], ":")[1])
			continue
		}
		if strings.Contains(lines[index], "Vendor.ID......:") {
			vendorID, err := strconv.Atoi(strings.TrimSpace(strings.Split(lines[index], ":")[1]))
			if err == nil {
				metal.VendorID = int32(vendorID)
				continue
			}
		}
		if strings.Contains(lines[index], "Vendor.........:") {
			metal.Vendor = strings.TrimSpace(strings.Split(lines[index], ":")[1])
			continue
		}
		if strings.Contains(lines[index], "Name...........:") {
			metal.Name = strings.TrimSpace(strings.Split(lines[index], ":")[1])
			continue
		}
		if strings.Contains(lines[index], "Processor(s)...:") {
			processorCount, err := strconv.Atoi(strings.TrimSpace(strings.Split(lines[index], ":")[1]))
			if err == nil {
				metal.Processors = int32(processorCount)
				continue
			}
		}
		if strings.Contains(lines[index], "Clock..........:") {
			if strings.TrimSpace(strings.Split(lines[index], ":")[1]) == "N/A" {
				metal.Clock = -1
				continue
			}
			clock, err := strconv.Atoi(strings.TrimSpace(strings.Split(lines[index], ":")[1]))
			if err == nil {
				metal.Clock = int32(clock)
				continue
			}
		}
		if strings.Contains(lines[index], "Memory.Total...:") {
			metal.MemoryTotal = strings.TrimSpace(strings.Split(lines[index], ":")[1])
			continue
		}
		if strings.Contains(lines[index], "Memory.Free....:") {
			metal.MemoryFree = strings.TrimSpace(strings.Split(lines[index], ":")[1])
			continue
		}
		if strings.HasPrefix(lines[index], "GPU.Properties.:") {
			break
		}
	}
	return metal
}

func (h *Hashcat) parseOpenCLBackendInfo(index int, lines []string) {
	h.OpenCLBackend = []*clientpb.OpenCLBackendInfo{}
	for ; index < len(lines); index++ {
		{
			line := strings.TrimSpace(lines[index])
			if line == "" {
				continue
			}
			if strings.Contains(line, "OpenCL Platform ID") {
				openCLs := h.parseOpenCLPlatform(index+1, lines)
				h.OpenCLBackend = append(h.OpenCLBackend, openCLs...)
				continue
			}
			if strings.HasPrefix(line, "CUDA") || strings.HasPrefix(line, "Metal") {
				break
			}
		}
	}
}

func (h *Hashcat) parseOpenCLPlatform(index int, lines []string) []*clientpb.OpenCLBackendInfo {
	platform := []*clientpb.OpenCLBackendInfo{}
	for ; index < len(lines); index++ {
		line := strings.TrimSpace(lines[index])
		if line == "" {
			continue
		}
		if strings.Contains(line, "Backend Device ID") {
			platform = append(platform, h.parseOpenCLDevice(index+1, lines))
			continue
		}
		if strings.HasPrefix(line, "OpenCL Platform ID") || strings.HasPrefix(line, "CUDA") || strings.HasPrefix(line, "Metal") {
			break
		}
	}
	return platform
}

func (h *Hashcat) parseOpenCLDevice(index int, lines []string) *clientpb.OpenCLBackendInfo {
	openCL := &clientpb.OpenCLBackendInfo{}
	for ; index < len(lines); index++ {
		if strings.TrimSpace(lines[index]) == "" {
			continue
		}
		if strings.Contains(lines[index], "Type...........:") {
			openCL.Type = strings.TrimSpace(strings.Split(lines[index], ":")[1])
			continue
		}
		if strings.Contains(lines[index], "Vendor.ID......:") {
			vendorID, err := strconv.Atoi(strings.TrimSpace(strings.Split(lines[index], ":")[1]))
			if err == nil {
				openCL.VendorID = int32(vendorID)
				continue
			}
		}
		if strings.Contains(lines[index], "Vendor.........:") {
			openCL.Vendor = strings.TrimSpace(strings.Split(lines[index], ":")[1])
			continue
		}
		if strings.Contains(lines[index], "Name...........:") {
			openCL.Name = strings.TrimSpace(strings.Split(lines[index], ":")[1])
			continue
		}
		if strings.Contains(lines[index], "Processor(s)...:") {
			processorCount, err := strconv.Atoi(strings.TrimSpace(strings.Split(lines[index], ":")[1]))
			if err == nil {
				openCL.Processors = int32(processorCount)
				continue
			}
		}
		if strings.Contains(lines[index], "Clock..........:") {
			if strings.TrimSpace(strings.Split(lines[index], ":")[1]) == "N/A" {
				openCL.Clock = -1
				continue
			}
			clock, err := strconv.Atoi(strings.TrimSpace(strings.Split(lines[index], ":")[1]))
			if err == nil {
				openCL.Clock = int32(clock)
				continue
			}
		}
		if strings.Contains(lines[index], "Memory.Total...:") {
			openCL.MemoryTotal = strings.TrimSpace(strings.Split(lines[index], ":")[1])
			continue
		}
		if strings.Contains(lines[index], "Memory.Free....:") {
			openCL.MemoryFree = strings.TrimSpace(strings.Split(lines[index], ":")[1])
			continue
		}
		if strings.Contains(lines[index], "OpenCL.Version.:") {
			openCL.Version = strings.TrimSpace(strings.Split(lines[index], ":")[1])
			continue
		}
		if strings.HasPrefix(lines[index], "Driver.Version.:") {
			break
		}
	}
	return openCL
}

func (h *Hashcat) Version() string {
	h.versionMu.Lock()
	defer h.versionMu.Unlock()
	if h.version != "" {
		return h.version
	}
	data, err := h.hashcatCmd([]string{"--version"})
	if err != nil {
		return ""
	}
	h.version = strings.TrimSpace(string(data))
	return h.version
}
