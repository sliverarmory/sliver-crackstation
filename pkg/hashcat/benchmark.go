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
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/sliverarmory/sliver-crackstation/pkg/protocompat"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const maxModuleDirectoryEntries = 10_000

// BenchmarkDeviceSpeed is the latest positive speed reported for one Hashcat
// backend device while benchmarking a hash mode.
type BenchmarkDeviceSpeed struct {
	Device int
	Speed  uint64
}

// BenchmarkProgress is a point-in-time view of a running Hashcat benchmark.
// HashMode and HashName identify the mode currently being prepared or measured.
// Last* retains the most recent usable result when Hashcat has already printed
// the next mode header but has not produced that mode's speed yet.
type BenchmarkProgress struct {
	HashMode         int32
	HashName         string
	TotalModes       int
	CompletedModes   int
	ModeComplete     bool
	Speed            uint64
	DeviceSpeeds     []BenchmarkDeviceSpeed
	LastHashMode     int32
	LastHashName     string
	LastSpeed        uint64
	LastDeviceSpeeds []BenchmarkDeviceSpeed
}

func (h *Hashcat) Benchmark(cmd *clientpb.CrackCommand) (map[int32]uint64, error) {
	return h.BenchmarkContext(context.Background(), cmd)
}

// BenchmarkContext runs a benchmark that can be stopped when the server
// connection generation which requested it goes away. This prevents a stale
// reconnect event from monopolizing Hashcat after a replacement connection is
// already ready to dispatch work.
func (h *Hashcat) BenchmarkContext(ctx context.Context, cmd *clientpb.CrackCommand) (map[int32]uint64, error) {
	return h.BenchmarkContextStreaming(ctx, cmd, nil)
}

// BenchmarkContextStreaming runs a benchmark and reports bounded progress as
// Hashcat prints each mode header and device or aggregate speed result. It does
// not add Hashcat's --status flags, which benchmark mode does not support.
func (h *Hashcat) BenchmarkContextStreaming(
	ctx context.Context,
	cmd *clientpb.CrackCommand,
	onProgress func(BenchmarkProgress),
) (map[int32]uint64, error) {
	if cmd == nil || (!cmd.Benchmark && !cmd.BenchmarkAll) {
		return nil, errors.New("invalid benchmark command")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	var progressObserver *benchmarkProgressObserver
	var onLine func([]byte)
	if onProgress != nil {
		totalModes := 0
		if cmd.BenchmarkAll {
			if installedModes, err := h.installedHashModes(); err == nil {
				totalModes = len(installedModes)
			}
		} else if _, explicitMode, err := EffectiveHashMode(cmd); err == nil && explicitMode {
			totalModes = 1
		}
		progressObserver = newBenchmarkProgressObserver(totalModes, onProgress)
		onLine = progressObserver.observeLine
	}

	result, runErr := h.crackWithResultStreamingContextObserved(ctx, cmd, nil, onLine)
	if progressObserver != nil && ctx.Err() == nil {
		progressObserver.finishCurrent()
	}
	benchmarks, outputErr := parseBenchmarkResult(result)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if len(benchmarks) == 0 {
		return nil, errors.Join(
			errors.New("hashcat benchmark produced no usable positive results"),
			runErr,
			outputErr,
		)
	}

	bulkIncomplete := runErr != nil || outputErr != nil
	if !cmd.BenchmarkAll || !bulkIncomplete {
		if bulkIncomplete {
			slog.Warn(
				"Hashcat benchmark exited after producing usable results",
				"modes", len(benchmarks),
				"run_err", runErr,
				"output_err", outputErr,
			)
		}
		return benchmarks, nil
	}

	installedModes, err := h.installedHashModes()
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("enumerate installed hash modes after incomplete benchmark-all: %w", err),
			runErr,
			outputErr,
		)
	}
	if progressObserver != nil {
		progressObserver.setTotalModes(len(installedModes))
	}

	var unavailableModes []int32
	for _, mode := range installedModes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, ok := benchmarks[mode]; ok {
			continue
		}

		selected, err := selectedBenchmarkCommand(cmd, mode)
		if err != nil {
			unavailableModes = append(unavailableModes, mode)
			slog.Warn("Failed to prepare exact hash-mode benchmark", "hash_mode", mode, "err", err)
			continue
		}
		selectedResult, selectedRunErr := h.crackWithResultStreamingContextObserved(ctx, selected, nil, onLine)
		if progressObserver != nil && ctx.Err() == nil {
			progressObserver.finishCurrent()
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		selectedBenchmarks, selectedOutputErr := parseBenchmarkResult(selectedResult)
		speed, found := selectedBenchmarks[mode]
		if selectedOutputErr != nil || !found || speed == 0 {
			unavailableModes = append(unavailableModes, mode)
			slog.Warn(
				"Skipping unavailable exact hash-mode benchmark",
				"hash_mode", mode,
				"run_err", selectedRunErr,
				"output_err", selectedOutputErr,
			)
			continue
		}
		benchmarks[mode] = speed
		if selectedRunErr != nil {
			slog.Warn(
				"Exact hash-mode benchmark exited after producing a usable result",
				"hash_mode", mode,
				"err", selectedRunErr,
			)
		}
	}

	if len(unavailableModes) != 0 {
		slog.Warn(
			"Hashcat benchmark-all skipped modes unavailable on this station",
			"modes", unavailableModes,
		)
	}
	return benchmarks, nil
}

type benchmarkProgressObserver struct {
	onProgress func(BenchmarkProgress)
	totalModes int

	hasCurrent       bool
	currentComplete  bool
	hashMode         int32
	hashName         string
	deviceSpeeds     map[int]uint64
	aggregateSpeed   uint64
	hasAggregate     bool
	completedModes   map[int32]struct{}
	lastHashMode     int32
	lastHashName     string
	lastSpeed        uint64
	lastDeviceSpeeds []BenchmarkDeviceSpeed
}

func newBenchmarkProgressObserver(totalModes int, onProgress func(BenchmarkProgress)) *benchmarkProgressObserver {
	return &benchmarkProgressObserver{
		onProgress:     onProgress,
		totalModes:     totalModes,
		deviceSpeeds:   map[int]uint64{},
		completedModes: map[int32]struct{}{},
	}
}

func (o *benchmarkProgressObserver) setTotalModes(totalModes int) {
	o.totalModes = totalModes
}

func (o *benchmarkProgressObserver) observeLine(line []byte) {
	trimmed := strings.TrimSpace(string(line))
	if strings.HasPrefix(trimmed, "* Hash-Mode") {
		o.finishCurrent()
		hashMode, hashName, err := parseBenchmarkHeader(trimmed)
		if err != nil {
			// Do not let speeds following a malformed header update the
			// previously observed mode.
			o.hasCurrent = false
			return
		}
		o.hasCurrent = true
		o.currentComplete = false
		o.hashMode = hashMode
		o.hashName = hashName
		o.deviceSpeeds = map[int]uint64{}
		o.aggregateSpeed = 0
		o.hasAggregate = false
		o.emit()
		return
	}
	if !o.hasCurrent {
		return
	}
	if trimmed == "" {
		o.finishCurrent()
		return
	}
	if o.currentComplete {
		return
	}

	device, aggregate, ok := parseBenchmarkSpeedTarget(trimmed)
	if !ok {
		return
	}
	speed, err := parseBenchmarkSpeed(trimmed)
	if err != nil || speed == 0 {
		return
	}
	if aggregate {
		o.aggregateSpeed = speed
		o.hasAggregate = true
	} else {
		o.deviceSpeeds[device] = speed
	}
	if aggregate {
		o.finishCurrent()
	} else {
		o.emit()
	}
}

// finishCurrent promotes the current measured rate to the latest completed
// result. A single-device benchmark has no aggregate Speed.#* line, so callers
// also invoke this at a blank separator, the next mode header, and process end.
func (o *benchmarkProgressObserver) finishCurrent() {
	if !o.hasCurrent || o.currentComplete || o.modeSpeed() == 0 {
		return
	}
	if _, completed := o.completedModes[o.hashMode]; !completed {
		o.completedModes[o.hashMode] = struct{}{}
	}
	o.currentComplete = true
	o.lastHashMode = o.hashMode
	o.lastHashName = o.hashName
	o.lastSpeed = o.modeSpeed()
	o.lastDeviceSpeeds = sortedBenchmarkDeviceSpeeds(o.deviceSpeeds)
	o.emit()
}

func (o *benchmarkProgressObserver) modeSpeed() uint64 {
	if o.hasAggregate {
		return o.aggregateSpeed
	}
	var total uint64
	for _, speed := range o.deviceSpeeds {
		if math.MaxUint64-total < speed {
			return math.MaxUint64
		}
		total += speed
	}
	return total
}

func (o *benchmarkProgressObserver) emit() {
	if o.onProgress == nil || !o.hasCurrent {
		return
	}
	o.onProgress(BenchmarkProgress{
		HashMode:         o.hashMode,
		HashName:         o.hashName,
		TotalModes:       o.totalModes,
		CompletedModes:   len(o.completedModes),
		ModeComplete:     o.currentComplete,
		Speed:            o.modeSpeed(),
		DeviceSpeeds:     sortedBenchmarkDeviceSpeeds(o.deviceSpeeds),
		LastHashMode:     o.lastHashMode,
		LastHashName:     o.lastHashName,
		LastSpeed:        o.lastSpeed,
		LastDeviceSpeeds: append([]BenchmarkDeviceSpeed(nil), o.lastDeviceSpeeds...),
	})
}

func sortedBenchmarkDeviceSpeeds(speeds map[int]uint64) []BenchmarkDeviceSpeed {
	devices := make([]int, 0, len(speeds))
	for device := range speeds {
		devices = append(devices, device)
	}
	sort.Ints(devices)
	result := make([]BenchmarkDeviceSpeed, 0, len(devices))
	for _, device := range devices {
		result = append(result, BenchmarkDeviceSpeed{Device: device, Speed: speeds[device]})
	}
	return result
}

func parseBenchmarkSpeedTarget(line string) (device int, aggregate bool, ok bool) {
	const prefix = "Speed.#"
	if !strings.HasPrefix(line, prefix) {
		return 0, false, false
	}
	colon := strings.IndexByte(line, ':')
	if colon < len(prefix) {
		return 0, false, false
	}
	label := strings.TrimRight(strings.TrimSpace(line[len(prefix):colon]), ".")
	if label == "*" {
		return 0, true, true
	}
	parsed, err := strconv.Atoi(label)
	if err != nil || parsed <= 0 {
		return 0, false, false
	}
	return parsed, false, true
}

func parseBenchmarkHeader(line string) (int32, string, error) {
	const prefix = "* Hash-Mode "
	header := strings.TrimSpace(line)
	if !strings.HasPrefix(header, prefix) {
		return 0, "", fmt.Errorf("malformed hash mode header %q", line)
	}
	remainder := strings.TrimPrefix(header, prefix)
	nameStart := strings.Index(remainder, " (")
	nameEnd := strings.LastIndex(remainder, ")")
	if nameStart <= 0 || nameEnd <= nameStart+1 {
		return 0, "", fmt.Errorf("malformed hash mode header %q", line)
	}
	mode, err := strconv.ParseInt(strings.TrimSpace(remainder[:nameStart]), 10, 32)
	if err != nil || mode < 0 {
		return 0, "", fmt.Errorf("malformed hash mode in header %q", line)
	}
	// Hashcat may append bracketed metadata after the mode name, for example
	// "[Iterations: 4095]". The last closing parenthesis still delimits the
	// complete name, including any parentheses within it.
	name := strings.TrimSpace(remainder[nameStart+2 : nameEnd])
	return int32(mode), name, nil
}

func parseBenchmarkResult(result CommandResult) (map[int32]uint64, error) {
	benchmarks, err := parseBenchmarkSections(string(result.Stdout))
	if result.StdoutTruncated {
		err = errors.Join(err, fmt.Errorf(
			"hashcat benchmark stdout was truncated after %d of %d bytes",
			len(result.Stdout),
			result.StdoutTotalBytes,
		))
	}
	return benchmarks, err
}

func selectedBenchmarkCommand(cmd *clientpb.CrackCommand, mode int32) (*clientpb.CrackCommand, error) {
	selected := proto.Clone(cmd).(*clientpb.CrackCommand)
	selected.AttackMode = clientpb.CrackAttackMode_NO_ATTACK
	selected.HashType = clientpb.HashType_INVALID
	selected.Benchmark = true
	selected.BenchmarkAll = false
	selected.LogfileDisable = true
	for _, field := range []protoreflect.FieldNumber{
		crackFieldBenchmarkMin,
		crackFieldBenchmarkMax,
		crackFieldHashMode,
		crackFieldIdentifyMode,
	} {
		if err := protocompat.Clear(selected, field); err != nil {
			return nil, err
		}
	}
	if err := protocompat.SetUint32(selected, crackFieldHashMode, uint32(mode)); err != nil {
		return nil, err
	}
	return selected, nil
}

func (h *Hashcat) installedHashModes() ([]int32, error) {
	root := h.hashcatDir
	if root == "" {
		root = h.cwd
	}
	if root == "" {
		return nil, errors.New("hashcat directory is not configured")
	}
	directory, err := os.Open(filepath.Join(root, "modules"))
	if err != nil {
		return nil, err
	}
	defer directory.Close()

	seen := map[int32]struct{}{}
	modes := []int32{}
	entriesRead := 0
	for {
		entries, readErr := directory.ReadDir(256)
		for _, entry := range entries {
			entriesRead++
			if entriesRead > maxModuleDirectoryEntries {
				return nil, fmt.Errorf("module directory contains more than %d entries", maxModuleDirectoryEntries)
			}
			if !entry.Type().IsRegular() {
				continue
			}
			mode, ok := canonicalModuleHashMode(entry.Name())
			if !ok {
				continue
			}
			if _, duplicate := seen[mode]; duplicate {
				continue
			}
			seen[mode] = struct{}{}
			modes = append(modes, mode)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return nil, readErr
		}
	}
	if len(modes) == 0 {
		return nil, errors.New("hashcat module directory contains no canonical modules")
	}
	sort.Slice(modes, func(i, j int) bool { return modes[i] < modes[j] })
	return modes, nil
}

func canonicalModuleHashMode(name string) (int32, bool) {
	extension := filepath.Ext(name)
	if extension != ".so" && extension != ".dll" {
		return 0, false
	}
	stem := strings.TrimSuffix(name, extension)
	const prefix = "module_"
	if !strings.HasPrefix(stem, prefix) {
		return 0, false
	}
	digits := strings.TrimPrefix(stem, prefix)
	if len(digits) != 5 {
		return 0, false
	}
	for _, digit := range digits {
		if digit < '0' || digit > '9' {
			return 0, false
		}
	}
	mode, err := strconv.ParseInt(digits, 10, 32)
	if err != nil {
		return 0, false
	}
	return int32(mode), true
}

func parseBenchmark(data string) (map[int32]uint64, error) {
	benchmarks, err := parseBenchmarkSections(data)
	if err != nil {
		return nil, err
	}
	return benchmarks, nil
}

func parseBenchmarkSections(data string) (map[int32]uint64, error) {
	benchmarks := map[int32]uint64{}
	var parseErrors []error
	lines := strings.Split(data, "\n")
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "* Hash-Mode") {
			hashMode, _, err := parseBenchmarkHeader(trimmed)
			if err != nil {
				parseErrors = append(parseErrors, fmt.Errorf("parse benchmark hash mode: %w", err))
				continue
			}
			speed, err := parseHashModeSpeed(index+1, lines)
			if err != nil {
				parseErrors = append(parseErrors, fmt.Errorf("parse hash mode %d benchmark: %w", hashMode, err))
				continue
			}
			if speed == 0 {
				parseErrors = append(parseErrors, fmt.Errorf("parse hash mode %d benchmark: speed is not positive", hashMode))
				continue
			}
			benchmarks[hashMode] = speed
		}
	}
	if len(benchmarks) == 0 && len(parseErrors) == 0 {
		parseErrors = append(parseErrors, errors.New("hashcat benchmark output contained no hash modes"))
	}
	return benchmarks, errors.Join(parseErrors...)
}

func parseHashModeSpeed(index int, lines []string) (uint64, error) {
	var aggregate *uint64
	var devices uint64
	foundDevice := false
	for _, line := range lines[index:] {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "* Hash-Mode") {
			break
		}
		if !strings.Contains(line, "Speed.#") {
			continue
		}
		speed, err := parseBenchmarkSpeed(line)
		if err != nil {
			return 0, err
		}
		if strings.Contains(line, "Speed.#*") {
			value := speed
			aggregate = &value
			continue
		}
		if math.MaxUint64-devices < speed {
			return 0, errors.New("combined benchmark speed overflows uint64")
		}
		devices += speed
		foundDevice = true
	}
	if aggregate != nil {
		return *aggregate, nil
	}
	if !foundDevice {
		return 0, errors.New("hash mode contained no speed result")
	}
	return devices, nil
}

func parseBenchmarkSpeed(line string) (uint64, error) {
	colon := strings.IndexByte(line, ':')
	if colon < 0 {
		return 0, fmt.Errorf("malformed speed line %q", line)
	}
	fields := strings.Fields(strings.SplitN(line[colon+1:], "(", 2)[0])
	if len(fields) < 2 {
		return 0, fmt.Errorf("malformed speed value %q", line)
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, fmt.Errorf("invalid speed %q", fields[0])
	}
	multiplier := float64(1)
	switch fields[1] {
	case "H/s":
	case "kH/s":
		multiplier = 1e3
	case "MH/s":
		multiplier = 1e6
	case "GH/s":
		multiplier = 1e9
	case "TH/s":
		multiplier = 1e12
	case "PH/s":
		multiplier = 1e15
	case "EH/s":
		multiplier = 1e18
	default:
		return 0, fmt.Errorf("unknown speed unit %q", fields[1])
	}
	scaled := value * multiplier
	// float64(math.MaxUint64) rounds up to 2^64, so comparing against
	// math.MaxUint64 would accidentally admit that unrepresentable boundary.
	if scaled >= 18446744073709551616.0 {
		return 0, errors.New("benchmark speed overflows uint64")
	}
	return uint64(scaled), nil
}
