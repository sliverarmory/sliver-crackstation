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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/sliverarmory/sliver-crackstation/assets"
)

func (h *Hashcat) Crack(cmd *clientpb.CrackCommand) ([]byte, error) {
	args, cleanup, err := h.parseUserTaskArgs(cmd)
	defer func() {
		for _, f := range cleanup {
			os.Remove(f)
		}
	}()
	if err != nil {
		return nil, err
	}
	return h.hashcatCmd(args)
}

func (h *Hashcat) parseUserTaskArgs(cmd *clientpb.CrackCommand) ([]string, []string, error) {
	var appTmpDir = assets.GetAppTmpDir()
	cleanup := []string{}

	args := []string{}
	if cmd.AttackMode != clientpb.CrackAttackMode_NO_ATTACK {
		args = append(args, fmt.Sprintf("--attack-mode=%d", cmd.AttackMode))
	}
	if cmd.HashType != clientpb.HashType_INVALID {
		args = append(args, fmt.Sprintf("--hash-type=%d", cmd.HashType))
	}
	if cmd.Quiet {
		args = append(args, "--quiet")
	}
	if cmd.HexCharset {
		args = append(args, "--hex-charset")
	}
	if cmd.HexSalt {
		args = append(args, "--hex-salt")
	}
	if cmd.HexWordlist {
		args = append(args, "--hex-wordlist")
	}
	if cmd.Force {
		args = append(args, "--force")
	}
	if cmd.DeprecatedCheckDisable {
		args = append(args, "--deprecated-check-disable")
	}
	if cmd.Status {
		args = append(args, "--status")
	}
	if cmd.StatusJSON {
		args = append(args, "--status-json")
	}
	if cmd.StatusTimer != 0 {
		args = append(args, fmt.Sprintf("--status-timer=%d", cmd.StatusTimer))
	}
	if cmd.StdinTimeoutAbort != 0 {
		args = append(args, fmt.Sprintf("--stdin-timeout-abort=%d", cmd.StdinTimeoutAbort))
	}
	if cmd.MachineReadable {
		args = append(args, "--machine-readable")
	}
	if cmd.KeepGuessing {
		args = append(args, "--keep-guessing")
	}
	if cmd.SelfTestDisable {
		args = append(args, "--self-test-disable")
	}
	if cmd.Loopback {
		args = append(args, "--loopback")
	}
	if len(cmd.MarkovHcstat2) != 0 {
		tmp, err := os.CreateTemp(appTmpDir, "markov-hcstat2")
		if err != nil {
			return nil, cleanup, err
		}
		tmp.Write(cmd.MarkovHcstat2)
		tmp.Close()
		cleanup = append(cleanup, tmp.Name())
		args = append(args, fmt.Sprintf("--markov-hcstat2=%s", tmp.Name()))
	}
	if cmd.MarkovDisable {
		args = append(args, "--markov-disable")
	}
	if cmd.MarkovClassic {
		args = append(args, "--markov-classic")
	}
	if cmd.MarkovThreshold != 0 {
		args = append(args, fmt.Sprintf("--markov-threshold=%d", cmd.MarkovThreshold))
	}
	if cmd.Runtime != 0 {
		args = append(args, fmt.Sprintf("--runtime=%d", cmd.Runtime))
	}
	if cmd.Session != "" {
		args = append(args, fmt.Sprintf("--session=%s", cmd.Session))
	}
	if cmd.Restore {
		args = append(args, "--restore")
	}
	if cmd.RestoreDisable {
		args = append(args, "--restore-disable")
	}
	if len(cmd.RestoreFile) != 0 {
		tmp, err := os.CreateTemp(appTmpDir, "restore-file")
		if err != nil {
			return nil, cleanup, err
		}
		tmp.Write(cmd.RestoreFile)
		tmp.Close()
		cleanup = append(cleanup, tmp.Name())
		args = append(args, fmt.Sprintf("--restore-file=%s", tmp.Name()))
	}
	if len(cmd.OutfileFormat) != 0 {
		formats := []string{}
		for _, format := range cmd.OutfileFormat {
			formats = append(formats, fmt.Sprintf("%d", format))
		}
		args = append(args, fmt.Sprintf("--outfile-format=%s", strings.Join(formats, ",")))
	}
	if cmd.OutfileAutohexDisable {
		args = append(args, "--outfile-autohex-disable")
	}
	if cmd.OutfileCheckTimer != 0 {
		args = append(args, fmt.Sprintf("--outfile-check-timer=%d", cmd.OutfileCheckTimer))
	}
	if cmd.WordlistAutohexDisable {
		args = append(args, "--wordlist-autohex-disable")
	}
	if cmd.Separator != "" {
		args = append(args, fmt.Sprintf("--separator=%s", cmd.Separator))
	}
	if cmd.Stdout {
		args = append(args, "--stdout")
	}
	if cmd.Show {
		args = append(args, "--show")
	}
	if cmd.Left {
		args = append(args, "--left")
	}
	if cmd.Username {
		args = append(args, "--username")
	}
	if cmd.Remove {
		args = append(args, "--remove")
	}
	if cmd.RemoveTimer != 0 {
		args = append(args, fmt.Sprintf("--remove-timer=%d", cmd.RemoveTimer))
	}
	if cmd.PotfileDisable {
		args = append(args, "--potfile-disable")
	}
	if len(cmd.Potfile) != 0 {
		potfilePath := ""
		candidate := string(cmd.Potfile)
		if filepath.IsAbs(candidate) {
			if _, err := os.Stat(candidate); err == nil {
				potfilePath = candidate
			}
		}
		if potfilePath == "" {
			tmp, err := os.CreateTemp(appTmpDir, "potfile")
			if err != nil {
				return nil, cleanup, err
			}
			tmp.Write(cmd.Potfile)
			tmp.Close()
			cleanup = append(cleanup, tmp.Name())
			potfilePath = tmp.Name()
		}
		args = append(args, fmt.Sprintf("--potfile-path=%s", potfilePath))
	}
	if cmd.EncodingFrom != clientpb.CrackEncoding_INVALID_ENCODING {
		args = append(args, fmt.Sprintf("--encoding-from=%s", cmd.EncodingFrom.String()))
	}
	if cmd.EncodingTo != clientpb.CrackEncoding_INVALID_ENCODING {
		args = append(args, fmt.Sprintf("--encoding-to=%s", cmd.EncodingTo.String()))
	}
	if cmd.DebugMode != 0 {
		args = append(args, fmt.Sprintf("--debug-mode=%d", cmd.DebugMode))
	}
	if cmd.LogfileDisable {
		args = append(args, "--logfile-disable")
	}
	if cmd.HccapxMessagePair != 0 {
		args = append(args, fmt.Sprintf("--hccapx-message-pair=%d", cmd.HccapxMessagePair))
	}
	if cmd.NonceErrorCorrections != 0 {
		args = append(args, fmt.Sprintf("--nonce-error-corrections=%d", cmd.NonceErrorCorrections))
	}
	if len(cmd.KeyboardLayoutMapping) != 0 {
		tmp, err := os.CreateTemp(appTmpDir, "keyboard-layout-mapping")
		if err != nil {
			return nil, cleanup, err
		}
		tmp.Write(cmd.KeyboardLayoutMapping)
		tmp.Close()
		cleanup = append(cleanup, tmp.Name())
		args = append(args, fmt.Sprintf("--keyboard-layout-mapping=%s", tmp.Name()))
	}
	if cmd.Benchmark {
		args = append(args, "--benchmark")
	}
	if cmd.BenchmarkAll {
		args = append(args, "--benchmark-all")
	}
	if cmd.SpeedOnly {
		args = append(args, "--speed-only")
	}
	if cmd.SegmentSize != 0 {
		args = append(args, fmt.Sprintf("--segment-size=%d", cmd.SegmentSize))
	}
	if cmd.BitmapMin != 0 {
		args = append(args, fmt.Sprintf("--bitmap-min=%d", cmd.BitmapMin))
	}
	if cmd.BitmapMax != 0 {
		args = append(args, fmt.Sprintf("--bitmap-max=%d", cmd.BitmapMax))
	}
	if len(cmd.CPUAffinity) != 0 {
		affinities := []string{}
		for _, affinity := range cmd.CPUAffinity {
			affinities = append(affinities, fmt.Sprintf("%d", affinity))
		}
		args = append(args, fmt.Sprintf("--cpu-affinity=%s", strings.Join(affinities, ",")))
	}
	if cmd.HookThreads != 0 {
		args = append(args, fmt.Sprintf("--hook-threads=%d", cmd.HookThreads))
	}
	if cmd.HashInfo {
		args = append(args, "--hash-info")
	}
	if cmd.BackendIgnoreCUDA {
		args = append(args, "--backend-ignore-cuda")
	}
	if cmd.BackendIgnoreHip {
		args = append(args, "--backend-ignore-hip")
	}
	if cmd.BackendIgnoreMetal {
		args = append(args, "--backend-ignore-metal")
	}
	if cmd.BackendIgnoreOpenCL {
		args = append(args, "--backend-ignore-opencl")
	}
	if cmd.BackendInfo {
		args = append(args, "--backend-info")
	}
	if len(cmd.BackendDevices) != 0 {
		devices := []string{}
		for _, device := range cmd.BackendDevices {
			devices = append(devices, fmt.Sprintf("%d", device))
		}
		args = append(args, fmt.Sprintf("--backend-devices=%s", strings.Join(devices, ",")))
	}
	if len(cmd.OpenCLDeviceTypes) != 0 {
		openCLTypes := []string{}
		for _, openCLType := range cmd.OpenCLDeviceTypes {
			openCLTypes = append(openCLTypes, fmt.Sprintf("%d", openCLType))
		}
		args = append(args, fmt.Sprintf("--opencl-device-types=%s", strings.Join(openCLTypes, ",")))
	}
	if cmd.OptimizedKernelEnable {
		args = append(args, "--optimized-kernel-enable")
	}
	if cmd.MultiplyAccelDisabled {
		args = append(args, "--multiply-accel-disabled")
	}
	if cmd.WorkloadProfile != clientpb.CrackWorkloadProfile_INVALID_WORKLOAD_PROFILE {
		args = append(args, fmt.Sprintf("--workload-profile=%d", cmd.WorkloadProfile))
	}
	if cmd.KernelAccel != 0 {
		args = append(args, fmt.Sprintf("--kernel-accel=%d", cmd.KernelAccel))
	}
	if cmd.KernelLoops != 0 {
		args = append(args, fmt.Sprintf("--kernel-loops=%d", cmd.KernelLoops))
	}
	if cmd.KernelThreads != 0 {
		args = append(args, fmt.Sprintf("--kernel-threads=%d", cmd.KernelThreads))
	}
	if cmd.BackendVectorWidth != 0 {
		args = append(args, fmt.Sprintf("--backend-vector-width=%d", cmd.BackendVectorWidth))
	}
	if cmd.SpinDamp != 0 {
		args = append(args, fmt.Sprintf("--spin-damp=%d", cmd.SpinDamp))
	}
	if cmd.HwmonDisable {
		args = append(args, "--hwmon-disable")
	}
	if cmd.HwmonTempAbort != 0 {
		args = append(args, fmt.Sprintf("--hwmon-temp-abort=%d", cmd.HwmonTempAbort))
	}
	if cmd.ScryptTMTO != 0 {
		args = append(args, fmt.Sprintf("--scrypt-tmto=%d", cmd.ScryptTMTO))
	}
	if cmd.Skip != 0 {
		args = append(args, fmt.Sprintf("--skip=%d", cmd.Skip))
	}
	if cmd.Limit != 0 {
		args = append(args, fmt.Sprintf("--limit=%d", cmd.Limit))
	}
	if cmd.Keyspace {
		args = append(args, "--keyspace")
	}
	if cmd.CustomCharset1 != "" {
		args = append(args, fmt.Sprintf("--custom-charset1=%s", cmd.CustomCharset1))
	}
	if cmd.CustomCharset2 != "" {
		args = append(args, fmt.Sprintf("--custom-charset2=%s", cmd.CustomCharset2))
	}
	if cmd.CustomCharset3 != "" {
		args = append(args, fmt.Sprintf("--custom-charset3=%s", cmd.CustomCharset3))
	}
	if cmd.CustomCharset4 != "" {
		args = append(args, fmt.Sprintf("--custom-charset4=%s", cmd.CustomCharset4))
	}
	if cmd.Increment {
		args = append(args, "--increment")
		if cmd.IncrementMin != 0 {
			args = append(args, fmt.Sprintf("--increment-min=%d", cmd.IncrementMin))
		}
		if cmd.IncrementMax != 0 {
			args = append(args, fmt.Sprintf("--increment-max=%d", cmd.IncrementMax))
		}
	}
	if len(cmd.RulesFile) != 0 {
		tmp, err := os.CreateTemp(appTmpDir, "rules")
		if err != nil {
			return nil, cleanup, err
		}
		tmp.Write(cmd.RulesFile)
		tmp.Close()
		cleanup = append(cleanup, tmp.Name())
		args = append(args, fmt.Sprintf("--rules=%s", tmp.Name()))
	}
	// rules
	if len(cmd.Hashes) != 0 {
		tmp, err := os.CreateTemp(appTmpDir, "hashes")
		if err != nil {
			return nil, cleanup, err
		}
		for _, hash := range cmd.Hashes {
			_, _ = tmp.WriteString(hash + "\n")
		}
		tmp.Close()
		cleanup = append(cleanup, tmp.Name())
		args = append(args, tmp.Name())
	}
	if cmd.Identify != "" {
		args = append(args, cmd.Identify)
	}

	return args, cleanup, nil
}
