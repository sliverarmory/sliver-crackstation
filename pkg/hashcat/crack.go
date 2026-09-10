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
	result, err := h.CrackWithResult(cmd)
	return result.Stdout, err
}

// CrackWithResult runs Hashcat and preserves both output streams and the exit
// code for the gRPC task result.
func (h *Hashcat) CrackWithResult(cmd *clientpb.CrackCommand) (CommandResult, error) {
	if cmd == nil {
		return CommandResult{ExitCode: -1}, fmt.Errorf("missing crack command")
	}
	v7Fields, err := readCrackCommandV7Fields(cmd)
	if err != nil {
		return CommandResult{ExitCode: -1}, fmt.Errorf("decode Hashcat 7 command fields: %w", err)
	}
	args, cleanup, err := h.parseUserTaskArgsWithFields(cmd, v7Fields)
	defer func() {
		for _, f := range cleanup {
			os.Remove(f)
		}
	}()
	if err != nil {
		return CommandResult{ExitCode: -1}, err
	}
	return h.runHashcat(args, v7Fields.stdin)
}

func (h *Hashcat) parseUserTaskArgs(cmd *clientpb.CrackCommand) ([]string, []string, error) {
	cleanup := []string{}
	if cmd == nil {
		return nil, cleanup, fmt.Errorf("missing crack command")
	}
	v7Fields, err := readCrackCommandV7Fields(cmd)
	if err != nil {
		return nil, cleanup, fmt.Errorf("decode Hashcat 7 command fields: %w", err)
	}
	return h.parseUserTaskArgsWithFields(cmd, v7Fields)
}

func (h *Hashcat) parseUserTaskArgsWithFields(cmd *clientpb.CrackCommand, v7Fields crackCommandV7Fields) ([]string, []string, error) {
	var appTmpDir = assets.GetAppTmpDir()
	cleanup := []string{}
	if v7Fields.restoreShowCommand && (cmd.Restore || v7Fields.restorePosition) {
		return nil, cleanup, fmt.Errorf("--restore and --restore-position are mutually exclusive")
	}
	if v7Fields.identifyMode && v7Fields.hashMode != nil {
		return nil, cleanup, fmt.Errorf("--identify and --hash-type are mutually exclusive")
	}

	args := []string{}
	if cmd.AttackMode != clientpb.CrackAttackMode_STRAIGHT && cmd.AttackMode != clientpb.CrackAttackMode_NO_ATTACK {
		args = append(args, fmt.Sprintf("--attack-mode=%d", cmd.AttackMode))
	}
	if !v7Fields.identifyMode {
		if v7Fields.hashMode != nil {
			args = append(args, fmt.Sprintf("--hash-type=%d", *v7Fields.hashMode))
		} else if cmd.HashType != clientpb.HashType_INVALID {
			args = append(args, fmt.Sprintf("--hash-type=%d", cmd.HashType))
		}
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
	if v7Fields.adviceDisable {
		args = append(args, "--advice-disable")
	}
	if v7Fields.pipelineStats {
		args = append(args, "--pipeline-stats")
	}
	if v7Fields.taskTimeBreakdown {
		args = append(args, "--task-time-breakdown")
	}
	if cmd.Status {
		args = append(args, "--status")
	}
	if cmd.StatusJSON {
		args = append(args, "--status-json")
	}
	if v7Fields.statusTimerV7 != nil {
		args = append(args, fmt.Sprintf("--status-timer=%d", *v7Fields.statusTimerV7))
	} else if cmd.StatusTimer != 0 {
		args = append(args, fmt.Sprintf("--status-timer=%d", cmd.StatusTimer))
	}
	if v7Fields.stdinTimeoutAbortV7 != nil {
		args = append(args, fmt.Sprintf("--stdin-timeout-abort=%d", *v7Fields.stdinTimeoutAbortV7))
	} else if cmd.StdinTimeoutAbort != 0 {
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
	if cmd.MarkovInverse {
		args = append(args, "--markov-inverse")
	}
	if cmd.MarkovThreshold != 0 {
		args = append(args, fmt.Sprintf("--markov-threshold=%d", cmd.MarkovThreshold))
	}
	if v7Fields.metalCompilerRuntime != 0 {
		args = append(args, fmt.Sprintf("--metal-compiler-runtime=%d", v7Fields.metalCompilerRuntime))
	}
	if cmd.Runtime != 0 {
		args = append(args, fmt.Sprintf("--runtime=%d", cmd.Runtime))
	}
	if cmd.Session != "" {
		args = append(args, fmt.Sprintf("--session=%s", cmd.Session))
	}
	if cmd.Restore {
		args = append(args, "--restore-position")
	}
	if cmd.RestoreDisable {
		args = append(args, "--restore-disable")
	}
	if v7Fields.restorePosition && !cmd.Restore {
		args = append(args, "--restore-position")
	}
	if v7Fields.restoreShowCommand {
		args = append(args, "--restore")
	}
	if len(cmd.RestoreFile) != 0 {
		tmp, err := os.CreateTemp(appTmpDir, "restore-file")
		if err != nil {
			return nil, cleanup, err
		}
		tmp.Write(cmd.RestoreFile)
		tmp.Close()
		cleanup = append(cleanup, tmp.Name())
		args = append(args, fmt.Sprintf("--restore-file-path=%s", tmp.Name()))
	}
	if v7Fields.outfile != "" {
		args = append(args, fmt.Sprintf("--outfile=%s", v7Fields.outfile))
	}
	if len(cmd.OutfileFormat) != 0 {
		formats := []string{}
		for _, format := range cmd.OutfileFormat {
			formats = append(formats, fmt.Sprintf("%d", format))
		}
		args = append(args, fmt.Sprintf("--outfile-format=%s", strings.Join(formats, ",")))
	}
	if v7Fields.outfileJSON {
		args = append(args, "--outfile-json")
	}
	if cmd.OutfileAutohexDisable {
		args = append(args, "--outfile-autohex-disable")
	}
	if v7Fields.outfileCheckTimerV7 != nil {
		args = append(args, fmt.Sprintf("--outfile-check-timer=%d", *v7Fields.outfileCheckTimerV7))
	} else if cmd.OutfileCheckTimer != 0 {
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
	if v7Fields.dynamicX {
		args = append(args, "--dynamic-x")
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
	if v7Fields.encodingFromName != "" {
		args = append(args, fmt.Sprintf("--encoding-from=%s", v7Fields.encodingFromName))
	} else if cmd.EncodingFrom != clientpb.CrackEncoding_INVALID_ENCODING {
		args = append(args, fmt.Sprintf("--encoding-from=%s", cmd.EncodingFrom.String()))
	}
	if v7Fields.encodingToName != "" {
		args = append(args, fmt.Sprintf("--encoding-to=%s", v7Fields.encodingToName))
	} else if cmd.EncodingTo != clientpb.CrackEncoding_INVALID_ENCODING {
		args = append(args, fmt.Sprintf("--encoding-to=%s", cmd.EncodingTo.String()))
	}
	if cmd.DebugMode != 0 {
		args = append(args, fmt.Sprintf("--debug-mode=%d", cmd.DebugMode))
	}
	if v7Fields.debugFile != "" {
		args = append(args, fmt.Sprintf("--debug-file=%s", v7Fields.debugFile))
	}
	if v7Fields.inductionDir != "" {
		args = append(args, fmt.Sprintf("--induction-dir=%s", v7Fields.inductionDir))
	}
	if v7Fields.outfileCheckDir != "" {
		args = append(args, fmt.Sprintf("--outfile-check-dir=%s", v7Fields.outfileCheckDir))
	}
	if v7Fields.seekDBPath != "" {
		args = append(args, fmt.Sprintf("--seekdb-path=%s", v7Fields.seekDBPath))
	}
	if cmd.LogfileDisable {
		args = append(args, "--logfile-disable")
	}
	if v7Fields.hccapxMessagePairV7 != nil {
		args = append(args, fmt.Sprintf("--hccapx-message-pair=%d", *v7Fields.hccapxMessagePairV7))
	} else if cmd.HccapxMessagePair != 0 {
		args = append(args, fmt.Sprintf("--hccapx-message-pair=%d", cmd.HccapxMessagePair))
	}
	if v7Fields.nonceErrorCorrectionsV7 != nil {
		args = append(args, fmt.Sprintf("--nonce-error-corrections=%d", *v7Fields.nonceErrorCorrectionsV7))
	} else if cmd.NonceErrorCorrections != 0 {
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
	if v7Fields.truecryptKeyfiles != "" {
		args = append(args, fmt.Sprintf("--truecrypt-keyfiles=%s", v7Fields.truecryptKeyfiles))
	}
	if v7Fields.veracryptKeyfiles != "" {
		args = append(args, fmt.Sprintf("--veracrypt-keyfiles=%s", v7Fields.veracryptKeyfiles))
	}
	if v7Fields.veracryptPimStart != nil {
		args = append(args, fmt.Sprintf("--veracrypt-pim-start=%d", *v7Fields.veracryptPimStart))
	}
	if v7Fields.veracryptPimStop != nil {
		args = append(args, fmt.Sprintf("--veracrypt-pim-stop=%d", *v7Fields.veracryptPimStop))
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
	if cmd.ProgressOnly {
		args = append(args, "--progress-only")
	}
	if v7Fields.benchmarkMin != 0 {
		args = append(args, fmt.Sprintf("--benchmark-min=%d", v7Fields.benchmarkMin))
	}
	if v7Fields.benchmarkMax != nil {
		args = append(args, fmt.Sprintf("--benchmark-max=%d", *v7Fields.benchmarkMax))
	}
	if cmd.SegmentSize != 0 {
		return nil, cleanup, fmt.Errorf("hashcat v7 does not support --segment-size")
	}
	if v7Fields.bitmapMinV7 != nil {
		args = append(args, fmt.Sprintf("--bitmap-min=%d", *v7Fields.bitmapMinV7))
	} else if cmd.BitmapMin != 0 {
		args = append(args, fmt.Sprintf("--bitmap-min=%d", cmd.BitmapMin))
	}
	if v7Fields.bitmapMaxV7 != nil {
		args = append(args, fmt.Sprintf("--bitmap-max=%d", *v7Fields.bitmapMaxV7))
	} else if cmd.BitmapMax != 0 {
		args = append(args, fmt.Sprintf("--bitmap-max=%d", cmd.BitmapMax))
	}
	for index, parameter := range v7Fields.bridgeParameters {
		if parameter != "" {
			args = append(args, fmt.Sprintf("--bridge-parameter%d=%s", index+1, parameter))
		}
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
	if v7Fields.hashInfoLevel > 2 {
		return nil, cleanup, fmt.Errorf("--hash-info-level must be 0, 1, or 2")
	}
	for range v7Fields.hashInfoLevel {
		args = append(args, "--hash-info")
	}
	if v7Fields.hashInfoLevel == 0 && cmd.HashInfo {
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
	if v7Fields.backendInfoLevel > 2 {
		return nil, cleanup, fmt.Errorf("--backend-info-level must be 0, 1, or 2")
	}
	for range v7Fields.backendInfoLevel {
		args = append(args, "--backend-info")
	}
	if v7Fields.backendInfoLevel == 0 && cmd.BackendInfo {
		args = append(args, "--backend-info")
	}
	if len(cmd.BackendDevices) != 0 {
		devices := []string{}
		for _, device := range cmd.BackendDevices {
			devices = append(devices, fmt.Sprintf("%d", device))
		}
		args = append(args, fmt.Sprintf("--backend-devices=%s", strings.Join(devices, ",")))
	}
	if v7Fields.backendDevicesVirtMulti != 0 {
		args = append(args, fmt.Sprintf("--backend-devices-virtmulti=%d", v7Fields.backendDevicesVirtMulti))
	}
	if v7Fields.backendDevicesVirtHost != 0 {
		args = append(args, fmt.Sprintf("--backend-devices-virthost=%d", v7Fields.backendDevicesVirtHost))
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
		args = append(args, "--multiply-accel-disable")
	}
	// Hashcat v7 keeps --workload-profile as an accepted no-op for command-line
	// compatibility. Preserve old gRPC requests by intentionally omitting it.
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
	if v7Fields.hwmonTempAbortV7 != nil {
		args = append(args, fmt.Sprintf("--hwmon-temp-abort=%d", *v7Fields.hwmonTempAbortV7))
	} else if cmd.HwmonTempAbort != 0 {
		args = append(args, fmt.Sprintf("--hwmon-temp-abort=%d", cmd.HwmonTempAbort))
	}
	if v7Fields.scryptTMTOV7 != nil {
		args = append(args, fmt.Sprintf("--scrypt-tmto=%d", *v7Fields.scryptTMTOV7))
	} else if cmd.ScryptTMTO != 0 {
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
	if v7Fields.totalCandidates {
		args = append(args, "--total-candidates")
	}
	if v7Fields.lookup != "" {
		args = append(args, fmt.Sprintf("--lookup=%s", v7Fields.lookup))
	}
	if v7Fields.ruleLeft != "" {
		args = append(args, fmt.Sprintf("--rule-left=%s", v7Fields.ruleLeft))
	}
	if v7Fields.ruleRight != "" {
		args = append(args, fmt.Sprintf("--rule-right=%s", v7Fields.ruleRight))
	}
	if cmd.GenerateRules != 0 {
		args = append(args, fmt.Sprintf("--generate-rules=%d", cmd.GenerateRules))
	}
	if v7Fields.generateRulesFuncMinV7 != nil {
		args = append(args, fmt.Sprintf("--generate-rules-func-min=%d", *v7Fields.generateRulesFuncMinV7))
	} else if cmd.GenerateRulesFunMin != 0 {
		args = append(args, fmt.Sprintf("--generate-rules-func-min=%d", cmd.GenerateRulesFunMin))
	}
	if v7Fields.generateRulesFuncMaxV7 != nil {
		args = append(args, fmt.Sprintf("--generate-rules-func-max=%d", *v7Fields.generateRulesFuncMaxV7))
	} else if cmd.GenerateRulesFunMax != 0 {
		args = append(args, fmt.Sprintf("--generate-rules-func-max=%d", cmd.GenerateRulesFunMax))
	}
	if cmd.GenerateRulesFuncSel != "" {
		args = append(args, fmt.Sprintf("--generate-rules-func-sel=%s", cmd.GenerateRulesFuncSel))
	}
	if v7Fields.generateRulesSeedV7 != nil {
		args = append(args, fmt.Sprintf("--generate-rules-seed=%d", *v7Fields.generateRulesSeedV7))
	} else if cmd.GenerateRulesSeed < 0 {
		return nil, cleanup, fmt.Errorf("hashcat v7 requires a non-negative --generate-rules-seed")
	} else if cmd.GenerateRulesSeed != 0 {
		args = append(args, fmt.Sprintf("--generate-rules-seed=%d", cmd.GenerateRulesSeed))
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
	for index, charset := range v7Fields.customCharsets {
		if charset != "" {
			args = append(args, fmt.Sprintf("--custom-charset%d=%s", index+5, charset))
		}
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
	if v7Fields.incrementInverse {
		args = append(args, "--increment-inverse")
	}
	if cmd.SlowCandidates {
		args = append(args, "--slow-candidates")
	}
	if v7Fields.bypassDelay != nil {
		args = append(args, fmt.Sprintf("--bypass-delay=%d", *v7Fields.bypassDelay))
	}
	if v7Fields.bypassThreshold != nil {
		args = append(args, fmt.Sprintf("--bypass-threshold=%d", *v7Fields.bypassThreshold))
	}
	if cmd.BrainServer {
		args = append(args, "--brain-server")
	}
	if v7Fields.brainServerTimerV7 != nil {
		args = append(args, fmt.Sprintf("--brain-server-timer=%d", *v7Fields.brainServerTimerV7))
	} else if cmd.BrainServerTimer != 0 {
		args = append(args, fmt.Sprintf("--brain-server-timer=%d", cmd.BrainServerTimer))
	}
	if cmd.BrainClient {
		args = append(args, "--brain-client")
	}
	if v7Fields.brainFeed {
		args = append(args, "--brain-feed")
	}
	if v7Fields.brainClientFeaturesV7 != 0 {
		args = append(args, fmt.Sprintf("--brain-client-features=%d", v7Fields.brainClientFeaturesV7))
	} else if cmd.BrainClientFeatures != "" {
		args = append(args, fmt.Sprintf("--brain-client-features=%s", cmd.BrainClientFeatures))
	}
	if cmd.BrainHost != "" {
		args = append(args, fmt.Sprintf("--brain-host=%s", cmd.BrainHost))
	}
	if cmd.BrainPort != 0 {
		args = append(args, fmt.Sprintf("--brain-port=%d", cmd.BrainPort))
	}
	if v7Fields.brainPasswordV7 != nil {
		args = append(args, fmt.Sprintf("--brain-password=%s", *v7Fields.brainPasswordV7))
	} else if cmd.BrainPassword != "" {
		args = append(args, fmt.Sprintf("--brain-password=%s", cmd.BrainPassword))
	}
	if v7Fields.brainSessionV7 != nil {
		args = append(args, fmt.Sprintf("--brain-session=0x%x", *v7Fields.brainSessionV7))
	} else if cmd.BrainSession != "" {
		args = append(args, fmt.Sprintf("--brain-session=%s", cmd.BrainSession))
	}
	if len(v7Fields.brainWhitelistV7) != 0 {
		whitelist := make([]string, 0, len(v7Fields.brainWhitelistV7))
		for _, session := range v7Fields.brainWhitelistV7 {
			whitelist = append(whitelist, fmt.Sprintf("0x%x", session))
		}
		args = append(args, fmt.Sprintf("--brain-session-whitelist=%s", strings.Join(whitelist, ",")))
	} else if cmd.BrainSessionWhitelist != "" {
		args = append(args, fmt.Sprintf("--brain-session-whitelist=%s", cmd.BrainSessionWhitelist))
	}
	if v7Fields.colorCracked {
		args = append(args, "--color-cracked")
	}
	if v7Fields.hashCopy {
		args = append(args, "--hash-copy")
	}
	if v7Fields.encryptWithPubkey != "" {
		args = append(args, fmt.Sprintf("--encrypt-with-pubkey=%s", v7Fields.encryptWithPubkey))
	}
	if v7Fields.identifyMode {
		args = append(args, "--identify")
	}
	rulesFiles := v7Fields.rulesFilesV7
	if len(rulesFiles) == 0 && len(cmd.RulesFile) != 0 {
		rulesFiles = [][]byte{cmd.RulesFile}
	}
	for _, rulesFile := range rulesFiles {
		tmp, err := os.CreateTemp(appTmpDir, "rules")
		if err != nil {
			return nil, cleanup, err
		}
		cleanup = append(cleanup, tmp.Name())
		if _, err := tmp.Write(rulesFile); err != nil {
			tmp.Close()
			return nil, cleanup, err
		}
		if err := tmp.Close(); err != nil {
			return nil, cleanup, err
		}
		args = append(args, fmt.Sprintf("--rules-file=%s", tmp.Name()))
	}
	operands := make([]string, 0, 1+len(v7Fields.positionalArguments))
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
		operands = append(operands, tmp.Name())
	}
	if len(v7Fields.positionalArguments) != 0 {
		operands = append(operands, v7Fields.positionalArguments...)
	} else if cmd.Identify != "" {
		// Field 100 predates Hashcat's --identify option and was historically
		// used as the single positional mask/wordlist argument.
		operands = append(operands, cmd.Identify)
	}
	for _, operand := range operands {
		if strings.ContainsRune(operand, '\x00') {
			return nil, cleanup, fmt.Errorf("hashcat positional arguments cannot contain NUL bytes")
		}
	}
	if len(operands) != 0 {
		// Hashcat deliberately enables GNU option permutation, so an operand
		// beginning with "--" would otherwise be interpreted as another option.
		args = append(args, "--")
		args = append(args, operands...)
	}

	return args, cleanup, nil
}
