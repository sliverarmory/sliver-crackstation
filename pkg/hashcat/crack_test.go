package hashcat

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestParseUserTaskArgsHashcatV7Options(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())

	h := &Hashcat{}
	args, cleanup, err := h.parseUserTaskArgs(&clientpb.CrackCommand{
		MultiplyAccelDisabled: true,
		Restore:               true,
		RestoreFile:           []byte("restore"),
		RulesFile:             []byte(":"),
	})
	for _, path := range cleanup {
		t.Cleanup(func() { _ = os.Remove(path) })
	}
	if err != nil {
		t.Fatalf("parseUserTaskArgs returned an error: %v", err)
	}

	joined := strings.Join(args, " ")
	for _, option := range []string{
		"--multiply-accel-disable",
		"--restore-position",
		"--restore-file-path=",
		"--rules-file=",
	} {
		if !strings.Contains(joined, option) {
			t.Errorf("expected %q in %q", option, joined)
		}
	}
	for _, obsolete := range []string{
		"--multiply-accel-disabled",
	} {
		if strings.Contains(joined, obsolete) {
			t.Errorf("did not expect obsolete option %q in %q", obsolete, joined)
		}
	}
	for _, arg := range args {
		if strings.HasPrefix(arg, "--restore-file=") || strings.HasPrefix(arg, "--rules=") {
			t.Errorf("did not expect obsolete option %q in %q", arg, joined)
		}
	}
}

func TestParseUserTaskArgsCompleteHashcatV7Surface(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())

	command := &clientpb.CrackCommand{
		MarkovInverse:         true,
		GenerateRules:         12,
		GenerateRulesFunMin:   1,
		GenerateRulesFunMax:   4,
		GenerateRulesFuncSel:  "ioTlc",
		GenerateRulesSeed:     7,
		SlowCandidates:        true,
		BrainClientFeatures:   "3",
		BrainHost:             "127.0.0.1",
		BrainPort:             6863,
		BrainPassword:         "secret",
		BrainSession:          "0x1",
		BrainSessionWhitelist: "0x1,0x2",
	}
	raw := []byte{}
	raw = appendUnknownString(raw, crackFieldOutfile, "result.txt")
	raw = appendUnknownString(raw, crackFieldDebugFile, "debug.txt")
	raw = appendUnknownString(raw, crackFieldInductionDir, "induct")
	raw = appendUnknownString(raw, crackFieldOutfileCheckDir, "outcheck")
	raw = appendUnknownString(raw, crackFieldTruecryptKeyfiles, "tc.key")
	raw = appendUnknownString(raw, crackFieldVeracryptKeyfiles, "vc.key")
	raw = appendUnknownUint32(raw, crackFieldVeracryptPimStart, 450)
	raw = appendUnknownUint32(raw, crackFieldVeracryptPimStop, 500)
	raw = appendUnknownString(raw, crackFieldRuleLeft, "c")
	raw = appendUnknownString(raw, crackFieldRuleRight, "^-")
	raw = appendUnknownBool(raw, crackFieldPipelineStats, true)
	raw = appendUnknownBool(raw, crackFieldTaskTimeBreakdown, true)
	raw = appendUnknownUint32(raw, crackFieldMetalCompilerRuntime, 180)
	raw = appendUnknownBool(raw, crackFieldRestorePosition, true)
	raw = appendUnknownBool(raw, crackFieldOutfileJSON, true)
	raw = appendUnknownBool(raw, crackFieldDynamicX, true)
	raw = appendUnknownString(raw, crackFieldSeekDBPath, "seekdb")
	raw = appendUnknownUint32(raw, crackFieldBenchmarkMin, 100)
	raw = appendUnknownUint32(raw, crackFieldBenchmarkMax, 1000)
	for index, field := range []protowire.Number{
		protowire.Number(crackFieldBridgeParameter1),
		protowire.Number(crackFieldBridgeParameter2),
		protowire.Number(crackFieldBridgeParameter3),
		protowire.Number(crackFieldBridgeParameter4),
	} {
		raw = appendUnknownString(raw, field, string(rune('a'+index)))
	}
	raw = appendUnknownUint32(raw, crackFieldBackendDevicesVirtMulti, 8)
	raw = appendUnknownUint32(raw, crackFieldBackendDevicesVirtHost, 2)
	raw = appendUnknownBool(raw, crackFieldTotalCandidates, true)
	raw = appendUnknownString(raw, crackFieldLookup, "candidate")
	for index, field := range []protowire.Number{
		protowire.Number(crackFieldCustomCharset5),
		protowire.Number(crackFieldCustomCharset6),
		protowire.Number(crackFieldCustomCharset7),
		protowire.Number(crackFieldCustomCharset8),
	} {
		raw = appendUnknownString(raw, field, "?d"+string(rune('5'+index)))
	}
	raw = appendUnknownBool(raw, crackFieldIncrementInverse, true)
	raw = appendUnknownUint32(raw, crackFieldBypassDelay, 5)
	raw = appendUnknownUint32(raw, crackFieldBypassThreshold, 6)
	raw = appendUnknownBool(raw, crackFieldColorCracked, true)
	raw = appendUnknownBool(raw, crackFieldHashCopy, true)
	raw = appendUnknownString(raw, crackFieldEncryptWithPubkey, "public.pem")
	raw = appendUnknownString(raw, crackFieldPositionalArguments, "?d?d")
	raw = appendUnknownString(raw, crackFieldPositionalArguments, "words.txt")
	raw = appendUnknownString(raw, crackFieldEncodingFromName, "windows-1252")
	raw = appendUnknownString(raw, crackFieldEncodingToName, "utf-8")
	raw = appendUnknownUint32(raw, crackFieldHashInfoLevel, 2)
	raw = appendUnknownUint32(raw, crackFieldBackendInfoLevel, 2)
	raw = appendUnknownUint32(raw, crackFieldHccapxMessagePairV7, 0)
	raw = appendUnknownUint32(raw, crackFieldNonceErrorCorrectionsV7, 0)
	raw = appendUnknownUint32(raw, crackFieldScryptTMTOV7, 0)
	raw = appendUnknownUint32(raw, crackFieldGenerateRulesSeedV7, 0)
	raw = appendUnknownUint32(raw, crackFieldBrainClientFeaturesV7, 3)
	raw = appendUnknownUint32(raw, crackFieldBrainSessionV7, 2)
	raw = appendUnknownPackedUint32(raw, crackFieldBrainWhitelistV7, []uint32{2, 3})
	raw = appendUnknownBytes(raw, crackFieldStdin, []byte("candidates\n"))
	raw = appendUnknownBool(raw, crackFieldAdviceDisable, true)
	raw = appendUnknownUint32(raw, crackFieldHashMode, 22000)
	raw = appendUnknownUint32(raw, crackFieldStatusTimerV7, 0)
	raw = appendUnknownUint32(raw, crackFieldStdinTimeoutAbortV7, 0)
	raw = appendUnknownUint32(raw, crackFieldOutfileCheckTimerV7, 0)
	raw = appendUnknownUint32(raw, crackFieldBitmapMinV7, 0)
	raw = appendUnknownUint32(raw, crackFieldBitmapMaxV7, 0)
	raw = appendUnknownUint32(raw, crackFieldHwmonTempAbortV7, 0)
	raw = appendUnknownBytes(raw, crackFieldRulesFilesV7, []byte(":"))
	raw = appendUnknownBytes(raw, crackFieldRulesFilesV7, []byte("$1"))
	raw = appendUnknownString(raw, crackFieldBrainPasswordV7, "v7-secret")
	raw = appendUnknownUint32(raw, crackFieldGenerateRulesFuncMinV7, 0)
	raw = appendUnknownUint32(raw, crackFieldGenerateRulesFuncMaxV7, 0)
	mergeCrackCommandWireFields(t, command, raw)

	h := &Hashcat{}
	args, cleanup, err := h.parseUserTaskArgs(command)
	for _, path := range cleanup {
		t.Cleanup(func() { _ = os.Remove(path) })
	}
	if err != nil {
		t.Fatalf("parseUserTaskArgs returned an error: %v", err)
	}
	for _, option := range []string{
		"--markov-inverse", "--generate-rules=12",
		"--generate-rules-func-min=0", "--generate-rules-func-max=0",
		"--generate-rules-func-sel=ioTlc", "--generate-rules-seed=0",
		"--slow-candidates", "--brain-client-features=3",
		"--brain-host=127.0.0.1", "--brain-port=6863", "--brain-password=v7-secret",
		"--outfile=result.txt", "--debug-file=debug.txt", "--induction-dir=induct",
		"--outfile-check-dir=outcheck", "--truecrypt-keyfiles=tc.key",
		"--veracrypt-keyfiles=vc.key", "--veracrypt-pim-start=450",
		"--veracrypt-pim-stop=500", "--rule-left=c", "--rule-right=^-",
		"--pipeline-stats", "--task-time-breakdown", "--metal-compiler-runtime=180",
		"--restore-position", "--outfile-json", "--dynamic-x", "--seekdb-path=seekdb",
		"--benchmark-min=100", "--benchmark-max=1000", "--bridge-parameter1=a",
		"--bridge-parameter2=b", "--bridge-parameter3=c", "--bridge-parameter4=d",
		"--backend-devices-virtmulti=8", "--backend-devices-virthost=2",
		"--total-candidates", "--lookup=candidate", "--custom-charset5=?d5",
		"--custom-charset6=?d6", "--custom-charset7=?d7", "--custom-charset8=?d8",
		"--increment-inverse", "--bypass-delay=5", "--bypass-threshold=6",
		"--color-cracked", "--hash-copy", "--encrypt-with-pubkey=public.pem",
		"?d?d", "words.txt", "--encoding-from=windows-1252",
		"--encoding-to=utf-8", "--hccapx-message-pair=0", "--nonce-error-corrections=0",
		"--scrypt-tmto=0", "--brain-client-features=3", "--brain-session=0x2",
		"--brain-session-whitelist=0x2,0x3", "--advice-disable", "--hash-type=22000",
		"--status-timer=0", "--stdin-timeout-abort=0", "--outfile-check-timer=0",
		"--bitmap-min=0", "--bitmap-max=0", "--hwmon-temp-abort=0",
	} {
		if !slices.Contains(args, option) {
			t.Errorf("expected exact argument %q in %q", option, args)
		}
	}
	if count := countExactArg(args, "--hash-info"); count != 2 {
		t.Errorf("--hash-info count = %d; want 2 in %q", count, args)
	}
	if count := countExactArg(args, "--backend-info"); count != 2 {
		t.Errorf("--backend-info count = %d; want 2 in %q", count, args)
	}
	rules := []string{}
	for _, arg := range args {
		if strings.HasPrefix(arg, "--rules-file=") {
			rules = append(rules, strings.TrimPrefix(arg, "--rules-file="))
		}
	}
	if len(rules) != 2 {
		t.Fatalf("rules-file count = %d; want 2 in %q", len(rules), args)
	}
	for index, want := range []string{":", "$1"} {
		data, err := os.ReadFile(rules[index])
		if err != nil || string(data) != want {
			t.Errorf("rules file %d = %q, %v; want %q", index, data, err, want)
		}
	}
}

func TestParseUserTaskArgsPreservesEmptyBrainPassword(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())
	command := &clientpb.CrackCommand{BrainPassword: "legacy-secret"}
	mergeCrackCommandWireFields(t, command, appendUnknownString(nil, crackFieldBrainPasswordV7, ""))
	args, _, err := (&Hashcat{}).parseUserTaskArgs(command)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(args, "--brain-password=") {
		t.Fatalf("args = %q; want explicit empty brain password", args)
	}
}

func TestParseUserTaskArgsIgnoresWrongWireBrainPassword(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())
	command := &clientpb.CrackCommand{BrainPassword: "legacy-secret"}
	mergeCrackCommandWireFields(t, command, appendUnknownUint32(nil, crackFieldBrainPasswordV7, 7))
	args, _, err := (&Hashcat{}).parseUserTaskArgs(command)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(args, "--brain-password=legacy-secret") {
		t.Fatalf("args = %q; wrong-wire optional string shadowed the legacy value", args)
	}
}

func TestParseUserTaskArgsMetaModesDoNotInheritDefaultHashOrAttackMode(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())

	benchmarkArgs, _, err := (&Hashcat{}).parseUserTaskArgs(&clientpb.CrackCommand{
		HashType:  clientpb.HashType_INVALID,
		Benchmark: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(benchmarkArgs, func(arg string) bool { return strings.HasPrefix(arg, "--attack-mode=") }) {
		t.Fatalf("benchmark args inherited an explicit attack mode: %q", benchmarkArgs)
	}

	identifyCommand := &clientpb.CrackCommand{HashType: clientpb.HashType_MD5}
	mergeCrackCommandWireFields(t, identifyCommand, appendUnknownBool(nil, crackFieldIdentifyMode, true))
	identifyArgs, _, err := (&Hashcat{}).parseUserTaskArgs(identifyCommand)
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(identifyArgs, func(arg string) bool { return strings.HasPrefix(arg, "--hash-type=") }) {
		t.Fatalf("identify args inherited a hash type: %q", identifyArgs)
	}
}

func TestParseUserTaskArgsModeSpecificHashcatV7Flags(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())

	tests := []struct {
		name    string
		command *clientpb.CrackCommand
		unknown []byte
		want    []string
	}{
		{
			name:    "progress only",
			command: &clientpb.CrackCommand{HashType: clientpb.HashType_INVALID, ProgressOnly: true},
			want:    []string{"--progress-only"},
		},
		{
			name:    "brain server",
			command: &clientpb.CrackCommand{HashType: clientpb.HashType_INVALID, BrainServer: true},
			unknown: appendUnknownUint32(nil, crackFieldBrainServerTimerV7, 0),
			want:    []string{"--brain-server", "--brain-server-timer=0"},
		},
		{
			name: "brain client",
			command: &clientpb.CrackCommand{
				HashType:            clientpb.HashType_INVALID,
				BrainClient:         true,
				BrainClientFeatures: "3",
				BrainHost:           "brain.example",
			},
			unknown: appendUnknownString(nil, crackFieldBrainPasswordV7, "secret"),
			want: []string{
				"--brain-client", "--brain-client-features=3",
				"--brain-host=brain.example", "--brain-password=secret",
			},
		},
		{
			name:    "brain feed",
			command: &clientpb.CrackCommand{HashType: clientpb.HashType_INVALID},
			unknown: func() []byte {
				raw := appendUnknownBool(nil, crackFieldBrainFeed, true)
				raw = appendUnknownString(raw, crackFieldBrainPasswordV7, "secret")
				return appendUnknownUint32(raw, crackFieldBrainSessionV7, 1)
			}(),
			want: []string{"--brain-feed", "--brain-password=secret", "--brain-session=0x1"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mergeCrackCommandWireFields(t, test.command, test.unknown)
			args, _, err := (&Hashcat{}).parseUserTaskArgs(test.command)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range test.want {
				if !slices.Contains(args, want) {
					t.Errorf("args = %q; want exact argument %q", args, want)
				}
			}
		})
	}
}

func countExactArg(args []string, target string) int {
	count := 0
	for _, arg := range args {
		if arg == target {
			count++
		}
	}
	return count
}

func TestParseUserTaskArgsRestoreShowCommand(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())

	command := &clientpb.CrackCommand{}
	mergeCrackCommandWireFields(t, command, appendUnknownBool(nil, crackFieldRestoreShowCommand, true))

	args, _, err := (&Hashcat{}).parseUserTaskArgs(command)
	if err != nil {
		t.Fatalf("parseUserTaskArgs returned an error: %v", err)
	}
	if !slices.Contains(args, "--restore") {
		t.Fatalf("args = %q; want --restore", args)
	}
}

func TestParseUserTaskArgsRejectsConflictingRestoreModes(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())

	command := &clientpb.CrackCommand{Restore: true}
	mergeCrackCommandWireFields(t, command, appendUnknownBool(nil, crackFieldRestoreShowCommand, true))

	_, _, err := (&Hashcat{}).parseUserTaskArgs(command)
	if err == nil {
		t.Fatal("expected an error for mutually exclusive restore modes")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseUserTaskArgsRejectsSegmentSize(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())

	h := &Hashcat{}
	_, _, err := h.parseUserTaskArgs(&clientpb.CrackCommand{SegmentSize: 32})
	if err == nil {
		t.Fatal("expected an error for the removed --segment-size option")
	}
	if !strings.Contains(err.Error(), "does not support --segment-size") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseUserTaskArgsIgnoresWorkloadProfile(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())

	h := &Hashcat{}
	args, _, err := h.parseUserTaskArgs(&clientpb.CrackCommand{WorkloadProfile: clientpb.CrackWorkloadProfile_HIGH})
	if err != nil {
		t.Fatalf("parseUserTaskArgs returned an error: %v", err)
	}
	if slices.ContainsFunc(args, func(arg string) bool { return strings.HasPrefix(arg, "--workload-profile") }) {
		t.Fatalf("args = %q; deprecated no-op should be omitted", args)
	}
}

func TestRedactHashcatArgs(t *testing.T) {
	args := []string{
		"--brain-host=brain.example",
		"--brain-password=hunter2",
		"--brain-password",
		"second-secret",
		"--lookup=plaintext-candidate",
		"--status",
	}
	redacted := redactHashcatArgs(args)
	joined := strings.Join(redacted, " ")
	if strings.Contains(joined, "hunter2") || strings.Contains(joined, "second-secret") || strings.Contains(joined, "plaintext-candidate") {
		t.Fatalf("redacted args leaked password: %q", joined)
	}
	if !strings.Contains(joined, "--brain-password=<redacted>") {
		t.Fatalf("redacted args missing marker: %q", joined)
	}
	if args[1] != "--brain-password=hunter2" {
		t.Fatalf("redaction mutated caller args: %q", args)
	}
}

func TestParseUserTaskArgsTerminatesOptionsBeforeOperands(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())

	command := &clientpb.CrackCommand{}
	raw := appendUnknownString(nil, crackFieldPositionalArguments, "--brain-password")
	raw = appendUnknownString(raw, crackFieldPositionalArguments, "not-an-option-value")
	mergeCrackCommandWireFields(t, command, raw)

	args, _, err := (&Hashcat{}).parseUserTaskArgs(command)
	if err != nil {
		t.Fatalf("parseUserTaskArgs returned an error: %v", err)
	}
	separator := slices.Index(args, "--")
	if separator < 0 || !slices.Equal(args[separator+1:], []string{"--brain-password", "not-an-option-value"}) {
		t.Fatalf("args = %q; positional operands were not protected", args)
	}
}

func TestParseUserTaskArgsRejectsNULOperand(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())

	command := &clientpb.CrackCommand{}
	mergeCrackCommandWireFields(t, command, appendUnknownString(nil, crackFieldPositionalArguments, "bad\x00operand"))
	_, _, err := (&Hashcat{}).parseUserTaskArgs(command)
	if err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("parseUserTaskArgs error = %v; want NUL rejection", err)
	}
}

func TestEffectiveHashModePrefersHashcatV7Field(t *testing.T) {
	legacy := &clientpb.CrackCommand{HashType: clientpb.HashType_NTLM}
	if mode, ok, err := EffectiveHashMode(legacy); err != nil || !ok || mode != 1000 {
		t.Fatalf("EffectiveHashMode(legacy) = %d, %v, %v; want 1000, true, nil", mode, ok, err)
	}

	v7 := &clientpb.CrackCommand{HashType: clientpb.HashType_MD5}
	mergeCrackCommandWireFields(t, v7, appendUnknownUint32(nil, crackFieldHashMode, 74000))
	if mode, ok, err := EffectiveHashMode(v7); err != nil || !ok || mode != 74000 {
		t.Fatalf("EffectiveHashMode(v7) = %d, %v, %v; want 74000, true, nil", mode, ok, err)
	}

	invalid := &clientpb.CrackCommand{HashType: clientpb.HashType_INVALID}
	if mode, ok, err := EffectiveHashMode(invalid); err != nil || ok || mode != 0 {
		t.Fatalf("EffectiveHashMode(invalid) = %d, %v, %v; want 0, false, nil", mode, ok, err)
	}

	outOfRange := &clientpb.CrackCommand{}
	mergeCrackCommandWireFields(t, outOfRange, appendUnknownUint32(nil, crackFieldHashMode, ^uint32(0)))
	if _, _, err := EffectiveHashMode(outOfRange); err == nil {
		t.Fatal("EffectiveHashMode(out of range) error = nil")
	}
}

func appendUnknownBool(raw []byte, field protowire.Number, value bool) []byte {
	raw = protowire.AppendTag(raw, field, protowire.VarintType)
	if value {
		return protowire.AppendVarint(raw, 1)
	}
	return protowire.AppendVarint(raw, 0)
}

func appendUnknownUint32(raw []byte, field protowire.Number, value uint32) []byte {
	raw = protowire.AppendTag(raw, field, protowire.VarintType)
	return protowire.AppendVarint(raw, uint64(value))
}

func appendUnknownString(raw []byte, field protowire.Number, value string) []byte {
	raw = protowire.AppendTag(raw, field, protowire.BytesType)
	return protowire.AppendString(raw, value)
}

func appendUnknownBytes(raw []byte, field protowire.Number, value []byte) []byte {
	raw = protowire.AppendTag(raw, field, protowire.BytesType)
	return protowire.AppendBytes(raw, value)
}

func appendUnknownPackedUint32(raw []byte, field protowire.Number, values []uint32) []byte {
	packed := []byte{}
	for _, value := range values {
		packed = protowire.AppendVarint(packed, uint64(value))
	}
	return appendUnknownBytes(raw, field, packed)
}

func mergeCrackCommandWireFields(t *testing.T, command *clientpb.CrackCommand, raw []byte) {
	t.Helper()
	if err := (proto.UnmarshalOptions{Merge: true}).Unmarshal(raw, command); err != nil {
		t.Fatalf("merge CrackCommand wire fields: %v", err)
	}
}
