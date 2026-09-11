package hashcat

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/sliverarmory/sliver-crackstation/assets"
	"github.com/sliverarmory/sliver-crackstation/pkg/protocompat"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	crackQueryCredentialIDsField             protoreflect.FieldNumber = 170
	crackQueryCredentialCollectionField      protoreflect.FieldNumber = 171
	crackQueryIncludeCrackedCredentialsField protoreflect.FieldNumber = 172
	crackQueryCrackstationSelectorField      protoreflect.FieldNumber = 173
	lastSupportedCrackCommandField           protoreflect.FieldNumber = 173
	maxManagedLookupBytes                                             = 4 << 10
	maxManagedIdentifyHashes                                          = 10_000
	maxManagedIdentifyBytes                                           = 8 << 20
)

// ManagedQueryMode identifies one bounded, output-only Hashcat query. These
// values are local to the independently released worker; the durable task
// protocol identifies all of them with CrackTaskKind 4.
type ManagedQueryMode uint8

const (
	ManagedQueryUnspecified ManagedQueryMode = iota
	ManagedQueryKeyspace
	ManagedQueryTotalCandidates
	ManagedQueryLookup
	ManagedQueryIdentify
	ManagedQueryHashInfo
)

func (mode ManagedQueryMode) String() string {
	switch mode {
	case ManagedQueryKeyspace:
		return "keyspace"
	case ManagedQueryTotalCandidates:
		return "total-candidates"
	case ManagedQueryLookup:
		return "lookup"
	case ManagedQueryIdentify:
		return "identify"
	case ManagedQueryHashInfo:
		return "hash-info"
	default:
		return "unspecified"
	}
}

// ManagedQueryResultError identifies a completed Hashcat process whose captured
// result violates the synchronous query result contract. Task handlers use this
// type to preserve the captured result for authoritative server validation.
type ManagedQueryResultError struct {
	err error
}

func (err *ManagedQueryResultError) Error() string {
	return err.err.Error()
}

func (err *ManagedQueryResultError) Unwrap() error {
	return err.err
}

// IsManagedQueryResultError reports whether err contains a strict query-result
// validation failure, including one joined with a Hashcat process exit error.
func IsManagedQueryResultError(err error) bool {
	var resultErr *ManagedQueryResultError
	return errors.As(err, &resultErr)
}

func managedQueryResultErrorf(format string, args ...any) error {
	return &ManagedQueryResultError{err: fmt.Errorf(format, args...)}
}

// ValidateManagedQueryCommand enforces the worker-side half of the
// synchronous query contract. Candidate-generator queries reuse the same
// managed-file and positional validation as durable crack tasks. Identify and
// hash-info have no attack operands, so they use a deliberately small field
// allowlist instead.
func (h *Hashcat) ValidateManagedQueryCommand(command *clientpb.CrackCommand) (ManagedQueryMode, error) {
	if command == nil {
		return ManagedQueryUnspecified, fmt.Errorf("missing crack command")
	}
	fields, err := readCrackCommandV7Fields(command)
	if err != nil {
		return ManagedQueryUnspecified, fmt.Errorf("decode Hashcat 7 command fields: %w", err)
	}
	reader, err := protocompat.NewReader(command)
	if err != nil {
		return ManagedQueryUnspecified, fmt.Errorf("decode crack command: %w", err)
	}
	if reader.Has(crackQueryCredentialIDsField) || reader.Has(crackQueryCredentialCollectionField) || reader.Has(crackQueryIncludeCrackedCredentialsField) {
		return ManagedQueryUnspecified, fmt.Errorf("credential selectors are not permitted in a crackstation query")
	}
	if err := rejectUnsupportedQueryFields(command); err != nil {
		return ManagedQueryUnspecified, err
	}

	lookupPresent := reader.HasBytes(crackFieldLookup)
	if lookupPresent && fields.lookup == "" {
		return ManagedQueryUnspecified, fmt.Errorf("hashcat lookup query cannot be empty")
	}
	modes := make([]ManagedQueryMode, 0, 5)
	if command.GetKeyspace() {
		modes = append(modes, ManagedQueryKeyspace)
	}
	if fields.totalCandidates {
		modes = append(modes, ManagedQueryTotalCandidates)
	}
	if fields.lookup != "" {
		modes = append(modes, ManagedQueryLookup)
	}
	if fields.identifyMode {
		modes = append(modes, ManagedQueryIdentify)
	}
	if command.GetHashInfo() || fields.hashInfoLevel != 0 {
		modes = append(modes, ManagedQueryHashInfo)
	}
	if len(modes) != 1 {
		return ManagedQueryUnspecified, fmt.Errorf("crackstation query must select exactly one mode (selected %d)", len(modes))
	}
	mode := modes[0]

	switch mode {
	case ManagedQueryKeyspace, ManagedQueryTotalCandidates, ManagedQueryLookup:
		if len(command.GetHashes()) != 0 {
			return ManagedQueryUnspecified, fmt.Errorf("%s query cannot include hashes", mode)
		}
		if (mode == ManagedQueryKeyspace || mode == ManagedQueryTotalCandidates) && (command.GetSkip() != 0 || command.GetLimit() != 0) {
			return ManagedQueryUnspecified, fmt.Errorf("%s query cannot include skip or limit", mode)
		}
		if mode == ManagedQueryLookup {
			if len(fields.lookup) > maxManagedLookupBytes {
				return ManagedQueryUnspecified, fmt.Errorf("lookup query exceeds %d bytes", maxManagedLookupBytes)
			}
			if !utf8.ValidString(fields.lookup) || strings.ContainsAny(fields.lookup, "\x00\r\n") {
				return ManagedQueryUnspecified, fmt.Errorf("lookup query must be valid UTF-8 without a line break or NUL")
			}
			if command.GetAttackMode() == clientpb.CrackAttackMode_STRAIGHT && len(commandAttackOperands(command, fields)) != 1 {
				return ManagedQueryUnspecified, fmt.Errorf("lookup query in straight attack mode requires exactly one managed wordlist operand")
			}
		}
		if err := validateManagedQueryOutputSettings(command, fields); err != nil {
			return ManagedQueryUnspecified, err
		}
		validationCommand := proto.Clone(command).(*clientpb.CrackCommand)
		if err := clearCrackQueryServerFields(validationCommand); err != nil {
			return ManagedQueryUnspecified, err
		}
		validationCommand.Keyspace = true
		if err := protocompat.Clear(validationCommand, crackFieldTotalCandidates); err != nil {
			return ManagedQueryUnspecified, err
		}
		if err := protocompat.Clear(validationCommand, crackFieldLookup); err != nil {
			return ManagedQueryUnspecified, err
		}
		if err := h.ValidateManagedTaskCommand(validationCommand); err != nil {
			return ManagedQueryUnspecified, fmt.Errorf("invalid %s query: %w", mode, err)
		}
	case ManagedQueryIdentify:
		if err := validateInformationQueryFields(command, mode, fields); err != nil {
			return ManagedQueryUnspecified, err
		}
		if len(command.GetHashes()) == 0 {
			return ManagedQueryUnspecified, fmt.Errorf("identify query requires at least one hash")
		}
		if len(command.GetHashes()) > maxManagedIdentifyHashes {
			return ManagedQueryUnspecified, fmt.Errorf("identify query exceeds %d hashes", maxManagedIdentifyHashes)
		}
		var totalBytes uint64
		for _, hash := range command.GetHashes() {
			if !utf8.ValidString(hash) || strings.TrimSpace(hash) == "" || strings.ContainsAny(hash, "\x00\r\n") {
				return ManagedQueryUnspecified, fmt.Errorf("identify query hash must be nonempty valid UTF-8 without a line break or NUL")
			}
			totalBytes += uint64(len(hash))
			if totalBytes > maxManagedIdentifyBytes {
				return ManagedQueryUnspecified, fmt.Errorf("identify query exceeds %d bytes", maxManagedIdentifyBytes)
			}
		}
		if command.GetHashType() != clientpb.HashType_INVALID {
			return ManagedQueryUnspecified, fmt.Errorf("identify query cannot include a hash type")
		}
		if fields.hashMode != nil {
			return ManagedQueryUnspecified, fmt.Errorf("identify query cannot include a hash mode")
		}
	case ManagedQueryHashInfo:
		if err := validateInformationQueryFields(command, mode, fields); err != nil {
			return ManagedQueryUnspecified, err
		}
		if fields.hashInfoLevel > 2 {
			return ManagedQueryUnspecified, fmt.Errorf("hash-info level must be 1 or 2")
		}
		if fields.hashMode != nil && *fields.hashMode > uint32(math.MaxInt32) {
			return ManagedQueryUnspecified, fmt.Errorf("hashcat hash mode exceeds the managed-query range")
		}
	}
	return mode, nil
}

func rejectUnsupportedQueryFields(command *clientpb.CrackCommand) error {
	populated, err := populatedCrackCommandFields(command)
	if err != nil {
		return err
	}
	for number := range populated {
		if number > lastSupportedCrackCommandField {
			return fmt.Errorf("crackstation query contains unsupported command field %d", number)
		}
	}
	return nil
}

func populatedCrackCommandFields(command *clientpb.CrackCommand) (map[protoreflect.FieldNumber]struct{}, error) {
	populated := map[protoreflect.FieldNumber]struct{}{}
	message := command.ProtoReflect()
	message.Range(func(field protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
		populated[field.Number()] = struct{}{}
		return true
	})
	raw := message.GetUnknown()
	for len(raw) != 0 {
		number, wireType, tagLength := protowire.ConsumeTag(raw)
		if tagLength < 0 {
			return nil, fmt.Errorf("decode crack query protobuf tag: %w", protowire.ParseError(tagLength))
		}
		raw = raw[tagLength:]
		valueLength := protowire.ConsumeFieldValue(number, wireType, raw)
		if valueLength < 0 {
			return nil, fmt.Errorf("decode crack query protobuf field %d: %w", number, protowire.ParseError(valueLength))
		}
		populated[protoreflect.FieldNumber(number)] = struct{}{}
		raw = raw[valueLength:]
	}
	return populated, nil
}

func validateInformationQueryFields(command *clientpb.CrackCommand, mode ManagedQueryMode, fields crackCommandV7Fields) error {
	populated, err := populatedCrackCommandFields(command)
	if err != nil {
		return err
	}
	allowed := map[protoreflect.FieldNumber]struct{}{
		1:                                   {}, // AttackMode: only STRAIGHT/NO_ATTACK are accepted below.
		2:                                   {}, // HashType: identify further restricts this to INVALID.
		4:                                   {}, // Quiet, forced by the server for deterministic output.
		19:                                  {}, // MarkovDisable, forced when no managed hcstat2 is present.
		26:                                  {}, // RestoreDisable.
		40:                                  {}, // PotfileDisable.
		48:                                  {}, // LogfileDisable.
		crackFieldHashCopy:                  {},
		crackFieldOutfileCheckTimerV7:       {},
		crackQueryCrackstationSelectorField: {},
	}
	switch mode {
	case ManagedQueryIdentify:
		allowed[3] = struct{}{}
		allowed[crackFieldIdentifyMode] = struct{}{}
	case ManagedQueryHashInfo:
		allowed[65] = struct{}{}
		allowed[crackFieldHashInfoLevel] = struct{}{}
		allowed[crackFieldHashMode] = struct{}{}
	default:
		return fmt.Errorf("invalid information query mode %d", mode)
	}
	for number := range populated {
		if _, ok := allowed[number]; !ok {
			return fmt.Errorf("%s query cannot include command field %d", mode, number)
		}
	}
	if command.GetAttackMode() != clientpb.CrackAttackMode_STRAIGHT && command.GetAttackMode() != clientpb.CrackAttackMode_NO_ATTACK {
		return fmt.Errorf("%s query cannot include attack mode %d", mode, command.GetAttackMode())
	}
	if fields.outfileCheckTimerV7 != nil && *fields.outfileCheckTimerV7 != 0 {
		return fmt.Errorf("%s query cannot enable outfile checking", mode)
	}
	return nil
}

func validateManagedQueryOutputSettings(command *clientpb.CrackCommand, fields crackCommandV7Fields) error {
	if command.GetStatus() || command.GetStatusJSON() || command.GetStatusTimer() != 0 || fields.statusTimerV7 != nil {
		return fmt.Errorf("crackstation query cannot enable status output")
	}
	if fields.outfile != "" || fields.outfileJSON || len(command.GetOutfileFormat()) != 0 || command.GetOutfileAutohexDisable() {
		return fmt.Errorf("crackstation query cannot configure an outfile")
	}
	if len(command.GetPotfile()) != 0 {
		return fmt.Errorf("crackstation query cannot configure a potfile")
	}
	if fields.colorCracked {
		return fmt.Errorf("crackstation query cannot enable colored recovered output")
	}
	return nil
}

func clearCrackQueryServerFields(command *clientpb.CrackCommand) error {
	for _, number := range []protoreflect.FieldNumber{
		crackQueryCredentialIDsField,
		crackQueryCredentialCollectionField,
		crackQueryIncludeCrackedCredentialsField,
		crackQueryCrackstationSelectorField,
	} {
		if err := protocompat.Clear(command, number); err != nil {
			return fmt.Errorf("clear server-only crack query field %d: %w", number, err)
		}
	}
	return nil
}

func prepareManagedQueryCommand(command *clientpb.CrackCommand, mode ManagedQueryMode) (*clientpb.CrackCommand, error) {
	prepared := proto.Clone(command).(*clientpb.CrackCommand)
	if err := clearCrackQueryServerFields(prepared); err != nil {
		return nil, err
	}

	prepared.Quiet = true
	prepared.Status = false
	prepared.StatusJSON = false
	prepared.StatusTimer = 0
	prepared.MachineReadable = false
	prepared.LogfileDisable = true
	prepared.RestoreDisable = true
	prepared.Potfile = nil
	prepared.PotfileDisable = true
	prepared.OutfileFormat = nil
	prepared.OutfileAutohexDisable = false
	prepared.OutfileCheckTimer = 0
	prepared.Keyspace = false
	prepared.HashInfo = false
	for _, number := range []protoreflect.FieldNumber{
		crackFieldOutfile,
		crackFieldOutfileJSON,
		crackFieldTotalCandidates,
		crackFieldLookup,
		crackFieldIdentifyMode,
		crackFieldHashInfoLevel,
		crackFieldStatusTimerV7,
	} {
		if err := protocompat.Clear(prepared, number); err != nil {
			return nil, fmt.Errorf("clear crack query field %d: %w", number, err)
		}
	}
	if err := protocompat.SetUint32(prepared, crackFieldOutfileCheckTimerV7, 0); err != nil {
		return nil, err
	}

	fields, err := readCrackCommandV7Fields(command)
	if err != nil {
		return nil, err
	}
	switch mode {
	case ManagedQueryKeyspace:
		prepared.Keyspace = true
	case ManagedQueryTotalCandidates:
		if err := protocompat.SetBool(prepared, crackFieldTotalCandidates, true); err != nil {
			return nil, err
		}
	case ManagedQueryLookup:
		if err := protocompat.SetString(prepared, crackFieldLookup, fields.lookup); err != nil {
			return nil, err
		}
	case ManagedQueryIdentify:
		if err := protocompat.SetBool(prepared, crackFieldIdentifyMode, true); err != nil {
			return nil, err
		}
	case ManagedQueryHashInfo:
		if fields.hashInfoLevel != 0 {
			if err := protocompat.SetUint32(prepared, crackFieldHashInfoLevel, fields.hashInfoLevel); err != nil {
				return nil, err
			}
		} else {
			prepared.HashInfo = true
		}
	default:
		return nil, fmt.Errorf("invalid managed query mode %d", mode)
	}
	return prepared, nil
}

type managedQueryPathReplacement struct {
	resolved  string
	reference string
}

// managedQueryPathReplacements records only exact paths returned by the managed
// file resolver. Hashcat may include input names in informational output; never
// return a crackstation-local cache path to an operator.
func (h *Hashcat) managedQueryPathReplacements(command *clientpb.CrackCommand, fields crackCommandV7Fields) ([]managedQueryPathReplacement, error) {
	references := []string{string(command.GetMarkovHcstat2())}
	rulesFiles := fields.rulesFilesV7
	if len(rulesFiles) == 0 && len(command.GetRulesFile()) != 0 {
		rulesFiles = [][]byte{command.GetRulesFile()}
	}
	for _, rulesFile := range rulesFiles {
		references = append(references, string(rulesFile))
	}
	references = append(references, commandAttackOperands(command, fields)...)

	byPath := map[string]string{}
	for _, reference := range references {
		if !strings.HasPrefix(reference, "crackfile://") {
			continue
		}
		resolved, managed, err := h.resolveFileReference(reference)
		if err != nil {
			return nil, err
		}
		if !managed {
			continue
		}
		if existing, ok := byPath[resolved]; ok && existing != reference {
			return nil, fmt.Errorf("managed crack file path resolves ambiguously for %q and %q", existing, reference)
		}
		byPath[resolved] = reference
	}

	replacements := make([]managedQueryPathReplacement, 0, len(byPath))
	for resolved, reference := range byPath {
		replacements = append(replacements, managedQueryPathReplacement{resolved: resolved, reference: reference})
	}
	sort.Slice(replacements, func(i, j int) bool {
		if len(replacements[i].resolved) != len(replacements[j].resolved) {
			return len(replacements[i].resolved) > len(replacements[j].resolved)
		}
		return replacements[i].resolved < replacements[j].resolved
	})
	return replacements, nil
}

func redactManagedQueryPaths(result CommandResult, replacements []managedQueryPathReplacement) CommandResult {
	for _, replacement := range replacements {
		result.Stdout = bytes.ReplaceAll(result.Stdout, []byte(replacement.resolved), []byte(replacement.reference))
		result.Stderr = bytes.ReplaceAll(result.Stderr, []byte(replacement.resolved), []byte(replacement.reference))
	}
	return result
}

// CrackManagedQueryWithResultContext runs a validated synchronous query in an
// isolated working directory. Output is always completely drained, captured
// to the CommandResult limit, and treated as a failure if truncation would make
// the synchronous response incomplete.
func (h *Hashcat) CrackManagedQueryWithResultContext(ctx context.Context, command *clientpb.CrackCommand) (CommandResult, ManagedQueryMode, error) {
	mode, err := h.ValidateManagedQueryCommand(command)
	if err != nil {
		return CommandResult{ExitCode: -1}, ManagedQueryUnspecified, err
	}
	prepared, err := prepareManagedQueryCommand(command, mode)
	if err != nil {
		return CommandResult{ExitCode: -1}, mode, err
	}
	fields, err := readCrackCommandV7Fields(prepared)
	if err != nil {
		return CommandResult{ExitCode: -1}, mode, fmt.Errorf("decode Hashcat 7 command fields: %w", err)
	}
	replacements, err := h.managedQueryPathReplacements(prepared, fields)
	if err != nil {
		return CommandResult{ExitCode: -1}, mode, fmt.Errorf("resolve managed query output paths: %w", err)
	}
	args, cleanup, err := h.parseUserTaskArgsWithFields(prepared, fields)
	defer func() {
		for _, path := range cleanup {
			_ = os.Remove(path)
		}
	}()
	if err != nil {
		return CommandResult{ExitCode: -1}, mode, err
	}
	workingDirectory, err := os.MkdirTemp(assets.GetAppTmpDir(), ManagedWorkDirPrefix)
	if err != nil {
		return CommandResult{ExitCode: -1}, mode, fmt.Errorf("create isolated Hashcat query working directory: %w", err)
	}
	defer os.RemoveAll(workingDirectory)

	result, runErr := h.runHashcatStreamingInDirectory(ctx, args, fields.stdin, nil, workingDirectory)
	result = redactManagedQueryPaths(result, replacements)
	var resultErr error
	if hasManagedQueryProcessResult(result) {
		resultErr = validateManagedQueryResult(mode, result)
	}
	return result, mode, errors.Join(runErr, resultErr)
}

func hasManagedQueryProcessResult(result CommandResult) bool {
	return result.ExitCode >= 0 || result.StdoutTotalBytes != 0 || result.StderrTotalBytes != 0 || result.StdoutTruncated || result.StderrTruncated
}

func validateManagedQueryResult(mode ManagedQueryMode, result CommandResult) error {
	if result.StdoutTruncated || result.StderrTruncated {
		return managedQueryResultErrorf("hashcat %s query output exceeded the capture limit", mode)
	}
	if result.ExitCode != 0 {
		return managedQueryResultErrorf("hashcat %s query exited with code %d", mode, result.ExitCode)
	}
	if !utf8.Valid(result.Stdout) || !utf8.Valid(result.Stderr) {
		return managedQueryResultErrorf("hashcat %s query returned invalid UTF-8", mode)
	}
	trimmed := bytes.TrimSpace(result.Stdout)
	if len(trimmed) == 0 {
		return managedQueryResultErrorf("hashcat %s query returned empty output", mode)
	}
	if mode == ManagedQueryKeyspace || mode == ManagedQueryTotalCandidates {
		value, err := strconv.ParseUint(string(trimmed), 10, 64)
		if err != nil || strconv.FormatUint(value, 10) != string(trimmed) {
			return managedQueryResultErrorf("hashcat %s query returned non-canonical decimal output %q", mode, trimmed)
		}
	}
	return nil
}

// ValidateManagedKeyspaceResult applies the synchronous query result contract
// to the legacy crack-keyspace execution path. A result with no evidence that
// Hashcat started is left to the caller's operational execution error.
func ValidateManagedKeyspaceResult(result CommandResult) error {
	if !hasManagedQueryProcessResult(result) {
		return nil
	}
	return validateManagedQueryResult(ManagedQueryKeyspace, result)
}
