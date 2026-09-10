package hashcat

import (
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/sliverarmory/sliver-crackstation/pkg/protocompat"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// These numbers are defined by the canonical CrackCommand in Sliver's
// protobuf/clientpb/client.proto. Crackstation intentionally reads them by
// number until a Sliver release containing the Hashcat 7 schema is available.
// Protobuf preserves fields unknown to the currently compiled descriptor, so
// an updated server can use the new API without making this build depend on
// unreleased Sliver source.
const (
	crackFieldOutfile                 protoreflect.FieldNumber = 28
	crackFieldDebugFile               protoreflect.FieldNumber = 45
	crackFieldInductionDir            protoreflect.FieldNumber = 46
	crackFieldOutfileCheckDir         protoreflect.FieldNumber = 47
	crackFieldTruecryptKeyfiles       protoreflect.FieldNumber = 52
	crackFieldVeracryptKeyfiles       protoreflect.FieldNumber = 53
	crackFieldVeracryptPimStart       protoreflect.FieldNumber = 54
	crackFieldVeracryptPimStop        protoreflect.FieldNumber = 55
	crackFieldRuleLeft                protoreflect.FieldNumber = 88
	crackFieldRuleRight               protoreflect.FieldNumber = 89
	crackFieldPipelineStats           protoreflect.FieldNumber = 114
	crackFieldTaskTimeBreakdown       protoreflect.FieldNumber = 115
	crackFieldMetalCompilerRuntime    protoreflect.FieldNumber = 116
	crackFieldRestorePosition         protoreflect.FieldNumber = 117
	crackFieldOutfileJSON             protoreflect.FieldNumber = 118
	crackFieldDynamicX                protoreflect.FieldNumber = 119
	crackFieldSeekDBPath              protoreflect.FieldNumber = 120
	crackFieldBenchmarkMin            protoreflect.FieldNumber = 121
	crackFieldBenchmarkMax            protoreflect.FieldNumber = 122
	crackFieldBridgeParameter1        protoreflect.FieldNumber = 123
	crackFieldBridgeParameter2        protoreflect.FieldNumber = 124
	crackFieldBridgeParameter3        protoreflect.FieldNumber = 125
	crackFieldBridgeParameter4        protoreflect.FieldNumber = 126
	crackFieldBackendDevicesVirtMulti protoreflect.FieldNumber = 127
	crackFieldBackendDevicesVirtHost  protoreflect.FieldNumber = 128
	crackFieldTotalCandidates         protoreflect.FieldNumber = 129
	crackFieldLookup                  protoreflect.FieldNumber = 130
	crackFieldCustomCharset5          protoreflect.FieldNumber = 131
	crackFieldCustomCharset6          protoreflect.FieldNumber = 132
	crackFieldCustomCharset7          protoreflect.FieldNumber = 133
	crackFieldCustomCharset8          protoreflect.FieldNumber = 134
	crackFieldIncrementInverse        protoreflect.FieldNumber = 135
	crackFieldBypassDelay             protoreflect.FieldNumber = 136
	crackFieldBypassThreshold         protoreflect.FieldNumber = 137
	crackFieldBrainFeed               protoreflect.FieldNumber = 138
	crackFieldColorCracked            protoreflect.FieldNumber = 139
	crackFieldHashCopy                protoreflect.FieldNumber = 140
	crackFieldEncryptWithPubkey       protoreflect.FieldNumber = 141
	crackFieldIdentifyMode            protoreflect.FieldNumber = 142
	crackFieldPositionalArguments     protoreflect.FieldNumber = 143
	crackFieldEncodingFromName        protoreflect.FieldNumber = 144
	crackFieldEncodingToName          protoreflect.FieldNumber = 145
	crackFieldHashInfoLevel           protoreflect.FieldNumber = 146
	crackFieldBackendInfoLevel        protoreflect.FieldNumber = 147
	crackFieldHccapxMessagePairV7     protoreflect.FieldNumber = 148
	crackFieldNonceErrorCorrectionsV7 protoreflect.FieldNumber = 149
	crackFieldScryptTMTOV7            protoreflect.FieldNumber = 150
	crackFieldGenerateRulesSeedV7     protoreflect.FieldNumber = 151
	crackFieldBrainClientFeaturesV7   protoreflect.FieldNumber = 152
	crackFieldBrainSessionV7          protoreflect.FieldNumber = 153
	crackFieldBrainWhitelistV7        protoreflect.FieldNumber = 154
	crackFieldStdin                   protoreflect.FieldNumber = 155
	crackFieldAdviceDisable           protoreflect.FieldNumber = 156
	crackFieldHashMode                protoreflect.FieldNumber = 157
	crackFieldRestoreShowCommand      protoreflect.FieldNumber = 158
	crackFieldBrainServerTimerV7      protoreflect.FieldNumber = 159
	crackFieldStatusTimerV7           protoreflect.FieldNumber = 160
	crackFieldStdinTimeoutAbortV7     protoreflect.FieldNumber = 161
	crackFieldOutfileCheckTimerV7     protoreflect.FieldNumber = 162
	crackFieldBitmapMinV7             protoreflect.FieldNumber = 163
	crackFieldBitmapMaxV7             protoreflect.FieldNumber = 164
	crackFieldHwmonTempAbortV7        protoreflect.FieldNumber = 165
	crackFieldRulesFilesV7            protoreflect.FieldNumber = 166
	crackFieldBrainPasswordV7         protoreflect.FieldNumber = 167
	crackFieldGenerateRulesFuncMinV7  protoreflect.FieldNumber = 168
	crackFieldGenerateRulesFuncMaxV7  protoreflect.FieldNumber = 169
)

type crackCommandV7Fields struct {
	outfile                 string
	debugFile               string
	inductionDir            string
	outfileCheckDir         string
	truecryptKeyfiles       string
	veracryptKeyfiles       string
	veracryptPimStart       *uint32
	veracryptPimStop        *uint32
	ruleLeft                string
	ruleRight               string
	pipelineStats           bool
	taskTimeBreakdown       bool
	metalCompilerRuntime    uint32
	restorePosition         bool
	outfileJSON             bool
	dynamicX                bool
	seekDBPath              string
	benchmarkMin            uint32
	benchmarkMax            *uint32
	bridgeParameters        [4]string
	backendDevicesVirtMulti uint32
	backendDevicesVirtHost  uint32
	totalCandidates         bool
	lookup                  string
	customCharsets          [4]string
	incrementInverse        bool
	bypassDelay             *uint32
	bypassThreshold         *uint32
	brainFeed               bool
	colorCracked            bool
	hashCopy                bool
	encryptWithPubkey       string
	identifyMode            bool
	positionalArguments     []string
	encodingFromName        string
	encodingToName          string
	hashInfoLevel           uint32
	backendInfoLevel        uint32
	hccapxMessagePairV7     *uint32
	nonceErrorCorrectionsV7 *uint32
	scryptTMTOV7            *uint32
	generateRulesSeedV7     *uint32
	brainClientFeaturesV7   uint32
	brainSessionV7          *uint32
	brainWhitelistV7        []uint32
	stdin                   []byte
	adviceDisable           bool
	hashMode                *uint32
	restoreShowCommand      bool
	brainServerTimerV7      *uint32
	statusTimerV7           *uint32
	stdinTimeoutAbortV7     *uint32
	outfileCheckTimerV7     *uint32
	bitmapMinV7             *uint32
	bitmapMaxV7             *uint32
	hwmonTempAbortV7        *uint32
	rulesFilesV7            [][]byte
	brainPasswordV7         *string
	generateRulesFuncMinV7  *uint32
	generateRulesFuncMaxV7  *uint32
}

type compatFieldReader struct {
	reader *protocompat.Reader
	err    error
}

func (r *compatFieldReader) bool(number protoreflect.FieldNumber) bool {
	if r.err != nil {
		return false
	}
	value, err := r.reader.Bool(number)
	if err != nil {
		r.err = err
	}
	return value
}

func (r *compatFieldReader) uint32(number protoreflect.FieldNumber) uint32 {
	if r.err != nil {
		return 0
	}
	value, err := r.reader.Uint32(number)
	if err != nil {
		r.err = err
	}
	return value
}

func (r *compatFieldReader) string(number protoreflect.FieldNumber) string {
	if r.err != nil {
		return ""
	}
	value, err := r.reader.String(number)
	if err != nil {
		r.err = err
	}
	return value
}

func (r *compatFieldReader) strings(number protoreflect.FieldNumber) []string {
	if r.err != nil {
		return nil
	}
	value, err := r.reader.Strings(number)
	if err != nil {
		r.err = err
	}
	return value
}

func (r *compatFieldReader) bytes(number protoreflect.FieldNumber) []byte {
	if r.err != nil {
		return nil
	}
	value, err := r.reader.Bytes(number)
	if err != nil {
		r.err = err
	}
	return value
}

func (r *compatFieldReader) bytesList(number protoreflect.FieldNumber) [][]byte {
	if r.err != nil {
		return nil
	}
	value, err := r.reader.BytesList(number)
	if err != nil {
		r.err = err
	}
	return value
}

func (r *compatFieldReader) uint32s(number protoreflect.FieldNumber) []uint32 {
	if r.err != nil {
		return nil
	}
	value, err := r.reader.Uint32s(number)
	if err != nil {
		r.err = err
	}
	return value
}

func (r *compatFieldReader) optionalUint32(number protoreflect.FieldNumber) *uint32 {
	if r.err != nil || !r.reader.HasVarint(number) {
		return nil
	}
	value := r.uint32(number)
	if r.err != nil {
		return nil
	}
	return &value
}

func (r *compatFieldReader) optionalString(number protoreflect.FieldNumber) *string {
	if r.err != nil || !r.reader.HasBytes(number) {
		return nil
	}
	value := r.string(number)
	if r.err != nil {
		return nil
	}
	return &value
}

func readCrackCommandV7Fields(command *clientpb.CrackCommand) (crackCommandV7Fields, error) {
	reader, err := protocompat.NewReader(command)
	if err != nil {
		return crackCommandV7Fields{}, err
	}
	fields := &compatFieldReader{reader: reader}
	values := crackCommandV7Fields{
		outfile:              fields.string(crackFieldOutfile),
		debugFile:            fields.string(crackFieldDebugFile),
		inductionDir:         fields.string(crackFieldInductionDir),
		outfileCheckDir:      fields.string(crackFieldOutfileCheckDir),
		truecryptKeyfiles:    fields.string(crackFieldTruecryptKeyfiles),
		veracryptKeyfiles:    fields.string(crackFieldVeracryptKeyfiles),
		veracryptPimStart:    fields.optionalUint32(crackFieldVeracryptPimStart),
		veracryptPimStop:     fields.optionalUint32(crackFieldVeracryptPimStop),
		ruleLeft:             fields.string(crackFieldRuleLeft),
		ruleRight:            fields.string(crackFieldRuleRight),
		pipelineStats:        fields.bool(crackFieldPipelineStats),
		taskTimeBreakdown:    fields.bool(crackFieldTaskTimeBreakdown),
		metalCompilerRuntime: fields.uint32(crackFieldMetalCompilerRuntime),
		restorePosition:      fields.bool(crackFieldRestorePosition),
		outfileJSON:          fields.bool(crackFieldOutfileJSON),
		dynamicX:             fields.bool(crackFieldDynamicX),
		seekDBPath:           fields.string(crackFieldSeekDBPath),
		benchmarkMin:         fields.uint32(crackFieldBenchmarkMin),
		benchmarkMax:         fields.optionalUint32(crackFieldBenchmarkMax),
		bridgeParameters: [4]string{
			fields.string(crackFieldBridgeParameter1),
			fields.string(crackFieldBridgeParameter2),
			fields.string(crackFieldBridgeParameter3),
			fields.string(crackFieldBridgeParameter4),
		},
		backendDevicesVirtMulti: fields.uint32(crackFieldBackendDevicesVirtMulti),
		backendDevicesVirtHost:  fields.uint32(crackFieldBackendDevicesVirtHost),
		totalCandidates:         fields.bool(crackFieldTotalCandidates),
		lookup:                  fields.string(crackFieldLookup),
		customCharsets: [4]string{
			fields.string(crackFieldCustomCharset5),
			fields.string(crackFieldCustomCharset6),
			fields.string(crackFieldCustomCharset7),
			fields.string(crackFieldCustomCharset8),
		},
		incrementInverse:    fields.bool(crackFieldIncrementInverse),
		bypassDelay:         fields.optionalUint32(crackFieldBypassDelay),
		bypassThreshold:     fields.optionalUint32(crackFieldBypassThreshold),
		brainFeed:           fields.bool(crackFieldBrainFeed),
		colorCracked:        fields.bool(crackFieldColorCracked),
		hashCopy:            fields.bool(crackFieldHashCopy),
		encryptWithPubkey:   fields.string(crackFieldEncryptWithPubkey),
		identifyMode:        fields.bool(crackFieldIdentifyMode),
		positionalArguments: fields.strings(crackFieldPositionalArguments),
		encodingFromName:    fields.string(crackFieldEncodingFromName),
		encodingToName:      fields.string(crackFieldEncodingToName),
		hashInfoLevel:       fields.uint32(crackFieldHashInfoLevel),
		backendInfoLevel:    fields.uint32(crackFieldBackendInfoLevel),
		hccapxMessagePairV7: fields.optionalUint32(crackFieldHccapxMessagePairV7),
		nonceErrorCorrectionsV7: fields.optionalUint32(
			crackFieldNonceErrorCorrectionsV7,
		),
		scryptTMTOV7:           fields.optionalUint32(crackFieldScryptTMTOV7),
		generateRulesSeedV7:    fields.optionalUint32(crackFieldGenerateRulesSeedV7),
		brainClientFeaturesV7:  fields.uint32(crackFieldBrainClientFeaturesV7),
		brainSessionV7:         fields.optionalUint32(crackFieldBrainSessionV7),
		brainWhitelistV7:       fields.uint32s(crackFieldBrainWhitelistV7),
		stdin:                  fields.bytes(crackFieldStdin),
		adviceDisable:          fields.bool(crackFieldAdviceDisable),
		hashMode:               fields.optionalUint32(crackFieldHashMode),
		restoreShowCommand:     fields.bool(crackFieldRestoreShowCommand),
		brainServerTimerV7:     fields.optionalUint32(crackFieldBrainServerTimerV7),
		statusTimerV7:          fields.optionalUint32(crackFieldStatusTimerV7),
		stdinTimeoutAbortV7:    fields.optionalUint32(crackFieldStdinTimeoutAbortV7),
		outfileCheckTimerV7:    fields.optionalUint32(crackFieldOutfileCheckTimerV7),
		bitmapMinV7:            fields.optionalUint32(crackFieldBitmapMinV7),
		bitmapMaxV7:            fields.optionalUint32(crackFieldBitmapMaxV7),
		hwmonTempAbortV7:       fields.optionalUint32(crackFieldHwmonTempAbortV7),
		rulesFilesV7:           fields.bytesList(crackFieldRulesFilesV7),
		brainPasswordV7:        fields.optionalString(crackFieldBrainPasswordV7),
		generateRulesFuncMinV7: fields.optionalUint32(crackFieldGenerateRulesFuncMinV7),
		generateRulesFuncMaxV7: fields.optionalUint32(crackFieldGenerateRulesFuncMaxV7),
	}
	return values, fields.err
}
