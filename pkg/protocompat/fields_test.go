package protocompat

import (
	"slices"
	"testing"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestReaderKnownFields(t *testing.T) {
	message := &clientpb.CrackCommand{
		Quiet:       true,
		StatusTimer: 17,
		Session:     "audit",
		Hashes:      []string{"one", "two"},
	}
	reader, err := NewReader(message)
	if err != nil {
		t.Fatalf("NewReader() error = %v", err)
	}

	quiet, err := reader.Bool(4)
	if err != nil || !quiet {
		t.Fatalf("Bool(4) = %v, %v; want true, nil", quiet, err)
	}
	timer, err := reader.Uint32(12)
	if err != nil || timer != 17 {
		t.Fatalf("Uint32(12) = %v, %v; want 17, nil", timer, err)
	}
	session, err := reader.String(24)
	if err != nil || session != "audit" {
		t.Fatalf("String(24) = %q, %v; want audit, nil", session, err)
	}
	hashes, err := reader.Strings(3)
	if err != nil || !slices.Equal(hashes, []string{"one", "two"}) {
		t.Fatalf("Strings(3) = %q, %v", hashes, err)
	}
}

func TestReaderUnknownFields(t *testing.T) {
	raw := protowire.AppendTag(nil, 114, protowire.VarintType)
	raw = protowire.AppendVarint(raw, 1)
	raw = protowire.AppendTag(raw, 116, protowire.VarintType)
	raw = protowire.AppendVarint(raw, 180)
	raw = protowire.AppendTag(raw, 120, protowire.BytesType)
	raw = protowire.AppendString(raw, "/tmp/seek")
	for _, value := range []string{"?d?d", "words.txt"} {
		raw = protowire.AppendTag(raw, 143, protowire.BytesType)
		raw = protowire.AppendString(raw, value)
	}
	raw = protowire.AppendTag(raw, 148, protowire.VarintType)
	raw = protowire.AppendVarint(raw, 0)
	packed := protowire.AppendVarint(nil, 2)
	packed = protowire.AppendVarint(packed, 3)
	raw = protowire.AppendTag(raw, 154, protowire.BytesType)
	raw = protowire.AppendBytes(raw, packed)
	for _, value := range [][]byte{[]byte(":"), []byte("$1")} {
		raw = protowire.AppendTag(raw, 166, protowire.BytesType)
		raw = protowire.AppendBytes(raw, value)
	}

	message := &clientpb.CrackCommand{}
	message.ProtoReflect().SetUnknown(raw)
	reader, err := NewReader(message)
	if err != nil {
		t.Fatalf("NewReader() error = %v", err)
	}

	pipelineStats, err := reader.Bool(114)
	if err != nil || !pipelineStats {
		t.Fatalf("Bool(114) = %v, %v; want true, nil", pipelineStats, err)
	}
	runtime, err := reader.Uint32(116)
	if err != nil || runtime != 180 {
		t.Fatalf("Uint32(116) = %v, %v; want 180, nil", runtime, err)
	}
	seekDB, err := reader.String(120)
	if err != nil || seekDB != "/tmp/seek" {
		t.Fatalf("String(120) = %q, %v", seekDB, err)
	}
	inputs, err := reader.Strings(143)
	if err != nil || !slices.Equal(inputs, []string{"?d?d", "words.txt"}) {
		t.Fatalf("Strings(143) = %q, %v", inputs, err)
	}
	if !reader.Has(148) {
		t.Fatal("Has(148) = false; want explicit zero to be present")
	}
	zero, err := reader.Uint32(148)
	if err != nil || zero != 0 {
		t.Fatalf("Uint32(148) = %d, %v; want 0, nil", zero, err)
	}
	whitelist, err := reader.Uint32s(154)
	if err != nil || !slices.Equal(whitelist, []uint32{2, 3}) {
		t.Fatalf("Uint32s(154) = %v, %v; want [2 3], nil", whitelist, err)
	}
	rules, err := reader.BytesList(166)
	if err != nil || len(rules) != 2 || string(rules[0]) != ":" || string(rules[1]) != "$1" {
		t.Fatalf("BytesList(166) = %q, %v; want [: $1], nil", rules, err)
	}
}

func TestReaderRejectsMalformedUnknownField(t *testing.T) {
	message := &clientpb.CrackCommand{}
	message.ProtoReflect().SetUnknown([]byte{0x80})
	if _, err := NewReader(message); err == nil {
		t.Fatal("NewReader() error = nil; want malformed wire error")
	}
}

func TestReaderSkipsUnknownOccurrencesWithWrongWireType(t *testing.T) {
	raw := protowire.AppendTag(nil, 148, protowire.VarintType)
	raw = protowire.AppendVarint(raw, 7)
	raw = protowire.AppendTag(raw, 148, protowire.BytesType)
	raw = protowire.AppendString(raw, "wrong wire type")
	raw = protowire.AppendTag(raw, 143, protowire.VarintType)
	raw = protowire.AppendVarint(raw, 9)
	raw = protowire.AppendTag(raw, 143, protowire.BytesType)
	raw = protowire.AppendString(raw, "operand")
	raw = protowire.AppendTag(raw, 167, protowire.VarintType)
	raw = protowire.AppendVarint(raw, 1)

	message := &clientpb.CrackCommand{}
	message.ProtoReflect().SetUnknown(raw)
	reader, err := NewReader(message)
	if err != nil {
		t.Fatalf("NewReader() error = %v", err)
	}
	value, err := reader.Uint32(148)
	if err != nil || value != 7 {
		t.Fatalf("Uint32(148) = %d, %v; want 7, nil", value, err)
	}
	values, err := reader.Strings(143)
	if err != nil || !slices.Equal(values, []string{"operand"}) {
		t.Fatalf("Strings(143) = %q, %v; want [operand], nil", values, err)
	}
	if reader.HasBytes(167) {
		t.Fatal("HasBytes(167) accepted a wrong-wire varint")
	}
}

func TestUnknownFieldSettersReplaceAndPreserve(t *testing.T) {
	message := &clientpb.CrackTask{}
	preserved := protowire.AppendTag(nil, 200, protowire.BytesType)
	preserved = protowire.AppendString(preserved, "preserve")
	message.ProtoReflect().SetUnknown(preserved)

	if err := SetBytes(message, 8, []byte("first")); err != nil {
		t.Fatalf("SetBytes(first) error = %v", err)
	}
	if err := SetBytes(message, 8, []byte("second")); err != nil {
		t.Fatalf("SetBytes(second) error = %v", err)
	}
	if err := SetInt32(message, 11, -1); err != nil {
		t.Fatalf("SetInt32() error = %v", err)
	}

	reader, err := NewReader(message)
	if err != nil {
		t.Fatalf("NewReader() error = %v", err)
	}
	stdout, err := reader.Bytes(8)
	if err != nil || string(stdout) != "second" {
		t.Fatalf("Bytes(8) = %q, %v; want second, nil", stdout, err)
	}
	preservedValue, err := reader.String(200)
	if err != nil || preservedValue != "preserve" {
		t.Fatalf("String(200) = %q, %v; want preserve, nil", preservedValue, err)
	}

	raw := message.ProtoReflect().GetUnknown()
	count := 0
	for len(raw) > 0 {
		number, typ, tagLen := protowire.ConsumeTag(raw)
		if tagLen < 0 {
			t.Fatalf("ConsumeTag() = %d", tagLen)
		}
		valueLen := protowire.ConsumeFieldValue(number, typ, raw[tagLen:])
		if valueLen < 0 {
			t.Fatalf("ConsumeFieldValue() = %d", valueLen)
		}
		if protoreflect.FieldNumber(number) == 8 {
			count++
		}
		raw = raw[tagLen+valueLen:]
	}
	if count != 1 {
		t.Fatalf("field 8 encoded %d times; want once", count)
	}
}

func TestSetInt32KnownField(t *testing.T) {
	message := &clientpb.CUDABackendInfo{}
	if err := SetInt32(message, 6, 40); err != nil {
		t.Fatalf("SetInt32() error = %v", err)
	}
	if message.Processors != 40 {
		t.Fatalf("Processors = %d; want 40", message.Processors)
	}
}

func TestScalarSettersPreserveUnknownPresence(t *testing.T) {
	message := &clientpb.Crackstation{}
	if err := SetString(message, 200, "value"); err != nil {
		t.Fatalf("SetString() error = %v", err)
	}
	if err := SetUint32(message, 201, 0); err != nil {
		t.Fatalf("SetUint32() error = %v", err)
	}
	if err := SetBool(message, 202, false); err != nil {
		t.Fatalf("SetBool() error = %v", err)
	}

	reader, err := NewReader(message)
	if err != nil {
		t.Fatalf("NewReader() error = %v", err)
	}
	value, err := reader.String(200)
	if err != nil || value != "value" {
		t.Fatalf("String(200) = %q, %v; want value, nil", value, err)
	}
	if !reader.Has(201) || !reader.Has(202) {
		t.Fatal("explicit zero scalar presence was not preserved")
	}
}

func TestSetMessageBytesListKnownAndUnknown(t *testing.T) {
	device := &clientpb.CUDABackendInfo{Name: "GPU"}
	rawDevice, err := proto.Marshal(device)
	if err != nil {
		t.Fatalf("marshal device: %v", err)
	}

	known := &clientpb.Crackstation{}
	if err := SetMessageBytesList(known, 100, [][]byte{rawDevice}); err != nil {
		t.Fatalf("SetMessageBytesList(known) error = %v", err)
	}
	if len(known.CUDA) != 1 || known.CUDA[0].Name != "GPU" {
		t.Fatalf("known repeated message = %#v", known.CUDA)
	}

	unknown := &clientpb.Crackstation{}
	if err := SetMessageBytesList(unknown, 200, [][]byte{rawDevice, rawDevice}); err != nil {
		t.Fatalf("SetMessageBytesList(unknown) error = %v", err)
	}
	count := 0
	raw := unknown.ProtoReflect().GetUnknown()
	for len(raw) > 0 {
		number, typ, tagLen := protowire.ConsumeTag(raw)
		valueLen := protowire.ConsumeFieldValue(number, typ, raw[tagLen:])
		if tagLen < 0 || valueLen < 0 {
			t.Fatal("malformed repeated unknown message")
		}
		if number == 200 {
			count++
		}
		raw = raw[tagLen+valueLen:]
	}
	if count != 2 {
		t.Fatalf("unknown repeated message count = %d; want 2", count)
	}
}

func TestSetStringsAndBytesListRoundTrip(t *testing.T) {
	message := &clientpb.CrackCommand{}
	wantStrings := []string{"crackfile://wordlist/abc", "?d?d"}
	wantBytes := [][]byte{[]byte("crackfile://rules/def"), {0, 1, 2, 0xff}}

	if err := SetStrings(message, 143, wantStrings); err != nil {
		t.Fatalf("SetStrings() error = %v", err)
	}
	if err := SetBytesList(message, 166, wantBytes); err != nil {
		t.Fatalf("SetBytesList() error = %v", err)
	}
	reader, err := NewReader(message)
	if err != nil {
		t.Fatalf("NewReader() error = %v", err)
	}
	gotStrings, err := reader.Strings(143)
	if err != nil || !slices.Equal(gotStrings, wantStrings) {
		t.Fatalf("Strings(143) = %q, %v; want %q, nil", gotStrings, err, wantStrings)
	}
	gotBytes, err := reader.BytesList(166)
	if err != nil || len(gotBytes) != len(wantBytes) {
		t.Fatalf("BytesList(166) = %q, %v; want %q, nil", gotBytes, err, wantBytes)
	}
	for index := range wantBytes {
		if !slices.Equal(gotBytes[index], wantBytes[index]) {
			t.Fatalf("BytesList(166)[%d] = %v; want %v", index, gotBytes[index], wantBytes[index])
		}
	}

	// Replacement must remove every prior occurrence while preserving other
	// unknown fields and the distinction between an empty list and stale data.
	if err := SetStrings(message, 143, []string{"replacement"}); err != nil {
		t.Fatalf("SetStrings(replacement) error = %v", err)
	}
	if err := SetBytesList(message, 166, nil); err != nil {
		t.Fatalf("SetBytesList(nil) error = %v", err)
	}
	reader, err = NewReader(message)
	if err != nil {
		t.Fatalf("NewReader(replacement) error = %v", err)
	}
	gotStrings, _ = reader.Strings(143)
	gotBytes, _ = reader.BytesList(166)
	if !slices.Equal(gotStrings, []string{"replacement"}) || len(gotBytes) != 0 {
		t.Fatalf("replacement round trip = %q, %q", gotStrings, gotBytes)
	}
}

func TestSetStringsAndBytesListKnownTypeChecks(t *testing.T) {
	message := &clientpb.CrackCommand{}
	if err := SetStrings(message, 75, []string{"bad"}); err == nil {
		t.Fatal("SetStrings() accepted known non-list string field")
	}
	if err := SetBytesList(message, 8, [][]byte{[]byte("bad")}); err == nil {
		t.Fatal("SetBytesList() accepted known singular bytes field")
	}
}
