// Package protocompat provides narrowly scoped helpers for reading and writing
// additive protobuf fields while two independently released components roll
// out a schema update. Known fields are accessed through reflection; fields
// unknown to the compiled descriptor are accessed through their preserved wire
// representation.
package protocompat

import (
	"fmt"
	"math"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type wireValue struct {
	typ    protowire.Type
	varint uint64
	bytes  []byte
}

// Reader indexes the known descriptor and preserved unknown fields of a
// protobuf message. It is safe to reuse for multiple field lookups as long as
// the underlying message is not mutated.
type Reader struct {
	message protoreflect.Message
	unknown map[protoreflect.FieldNumber][]wireValue
}

// NewReader constructs a field reader and validates the message's unknown wire
// data. Protobuf unmarshalling normally performs this validation already; the
// explicit error is useful for callers and tests that construct messages.
func NewReader(message protoreflect.ProtoMessage) (*Reader, error) {
	if message == nil {
		return nil, fmt.Errorf("nil protobuf message")
	}

	reader := &Reader{
		message: message.ProtoReflect(),
		unknown: map[protoreflect.FieldNumber][]wireValue{},
	}
	if err := reader.indexUnknown(); err != nil {
		return nil, err
	}
	return reader, nil
}

func (r *Reader) indexUnknown() error {
	raw := r.message.GetUnknown()
	for len(raw) > 0 {
		number, typ, tagLen := protowire.ConsumeTag(raw)
		if tagLen < 0 {
			return fmt.Errorf("decode protobuf tag: %w", protowire.ParseError(tagLen))
		}
		raw = raw[tagLen:]

		value := wireValue{typ: typ}
		var valueLen int
		switch typ {
		case protowire.VarintType:
			value.varint, valueLen = protowire.ConsumeVarint(raw)
		case protowire.BytesType:
			value.bytes, valueLen = protowire.ConsumeBytes(raw)
		default:
			valueLen = protowire.ConsumeFieldValue(number, typ, raw)
		}
		if valueLen < 0 {
			return fmt.Errorf("decode protobuf field %d: %w", number, protowire.ParseError(valueLen))
		}
		if typ == protowire.VarintType || typ == protowire.BytesType {
			r.unknown[protoreflect.FieldNumber(number)] = append(
				r.unknown[protoreflect.FieldNumber(number)], value,
			)
		}
		raw = raw[valueLen:]
	}
	return nil
}

// Bool reads a singular bool field.
func (r *Reader) Bool(number protoreflect.FieldNumber) (bool, error) {
	if field := r.message.Descriptor().Fields().ByNumber(number); field != nil {
		if field.IsList() || field.Kind() != protoreflect.BoolKind {
			return false, fieldTypeError(number, "bool", field)
		}
		return r.message.Get(field).Bool(), nil
	}
	value, ok := lastUnknownOfType(r.unknown[number], protowire.VarintType)
	if !ok {
		return false, nil
	}
	return value.varint != 0, nil
}

// Uint32 reads a singular uint32 field.
func (r *Reader) Uint32(number protoreflect.FieldNumber) (uint32, error) {
	if field := r.message.Descriptor().Fields().ByNumber(number); field != nil {
		if field.IsList() || field.Kind() != protoreflect.Uint32Kind {
			return 0, fieldTypeError(number, "uint32", field)
		}
		return uint32(r.message.Get(field).Uint()), nil
	}
	value, ok := lastUnknownOfType(r.unknown[number], protowire.VarintType)
	if !ok {
		return 0, nil
	}
	if value.varint > math.MaxUint32 {
		return 0, fmt.Errorf("protobuf field %d is not a uint32", number)
	}
	return uint32(value.varint), nil
}

// Uint64 reads a singular uint64 field.
func (r *Reader) Uint64(number protoreflect.FieldNumber) (uint64, error) {
	if field := r.message.Descriptor().Fields().ByNumber(number); field != nil {
		if field.IsList() || field.Kind() != protoreflect.Uint64Kind {
			return 0, fieldTypeError(number, "uint64", field)
		}
		return r.message.Get(field).Uint(), nil
	}
	value, ok := lastUnknownOfType(r.unknown[number], protowire.VarintType)
	if !ok {
		return 0, nil
	}
	return value.varint, nil
}

// Int32 reads a singular int32 field.
func (r *Reader) Int32(number protoreflect.FieldNumber) (int32, error) {
	if field := r.message.Descriptor().Fields().ByNumber(number); field != nil {
		if field.IsList() || field.Kind() != protoreflect.Int32Kind {
			return 0, fieldTypeError(number, "int32", field)
		}
		return int32(r.message.Get(field).Int()), nil
	}
	value, ok := lastUnknownOfType(r.unknown[number], protowire.VarintType)
	if !ok {
		return 0, nil
	}
	return int32(value.varint), nil
}

// Uint32s reads a repeated uint32 field in either packed or unpacked form.
func (r *Reader) Uint32s(number protoreflect.FieldNumber) ([]uint32, error) {
	if field := r.message.Descriptor().Fields().ByNumber(number); field != nil {
		if !field.IsList() || field.Kind() != protoreflect.Uint32Kind {
			return nil, fieldTypeError(number, "repeated uint32", field)
		}
		list := r.message.Get(field).List()
		values := make([]uint32, list.Len())
		for index := 0; index < list.Len(); index++ {
			values[index] = uint32(list.Get(index).Uint())
		}
		return values, nil
	}

	values := []uint32{}
	for _, value := range r.unknown[number] {
		switch value.typ {
		case protowire.VarintType:
			if value.varint > math.MaxUint32 {
				return nil, fmt.Errorf("protobuf field %d contains a value larger than uint32", number)
			}
			values = append(values, uint32(value.varint))
		case protowire.BytesType:
			packed := value.bytes
			for len(packed) > 0 {
				item, itemLen := protowire.ConsumeVarint(packed)
				if itemLen < 0 {
					return nil, fmt.Errorf("decode packed protobuf field %d: %w", number, protowire.ParseError(itemLen))
				}
				if item > math.MaxUint32 {
					return nil, fmt.Errorf("protobuf field %d contains a value larger than uint32", number)
				}
				values = append(values, uint32(item))
				packed = packed[itemLen:]
			}
		default:
			// Protobuf decoders skip occurrences with an incompatible wire type.
			continue
		}
	}
	return values, nil
}

// Has reports whether a field is present. It preserves presence for optional
// scalar fields, including an explicitly encoded zero.
func (r *Reader) Has(number protoreflect.FieldNumber) bool {
	if field := r.message.Descriptor().Fields().ByNumber(number); field != nil {
		return r.message.Has(field)
	}
	return len(r.unknown[number]) > 0
}

// HasVarint reports whether a scalar varint occurrence is present. Unlike Has,
// it ignores an unknown occurrence of the same field number with a wire type a
// generated protobuf decoder would skip.
func (r *Reader) HasVarint(number protoreflect.FieldNumber) bool {
	if field := r.message.Descriptor().Fields().ByNumber(number); field != nil {
		return r.message.Has(field)
	}
	_, ok := lastUnknownOfType(r.unknown[number], protowire.VarintType)
	return ok
}

// HasBytes reports whether a length-delimited occurrence is present. It
// ignores a same-number unknown field with a wire type generated protobuf code
// would skip.
func (r *Reader) HasBytes(number protoreflect.FieldNumber) bool {
	if field := r.message.Descriptor().Fields().ByNumber(number); field != nil {
		return r.message.Has(field)
	}
	_, ok := lastUnknownOfType(r.unknown[number], protowire.BytesType)
	return ok
}

// String reads a singular string field.
func (r *Reader) String(number protoreflect.FieldNumber) (string, error) {
	if field := r.message.Descriptor().Fields().ByNumber(number); field != nil {
		if field.IsList() || field.Kind() != protoreflect.StringKind {
			return "", fieldTypeError(number, "string", field)
		}
		return r.message.Get(field).String(), nil
	}
	value, ok := lastUnknownOfType(r.unknown[number], protowire.BytesType)
	if !ok {
		return "", nil
	}
	return string(value.bytes), nil
}

// Bytes reads a singular bytes field.
func (r *Reader) Bytes(number protoreflect.FieldNumber) ([]byte, error) {
	if field := r.message.Descriptor().Fields().ByNumber(number); field != nil {
		if field.IsList() || field.Kind() != protoreflect.BytesKind {
			return nil, fieldTypeError(number, "bytes", field)
		}
		return append([]byte(nil), r.message.Get(field).Bytes()...), nil
	}
	value, ok := lastUnknownOfType(r.unknown[number], protowire.BytesType)
	if !ok {
		return nil, nil
	}
	return append([]byte(nil), value.bytes...), nil
}

// BytesList reads a repeated bytes field and returns independent copies of
// each value.
func (r *Reader) BytesList(number protoreflect.FieldNumber) ([][]byte, error) {
	if field := r.message.Descriptor().Fields().ByNumber(number); field != nil {
		if !field.IsList() || field.Kind() != protoreflect.BytesKind {
			return nil, fieldTypeError(number, "repeated bytes", field)
		}
		list := r.message.Get(field).List()
		values := make([][]byte, list.Len())
		for index := 0; index < list.Len(); index++ {
			values[index] = append([]byte(nil), list.Get(index).Bytes()...)
		}
		return values, nil
	}

	values := make([][]byte, 0, len(r.unknown[number]))
	for _, value := range r.unknown[number] {
		if value.typ != protowire.BytesType {
			continue
		}
		values = append(values, append([]byte(nil), value.bytes...))
	}
	return values, nil
}

// Strings reads a repeated string field.
func (r *Reader) Strings(number protoreflect.FieldNumber) ([]string, error) {
	if field := r.message.Descriptor().Fields().ByNumber(number); field != nil {
		if !field.IsList() || field.Kind() != protoreflect.StringKind {
			return nil, fieldTypeError(number, "repeated string", field)
		}
		list := r.message.Get(field).List()
		values := make([]string, list.Len())
		for index := 0; index < list.Len(); index++ {
			values[index] = list.Get(index).String()
		}
		return values, nil
	}

	values := make([]string, 0, len(r.unknown[number]))
	for _, value := range r.unknown[number] {
		if value.typ != protowire.BytesType {
			continue
		}
		values = append(values, string(value.bytes))
	}
	return values, nil
}

func lastUnknownOfType(values []wireValue, typ protowire.Type) (wireValue, bool) {
	for index := len(values) - 1; index >= 0; index-- {
		if values[index].typ == typ {
			return values[index], true
		}
	}
	return wireValue{}, false
}

func fieldTypeError(number protoreflect.FieldNumber, expected string, field protoreflect.FieldDescriptor) error {
	return fmt.Errorf("protobuf field %d is %s, expected %s", number, field.Kind(), expected)
}

// SetBytes sets a bytes field. If the compiled descriptor predates the field,
// the value is encoded into the message's unknown field set.
func SetBytes(message protoreflect.ProtoMessage, number protoreflect.FieldNumber, value []byte) error {
	if message == nil {
		return fmt.Errorf("nil protobuf message")
	}
	reflected := message.ProtoReflect()
	if field := reflected.Descriptor().Fields().ByNumber(number); field != nil {
		if field.IsList() || field.Kind() != protoreflect.BytesKind {
			return fieldTypeError(number, "bytes", field)
		}
		reflected.Set(field, protoreflect.ValueOfBytes(append([]byte(nil), value...)))
		return nil
	}

	raw, err := withoutUnknownField(reflected.GetUnknown(), number)
	if err != nil {
		return err
	}
	if len(value) > 0 {
		raw = protowire.AppendTag(raw, protowire.Number(number), protowire.BytesType)
		raw = protowire.AppendBytes(raw, value)
	}
	reflected.SetUnknown(raw)
	return nil
}

// SetString sets a string field, using unknown wire data when necessary.
func SetString(message protoreflect.ProtoMessage, number protoreflect.FieldNumber, value string) error {
	if message == nil {
		return fmt.Errorf("nil protobuf message")
	}
	reflected := message.ProtoReflect()
	if field := reflected.Descriptor().Fields().ByNumber(number); field != nil {
		if field.IsList() || field.Kind() != protoreflect.StringKind {
			return fieldTypeError(number, "string", field)
		}
		reflected.Set(field, protoreflect.ValueOfString(value))
		return nil
	}

	raw, err := withoutUnknownField(reflected.GetUnknown(), number)
	if err != nil {
		return err
	}
	if value != "" {
		raw = protowire.AppendTag(raw, protowire.Number(number), protowire.BytesType)
		raw = protowire.AppendString(raw, value)
	}
	reflected.SetUnknown(raw)
	return nil
}

// SetUint32 sets a uint32 field. Unknown fields are encoded even when value is
// zero so callers can preserve presence for a future optional field.
func SetUint32(message protoreflect.ProtoMessage, number protoreflect.FieldNumber, value uint32) error {
	if message == nil {
		return fmt.Errorf("nil protobuf message")
	}
	reflected := message.ProtoReflect()
	if field := reflected.Descriptor().Fields().ByNumber(number); field != nil {
		if field.IsList() || field.Kind() != protoreflect.Uint32Kind {
			return fieldTypeError(number, "uint32", field)
		}
		reflected.Set(field, protoreflect.ValueOfUint32(value))
		return nil
	}

	raw, err := withoutUnknownField(reflected.GetUnknown(), number)
	if err != nil {
		return err
	}
	raw = protowire.AppendTag(raw, protowire.Number(number), protowire.VarintType)
	raw = protowire.AppendVarint(raw, uint64(value))
	reflected.SetUnknown(raw)
	return nil
}

// SetUint64 sets a uint64 field, using unknown wire data when necessary.
func SetUint64(message protoreflect.ProtoMessage, number protoreflect.FieldNumber, value uint64) error {
	if message == nil {
		return fmt.Errorf("nil protobuf message")
	}
	reflected := message.ProtoReflect()
	if field := reflected.Descriptor().Fields().ByNumber(number); field != nil {
		if field.IsList() || field.Kind() != protoreflect.Uint64Kind {
			return fieldTypeError(number, "uint64", field)
		}
		reflected.Set(field, protoreflect.ValueOfUint64(value))
		return nil
	}

	raw, err := withoutUnknownField(reflected.GetUnknown(), number)
	if err != nil {
		return err
	}
	if value != 0 {
		raw = protowire.AppendTag(raw, protowire.Number(number), protowire.VarintType)
		raw = protowire.AppendVarint(raw, value)
	}
	reflected.SetUnknown(raw)
	return nil
}

// SetBool sets a bool field. Unknown fields are encoded even when value is
// false so callers can preserve presence for a future optional field.
func SetBool(message protoreflect.ProtoMessage, number protoreflect.FieldNumber, value bool) error {
	if message == nil {
		return fmt.Errorf("nil protobuf message")
	}
	reflected := message.ProtoReflect()
	if field := reflected.Descriptor().Fields().ByNumber(number); field != nil {
		if field.IsList() || field.Kind() != protoreflect.BoolKind {
			return fieldTypeError(number, "bool", field)
		}
		reflected.Set(field, protoreflect.ValueOfBool(value))
		return nil
	}

	raw, err := withoutUnknownField(reflected.GetUnknown(), number)
	if err != nil {
		return err
	}
	raw = protowire.AppendTag(raw, protowire.Number(number), protowire.VarintType)
	if value {
		raw = protowire.AppendVarint(raw, 1)
	} else {
		raw = protowire.AppendVarint(raw, 0)
	}
	reflected.SetUnknown(raw)
	return nil
}

// SetMessageBytesList replaces a repeated message field with messages encoded
// in protobuf wire format. It supports both a future known descriptor and an
// older descriptor that preserves the field as unknown data.
func SetMessageBytesList(message protoreflect.ProtoMessage, number protoreflect.FieldNumber, values [][]byte) error {
	if message == nil {
		return fmt.Errorf("nil protobuf message")
	}
	reflected := message.ProtoReflect()
	if field := reflected.Descriptor().Fields().ByNumber(number); field != nil {
		if !field.IsList() || field.Kind() != protoreflect.MessageKind {
			return fieldTypeError(number, "repeated message", field)
		}
		list := reflected.Mutable(field).List()
		list.Truncate(0)
		for index, raw := range values {
			item := list.NewElement()
			if err := proto.Unmarshal(raw, item.Message().Interface()); err != nil {
				return fmt.Errorf("decode protobuf field %d item %d: %w", number, index, err)
			}
			list.Append(item)
		}
		return nil
	}

	raw, err := withoutUnknownField(reflected.GetUnknown(), number)
	if err != nil {
		return err
	}
	for _, value := range values {
		raw = protowire.AppendTag(raw, protowire.Number(number), protowire.BytesType)
		raw = protowire.AppendBytes(raw, value)
	}
	reflected.SetUnknown(raw)
	return nil
}

// SetInt32 sets an int32 field, using unknown wire data when necessary.
func SetInt32(message protoreflect.ProtoMessage, number protoreflect.FieldNumber, value int32) error {
	if message == nil {
		return fmt.Errorf("nil protobuf message")
	}
	reflected := message.ProtoReflect()
	if field := reflected.Descriptor().Fields().ByNumber(number); field != nil {
		if field.IsList() || field.Kind() != protoreflect.Int32Kind {
			return fieldTypeError(number, "int32", field)
		}
		reflected.Set(field, protoreflect.ValueOfInt32(value))
		return nil
	}

	raw, err := withoutUnknownField(reflected.GetUnknown(), number)
	if err != nil {
		return err
	}
	if value != 0 {
		raw = protowire.AppendTag(raw, protowire.Number(number), protowire.VarintType)
		raw = protowire.AppendVarint(raw, uint64(int64(value)))
	}
	reflected.SetUnknown(raw)
	return nil
}

func withoutUnknownField(raw []byte, target protoreflect.FieldNumber) ([]byte, error) {
	filtered := make([]byte, 0, len(raw))
	for len(raw) > 0 {
		fieldStart := raw
		number, typ, tagLen := protowire.ConsumeTag(raw)
		if tagLen < 0 {
			return nil, fmt.Errorf("decode protobuf tag: %w", protowire.ParseError(tagLen))
		}
		valueLen := protowire.ConsumeFieldValue(number, typ, raw[tagLen:])
		if valueLen < 0 {
			return nil, fmt.Errorf("decode protobuf field %d: %w", number, protowire.ParseError(valueLen))
		}
		fieldLen := tagLen + valueLen
		if protoreflect.FieldNumber(number) != target {
			filtered = append(filtered, fieldStart[:fieldLen]...)
		}
		raw = fieldStart[fieldLen:]
	}
	return filtered, nil
}
