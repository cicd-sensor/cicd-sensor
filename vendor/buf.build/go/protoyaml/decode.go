// Copyright 2023-2024 Buf Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package protoyaml

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v3"
)

var (
	// We have to initialize this from an init() function below
	// instead of via initializer expression here to avoid the Go
	// compiler complaining about a potential initialization cycle
	// (the initializer expression refers to the function
	// unmarshalAnyMsg, which indirectly refers back to this var).
	wktUnmarshalers map[protoreflect.FullName]customUnmarshaler
)

// UnmarshalOptions is a configurable YAML format parser for Protobuf messages.
type UnmarshalOptions struct {
	// The path for the data being unmarshaled.
	//
	// If set, this will be used when producing error messages.
	Path string
	// Validator is a validator to run after unmarshaling a message.
	Validator Validator
	// CustomUnmarshaler is a custom unmarshaler to use for specific message types.
	CustomUnmarshaler CustomUnmarshaler
	// Resolver is the Protobuf type resolver to use.
	Resolver interface {
		protoregistry.MessageTypeResolver
		protoregistry.ExtensionTypeResolver
	}

	// If AllowPartial is set, input for messages that will result in missing
	// required fields will not return an error.
	AllowPartial bool

	// DiscardUnknown specifies whether to discard unknown fields instead of
	// returning an error.
	DiscardUnknown bool
}

// Validator is an interface for validating a Protobuf message produced from a given YAML node.
type Validator interface {
	// Validate the given message.
	Validate(message proto.Message) error
}

// CustomUnmarshaler is an interface for custom unmarshaling of Protobuf messages.
type CustomUnmarshaler interface {
	// Unmarshal the given node into the given message.
	//
	// Returns an error if the node is invalid for the message.
	// Returns (true, nil) if the node was handled by the custom unmarshaler.
	// Otherwise, returns (false, nil), to indicate that the node should be
	// unmarshaled by the default unmarshaler.
	//
	// When unmarshaling a google.protobuf.Any message, the `@type` field is
	// included in the node.
	//
	// The 'message' argument maybe [dynamicpb.Message] or a concrete message type
	// depending on the [UnmarshalOptions].Resolver used.
	Unmarshal(node *yaml.Node, message proto.Message) (bool, error)
}

// Unmarshal a Protobuf message from the given YAML data.
func Unmarshal(data []byte, message proto.Message) error {
	return (UnmarshalOptions{}).Unmarshal(data, message)
}

// Unmarshal a Protobuf message from the given YAML data.
func (o UnmarshalOptions) Unmarshal(data []byte, message proto.Message) error {
	var yamlFile yaml.Node
	if err := yaml.Unmarshal(data, &yamlFile); err != nil {
		return err
	}
	if err := o.unmarshalNode(&yamlFile, message, data); err != nil {
		return err
	}
	if !o.AllowPartial {
		if err := proto.CheckInitialized(message); err != nil {
			return err
		}
	}
	return nil
}

// ParseDuration parses a duration string into a durationpb.Duration.
//
// Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
//
// This function supports the full range of durationpb.Duration values, including
// those outside the range of time.Duration.
func ParseDuration(str string) (*durationpb.Duration, error) {
	// [-+]?([0-9]*(\.[0-9]*)?[a-z]+)+
	neg := false

	// Consume [-+]?
	if str != "" {
		c := str[0]
		if c == '-' || c == '+' {
			neg = c == '-'
			str = str[1:]
		}
	}
	// Special case: if all that is left is "0", this is zero.
	if str == "0" {
		var empty *durationpb.Duration
		return empty, nil
	}
	if str == "" {
		return nil, errors.New("invalid duration")
	}
	totalNanos := &big.Int{}
	var err error
	for str != "" {
		str, err = parseDurationNext(str, totalNanos)
		if err != nil {
			return nil, err
		}
	}
	if neg {
		totalNanos.Neg(totalNanos)
	}
	result := &durationpb.Duration{}
	quo, rem := totalNanos.QuoRem(totalNanos, nanosPerSecond, &big.Int{})
	if !quo.IsInt64() {
		return nil, errors.New("invalid duration: out of range")
	}
	result.Seconds = quo.Int64()
	result.Nanos = int32(rem.Int64()) //nolint:gosec // not an overflow risk; value is less than 2^30
	return result, nil
}

func (o UnmarshalOptions) unmarshalNode(node *yaml.Node, message proto.Message, data []byte) error {
	if node.Kind == 0 {
		return nil
	}
	unm := &unmarshaler{
		options:   o,
		validator: o.Validator,
		lines:     strings.Split(string(data), "\n"),
	}

	// Unwrap the document node
	if node.Kind == yaml.DocumentNode {
		if len(node.Content) != 1 {
			return errors.New("expected exactly one node in document")
		}
		node = node.Content[0]
	}

	unm.unmarshalMessage(node, message, false)
	if unm.validator != nil {
		err := unm.validator.Validate(message)
		var verr *protovalidate.ValidationError
		switch {
		case err == nil: // Valid.
		case errors.As(err, &verr):
			for _, violation := range verr.Violations {
				closest := unm.nodeClosestToPath(node, message.ProtoReflect().Descriptor(), protovalidate.FieldPathString(violation.Proto.GetField()), violation.Proto.GetForKey())
				unm.addError(closest, &violationError{
					Violation: violation.Proto,
				})
			}
		default:
			unm.addError(node, err)
		}
	}

	return errors.Join(unm.errors...)
}

const atTypeFieldName = "@type"

type protoResolver interface {
	protoregistry.MessageTypeResolver
	protoregistry.ExtensionTypeResolver
}

type unmarshaler struct {
	options   UnmarshalOptions
	errors    []error
	validator Validator
	lines     []string
}

func (u *unmarshaler) addError(node *yaml.Node, err error) {
	u.errors = append(u.errors, &nodeError{
		Path:  u.options.Path,
		Node:  node,
		cause: err,
		line:  u.lines[node.Line-1],
	})
}
func (u *unmarshaler) addErrorf(node *yaml.Node, format string, args ...interface{}) {
	u.addError(node, fmt.Errorf(format, args...))
}

func (u *unmarshaler) checkKind(node *yaml.Node, expected yaml.Kind) bool {
	if node.Kind != expected {
		u.addErrorf(node, "expected %v, got %v", getNodeKind(expected), getNodeKind(node.Kind))
		return false
	}
	return true
}

func (u *unmarshaler) checkTag(node *yaml.Node, expected string) {
	if node.Tag != "" && node.Tag != expected {
		u.addErrorf(node, "expected tag %v, got %v", expected, node.Tag)
	}
}

func (u *unmarshaler) findAnyTypeURL(node *yaml.Node) string {
	typeURL := ""
	for i := 1; i < len(node.Content); i += 2 {
		keyNode := node.Content[i-1]
		valueNode := node.Content[i]
		if keyNode.Value == atTypeFieldName && u.checkKind(valueNode, yaml.ScalarNode) {
			typeURL = valueNode.Value
			break
		}
	}
	return typeURL
}

func (u *unmarshaler) resolveAnyType(typeURL string) (protoreflect.MessageType, error) {
	// Get the message type.
	msgType, err := u.getResolver().FindMessageByURL(typeURL)
	if err != nil {
		return nil, err
	}
	return msgType, nil
}

func (u *unmarshaler) findAnyType(node *yaml.Node) (protoreflect.MessageType, error) {
	typeURL := u.findAnyTypeURL(node)
	if typeURL == "" {
		return nil, errors.New("missing @type field")
	}
	return u.resolveAnyType(typeURL)
}

// Unmarshal the field based on the field kind, ignoring IsList and IsMap,
// which are handled by the caller.
func (u *unmarshaler) unmarshalScalar(
	node *yaml.Node,
	field protoreflect.FieldDescriptor,
	forKey bool,
) (protoreflect.Value, bool) {
	switch field.Kind() {
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(u.unmarshalBool(node, forKey)), true
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		//nolint:gosec // not overflow risk since unmarshalInteger does range check
		return protoreflect.ValueOfInt32(int32(u.unmarshalInteger(node, 32))), true
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return protoreflect.ValueOfInt64(u.unmarshalInteger(node, 64)), true
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		//nolint:gosec // not overflow risk since unmarshalUnsigned does range check
		return protoreflect.ValueOfUint32(uint32(u.unmarshalUnsigned(node, 32))), true
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(u.unmarshalUnsigned(node, 64)), true
	case protoreflect.FloatKind:
		return protoreflect.ValueOfFloat32(float32(u.unmarshalFloat(node, 32))), true
	case protoreflect.DoubleKind:
		return protoreflect.ValueOfFloat64(u.unmarshalFloat(node, 64)), true
	case protoreflect.StringKind:
		u.checkKind(node, yaml.ScalarNode)
		return protoreflect.ValueOfString(node.Value), true
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes(u.unmarshalBytes(node)), true
	case protoreflect.EnumKind:
		return protoreflect.ValueOfEnum(u.unmarshalEnum(node, field)), true
	default:
		u.addErrorf(node, "unimplemented scalar type %v", field.Kind())
		return protoreflect.Value{}, false
	}
}

// Base64 decodes the given node value.
func (u *unmarshaler) unmarshalBytes(node *yaml.Node) []byte {
	if !u.checkKind(node, yaml.ScalarNode) {
		return nil
	}

	enc := base64.StdEncoding
	if strings.ContainsAny(node.Value, "-_") {
		enc = base64.URLEncoding
	}
	if len(node.Value)%4 != 0 {
		enc = enc.WithPadding(base64.NoPadding)
	}

	// base64 decode the value.
	data, err := enc.DecodeString(node.Value)
	if err != nil {
		u.addErrorf(node, "invalid base64: %v", err)
	}
	return data
}

// Unmarshal raw `true` or `false` values, only allowing for strings for keys.
func (u *unmarshaler) unmarshalBool(node *yaml.Node, forKey bool) bool {
	if u.checkKind(node, yaml.ScalarNode) {
		switch node.Value {
		case "true":
			if !forKey {
				u.checkTag(node, "!!bool")
			}
			return true
		case "false":
			if !forKey {
				u.checkTag(node, "!!bool")
			}
			return false
		default:
			u.addErrorf(node, "expected bool, got %#v", node.Value)
		}
	}
	return false
}

// Unmarshal the given node into an enum value.
//
// Accepts either the enum name or number.
func (u *unmarshaler) unmarshalEnum(node *yaml.Node, field protoreflect.FieldDescriptor) protoreflect.EnumNumber {
	u.checkKind(node, yaml.ScalarNode)
	// Get the enum descriptor.
	enumDesc := field.Enum()
	if enumDesc.FullName() == "google.protobuf.NullValue" {
		return 0
	}
	// Get the enum value.
	enumVal := enumDesc.Values().ByName(protoreflect.Name(node.Value))
	if enumVal == nil {
		lit, err := parseIntLiteral(node.Value, false)
		if err != nil {
			u.addErrorf(node, "unknown enum value %#v, expected one of %v", node.Value,
				getEnumValueNames(enumDesc.Values()))
			return 0
		} else if err := lit.checkI32(field); err != nil {
			u.addErrorf(node, "%w, expected one of %v", err,
				getEnumValueNames(enumDesc.Values()))
			return 0
		}
		//nolint:gosec // not overflow risk since list.checkI32 call above does range check
		num := protoreflect.EnumNumber(lit.value)
		if lit.negative {
			num = -num
		}
		return num
	}
	return enumVal.Number()
}

// Unmarshal the given node into a float with the given bits.
func (u *unmarshaler) unmarshalFloat(node *yaml.Node, bits int) float64 {
	if !u.checkKind(node, yaml.ScalarNode) {
		return 0
	}

	parsed, err := strconv.ParseFloat(node.Value, bits)
	if err != nil {
		u.addErrorf(node, "invalid float: %v", err)
	}
	return parsed
}

// Unmarshal the given node into an unsigned integer with the given bits.
func (u *unmarshaler) unmarshalUnsigned(node *yaml.Node, bits int) uint64 {
	if !u.checkKind(node, yaml.ScalarNode) {
		return 0
	}

	parsed, err := parseUintLiteral(node.Value, true)
	if err != nil {
		u.addErrorf(node, "invalid integer: %v", err)
	}
	if bits < 64 && parsed >= 1<<bits {
		u.addErrorf(node, "integer is too large: > %v", 1<<bits-1)
	}
	return parsed
}

// Unmarshal the given node into a signed integer with the given bits.
func (u *unmarshaler) unmarshalInteger(node *yaml.Node, bits int) int64 {
	if !u.checkKind(node, yaml.ScalarNode) {
		return 0
	}

	lit, err := parseIntLiteral(node.Value, true)
	if err != nil {
		u.addErrorf(node, "invalid integer: %v", err)
	}
	if lit.negative {
		if lit.value <= 1<<(bits-1) {
			//nolint:gosec // we just checked on previous line so not overflow risk
			return -int64(lit.value)
		}
		u.addErrorf(node, "integer is too small: < %v", -(1 << (bits - 1)))
	} else if lit.value >= 1<<(bits-1) {
		u.addErrorf(node, "integer is too large: > %v", 1<<(bits-1)-1)
	}
	//nolint:gosec // we just checked above so not overflow risk
	return int64(lit.value)
}

func getFieldNames(fields protoreflect.FieldDescriptors) []protoreflect.Name {
	names := make([]protoreflect.Name, 0, fields.Len())
	for i := range fields.Len() {
		names = append(names, fields.Get(i).Name())
		if i > 5 {
			names = append(names, "...")
			break
		}
	}
	return names
}

func getEnumValueNames(values protoreflect.EnumValueDescriptors) []protoreflect.Name {
	names := make([]protoreflect.Name, 0, values.Len())
	for i := range values.Len() {
		names = append(names, values.Get(i).Name())
		if i > 5 {
			names = append(names, "...")
			break
		}
	}
	return names
}

func getNodeKind(kind yaml.Kind) string {
	switch kind {
	case yaml.DocumentNode:
		return "document"
	case yaml.SequenceNode:
		return "sequence"
	case yaml.MappingNode:
		return "mapping"
	case yaml.ScalarNode:
		return "scalar"
	case yaml.AliasNode:
		return "alias"
	}
	return fmt.Sprintf("unknown(%d)", kind)
}

// Parses Octal, Hex, Binary, Decimal, and Unsigned Integer Float literals.
//
// Conversion through JSON/YAML may have converted integers into floats, including
// exponential notation. This function will parse those values back into integers
// if possible.
func parseUintLiteral(value string, allowBytes bool) (uint64, error) { //nolint:gocyclo
	// Try to parse as an unsigned integer.
	base := 10
	remaining := value
	if len(value) >= 2 && strings.HasPrefix(value, "0") {
		switch value[1] {
		case 'x', 'X':
			base = 16
			remaining = value[2:]
		case 'o', 'O':
			base = 8
			remaining = value[2:]
		case 'b', 'B':
			base = 2
			remaining = value[2:]
		}
	}
	parsed, uintErr := strconv.ParseUint(remaining, base, 64)
	if uintErr == nil {
		return parsed, nil
	}

	// Try to parse as an unsigned integer encoded as a float.
	parsedFloat, floatErr := strconv.ParseFloat(value, 64)
	if floatErr == nil {
		if parsedFloat < 0 || math.IsInf(parsedFloat, 0) || math.IsNaN(parsedFloat) {
			return 0, uintErr
		}

		// See if it's actually an integer.
		parsed = uint64(parsedFloat)
		if float64(parsed) != parsedFloat || parsed >= (1<<53) {
			return parsed, errors.New("precision loss")
		}
		return parsed, nil
	}
	if !allowBytes {
		// Skip bytes parsing for non-integer values.
		return 0, uintErr
	}

	// Try to parse integers (int32, int64, uint32, uint64) as bytes.
	byteCount := &big.Int{}
	rem, bytesErr := parseBytes(value, byteCount)
	switch {
	case bytesErr != nil:
		return 0, bytesErr // Likely a better error message.
	case rem != "": // Extra characters.
		return 0, uintErr
	}
	if byteCount.BitLen() > 64 {
		return 0, errors.New("integer is too large")
	}
	return byteCount.Uint64(), nil
}

type intLit struct {
	negative bool
	value    uint64
}

func (lit intLit) checkI32(field protoreflect.FieldDescriptor) error {
	switch {
	case lit.negative && lit.value > 1<<31: // Underflow.
		return fmt.Errorf("expected int32 for %v, got int64", field.FullName())
	case !lit.negative && lit.value >= 1<<31: // Overflow.
		return fmt.Errorf("expected int32 for %v, got int64", field.FullName())
	}
	return nil
}

func parseIntLiteral(value string, allowBytes bool) (intLit, error) {
	var lit intLit
	if strings.HasPrefix(value, "-") {
		lit.negative = true
		value = value[1:]
	}
	var err error
	lit.value, err = parseUintLiteral(value, allowBytes)
	return lit, err
}

func (u *unmarshaler) getResolver() protoResolver {
	if u.options.Resolver != nil {
		return u.options.Resolver
	}
	return protoregistry.GlobalTypes
}

// findField searches for the field with the given 'key' by extension type, JSONName, TextName,
// and finally by Number.
func (u *unmarshaler) findField(key string, msgDesc protoreflect.MessageDescriptor) (protoreflect.FieldDescriptor, error) {
	fields := msgDesc.Fields()
	if strings.HasPrefix(key, "[") && strings.HasSuffix(key, "]") {
		extName := protoreflect.FullName(key[1 : len(key)-1])
		extType, err := u.getResolver().FindExtensionByName(extName)
		if err != nil {
			return nil, err
		}
		result := extType.TypeDescriptor()
		if !msgDesc.ExtensionRanges().Has(result.Number()) || result.ContainingMessage().FullName() != msgDesc.FullName() {
			return nil, fmt.Errorf("message %v cannot be extended by %v", msgDesc.FullName(), result.FullName())
		}
		return result, nil
	}
	if field := fields.ByJSONName(key); field != nil {
		return field, nil
	}
	if field := fields.ByTextName(key); field != nil {
		return field, nil
	}
	num, err := strconv.ParseInt(key, 10, 32)
	if err == nil && num > 0 && num <= math.MaxInt32 {
		if field := fields.ByNumber(protoreflect.FieldNumber(num)); field != nil {
			return field, nil
		}
	}
	return nil, protoregistry.NotFound
}

// Unmarshal a field, handling isList/isMap.
func (u *unmarshaler) unmarshalField(node *yaml.Node, field protoreflect.FieldDescriptor, message proto.Message) {
	if oneofDesc := field.ContainingOneof(); oneofDesc != nil && !oneofDesc.IsSynthetic() {
		// Check if another field in the oneof is already set.
		if whichOne := message.ProtoReflect().WhichOneof(oneofDesc); whichOne != nil {
			u.addErrorf(node, "field %v is already set for oneof %v", whichOne.Name(), oneofDesc.Name())
			return
		}
	}

	switch {
	case field.IsList():
		u.unmarshalList(node, field, message.ProtoReflect().Mutable(field).List())
	case field.IsMap():
		u.unmarshalMap(node, field, message.ProtoReflect().Mutable(field).Map())
	case field.Message() != nil:
		u.unmarshalMessage(node, message.ProtoReflect().Mutable(field).Message().Interface(), false)
	default:
		if val, ok := u.unmarshalScalar(node, field, false); ok {
			message.ProtoReflect().Set(field, val)
		}
	}
}

// Unmarshal the list, with explicit handling for lists of messages.
func (u *unmarshaler) unmarshalList(node *yaml.Node, field protoreflect.FieldDescriptor, list protoreflect.List) {
	if u.checkKind(node, yaml.SequenceNode) {
		switch field.Kind() {
		case protoreflect.MessageKind, protoreflect.GroupKind:
			for _, itemNode := range node.Content {
				msgVal := list.NewElement()
				u.unmarshalMessage(itemNode, msgVal.Message().Interface(), false)
				list.Append(msgVal)
			}
		default:
			for _, itemNode := range node.Content {
				val, ok := u.unmarshalScalar(itemNode, field, false)
				if !ok {
					continue
				}
				list.Append(val)
			}
		}
	}
}

// Unmarshal the map, with explicit handling for maps to messages.
func (u *unmarshaler) unmarshalMap(node *yaml.Node, field protoreflect.FieldDescriptor, mapVal protoreflect.Map) {
	if !u.checkKind(node, yaml.MappingNode) {
		return
	}
	mapKeyField := field.MapKey()
	mapValueField := field.MapValue()
	for i := 1; i < len(node.Content); i += 2 {
		keyNode := node.Content[i-1]
		valueNode := node.Content[i]
		mapKey, ok := u.unmarshalScalar(keyNode, mapKeyField, true)
		if !ok {
			continue
		}
		switch mapValueField.Kind() {
		case protoreflect.MessageKind, protoreflect.GroupKind:
			mapValue := mapVal.NewValue()
			u.unmarshalMessage(valueNode, mapValue.Message().Interface(), false)
			mapVal.Set(mapKey.MapKey(), mapValue)
		default:
			val, ok := u.unmarshalScalar(valueNode, mapValueField, false)
			if !ok {
				continue
			}
			mapVal.Set(mapKey.MapKey(), val)
		}
	}
}

func isNull(node *yaml.Node) bool {
	return node.Tag == "!!null"
}

// Resolve the node to be used with the custom unmarshaler. Returns nil if the
// there was an error.
func (u *unmarshaler) findNodeForCustom(node *yaml.Node, forAny bool) *yaml.Node {
	if !forAny {
		return node
	}
	if !u.checkKind(node, yaml.MappingNode) {
		return nil
	}
	var valueNode *yaml.Node
	for i := 1; i < len(node.Content); i += 2 {
		keyNode := node.Content[i-1]
		switch keyNode.Value {
		case "value":
			valueNode = node.Content[i]
		case atTypeFieldName:
			continue // Skip the @type field for Any messages
		default:
			u.addErrorf(keyNode, "unknown field %#v, expended one of %v", keyNode.Value, []string{"value", atTypeFieldName})
			return nil
		}
	}
	if valueNode == nil {
		u.addErrorf(node, "missing \"value\" field")
	}
	return valueNode
}

// Unmarshal the given yaml node into the given proto.Message.
func (u *unmarshaler) unmarshalMessage(node *yaml.Node, message proto.Message, forAny bool) {
	if u.options.CustomUnmarshaler != nil {
		if ok, err := u.options.CustomUnmarshaler.Unmarshal(node, message); err != nil {
			u.addError(node, err)
			return
		} else if ok {
			return // Custom unmarshaler handled the decoding.
		}
	}
	// Check for a custom unmarshaler
	if custom, ok := wktUnmarshalers[message.ProtoReflect().Descriptor().FullName()]; ok {
		valueNode := u.findNodeForCustom(node, forAny)
		if valueNode == nil {
			return // Error already added.
		} else if custom(u, valueNode, message) {
			return // Custom unmarshaler handled the decoding.
		}
	}
	if isNull(node) {
		return // Null is always allowed for messages
	}
	if node.Kind != yaml.MappingNode {
		u.addErrorf(node, "expected fields for %v, got %v",
			message.ProtoReflect().Descriptor().FullName(), getNodeKind(node.Kind))
		return
	}
	u.unmarshalMessageFields(node, message, forAny)
}

func (u *unmarshaler) unmarshalMessageFields(node *yaml.Node, message proto.Message, forAny bool) {
	// Decode the fields
	msgDesc := message.ProtoReflect().Descriptor()
	for i := 0; i < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		var key string
		switch keyNode.Kind {
		case yaml.ScalarNode:
			key = keyNode.Value
		case yaml.SequenceNode:
			// Interpret single element sequences as extension field.
			if len(keyNode.Content) == 1 && keyNode.Content[0].Kind == yaml.ScalarNode {
				key = "[" + keyNode.Content[0].Value + "]"
				break
			}
			fallthrough
		default:
			// Report an error for non-scalar keys (or sequences with multiple elements).
			u.checkKind(keyNode, yaml.ScalarNode) // Always returns false.
			continue
		}

		if forAny && key == atTypeFieldName {
			continue // Skip the @type field for Any messages
		}
		field, err := u.findField(key, msgDesc)
		switch {
		case errors.Is(err, protoregistry.NotFound):
			if !u.options.DiscardUnknown {
				u.addErrorf(keyNode, "unknown field %#v, expected one of %v", key, getFieldNames(msgDesc.Fields()))
			}
		case err != nil:
			u.addError(keyNode, err)
		default:
			valueNode := node.Content[i+1]
			u.unmarshalField(valueNode, field, message)
		}
	}
}

type customUnmarshaler func(u *unmarshaler, node *yaml.Node, message proto.Message) bool

func unmarshalAnyMsg(unm *unmarshaler, node *yaml.Node, message proto.Message) bool {
	if node.Kind != yaml.MappingNode || len(node.Content) == 0 {
		return false
	}
	anyVal, ok := message.(*anypb.Any)
	if !ok {
		anyVal = &anypb.Any{}
	}

	// Get the message type.
	msgType, err := unm.findAnyType(node)
	if err != nil {
		unm.addError(node, err)
		return true
	}

	protoVal := msgType.New()
	unm.unmarshalMessage(node, protoVal.Interface(), true)
	if err = anyVal.MarshalFrom(protoVal.Interface()); err != nil {
		unm.addErrorf(node, "failed to marshal %v: %v", msgType.Descriptor().FullName(), err)
	}

	if !ok {
		return setFieldByName(message, "type_url", protoreflect.ValueOfString(anyVal.GetTypeUrl())) &&
			setFieldByName(message, "value", protoreflect.ValueOfBytes(anyVal.GetValue()))
	}

	return true
}

const (
	maxTimestampSeconds = 253402300799
	minTimestampSeconds = -62135596800
)

// Format is RFC3339Nano, limited to the range 0001-01-01T00:00:00Z to
// 9999-12-31T23:59:59Z inclusive.
func parseTimestamp(txt string, timestamp *timestamppb.Timestamp) error {
	parsed, err := time.Parse(time.RFC3339Nano, txt)
	if err != nil {
		return err
	}
	// Validate seconds.
	secs := parsed.Unix()
	if secs < minTimestampSeconds {
		return errors.New("before 0001-01-01T00:00:00Z")
	} else if secs > maxTimestampSeconds {
		return errors.New("after 9999-12-31T23:59:59Z")
	}
	// Validate nanos.
	subsecond := strings.LastIndexByte(txt, '.')
	timezone := strings.LastIndexAny(txt, "Z-+")
	if subsecond >= 0 && timezone >= subsecond && timezone-subsecond > len(".999999999") {
		return errors.New("too many fractional second digits")
	}

	timestamp.Seconds = secs
	timestamp.Nanos = int32(parsed.Nanosecond()) //nolint:gosec // not an overflow risk; value is less than 2^30
	return nil
}

func setFieldByName(message proto.Message, name string, value protoreflect.Value) bool {
	field := message.ProtoReflect().Descriptor().Fields().ByName(protoreflect.Name(name))
	if field == nil {
		return false
	}
	message.ProtoReflect().Set(field, value)
	return true
}

func unmarshalDurationMsg(unm *unmarshaler, node *yaml.Node, message proto.Message) bool {
	if node.Kind != yaml.ScalarNode || len(node.Value) == 0 || isNull(node) {
		return false
	}
	duration, err := ParseDuration(node.Value)
	if err != nil {
		unm.addError(node, err)
		return true
	}

	if value, ok := message.(*durationpb.Duration); ok {
		value.Seconds = duration.GetSeconds()
		value.Nanos = duration.GetNanos()
		return true
	}

	// Set the fields dynamically.
	return setFieldByName(message, "seconds", protoreflect.ValueOfInt64(duration.GetSeconds())) &&
		setFieldByName(message, "nanos", protoreflect.ValueOfInt32(duration.GetNanos()))
}

func unmarshalTimestampMsg(unm *unmarshaler, node *yaml.Node, message proto.Message) bool {
	if node.Kind != yaml.ScalarNode || len(node.Value) == 0 || isNull(node) {
		return false
	}
	timestamp, ok := message.(*timestamppb.Timestamp)
	if !ok {
		timestamp = &timestamppb.Timestamp{}
	}
	err := parseTimestamp(node.Value, timestamp)
	if err != nil {
		unm.addErrorf(node, "invalid timestamp: %v", err)
	} else if !ok {
		return setFieldByName(message, "seconds", protoreflect.ValueOfInt64(timestamp.GetSeconds())) &&
			setFieldByName(message, "nanos", protoreflect.ValueOfInt32(timestamp.GetNanos()))
	}
	return true
}

// Forwards unmarshaling to the "value" field of the given wrapper message.
func unmarshalWrapperMsg(unm *unmarshaler, node *yaml.Node, message proto.Message) bool {
	valueField := message.ProtoReflect().Descriptor().Fields().ByName("value")
	if node.Kind == yaml.MappingNode || valueField == nil {
		return false
	}
	unm.unmarshalField(node, valueField, message)
	return true
}

func dynSetValue(message proto.Message, value *structpb.Value) bool {
	switch val := value.GetKind().(type) {
	case *structpb.Value_NullValue:
		return setFieldByName(message, "null_value", protoreflect.ValueOfEnum(protoreflect.EnumNumber(val.NullValue)))
	case *structpb.Value_NumberValue:
		return setFieldByName(message, "number_value", protoreflect.ValueOfFloat64(val.NumberValue))
	case *structpb.Value_StringValue:
		return setFieldByName(message, "string_value", protoreflect.ValueOfString(val.StringValue))
	case *structpb.Value_BoolValue:
		return setFieldByName(message, "bool_value", protoreflect.ValueOfBool(val.BoolValue))
	case *structpb.Value_ListValue:
		listFld := message.ProtoReflect().Descriptor().Fields().ByName("list_value")
		if listFld == nil {
			return false
		}
		listVal := message.ProtoReflect().Mutable(listFld).Message().Interface()
		return dynSetListValue(listVal, val.ListValue)
	case *structpb.Value_StructValue:
		structFld := message.ProtoReflect().Descriptor().Fields().ByName("struct_value")
		if structFld == nil {
			return false
		}
		structVal := message.ProtoReflect().Mutable(structFld).Message().Interface()
		return dynSetStruct(structVal, val.StructValue)
	}
	return false
}

func dynSetListValue(message proto.Message, list *structpb.ListValue) bool {
	valuesFld := message.ProtoReflect().Descriptor().Fields().ByName("values")
	if valuesFld == nil {
		return false
	}
	values := message.ProtoReflect().Mutable(valuesFld).List()
	for _, item := range list.GetValues() {
		value := values.NewElement()
		if !dynSetValue(value.Message().Interface(), item) {
			return false
		}
		values.Append(value)
	}
	return true
}

func dynSetStruct(message proto.Message, structVal *structpb.Struct) bool {
	fieldsFld := message.ProtoReflect().Descriptor().Fields().ByName("fields")
	if fieldsFld == nil {
		return false
	}
	fields := message.ProtoReflect().Mutable(fieldsFld).Map()
	for key, item := range structVal.GetFields() {
		value := fields.NewValue()
		if !dynSetValue(value.Message().Interface(), item) {
			return false
		}
		fields.Set(protoreflect.ValueOfString(key).MapKey(), value)
	}
	return true
}

func unmarshalValueMsg(unm *unmarshaler, node *yaml.Node, message proto.Message) bool {
	value, ok := message.(*structpb.Value)
	if !ok {
		value = &structpb.Value{}
	}
	unm.unmarshalValue(node, value)
	if !ok {
		return dynSetValue(message, value)
	}
	return true
}

func unmarshalListValueMsg(unm *unmarshaler, node *yaml.Node, message proto.Message) bool {
	if node.Kind != yaml.SequenceNode {
		return false
	}
	listValue, ok := message.(*structpb.ListValue)
	if !ok {
		listValue = &structpb.ListValue{}
	}
	unm.unmarshalListValue(node, listValue)
	if !ok {
		return dynSetListValue(message, listValue)
	}
	return true
}

func unmarshalStructMsg(unm *unmarshaler, node *yaml.Node, message proto.Message) bool {
	if node.Kind != yaml.MappingNode {
		return false
	}
	structVal, ok := message.(*structpb.Struct)
	if !ok {
		structVal = &structpb.Struct{}
	}
	unm.unmarshalStruct(node, structVal)
	if !ok {
		return dynSetStruct(message, structVal)
	}
	return true
}

// Unmarshal the given yaml node into a structpb.Value, using the given
// field descriptor to validate the type, if non-nil.
func (u *unmarshaler) unmarshalValue(
	node *yaml.Node,
	value *structpb.Value,
) {
	// Unmarshal the value.
	switch node.Kind {
	case yaml.SequenceNode: // A list.
		listValue := &structpb.ListValue{}
		u.unmarshalListValue(node, listValue)
		value.Kind = &structpb.Value_ListValue{ListValue: listValue}
	case yaml.MappingNode: // A message or map.
		structVal := &structpb.Struct{}
		u.unmarshalStruct(node, structVal)
		value.Kind = &structpb.Value_StructValue{StructValue: structVal}
	case yaml.ScalarNode:
		u.unmarshalScalarValue(node, value)
	case 0:
		value.Kind = &structpb.Value_NullValue{}
	default:
		u.addErrorf(node, "unimplemented value kind: %v", getNodeKind(node.Kind))
	}
}

// Unmarshal the given yaml node into a structpb.ListValue, using the given field
// descriptor to validate each item, if non-nil.
func (u *unmarshaler) unmarshalListValue(
	node *yaml.Node,
	list *structpb.ListValue,
) {
	for _, itemNode := range node.Content {
		itemValue := &structpb.Value{}
		u.unmarshalValue(itemNode, itemValue)
		list.Values = append(list.GetValues(), itemValue)
	}
}

// Unmarshal the given yaml node into a structpb.Struct
//
// Structs can represent either a message or a map.
// For messages, the message descriptor can be provided or inferred from the node.
// For maps, the field descriptor can be provided to validate the map keys/values.
func (u *unmarshaler) unmarshalStruct(
	node *yaml.Node,
	message *structpb.Struct,
) {
	for i := 1; i < len(node.Content); i += 2 {
		keyNode := node.Content[i-1]
		// Validate the key.
		if !u.checkKind(keyNode, yaml.ScalarNode) {
			continue
		}

		// Unmarshal the value.
		valueNode := node.Content[i]
		value := &structpb.Value{}
		u.unmarshalValue(valueNode, value)
		if message.GetFields() == nil {
			message.Fields = make(map[string]*structpb.Value)
		}
		message.Fields[keyNode.Value] = value
	}
}

func (u *unmarshaler) unmarshalScalarValue(node *yaml.Node, value *structpb.Value) {
	switch node.Tag {
	case "!!null":
		value.Kind = &structpb.Value_NullValue{}
	case "!!bool":
		u.unmarshalScalarBool(node, value)
	default:
		u.unmarshalScalarString(node, value)
	}
}

// bool, string, or bytes.
func (u *unmarshaler) unmarshalScalarBool(node *yaml.Node, value *structpb.Value) {
	switch node.Value {
	case "true":
		value.Kind = &structpb.Value_BoolValue{BoolValue: true}
	case "false":
		value.Kind = &structpb.Value_BoolValue{BoolValue: false}
	default: // This is a string, not a bool.
		value.Kind = &structpb.Value_StringValue{StringValue: node.Value}
	}
}

// Can be string, bytes, float, or int.
func (u *unmarshaler) unmarshalScalarString(node *yaml.Node, value *structpb.Value) {
	if node.Tag == "!!str" {
		// Explicitly tagged string.
		value.Kind = &structpb.Value_StringValue{StringValue: node.Value}
		return
	}

	floatVal, err := strconv.ParseFloat(node.Value, 64)
	if err != nil {
		value.Kind = &structpb.Value_StringValue{StringValue: node.Value}
		return
	}

	if math.IsInf(floatVal, 0) || math.IsNaN(floatVal) {
		// String or float.
		value.Kind = &structpb.Value_StringValue{StringValue: node.Value}
		return
	}

	// Float or int.
	u.unmarshalScalarFloat(node, value, floatVal)
}

func (u *unmarshaler) unmarshalScalarFloat(node *yaml.Node, value *structpb.Value, floatVal float64) {
	// Try to parse it as in integer, to see if the float representation is lossy.
	lit, litErr := parseIntLiteral(node.Value, false)

	// Check if we can represent this as a number.
	floatUintVal := uint64(math.Abs(floatVal))      // The uint64 representation of the float.
	if litErr != nil || floatUintVal == lit.value { // Safe to represent as a number.
		value.Kind = &structpb.Value_NumberValue{NumberValue: floatVal}
	} else { // Keep string representation.
		value.Kind = &structpb.Value_StringValue{StringValue: node.Value}
	}
}

// NodeClosestToPath returns the node closest to the given field path.
//
// If toKey is true, the key node is returned if the path points to a map entry.
//
// Example field paths:
//   - 'foo' -> the field foo
//   - 'foo[0]' -> the first element of the repeated field foo or the map entry with key '0'
//   - 'foo.bar' -> the field bar in the message field foo
//   - 'foo["bar"]' -> the map entry with key 'bar' in the map field foo
func (u *unmarshaler) nodeClosestToPath(root *yaml.Node, msgDesc protoreflect.MessageDescriptor, path string, toKey bool) *yaml.Node {
	parsedPath, err := parseFieldPath(path)
	if err != nil {
		return root
	}
	return u.findNodeByPath(root, msgDesc, parsedPath, toKey)
}

func parseFieldPath(path string) ([]string, error) {
	if len(path) == 0 {
		return nil, nil
	}
	next, path := parseNextFieldName(path)
	result := []string{next}
	for len(path) > 0 {
		switch path[0] {
		case '[': // Parse array index or map key.
			next, path = parseNextValue(path[1:])
		case '.': // Parse field name.
			next, path = parseNextFieldName(path[1:])
		default:
			return nil, errors.New("invalid path")
		}
		result = append(result, next)
	}
	return result, nil
}

func parseNextFieldName(path string) (string, string) {
	for i := range len(path) {
		switch path[i] {
		case '.':
			return path[:i], path[i:]
		case '[':
			return path[:i], path[i:]
		}
	}
	return path, ""
}

func parseNextValue(path string) (string, string) {
	if len(path) == 0 {
		return "", ""
	}
	if path[0] == '"' {
		// Parse string.
		for i := 1; i < len(path); i++ {
			switch path[i] {
			case '\\':
				i++ // Skip escaped character.
			case '"':
				result, err := strconv.Unquote(path[:i+1])
				if err != nil {
					return "", ""
				}
				return result, path[i+2:]
			}
		}
		return path, ""
	}
	// Go til the trailing ']'
	for i := range len(path) {
		if path[i] == ']' {
			return path[:i], path[i+1:]
		}
	}
	return path, ""
}

// Returns the node as close to the given path as possible.
func (u *unmarshaler) findNodeByPath(root *yaml.Node, msgDesc protoreflect.MessageDescriptor, path []string, toKey bool) *yaml.Node {
	cur := root
	curMsg := msgDesc
	var curMap protoreflect.FieldDescriptor
	for i, key := range path {
		switch cur.Kind {
		case yaml.MappingNode:
			if curMsg != nil {
				field, err := u.findField(key, curMsg)
				if err != nil {
					return cur
				}
				var found bool
				cur, found = findNodeByField(cur, field)
				switch {
				case !found:
					return cur
				case field.IsMap():
					curMap = field
					curMsg = nil
				default:
					curMap = nil
					curMsg = field.Message()
				}
			} else if curMap != nil {
				var found bool
				var keyNode *yaml.Node
				keyNode, cur, found = findEntryByKey(cur, key)
				if !found {
					return cur
				}
				if i == len(path)-1 && toKey {
					return keyNode
				}
				curMsg = curMap.MapValue().Message()
				curMap = nil
			}
		case yaml.SequenceNode:
			idx, err := strconv.Atoi(key)
			if err != nil || idx < 0 || idx >= len(cur.Content) {
				return cur
			}
			cur = cur.Content[idx]
		default:
			return cur
		}
	}
	return cur
}

func findNodeByField(cur *yaml.Node, field protoreflect.FieldDescriptor) (*yaml.Node, bool) {
	fieldNum := fmt.Sprintf("%d", field.Number())
	for i := 1; i < len(cur.Content); i += 2 {
		keyNode := cur.Content[i-1]
		if keyNode.Value == string(field.Name()) ||
			keyNode.Value == field.JSONName() ||
			keyNode.Value == fieldNum {
			return cur.Content[i], true
		}
	}
	return cur, false
}

func findEntryByKey(cur *yaml.Node, key string) (*yaml.Node, *yaml.Node, bool) {
	for i := 1; i < len(cur.Content); i += 2 {
		keyNode := cur.Content[i-1]
		if keyNode.Value == key {
			return keyNode, cur.Content[i], true
		}
	}
	return nil, cur, false
}

// nanosPerSecond is the number of nanoseconds in a second.
var nanosPerSecond = new(big.Int).SetUint64(uint64(time.Second / time.Nanosecond))

// durationUnitNames is the (normalized) list of time unit names.
var durationUnitNames = []string{"h", "m", "s", "ms", "us", "ns"}

// nanosPerUnitMap is a map of time unit names to their duration in nanoseconds.
var nanosPerUnitMap = map[string]*big.Int{
	"ns": new(big.Int).SetUint64(1), // Identity for nanos.
	"us": new(big.Int).SetUint64(uint64(time.Microsecond / time.Nanosecond)),
	"µs": new(big.Int).SetUint64(uint64(time.Microsecond / time.Nanosecond)), // U+00B5 = micro symbol
	"μs": new(big.Int).SetUint64(uint64(time.Microsecond / time.Nanosecond)), // U+03BC = Greek letter mu
	"ms": new(big.Int).SetUint64(uint64(time.Millisecond / time.Nanosecond)),
	"s":  nanosPerSecond,
	"m":  new(big.Int).SetUint64(uint64(time.Minute / time.Nanosecond)),
	"h":  new(big.Int).SetUint64(uint64(time.Hour / time.Nanosecond)),
}

// parseDurationNest parses a single segment of the duration string.
func parseDurationNext(str string, totalNanos *big.Int) (string, error) {
	// Parse the number and unit.
	whole, frac, scale, unitName, str, err := parseNumberWithUnit(str)
	if err != nil {
		return "", err
	}
	if unitName == "" {
		return "", fmt.Errorf("invalid duration: missing unit, expected one of %v", durationUnitNames)
	}

	nanosPerUnit, ok := nanosPerUnitMap[unitName]
	if !ok {
		return "", fmt.Errorf("invalid duration: unknown unit, expected one of %v", durationUnitNames)
	}

	// Convert to nanos and add to total.
	// totalNanos += whole * nanosPerUnit + frac * nanosPerUnit / scale
	if whole > 0 {
		wholeNanos := &big.Int{}
		wholeNanos.SetUint64(whole)
		wholeNanos.Mul(wholeNanos, nanosPerUnit)
		totalNanos.Add(totalNanos, wholeNanos)
	}
	if frac > 0 {
		fracNanos := &big.Int{}
		fracNanos.SetUint64(frac)
		fracNanos.Mul(fracNanos, nanosPerUnit)
		rem := &big.Int{}
		fracNanos.QuoRem(fracNanos, scale, rem)
		if rem.Uint64() > 0 {
			return "", errors.New("invalid duration: fractional nanos")
		}
		totalNanos.Add(totalNanos, fracNanos)
	}
	return str, nil
}

// bytesUnitNames is the list of byte unit names.
// E is exabyte, P is petabyte, T is terabyte, G is gigabyte, M is megabyte, K is kilobyte.
// The i suffix indicates a binary unit (e.g., Ki = 1024).
var bytesUnitNames = []string{"k", "M", "G", "T", "P", "E", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei"}

// A map from unit to the number of bytes in that unit.
var bytesPerUnitMap = map[string]int64{
	"k":  1000,
	"Ki": 1 << 10,
	"M":  1000 * 1000,
	"Mi": 1 << 20,
	"G":  1000 * 1000 * 1000,
	"Gi": 1 << 30,
	"T":  1000 * 1000 * 1000 * 1000,
	"Ti": 1 << 40,
	"P":  1000 * 1000 * 1000 * 1000 * 1000,
	"Pi": 1 << 50,
	"E":  1000 * 1000 * 1000 * 1000 * 1000 * 1000,
	"Ei": 1 << 60,
}

func parseBytes(str string, totalBytes *big.Int) (string, error) {
	whole, frac, scale, unitName, str, err := parseNumberWithUnit(str)
	if err != nil {
		return "", err
	}

	bytesPerUnit, ok := bytesPerUnitMap[unitName]
	if !ok {
		return "", fmt.Errorf("invalid bytes: unknown unit, expected one of %v", bytesUnitNames)
	}

	// Convert to bytes and add to total.
	// totalBytes += whole * bytesPerUnit + frac * bytesPerUnit / scale
	if whole > 0 {
		wholeBytes := &big.Int{}
		wholeBytes.SetUint64(whole)
		wholeBytes.Mul(wholeBytes, big.NewInt(bytesPerUnit))
		totalBytes.Add(totalBytes, wholeBytes)
	}
	if frac > 0 {
		fracBytes := &big.Int{}
		fracBytes.SetUint64(frac)
		fracBytes.Mul(fracBytes, big.NewInt(bytesPerUnit))
		rem := &big.Int{}
		fracBytes.QuoRem(fracBytes, scale, rem)
		totalBytes.Add(totalBytes, fracBytes)
	}
	return str, nil
}

func parseNumberWithUnit(str string) (whole, frac uint64, scale *big.Int, unitName string, rem string, err error) {
	if len(str) == 0 {
		return 0, 0, nil, "", str, errors.New("expected number")
	}
	// The next character must be [0-9.]
	if str[0] != '.' && (str[0] < '0' || str[0] > '9') {
		return whole, frac, scale, unitName, str, errors.New("invalid number, expected digit")
	}
	var pre bool // Whether we have seen a digit before the dot.
	whole, str, pre, err = leadingInt(str)
	if err != nil {
		return whole, frac, scale, unitName, str, err
	}
	var post bool // Whether we have seen a digit after the dot.
	if str != "" && str[0] == '.' {
		str = str[1:]
		frac, scale, str, post = leadingFrac(str)
	}
	if !pre && !post {
		return whole, frac, scale, unitName, str, errors.New("invalid number, expected digit")
	}

	end := unitEnd(str)
	unitName = str[:end]
	str = str[end:]
	return whole, frac, scale, unitName, str, nil
}

func unitEnd(str string) int {
	var i int
	for ; i < len(str); i++ {
		c := str[i]
		if c == '.' || c == '-' || '0' <= c && c <= '9' {
			return i
		}
	}
	return i
}

func leadingFrac(str string) (result uint64, scale *big.Int, rem string, post bool) {
	var i int
	scale = big.NewInt(1)
	big10 := big.NewInt(10)
	var overflow bool
	for ; i < len(str); i++ {
		chr := str[i]
		if chr < '0' || chr > '9' {
			break
		}
		if overflow {
			continue
		}
		if result > (1<<63-1)/10 {
			overflow = true
			continue
		}
		temp := result*10 + uint64(chr-'0')
		if temp > 1<<63 {
			overflow = true
			continue
		}
		result = temp
		scale.Mul(scale, big10)
	}
	return result, scale, str[i:], i > 0
}

func leadingInt(str string) (result uint64, rem string, pre bool, err error) {
	var i int
	for ; i < len(str); i++ {
		c := str[i]
		if c < '0' || c > '9' {
			break
		}
		newResult := result*10 + uint64(c-'0')
		if newResult < result {
			return 0, str, i > 0, errors.New("integer overflow")
		}
		result = newResult
	}
	return result, str[i:], i > 0, nil
}

func init() { //nolint:gochecknoinits
	wktUnmarshalers = map[protoreflect.FullName]customUnmarshaler{
		"google.protobuf.Any":         unmarshalAnyMsg,
		"google.protobuf.Duration":    unmarshalDurationMsg,
		"google.protobuf.Timestamp":   unmarshalTimestampMsg,
		"google.protobuf.BoolValue":   unmarshalWrapperMsg,
		"google.protobuf.BytesValue":  unmarshalWrapperMsg,
		"google.protobuf.DoubleValue": unmarshalWrapperMsg,
		"google.protobuf.FloatValue":  unmarshalWrapperMsg,
		"google.protobuf.Int32Value":  unmarshalWrapperMsg,
		"google.protobuf.Int64Value":  unmarshalWrapperMsg,
		"google.protobuf.UInt32Value": unmarshalWrapperMsg,
		"google.protobuf.UInt64Value": unmarshalWrapperMsg,
		"google.protobuf.StringValue": unmarshalWrapperMsg,
		"google.protobuf.Value":       unmarshalValueMsg,
		"google.protobuf.ListValue":   unmarshalListValueMsg,
		"google.protobuf.Struct":      unmarshalStructMsg,
	}
}
