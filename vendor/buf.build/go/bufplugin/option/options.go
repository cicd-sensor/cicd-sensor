// Copyright 2024-2025 Buf Technologies, Inc.
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

//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package option

import (
	"errors"
	"fmt"
	"reflect"

	optionv1 "buf.build/gen/go/bufbuild/bufplugin/protocolbuffers/go/buf/plugin/option/v1"
)

// EmptyOptions is an instance of Options with no keys.
var EmptyOptions = newOptionsNoValidate(nil)

// Options are key/values that can control the behavior of a RuleHandler,
// and can control the value of the Purpose string of the Rule.
//
// For example, if you had a Rule that checked that the suffix of all Services was "API",
// you may want an option with key "service_suffix" that can override the suffix "API" to
// another suffix such as "Service". This would result in the behavior of the check changing,
// as well as result in the Purpose string potentially changing to specify that the
// expected suffix is "Service" instead of "API".
//
// It is not possible to set a key with a not-present value. Do not add an Option with
// a given key to denote that the key is not set.
type Options interface {
	// Get gets the option value for the given key.
	//
	// Values will be one of:
	//
	// - int64
	// - float64
	// - string
	// - []byte
	// - bool
	// - A slice of any of the above, recursively (i.e. []string, [][]int64, ...)
	//
	// A caller should not modify a returned value.
	//
	// The key must have at least four characters.
	// The key must start and end with a lowercase letter from a-z, and only consist
	// of lowercase letters from a-z and underscores.
	Get(key string) (any, bool)
	// Range ranges over all key/value pairs.
	//
	// The range order is not deterministic.
	Range(f func(key string, value any))

	// ToProto converts the Options to its Protobuf representation.
	ToProto() ([]*optionv1.Option, error)

	isOption()
}

// NewOptions returns a new validated Options for the given key/value map.
func NewOptions(keyToValue map[string]any) (Options, error) {
	if err := validateKeyToValue(keyToValue); err != nil {
		return nil, err
	}
	return newOptionsNoValidate(keyToValue), nil
}

// OptionsForProtoOptions returns a new Options for the given optionv1.Options.
func OptionsForProtoOptions(protoOptions []*optionv1.Option) (Options, error) {
	keyToValue := make(map[string]any, len(protoOptions))
	for _, protoOption := range protoOptions {
		value, err := protoValueToValue(protoOption.GetValue())
		if err != nil {
			return nil, err
		}
		keyToValue[protoOption.GetKey()] = value
	}
	return NewOptions(keyToValue)
}

// GetBoolValue gets a bool value from the Options.
//
// If the value is present and is not of type bool, an error is returned.
func GetBoolValue(options Options, key string) (bool, error) {
	anyValue, ok := options.Get(key)
	if !ok {
		return false, nil
	}
	value, ok := anyValue.(bool)
	if !ok {
		return false, newUnexpectedOptionValueTypeError(key, false, anyValue)
	}
	return value, nil
}

// GetInt64Value gets a int64 value from the Options.
//
// If the value is present and is not of type int64, an error is returned.
func GetInt64Value(options Options, key string) (int64, error) {
	anyValue, ok := options.Get(key)
	if !ok {
		return 0, nil
	}
	value, ok := anyValue.(int64)
	if !ok {
		return 0, newUnexpectedOptionValueTypeError(key, int64(0), anyValue)
	}
	return value, nil
}

// GetFloat64Value gets a float64 value from the Options.
//
// If the value is present and is not of type float64, an error is returned.
func GetFloat64Value(options Options, key string) (float64, error) {
	anyValue, ok := options.Get(key)
	if !ok {
		return 0.0, nil
	}
	value, ok := anyValue.(float64)
	if !ok {
		return 0.0, newUnexpectedOptionValueTypeError(key, float64(0.0), anyValue)
	}
	return value, nil
}

// GetStringValue gets a string value from the Options.
//
// If the value is present and is not of type string, an error is returned.
func GetStringValue(options Options, key string) (string, error) {
	anyValue, ok := options.Get(key)
	if !ok {
		return "", nil
	}
	value, ok := anyValue.(string)
	if !ok {
		return "", newUnexpectedOptionValueTypeError(key, "", anyValue)
	}
	return value, nil
}

// GetBytesValue gets a bytes value from the Options.
//
// If the value is present and is not of type bytes, an error is returned.
func GetBytesValue(options Options, key string) ([]byte, error) {
	anyValue, ok := options.Get(key)
	if !ok {
		return nil, nil
	}
	value, ok := anyValue.([]byte)
	if !ok {
		return nil, newUnexpectedOptionValueTypeError(key, []byte{}, anyValue)
	}
	return value, nil
}

// GetInt64SliceValue gets a []int64 value from the Options.
//
// If the value is present and is not of type []int64, an error is returned.
func GetInt64SliceValue(options Options, key string) ([]int64, error) {
	anyValue, ok := options.Get(key)
	if !ok {
		return nil, nil
	}
	value, ok := anyValue.([]int64)
	if !ok {
		return nil, newUnexpectedOptionValueTypeError(key, []int64{}, anyValue)
	}
	return value, nil
}

// GetFloat64SliceValue gets a []float64 value from the Options.
//
// If the value is present and is not of type []float64, an error is returned.
func GetFloat64SliceValue(options Options, key string) ([]float64, error) {
	anyValue, ok := options.Get(key)
	if !ok {
		return nil, nil
	}
	value, ok := anyValue.([]float64)
	if !ok {
		return nil, newUnexpectedOptionValueTypeError(key, []float64{}, anyValue)
	}
	return value, nil
}

// GetStringSliceValue gets a []string value from the Options.
//
// If the value is present and is not of type []string, an error is returned.
func GetStringSliceValue(options Options, key string) ([]string, error) {
	anyValue, ok := options.Get(key)
	if !ok {
		return nil, nil
	}
	value, ok := anyValue.([]string)
	if !ok {
		return nil, newUnexpectedOptionValueTypeError(key, []string{}, anyValue)
	}
	return value, nil
}

// *** PRIVATE ***

type options struct {
	keyToValue map[string]any
}

func newOptionsNoValidate(keyToValue map[string]any) *options {
	if keyToValue == nil {
		keyToValue = make(map[string]any)
	}
	return &options{
		keyToValue: keyToValue,
	}
}

func (o *options) Get(key string) (any, bool) {
	value, ok := o.keyToValue[key]
	return value, ok
}

func (o *options) Range(f func(key string, value any)) {
	for key, value := range o.keyToValue {
		f(key, value)
	}
}

func (o *options) ToProto() ([]*optionv1.Option, error) {
	if o == nil {
		return nil, nil
	}
	protoOptions := make([]*optionv1.Option, 0, len(o.keyToValue))
	for key, value := range o.keyToValue {
		protoValue, err := valueToProtoValue(value)
		if err != nil {
			return nil, err
		}
		// Assuming that we've validated that no values are empty.
		protoOptions = append(
			protoOptions,
			&optionv1.Option{
				Key:   key,
				Value: protoValue,
			},
		)
	}
	return protoOptions, nil
}

func (*options) isOption() {}

// You can assume that value is a valid value.
func valueToProtoValue(value any) (*optionv1.Value, error) {
	switch reflectValue := reflect.ValueOf(value); reflectValue.Kind() {
	case reflect.Bool:
		return &optionv1.Value{
			Type: &optionv1.Value_BoolValue{
				BoolValue: reflectValue.Bool(),
			},
		}, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return &optionv1.Value{
			Type: &optionv1.Value_Int64Value{
				Int64Value: reflectValue.Int(),
			},
		}, nil
	case reflect.Float32, reflect.Float64:
		return &optionv1.Value{
			Type: &optionv1.Value_DoubleValue{
				DoubleValue: reflectValue.Float(),
			},
		}, nil
	case reflect.String:
		return &optionv1.Value{
			Type: &optionv1.Value_StringValue{
				StringValue: reflectValue.String(),
			},
		}, nil
	case reflect.Slice:
		if t, ok := value.([]byte); ok {
			return &optionv1.Value{
				Type: &optionv1.Value_BytesValue{
					BytesValue: t,
				},
			}, nil
		}
		values := make([]*optionv1.Value, reflectValue.Len())
		for i := range reflectValue.Len() {
			subValue, err := valueToProtoValue(reflectValue.Index(i).Interface())
			if err != nil {
				return nil, err
			}
			values[i] = subValue
		}
		return &optionv1.Value{
			Type: &optionv1.Value_ListValue{
				ListValue: &optionv1.ListValue{
					Values: values,
				},
			},
		}, nil
	case reflect.Invalid, reflect.Uintptr, reflect.Complex64, reflect.Complex128, reflect.Array, reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer | reflect.Ptr, reflect.Struct, reflect.UnsafePointer:
		return nil, fmt.Errorf("invalid type for Options value %T", value)
	default:
		return nil, fmt.Errorf("invalid type for Options value %T", value)
	}
}

func protoValueToValue(protoValue *optionv1.Value) (any, error) {
	if protoValue == nil {
		return nil, errors.New("invalid optionv1.Value: value cannot be nil")
	}
	switch {
	case protoValue.GetBoolValue():
		return protoValue.GetBoolValue(), nil
	case protoValue.GetInt64Value() != 0:
		return protoValue.GetInt64Value(), nil
	case protoValue.GetDoubleValue() != 0:
		return protoValue.GetDoubleValue(), nil
	case len(protoValue.GetStringValue()) > 0:
		return protoValue.GetStringValue(), nil
	case len(protoValue.GetBytesValue()) > 0:
		return protoValue.GetBytesValue(), nil
	case protoValue.GetListValue() != nil:
		protoListValue := protoValue.GetListValue()
		protoListValues := protoListValue.GetValues()
		if len(protoListValues) == 0 {
			return nil, errors.New("invalid optionv1.Value: list_values had no values")
		}
		anySlice := make([]any, len(protoListValue.GetValues()))
		for i, protoSubValue := range protoListValues {
			subValue, err := protoValueToValue(protoSubValue)
			if err != nil {
				return nil, err
			}
			anySlice[i] = subValue
		}
		// We know this is of at least length 1
		anySliceFirstType := reflect.TypeOf(anySlice[0])
		for i := 1; i < len(anySlice); i++ {
			anySliceSubType := reflect.TypeOf(anySlice[i])
			if anySliceFirstType != anySliceSubType {
				return nil, fmt.Errorf("invalid optionv1.Value: list_values must have values of the same type but detected types %v and %v", anySliceFirstType, anySliceSubType)
			}
		}
		reflectSlice := reflect.MakeSlice(reflect.SliceOf(anySliceFirstType), 0, len(anySlice))
		for _, anySliceSubValue := range anySlice {
			reflectSlice = reflect.Append(reflectSlice, reflect.ValueOf(anySliceSubValue))
		}
		return reflectSlice.Interface(), nil
	default:
		return nil, errors.New("invalid optionv1.Value: no value of oneof is set")
	}
}

func validateKeyToValue(keyToValue map[string]any) error {
	for key, value := range keyToValue {
		// This should all be validated via protovalidate, and the below doesn't
		// even encapsulate all the validation.
		if len(key) == 0 {
			return errors.New("invalid option key: key cannot be empty")
		}
		if err := validateValue(value); err != nil {
			return err
		}
	}
	return nil
}

func validateValue(value any) error {
	if value == nil {
		return errors.New("invalid option value: value cannot be nil")
	}
	switch reflectValue := reflect.ValueOf(value); reflectValue.Kind() {
	case reflect.Bool:
		t := reflectValue.Bool()
		if !t {
			return errors.New("invalid option value: bool must be true")
		}
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		t := reflectValue.Int()
		if t == 0 {
			return errors.New("invalid option value: int must be non-zero")
		}
		return nil
	case reflect.Float32, reflect.Float64:
		t := reflectValue.Float()
		if t == 0 {
			return errors.New("invalid option value: float must be non-zero")
		}
		return nil
	case reflect.String:
		t := reflectValue.String()
		if t == "" {
			return errors.New("invalid option value: string must be non-empty")
		}
		return nil
	case reflect.Slice:
		vLen := reflectValue.Len()
		if vLen == 0 {
			return errors.New("invalid option value: slice must be non-empty")
		}
		firstValue := reflectValue.Index(0).Interface()
		firstValueType := reflect.TypeOf(firstValue)
		for i := 1; i < vLen; i++ {
			subValue := reflectValue.Index(i).Interface()
			subValueType := reflect.TypeOf(subValue)
			// reflect.Types are comparable with == per documentation.
			if firstValueType != subValueType {
				return fmt.Errorf("invalid option value: slice must have values of the same type but detected types %v and %v", firstValueType, subValueType)
			}
		}
		return nil
	case reflect.Invalid, reflect.Uintptr, reflect.Complex64, reflect.Complex128, reflect.Array, reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer | reflect.Ptr, reflect.Struct, reflect.UnsafePointer:
		return fmt.Errorf("invalid option value: unhandled type %T", value)
	default:
		return fmt.Errorf("invalid option value: unhandled type %T", value)
	}
}
