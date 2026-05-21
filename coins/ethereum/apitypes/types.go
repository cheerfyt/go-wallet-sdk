// Copyright 2018 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package apitypes provides the EIP-712 typed-data model and encoder used by
// the SDK. It is derived from upstream go-ethereum's
// signer/core/apitypes/types.go but carries local hardening fixes that upstream
// does not yet have:
//
//   - Reference-type regex anchored to ASCII uppercase start.
//   - Bare "int"/"uint" normalized to "int256"/"uint256" during EncodeType.
//   - Signed integer range validated against [-(2^(N-1)), 2^(N-1)-1].
//   - Fixed-size array lengths validated recursively at every dimension.
//   - int/uint/bytes sizes reject leading zeros and enforce step-of-8 for ints.
//
// UI-only helpers (SendTxArgs, SigFormat, ValidatorData, Format/Pprint) are
// intentionally omitted — the SDK only needs hashing.
//
// Upstream:  https://github.com/ethereum/go-ethereum/blob/master/signer/core/apitypes/types.go
// License:   LGPL-3.0-or-later (see crypto/go-ethereum/COPYING.LESSER)
// Pinned at: <TODO: fill in upstream commit SHA or release tag this file was
//            ported from, e.g. v1.14.11 / commit abcdef0>
package apitypes

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
)

// ASCII-only start character keeps this regex aligned with Type.IsReferenceType
// and with ethers.js / viem / MetaMask, which all treat type names as ASCII.
var typedDataReferenceTypeRegexp = regexp.MustCompile(`^[A-Z][A-Za-z0-9_]*(\[\d*\])*$`)

// TypedData is the top-level EIP-712 message.
type TypedData struct {
	Types       Types            `json:"types"`
	PrimaryType string           `json:"primaryType"`
	Domain      TypedDataDomain  `json:"domain"`
	Message     TypedDataMessage `json:"message"`
}

// Type is one field of a struct described in Types.
type Type struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// IsArray reports whether the type has an array suffix (dynamic or fixed).
func (t *Type) IsArray() bool {
	return len(t.Type) > 0 && t.Type[len(t.Type)-1] == ']'
}

// TypeName returns the canonical name of the type with array dimensions stripped.
// For "Person[]" or "Person[3]" it returns "Person".
func (t *Type) TypeName() string {
	if idx := strings.Index(t.Type, "["); idx >= 0 {
		return t.Type[:idx]
	}
	return t.Type
}

// IsReferenceType reports whether the type names a custom struct. Per EIP-712
// interop, reference types must start with an ASCII uppercase letter.
func (t *Type) IsReferenceType() bool {
	if len(t.Type) == 0 {
		return false
	}
	c := t.Type[0]
	return c >= 'A' && c <= 'Z'
}

// Types maps a struct name to its ordered field list.
type Types map[string][]Type

// TypePriority is used when sorting dependencies during EncodeType.
type TypePriority struct {
	Type  string
	Value uint
}

// TypedDataMessage holds the primary-type message payload.
type TypedDataMessage = map[string]interface{}

// TypedDataDomain carries the EIP-712 domain separator fields.
type TypedDataDomain struct {
	Name              string   `json:"name"`
	Version           string   `json:"version"`
	ChainId           *big.Int `json:"chainId"`
	VerifyingContract string   `json:"verifyingContract"`
	Salt              string   `json:"salt"`
}

// HashStruct generates a keccak256 hash of the encoding of the provided data.
func (typedData *TypedData) HashStruct(primaryType string, data TypedDataMessage) ([]byte, error) {
	encodedData, err := typedData.EncodeData(primaryType, data, 1)
	if err != nil {
		return nil, err
	}
	return crypto.Keccak256(encodedData), nil
}

// Dependencies returns the set of custom types referenced from primaryType,
// ordered primary-first then alphabetically.
func (typedData *TypedData) Dependencies(primaryType string, found []string) []string {
	primaryType = strings.Split(primaryType, "[")[0]

	if contains(found, primaryType) {
		return found
	}
	if typedData.Types[primaryType] == nil {
		return found
	}
	found = append(found, primaryType)
	for _, field := range typedData.Types[primaryType] {
		for _, dep := range typedData.Dependencies(field.Type, found) {
			if !contains(found, dep) {
				found = append(found, dep)
			}
		}
	}
	return found
}

func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

// normalizeType normalizes bare int/uint to int256/uint256 per EIP-712 canonical
// form. Array variants are handled too: int[] → int256[], uint[3] → uint256[3].
// A user-declared struct literally named "int" or "uint" is left alone.
func (typedData *TypedData) normalizeType(t string) string {
	base, rest := t, ""
	if idx := strings.Index(t, "["); idx >= 0 {
		base = t[:idx]
		rest = t[idx:]
	}
	if base == "int" && typedData.Types["int"] == nil {
		return "int256" + rest
	}
	if base == "uint" && typedData.Types["uint"] == nil {
		return "uint256" + rest
	}
	return t
}

// EncodeType generates the encoding
//
//	name ‖ "(" ‖ member₁ ‖ "," ‖ … ‖ memberₙ ")"
//
// where each member is `type ‖ " " ‖ name`. Dependencies are appended
// primary-first then alphabetically.
func (typedData *TypedData) EncodeType(primaryType string) hexutil.Bytes {
	deps := typedData.Dependencies(primaryType, []string{})
	if len(deps) > 0 {
		slicedDeps := deps[1:]
		sort.Strings(slicedDeps)
		deps = append([]string{primaryType}, slicedDeps...)
	}

	var buffer bytes.Buffer
	for _, dep := range deps {
		buffer.WriteString(dep)
		buffer.WriteString("(")
		for i, obj := range typedData.Types[dep] {
			if i > 0 {
				buffer.WriteString(",")
			}
			buffer.WriteString(typedData.normalizeType(obj.Type))
			buffer.WriteString(" ")
			buffer.WriteString(obj.Name)
		}
		buffer.WriteString(")")
	}
	return buffer.Bytes()
}

// TypeHash returns keccak256 of EncodeType.
func (typedData *TypedData) TypeHash(primaryType string) []byte {
	return crypto.Keccak256(typedData.EncodeType(primaryType))
}

// EncodeData generates `enc(value₁) ‖ enc(value₂) ‖ … ‖ enc(valueₙ)`,
// where each member is 32 bytes.
func (typedData *TypedData) EncodeData(primaryType string, data map[string]interface{}, depth int) ([]byte, error) {
	if err := typedData.validate(); err != nil {
		return nil, err
	}

	if typedData.Types[primaryType] == nil {
		return nil, fmt.Errorf("type %q is not defined", primaryType)
	}

	buffer := bytes.Buffer{}
	buffer.Write(typedData.TypeHash(primaryType))
	for _, field := range typedData.Types[primaryType] {
		encType := field.Type
		encValue := data[field.Name]
		if encType[len(encType)-1:] == "]" {
			encodedData, err := typedData.encodeArrayValue(encValue, encType, depth)
			if err != nil {
				return nil, err
			}
			buffer.Write(encodedData)
		} else if typedData.Types[field.Type] != nil {
			mapValue, ok := encValue.(map[string]interface{})
			if !ok {
				return nil, dataMismatchError(encType, encValue)
			}
			encodedData, err := typedData.EncodeData(field.Type, mapValue, depth+1)
			if err != nil {
				return nil, err
			}
			buffer.Write(crypto.Keccak256(encodedData))
		} else {
			byteValue, err := typedData.EncodePrimitiveValue(encType, encValue, depth)
			if err != nil {
				return nil, err
			}
			buffer.Write(byteValue)
		}
	}
	return buffer.Bytes(), nil
}

// StripOuterArrayDim strips the outermost array dimension suffix ("[N]" or "[]")
// so recursive encodeArrayValue calls see the inner dimensions intact. Each
// recursion level therefore revalidates the fixed length at its own dimension.
//
//	"uint256[3][2]" → "uint256[3]"   "uint256[]"   → "uint256"
//	"Person[3][2]"  → "Person[3]"     (no trailing "]") → unchanged
func StripOuterArrayDim(encType string) string {
	if !strings.HasSuffix(encType, "]") {
		return encType
	}
	idx := strings.LastIndex(encType, "[")
	if idx < 0 {
		return encType
	}
	return encType[:idx]
}

// parseFixedArrayLen extracts the expected length from the outermost array
// dimension. Returns (length, true) for fixed arrays like "uint256[3]";
// (0, false) for dynamic arrays and non-arrays.
func parseFixedArrayLen(encType string) (int, bool) {
	lastClose := len(encType) - 1
	if lastClose < 0 || encType[lastClose] != ']' {
		return 0, false
	}
	lastOpen := strings.LastIndex(encType[:lastClose], "[")
	if lastOpen < 0 {
		return 0, false
	}
	dimStr := encType[lastOpen+1 : lastClose]
	if dimStr == "" {
		return 0, false
	}
	n, err := strconv.Atoi(dimStr)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

func (typedData *TypedData) encodeArrayValue(encValue interface{}, encType string, depth int) (hexutil.Bytes, error) {
	arrayValue, err := convertDataToSlice(encValue)
	if err != nil {
		return nil, dataMismatchError(encType, encValue)
	}

	// Reject length-mismatched fixed arrays at the outermost level; the recursive
	// call below rechecks each inner dimension after stripOuterArrayDim.
	if expectedLen, ok := parseFixedArrayLen(encType); ok {
		if len(arrayValue) != expectedLen {
			return nil, fmt.Errorf("array length mismatch for %s: expected %d, got %d", encType, expectedLen, len(arrayValue))
		}
	}

	arrayBuffer := new(bytes.Buffer)
	parsedType := StripOuterArrayDim(encType)
	for _, item := range arrayValue {
		if item == nil {
			return nil, dataMismatchError(parsedType, item)
		}
		if reflect.TypeOf(item).Kind() == reflect.Slice ||
			reflect.TypeOf(item).Kind() == reflect.Array {
			encodedData, err := typedData.encodeArrayValue(item, parsedType, depth+1)
			if err != nil {
				return nil, err
			}
			arrayBuffer.Write(encodedData)
		} else {
			if typedData.Types[parsedType] != nil {
				mapValue, ok := item.(map[string]interface{})
				if !ok {
					return nil, dataMismatchError(parsedType, item)
				}
				encodedData, err := typedData.EncodeData(parsedType, mapValue, depth+1)
				if err != nil {
					return nil, err
				}
				arrayBuffer.Write(crypto.Keccak256(encodedData))
			} else {
				bytesValue, err := typedData.EncodePrimitiveValue(parsedType, item, depth)
				if err != nil {
					return nil, err
				}
				arrayBuffer.Write(bytesValue)
			}
		}
	}
	return crypto.Keccak256(arrayBuffer.Bytes()), nil
}

func convertDataToSlice(encValue interface{}) ([]interface{}, error) {
	var outEncValue []interface{}
	rv := reflect.ValueOf(encValue)
	if rv.Kind() == reflect.Slice {
		for i := 0; i < rv.Len(); i++ {
			outEncValue = append(outEncValue, rv.Index(i).Interface())
		}
	} else {
		return outEncValue, fmt.Errorf("provided data '%v' is not slice", encValue)
	}
	return outEncValue, nil
}

// parseBytes accepts []byte or a 0x-prefixed hex string.
func parseBytes(encType interface{}) ([]byte, bool) {
	switch v := encType.(type) {
	case []byte:
		return v, true
	case string:
		b, err := hexutil.Decode(v)
		if err != nil {
			return nil, false
		}
		return b, true
	default:
		return nil, false
	}
}

// ParseInteger coerces encValue into a *big.Int and validates that it fits
// the range of the EIP-712 integer type encType (e.g. "uint256", "int8",
// "uint"). Unsigned types reject negative values; signed types enforce
// [-(2^(N-1)), 2^(N-1)-1]. Returns an error for malformed sizes, leading
// zeros, or out-of-range values.
func ParseInteger(encType string, encValue interface{}) (*big.Int, error) {
	var (
		length int
		signed = strings.HasPrefix(encType, "int")
		b      *big.Int
	)
	if encType == "int" || encType == "uint" {
		length = 256
	} else {
		lengthStr := ""
		if strings.HasPrefix(encType, "uint") {
			lengthStr = strings.TrimPrefix(encType, "uint")
		} else {
			lengthStr = strings.TrimPrefix(encType, "int")
		}
		atoiSize, err := strconv.Atoi(lengthStr)
		if err != nil {
			return nil, fmt.Errorf("invalid size on integer: %v", lengthStr)
		}
		// Reject leading zeros (e.g., "uint08")
		if lengthStr != strconv.Itoa(atoiSize) {
			return nil, fmt.Errorf("invalid type format: %v (leading zeros not allowed)", encType)
		}
		length = atoiSize
	}
	switch v := encValue.(type) {
	case *big.Int:
		b = v
	case json.Number:
		var hexIntValue big.Int
		if err := hexIntValue.UnmarshalText([]byte(v.String())); err != nil {
			return nil, err
		}
		b = &hexIntValue
	case string:
		var hexIntValue big.Int
		if err := hexIntValue.UnmarshalText([]byte(v)); err != nil {
			return nil, err
		}
		b = &hexIntValue
	case float64:
		// JSON parses non-strings as float64. Fail if we cannot
		// convert it losslessly.
		if float64(int64(v)) == v {
			b = big.NewInt(int64(v))
		} else {
			return nil, fmt.Errorf("invalid float value %v for type %v", v, encType)
		}
	}
	if b == nil {
		return nil, fmt.Errorf("invalid integer value %v/%v for type %v", encValue, reflect.TypeOf(encValue), encType)
	}
	if !signed && b.Sign() == -1 {
		return nil, fmt.Errorf("invalid negative value for unsigned type %v", encType)
	}
	if signed {
		// intN: [-(2^(N-1)), 2^(N-1)-1]. Upstream only checks BitLen, which
		// accepts 128 for int8; we reject it.
		limit := new(big.Int).Lsh(big.NewInt(1), uint(length-1))
		maxPositive := new(big.Int).Sub(limit, big.NewInt(1))
		minNegative := new(big.Int).Neg(limit)
		if b.Cmp(maxPositive) > 0 || b.Cmp(minNegative) < 0 {
			return nil, fmt.Errorf("value out-of-bounds for %v", encType)
		}
	} else {
		if b.BitLen() > length {
			return nil, fmt.Errorf("integer larger than '%v'", encType)
		}
	}
	return b, nil
}

// EncodePrimitiveValue encodes a single leaf value into its 32-byte EIP-712
// representation.
func (typedData *TypedData) EncodePrimitiveValue(encType string, encValue interface{}, depth int) ([]byte, error) {
	switch encType {
	case "address":
		stringValue, ok := encValue.(string)
		if !ok || !common.IsHexAddress(stringValue) {
			return nil, dataMismatchError(encType, encValue)
		}
		retval := make([]byte, 32)
		copy(retval[12:], common.HexToAddress(stringValue).Bytes())
		return retval, nil
	case "bool":
		boolValue, ok := encValue.(bool)
		if !ok {
			return nil, dataMismatchError(encType, encValue)
		}
		if boolValue {
			return math.PaddedBigBytes(big.NewInt(1), 32), nil
		}
		return math.PaddedBigBytes(big.NewInt(0), 32), nil
	case "string":
		strVal, ok := encValue.(string)
		if !ok {
			return nil, dataMismatchError(encType, encValue)
		}
		return crypto.Keccak256([]byte(strVal)), nil
	case "bytes":
		bytesValue, ok := parseBytes(encValue)
		if !ok {
			return nil, dataMismatchError(encType, encValue)
		}
		return crypto.Keccak256(bytesValue), nil
	}
	if strings.HasPrefix(encType, "bytes") {
		lengthStr := strings.TrimPrefix(encType, "bytes")
		length, err := strconv.Atoi(lengthStr)
		if err != nil {
			return nil, fmt.Errorf("invalid size on bytes: %v", lengthStr)
		}
		if length < 0 || length > 32 {
			return nil, fmt.Errorf("invalid size on bytes: %d", length)
		}
		if byteValue, ok := parseBytes(encValue); !ok || len(byteValue) != length {
			return nil, dataMismatchError(encType, encValue)
		} else {
			dst := make([]byte, 32)
			copy(dst, byteValue)
			return dst, nil
		}
	}
	if strings.HasPrefix(encType, "int") || strings.HasPrefix(encType, "uint") {
		b, err := ParseInteger(encType, encValue)
		if err != nil {
			return nil, err
		}
		return math.U256Bytes(b), nil
	}
	return nil, fmt.Errorf("unrecognized type '%s'", encType)
}

func dataMismatchError(encType string, encValue interface{}) error {
	return fmt.Errorf("provided data '%v' doesn't match type '%s'", encValue, encType)
}

// validate walks the Types map and domain to ensure structural soundness.
func (typedData *TypedData) validate() error {
	if err := typedData.Types.validate(); err != nil {
		return err
	}
	if err := typedData.Domain.validate(); err != nil {
		return err
	}
	return nil
}

// Map returns a map representation of the full typed data.
func (typedData *TypedData) Map() map[string]interface{} {
	return map[string]interface{}{
		"types":       typedData.Types,
		"domain":      typedData.Domain.Map(),
		"primaryType": typedData.PrimaryType,
		"message":     typedData.Message,
	}
}

// validate checks that Types is conformant to the EIP-712 spec: every declared
// type has a non-empty key, fields have names and types, no self-reference,
// reference types resolve, and primitive types are syntactically valid.
func (t Types) validate() error {
	for typeKey, typeArr := range t {
		if len(typeKey) == 0 {
			return fmt.Errorf("empty type key")
		}
		for i, typeObj := range typeArr {
			if len(typeObj.Type) == 0 {
				return fmt.Errorf("type %q:%d: empty Type", typeKey, i)
			}
			if len(typeObj.Name) == 0 {
				return fmt.Errorf("type %q:%d: empty Name", typeKey, i)
			}
			if typeKey == typeObj.Type {
				return fmt.Errorf("type %q cannot reference itself", typeObj.Type)
			}
			if typeObj.IsReferenceType() {
				if _, exist := t[typeObj.TypeName()]; !exist {
					return fmt.Errorf("reference type %q is undefined", typeObj.Type)
				}
				if !typedDataReferenceTypeRegexp.MatchString(typeObj.Type) {
					return fmt.Errorf("unknown reference type %q", typeObj.Type)
				}
			} else if !IsPrimitiveTypeValid(typeObj.Type) {
				return fmt.Errorf("unknown type %q", typeObj.Type)
			}
		}
	}
	return nil
}

// stripArrayDimensions removes and validates array dimension suffixes.
// "uint256[3][]" → ("uint256", true); "uint256" → ("uint256", true).
// Malformed syntax (e.g., unmatched brackets, zero/negative lengths) yields ("", false).
func stripArrayDimensions(t string) (string, bool) {
	idx := strings.Index(t, "[")
	if idx < 0 {
		return t, true
	}
	base := t[:idx]
	rest := t[idx:]
	for len(rest) > 0 {
		if rest[0] != '[' {
			return "", false
		}
		end := strings.Index(rest, "]")
		if end < 0 {
			return "", false
		}
		dim := rest[1:end]
		if dim != "" {
			n, err := strconv.Atoi(dim)
			if err != nil || n <= 0 {
				return "", false
			}
		}
		rest = rest[end+1:]
	}
	return base, true
}

// IsPrimitiveTypeValid reports whether a type string is a valid EIP-712
// primitive, accepting both dynamic and fixed array variants.
func IsPrimitiveTypeValid(primitiveType string) bool {
	base, ok := stripArrayDimensions(primitiveType)
	if !ok {
		return false
	}
	return isBaseTypeValid(base)
}

func isBaseTypeValid(base string) bool {
	switch base {
	case "address", "bool", "string", "bytes":
		return true
	}
	if strings.HasPrefix(base, "bytes") {
		lengthStr := strings.TrimPrefix(base, "bytes")
		length, err := strconv.Atoi(lengthStr)
		if err != nil {
			return false
		}
		if lengthStr != strconv.Itoa(length) {
			return false
		}
		return length >= 1 && length <= 32
	}
	return isValidIntBase(base)
}

// isValidIntBase accepts bare "int"/"uint" and sized intN/uintN with
// N in 8..256 stepping by 8.
func isValidIntBase(base string) bool {
	var prefix string
	if strings.HasPrefix(base, "uint") {
		prefix = "uint"
	} else if strings.HasPrefix(base, "int") {
		prefix = "int"
	} else {
		return false
	}
	sizeStr := strings.TrimPrefix(base, prefix)
	if sizeStr == "" {
		return true
	}
	size, err := strconv.Atoi(sizeStr)
	if err != nil {
		return false
	}
	if sizeStr != strconv.Itoa(size) {
		return false
	}
	return size >= 8 && size <= 256 && size%8 == 0
}

// validate ensures the domain has at least one populated field.
func (domain *TypedDataDomain) validate() error {
	if domain.ChainId == nil && len(domain.Name) == 0 && len(domain.Version) == 0 && len(domain.VerifyingContract) == 0 && len(domain.Salt) == 0 {
		return errors.New("domain is undefined")
	}
	return nil
}

// Map returns the domain as a map with only populated fields present.
func (domain *TypedDataDomain) Map() map[string]interface{} {
	dataMap := map[string]interface{}{}
	if domain.ChainId != nil {
		dataMap["chainId"] = domain.ChainId
	}
	if len(domain.Name) > 0 {
		dataMap["name"] = domain.Name
	}
	if len(domain.Version) > 0 {
		dataMap["version"] = domain.Version
	}
	if len(domain.VerifyingContract) > 0 {
		dataMap["verifyingContract"] = domain.VerifyingContract
	}
	if len(domain.Salt) > 0 {
		dataMap["salt"] = domain.Salt
	}
	return dataMap
}
