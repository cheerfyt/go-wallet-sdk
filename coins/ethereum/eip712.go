package ethereum

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"golang.org/x/crypto/sha3"

	"github.com/okx/go-wallet-sdk/coins/ethereum/apitypes"
	"github.com/okx/go-wallet-sdk/util"
)

// Re-export the apitypes EIP-712 model under the ethereum package so existing
// callers continue to reference ethereum.TypedData / ethereum.Type / ...
// unchanged.
type (
	TypedData        = apitypes.TypedData
	Type             = apitypes.Type
	Types            = apitypes.Types
	TypePriority     = apitypes.TypePriority
	TypedDataMessage = apitypes.TypedDataMessage
	TypedDataDomain  = apitypes.TypedDataDomain
)

// TypedDataAndHash is a helper function that calculates a hash for typed data
// conforming to EIP-712. This hash can then be safely used to calculate a
// signature.
//
// See https://eips.ethereum.org/EIPS/eip-712 for the full specification.
//
// This gives context to the signed typed data and prevents signing of
// transactions.
func TypedDataAndHash(typedData TypedData) ([]byte, string, error) {
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return nil, "", err
	}
	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return nil, "", err
	}
	rawData := fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash))
	return keccak256([]byte(rawData)), rawData, nil
}

func EIP712Hash(typedData TypedData) string {
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return ""
	}
	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return ""
	}
	rawData := []byte(fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash)))
	return "0x" + hex.EncodeToString(keccak256(rawData))
}

func EIP712ParamsHash(typedData TypedData) string {
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return ""
	}
	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return ""
	}
	res := map[string]string{
		"domainSeparator": hex.EncodeToString(domainSeparator),
		"typedDataHash":   hex.EncodeToString(typedDataHash),
	}
	jsonValue, err := json.Marshal(res)
	if err != nil {
		return ""
	}
	return string(jsonValue)
}

func EIP712HashWithTypedDataHash(domainSeparatorHex, typedDataHashHex string) string {
	domainSeparator := util.RemoveZeroHex(domainSeparatorHex)
	typedDataHash := util.RemoveZeroHex(typedDataHashHex)
	rawData := []byte(fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash)))
	return "0x" + hex.EncodeToString(keccak256(rawData))
}

func keccak256(data []byte) []byte {
	s := sha3.NewLegacyKeccak256()
	s.Write(data)
	return s.Sum(nil)
}

// Unexported forwarders kept only so in-package tests can exercise the
// apitypes helpers without importing the new package qualifier.
func isPrimitiveTypeValid(t string) bool { return apitypes.IsPrimitiveTypeValid(t) }
func parseInteger(encType string, encValue interface{}) (*big.Int, error) {
	return apitypes.ParseInteger(encType, encValue)
}
func stripOuterArrayDim(encType string) string { return apitypes.StripOuterArrayDim(encType) }

// ---------------------------------------------------------------------------
// Address and hex helpers.
//
// These predate the EIP-712 extraction and are still referenced by
// tx_dynamic_fee.go (Address, HexToAddress). They live in this file for
// historical reasons; moving them is out of scope for this refactor.
// ---------------------------------------------------------------------------

func has0xPrefix(input string) bool {
	return len(input) >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')
}

// Address represents the 20 byte address of an Ethereum account.
type Address [20]byte

// BytesToAddress returns Address with value b.
// If b is larger than len(h), b will be cropped from the left.
func BytesToAddress(b []byte) Address {
	var a Address
	a.SetBytes(b)
	return a
}

func (a *Address) SetBytes(b []byte) {
	if len(b) > len(a) {
		b = b[len(b)-20:]
	}
	copy(a[20-len(b):], b)
}

// BigToAddress returns Address with byte values of b.
// If b is larger than len(h), b will be cropped from the left.
func BigToAddress(b *big.Int) Address { return BytesToAddress(b.Bytes()) }

// FromHex returns the bytes represented by the hexadecimal string s.
// s may be prefixed with "0x".
func FromHex(s string) []byte {
	if has0xPrefix(s) {
		s = s[2:]
	}
	if len(s)%2 == 1 {
		s = "0" + s
	}
	return Hex2Bytes(s)
}

// Hex2Bytes returns the bytes represented by the hexadecimal string str.
func Hex2Bytes(str string) []byte {
	h, _ := hex.DecodeString(str)
	return h
}

// HexToAddress returns Address with byte values of s.
// If s is larger than len(h), s will be cropped from the left.
func HexToAddress(s string) Address { return BytesToAddress(FromHex(s)) }

// IsHexAddress verifies whether a string can represent a valid hex-encoded
// Ethereum address.
func IsHexAddress(s string) bool {
	if has0xPrefix(s) {
		s = s[2:]
	}
	return len(s) == 2*20 && isHex(s)
}

func isHex(str string) bool {
	if len(str)%2 != 0 {
		return false
	}
	for _, c := range []byte(str) {
		if !isHexCharacter(c) {
			return false
		}
	}
	return true
}

// Bytes gets the string representation of the underlying address.
func (a Address) Bytes() []byte { return a[:] }

// Hex returns an EIP55-compliant hex string representation of the address.
func (a Address) Hex() string {
	return string(a.checksumHex())
}

func (a Address) hex() []byte {
	var buf [len(a)*2 + 2]byte
	copy(buf[:2], "0x")
	hex.Encode(buf[2:], a[:])
	return buf[:]
}

func (a *Address) checksumHex() []byte {
	buf := a.hex()
	sha := sha3.NewLegacyKeccak256()
	sha.Write(buf[2:])
	hash := sha.Sum(nil)
	for i := 2; i < len(buf); i++ {
		hashByte := hash[(i-2)/2]
		if i%2 == 0 {
			hashByte = hashByte >> 4
		} else {
			hashByte &= 0xf
		}
		if buf[i] > '9' && hashByte > 7 {
			buf[i] -= 32
		}
	}
	return buf[:]
}

// String implements fmt.Stringer.
func (a Address) String() string {
	return a.Hex()
}
