package account

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/sha3"
)

// Algorithm identifies the cryptographic signature scheme of an XYO Account.
type Algorithm string

const (
	// AlgorithmSecp256k1 is the classical ECDSA secp256k1 scheme (40-char hex address).
	AlgorithmSecp256k1 Algorithm = "secp256k1"
	// AlgorithmMLDSA65 is the post-quantum FIPS 204 ML-DSA-65 scheme (qm65 Bech32m address).
	AlgorithmMLDSA65 Algorithm = "ml-dsa-65"

	// QuantHRPMLDSA65 is the Bech32m human-readable part for ML-DSA-65 addresses.
	QuantHRPMLDSA65 = "qm65"

	// AddressByteLength is the canonical byte length of an XYO address payload.
	AddressByteLength = 20
)

// Keccak256 computes the pre-NIST Ethereum Keccak-256 digest of data.
func Keccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}

// AddressFromPublicKey derives the 20-byte XYO address payload from public key bytes:
// the last 20 bytes of Keccak-256(publicKey).
// For secp256k1, publicKey must be the 64-byte uncompressed (X || Y) without the 0x04 prefix.
// For ML-DSA-65, publicKey is the 1952-byte encoded public key.
func AddressFromPublicKey(publicKey []byte) []byte {
	digest := Keccak256(publicKey)
	out := make([]byte, AddressByteLength)
	copy(out, digest[len(digest)-AddressByteLength:])
	return out
}

// EncodeQuantAddress encodes a 20-byte address payload as a lowercase Bech32m quant address.
func EncodeQuantAddress(hrp string, addressBytes []byte) (string, error) {
	if len(addressBytes) != AddressByteLength {
		return "", fmt.Errorf("quant address payload must be %d bytes, got %d", AddressByteLength, len(addressBytes))
	}
	return EncodeBech32m(hrp, addressBytes)
}

// DecodedQuantAddress holds the decoded HRP and 20-byte payload of a Bech32m quant address.
type DecodedQuantAddress struct {
	HRP   string
	Bytes []byte
}

// TryDecodeQuantAddress attempts to decode a strictly lowercase Bech32m quant address,
// returning nil if decoding fails.
func TryDecodeQuantAddress(address string) *DecodedQuantAddress {
	hrp, payload, err := DecodeQuantAddress(address)
	if err != nil {
		return nil
	}
	return &DecodedQuantAddress{HRP: hrp, Bytes: payload}
}

// DecodeQuantAddress decodes a strictly lowercase Bech32m quant address into (hrp, 20-byte payload).
func DecodeQuantAddress(address string) (string, []byte, error) {
	if address != strings.ToLower(address) {
		return "", nil, errors.New("quant address must be lowercase")
	}
	hrp, payload, err := DecodeBech32m(address)
	if err != nil {
		return "", nil, err
	}
	if len(payload) != AddressByteLength {
		return "", nil, fmt.Errorf("quant address decoded to %d bytes, expected %d", len(payload), AddressByteLength)
	}
	return hrp, payload, nil
}

// IsLegacyAddress reports whether s is a valid 40-character hexadecimal secp256k1 address
// (with or without a 0x prefix).
func IsLegacyAddress(s string) bool {
	clean := StripHexPrefix(s)
	if len(clean) != AddressByteLength*2 {
		return false
	}
	for i := 0; i < len(clean); i++ {
		c := clean[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// IsQuantAddress reports whether s is a valid lowercase Bech32m ML-DSA-65 quant address.
func IsQuantAddress(s string) bool {
	hrp, payload, err := DecodeQuantAddress(s)
	return err == nil && hrp == QuantHRPMLDSA65 && len(payload) == AddressByteLength
}

// IsAddress reports whether s is a valid XYO address (either legacy hex or quant Bech32m).
func IsAddress(s string) bool {
	return IsLegacyAddress(s) || IsQuantAddress(s)
}

// AlgorithmFromAddress returns the signing algorithm associated with an XYO address.
func AlgorithmFromAddress(address string) (Algorithm, error) {
	if IsQuantAddress(address) {
		return AlgorithmMLDSA65, nil
	}
	if IsLegacyAddress(address) {
		return AlgorithmSecp256k1, nil
	}
	return "", fmt.Errorf("invalid XYO address: %q", address)
}

// AddressBytes decodes an XYO address (legacy hex or quant Bech32m) into its raw 20 bytes.
func AddressBytes(address string) ([]byte, error) {
	if IsQuantAddress(address) {
		_, payload, err := DecodeQuantAddress(address)
		return payload, err
	}
	if IsLegacyAddress(address) {
		return hex.DecodeString(StripHexPrefix(address))
	}
	return nil, fmt.Errorf("invalid XYO address: %q", address)
}

// NormalizeAddress normalizes a valid XYO address to canonical lowercase form without 0x prefix.
func NormalizeAddress(address string) (string, error) {
	if IsQuantAddress(address) {
		return address, nil
	}
	if IsLegacyAddress(address) {
		return strings.ToLower(StripHexPrefix(address)), nil
	}
	return "", fmt.Errorf("invalid XYO address: %q", address)
}

// StripHexPrefix removes a leading "0x" or "0X" prefix if present.
func StripHexPrefix(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
}

// DecodeHex decodes a hex string (with optional 0x prefix) into bytes.
func DecodeHex(s string) ([]byte, error) {
	clean := StripHexPrefix(strings.TrimSpace(s))
	if len(clean)%2 == 1 {
		clean = "0" + clean
	}
	return hex.DecodeString(clean)
}
