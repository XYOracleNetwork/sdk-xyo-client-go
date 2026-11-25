package account

import (
	"bytes"
	"encoding/hex"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// IsCanonicalSecp256k1Signature reports whether sig is a 64-byte compact r||s signature
// with non-zero r, non-zero s, both < secp256k1 order n, and low-S (s <= n/2) per BIP-62 / XYO v9.
func IsCanonicalSecp256k1Signature(sig []byte) bool {
	if len(sig) != Secp256k1SignatureSize {
		return false
	}
	var r, s secp256k1.ModNScalar
	if overflow := r.SetByteSlice(sig[:32]); overflow || r.IsZero() {
		return false
	}
	if overflow := s.SetByteSlice(sig[32:]); overflow || s.IsZero() {
		return false
	}
	return !s.IsOverHalfOrder()
}

// VerifySecp256k1Signature verifies a 64-byte canonical low-S secp256k1 signature against a
// 20-byte address and 32-byte hash by recovering the public key across recovery IDs 0..3.
func VerifySecp256k1Signature(addressBytes, hash, signature []byte) bool {
	if len(addressBytes) != AddressByteLength || len(hash) != HashSize {
		return false
	}
	if !IsCanonicalSecp256k1Signature(signature) {
		return false
	}

	var compact [65]byte
	copy(compact[1:], signature)
	for recID := byte(0); recID < 4; recID++ {
		compact[0] = 27 + recID
		pub, _, err := ecdsa.RecoverCompact(compact[:], hash)
		if err != nil {
			continue
		}
		uncompressed := pub.SerializeUncompressed()
		recovered := AddressFromPublicKey(uncompressed[1:])
		if bytes.Equal(recovered, addressBytes) {
			return true
		}
	}
	return false
}

// VerifyMLDSA65Bundle verifies a 5261-byte XYO ML-DSA-65 wire bundle (publicKey || signature)
// against a 20-byte quant address payload and message hash.
func VerifyMLDSA65Bundle(addressBytes, hash, bundle []byte) bool {
	if len(addressBytes) != AddressByteLength || len(bundle) != MLDSA65BundleSize {
		return false
	}
	pkBytes, sigBytes, err := UnbundleMLDSA65Signature(bundle)
	if err != nil {
		return false
	}
	if !bytes.Equal(AddressFromPublicKey(pkBytes), addressBytes) {
		return false
	}
	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(pkBytes); err != nil {
		return false
	}
	return mldsa65.Verify(&pk, hash, nil, sigBytes)
}

// VerifySignature dispatches verification by address format (secp256k1 hex or ML-DSA-65 qm65 Bech32m).
func VerifySignature(address string, hash []byte, signature []byte) bool {
	alg, err := AlgorithmFromAddress(address)
	if err != nil {
		return false
	}
	addrBytes, err := AddressBytes(address)
	if err != nil {
		return false
	}
	switch alg {
	case AlgorithmSecp256k1:
		return VerifySecp256k1Signature(addrBytes, hash, signature)
	case AlgorithmMLDSA65:
		return VerifyMLDSA65Bundle(addrBytes, hash, signature)
	default:
		return false
	}
}

// VerifySignatureHex verifies a hex-encoded signature against an XYO address and hex-encoded 32-byte hash.
func VerifySignatureHex(address, hashHex, sigHex string) bool {
	hashBytes, err := hex.DecodeString(StripHexPrefix(hashHex))
	if err != nil {
		return false
	}
	sigBytes, err := hex.DecodeString(StripHexPrefix(sigHex))
	if err != nil {
		return false
	}
	return VerifySignature(address, hashBytes, sigBytes)
}
