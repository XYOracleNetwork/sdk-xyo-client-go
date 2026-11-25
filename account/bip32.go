package account

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	// HardenedOffset is 2^31 (0x80000000) per BIP-32.
	HardenedOffset uint32 = 0x80000000
)

// ExtendedKey represents a BIP-32 extended private key (private key + 32-byte chain code).
type ExtendedKey struct {
	Key       []byte // 32-byte private key
	ChainCode []byte // 32-byte chain code
	Depth     uint8
	ChildNum  uint32
}

// NewMasterKey derives the BIP-32 master extended private key from a seed (typically 64 bytes from BIP-39).
func NewMasterKey(seed []byte) (*ExtendedKey, error) {
	if len(seed) < 16 || len(seed) > 64 {
		return nil, fmt.Errorf("BIP-32 seed must be 16..64 bytes, got %d", len(seed))
	}
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	mac.Write(seed)
	I := mac.Sum(nil)
	il, ir := I[:32], I[32:]

	var scalar secp256k1.ModNScalar
	if overflow := scalar.SetByteSlice(il); overflow || scalar.IsZero() {
		return nil, errors.New("derived invalid BIP-32 master key")
	}

	key := make([]byte, 32)
	copy(key, il)
	cc := make([]byte, 32)
	copy(cc, ir)
	return &ExtendedKey{
		Key:       key,
		ChainCode: cc,
		Depth:     0,
		ChildNum:  0,
	}, nil
}

// DeriveChild derives a direct child extended private key for index (use index >= HardenedOffset for hardened).
func (k *ExtendedKey) DeriveChild(index uint32) (*ExtendedKey, error) {
	var parentScalar secp256k1.ModNScalar
	if overflow := parentScalar.SetByteSlice(k.Key); overflow || parentScalar.IsZero() {
		return nil, errors.New("invalid parent private key")
	}
	parentPriv := secp256k1.NewPrivateKey(&parentScalar)

	data := make([]byte, 37)
	if index >= HardenedOffset {
		data[0] = 0x00
		copy(data[1:33], k.Key)
	} else {
		copy(data[0:33], parentPriv.PubKey().SerializeCompressed())
	}
	binary.BigEndian.PutUint32(data[33:37], index)

	mac := hmac.New(sha512.New, k.ChainCode)
	mac.Write(data)
	I := mac.Sum(nil)
	il, ir := I[:32], I[32:]

	var tweak secp256k1.ModNScalar
	if overflow := tweak.SetByteSlice(il); overflow {
		return nil, errors.New("BIP-32 child key tweak >= curve order")
	}
	tweak.Add(&parentScalar)
	if tweak.IsZero() {
		return nil, errors.New("BIP-32 derived zero child key")
	}

	childKeyBytes := tweak.Bytes()
	childKey := make([]byte, 32)
	copy(childKey, childKeyBytes[:])
	childCC := make([]byte, 32)
	copy(childCC, ir)

	return &ExtendedKey{
		Key:       childKey,
		ChainCode: childCC,
		Depth:     k.Depth + 1,
		ChildNum:  index,
	}, nil
}

// DerivePath derives a descendant ExtendedKey along a BIP-32 path such as "m/44'/60'/0'/0/0" or "44'/60'/0'/0/0".
func (k *ExtendedKey) DerivePath(path string) (*ExtendedKey, error) {
	indices, err := ParseDerivationPath(path)
	if err != nil {
		return nil, err
	}
	cur := k
	for _, idx := range indices {
		cur, err = cur.DeriveChild(idx)
		if err != nil {
			return nil, err
		}
	}
	return cur, nil
}

// ParseDerivationPath parses a BIP-32/BIP-44 path into child index uint32 values.
// Supports "'" or "h" or "H" for hardened segments, and optional leading "m/" or "m".
func ParseDerivationPath(path string) ([]uint32, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" || trimmed == "m" || trimmed == "M" {
		return nil, nil
	}
	parts := strings.Split(trimmed, "/")
	if parts[0] == "m" || parts[0] == "M" {
		parts = parts[1:]
	}
	indices := make([]uint32, 0, len(parts))
	for _, seg := range parts {
		if seg == "" {
			return nil, fmt.Errorf("empty segment in derivation path %q", path)
		}
		hardened := false
		if strings.HasSuffix(seg, "'") || strings.HasSuffix(seg, "h") || strings.HasSuffix(seg, "H") {
			hardened = true
			seg = seg[:len(seg)-1]
		}
		val, err := strconv.ParseUint(seg, 10, 31)
		if err != nil {
			return nil, fmt.Errorf("invalid derivation path segment %q in %q: %w", seg, path, err)
		}
		idx := uint32(val)
		if hardened {
			idx |= HardenedOffset
		}
		indices = append(indices, idx)
	}
	return indices, nil
}
