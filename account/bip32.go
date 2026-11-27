package account

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	// HardenedOffset is 2^31 (0x80000000) per BIP-32.
	HardenedOffset uint32 = 0x80000000

	// bip32MainnetPrivateVersion is the standard BIP-32 mainnet xprv version magic (0x0488ADE4).
	bip32MainnetPrivateVersion uint32 = 0x0488ADE4
)

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// ExtendedKey represents a BIP-32 extended private key (private key + 32-byte chain code).
type ExtendedKey struct {
	Key       []byte // 32-byte private key
	ChainCode []byte // 32-byte chain code
	Depth     uint8
	ChildNum  uint32
}

// Clone returns a deep copy of the ExtendedKey.
func (k *ExtendedKey) Clone() *ExtendedKey {
	if k == nil {
		return nil
	}
	return &ExtendedKey{
		Key:       append([]byte(nil), k.Key...),
		ChainCode: append([]byte(nil), k.ChainCode...),
		Depth:     k.Depth,
		ChildNum:  k.ChildNum,
	}
}

// ParseExtendedKey decodes a Base58Check-encoded BIP-32 extended private key (xprv...).
func ParseExtendedKey(encoded string) (*ExtendedKey, error) {
	raw, err := base58CheckDecode(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("decode extended key: %w", err)
	}
	if len(raw) != 78 {
		return nil, fmt.Errorf("invalid extended key payload length: got %d, want 78", len(raw))
	}
	// raw[0:4] is version, raw[4] is depth, raw[5:9] is parent fingerprint,
	// raw[9:13] is child number, raw[13:45] is chain code, raw[45] is 0x00 for private keys,
	// raw[46:78] is 32-byte private key.
	if raw[45] != 0x00 {
		return nil, errors.New("extended key is not a private key (expected 0x00 key prefix)")
	}
	depth := raw[4]
	childNum := binary.BigEndian.Uint32(raw[9:13])
	cc := make([]byte, 32)
	copy(cc, raw[13:45])
	key := make([]byte, 32)
	copy(key, raw[46:78])

	var scalar secp256k1.ModNScalar
	if overflow := scalar.SetByteSlice(key); overflow || scalar.IsZero() {
		return nil, errors.New("extended key contains invalid secp256k1 private scalar")
	}

	return &ExtendedKey{
		Key:       key,
		ChainCode: cc,
		Depth:     depth,
		ChildNum:  childNum,
	}, nil
}

// Serialize encodes the ExtendedKey as a Base58Check BIP-32 mainnet xprv string.
func (k *ExtendedKey) Serialize() string {
	buf := make([]byte, 78)
	binary.BigEndian.PutUint32(buf[0:4], bip32MainnetPrivateVersion)
	buf[4] = k.Depth
	// Parent fingerprint left zero when unknown
	binary.BigEndian.PutUint32(buf[9:13], k.ChildNum)
	copy(buf[13:45], k.ChainCode)
	buf[45] = 0x00
	copy(buf[46:78], k.Key)
	return base58CheckEncode(buf)
}

func base58CheckEncode(payload []byte) string {
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])
	full := make([]byte, len(payload)+4)
	copy(full, payload)
	copy(full[len(payload):], second[:4])

	num := new(big.Int).SetBytes(full)
	base := big.NewInt(58)
	mod := new(big.Int)
	var encoded []byte
	for num.Sign() > 0 {
		num.DivMod(num, base, mod)
		encoded = append(encoded, base58Alphabet[mod.Int64()])
	}
	for _, b := range full {
		if b != 0 {
			break
		}
		encoded = append(encoded, base58Alphabet[0])
	}
	for i, j := 0, len(encoded)-1; i < j; i, j = i+1, j-1 {
		encoded[i], encoded[j] = encoded[j], encoded[i]
	}
	return string(encoded)
}

func base58CheckDecode(s string) ([]byte, error) {
	if len(s) == 0 {
		return nil, errors.New("empty base58 string")
	}
	num := big.NewInt(0)
	base := big.NewInt(58)
	for i := 0; i < len(s); i++ {
		idx := strings.IndexByte(base58Alphabet, s[i])
		if idx < 0 {
			return nil, fmt.Errorf("invalid base58 character %q", s[i])
		}
		num.Mul(num, base)
		num.Add(num, big.NewInt(int64(idx)))
	}
	decoded := num.Bytes()
	leadingZeros := 0
	for leadingZeros < len(s) && s[leadingZeros] == base58Alphabet[0] {
		leadingZeros++
	}
	full := make([]byte, leadingZeros+len(decoded))
	copy(full[leadingZeros:], decoded)
	if len(full) < 4 {
		return nil, errors.New("base58check payload too short")
	}
	payload := full[:len(full)-4]
	checksum := full[len(full)-4:]
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])
	for i := 0; i < 4; i++ {
		if checksum[i] != second[i] {
			return nil, errors.New("invalid base58check checksum")
		}
	}
	return payload, nil
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
