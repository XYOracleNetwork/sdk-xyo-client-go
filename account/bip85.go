package account

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"strings"
)

const (
	// Bip85Purpose is the BIP-85 purpose index (83696968').
	Bip85Purpose uint32 = 83696968
	// Bip85HexApp is the BIP-85 Hex application index (128169').
	Bip85HexApp uint32 = 128169
	// Bip85HmacKey is the constant HMAC-SHA512 key defined by BIP-85.
	Bip85HmacKey = "bip-entropy-from-k"
	// Bip85SeedBytes is the 32-byte entropy length used for ML-DSA-65 seeds.
	Bip85SeedBytes = 32
	// Bip85DefaultQuantLeafPath is the default BIP-85 leaf tail appended to non-BIP-85 paths.
	Bip85DefaultQuantLeafPath = "83696968'/128169'/32'/0'"
	// Bip85DefaultQuantPath is the default full BIP-85 derivation path for ML-DSA-65 accounts.
	Bip85DefaultQuantPath = "m/83696968'/128169'/32'/0'"
)

// Bip85EntropyFromKey derives BIP-85 entropy of length numBytes (1..64) from a 32-byte private key:
// HMAC-SHA512(key="bip-entropy-from-k", msg=privateKey)[:numBytes].
func Bip85EntropyFromKey(privateKey []byte, numBytes int) ([]byte, error) {
	if len(privateKey) != PrivateKeySize {
		return nil, fmt.Errorf("BIP-85 private key must be %d bytes, got %d", PrivateKeySize, len(privateKey))
	}
	if numBytes < 1 || numBytes > 64 {
		return nil, fmt.Errorf("BIP-85 entropy length must be 1..64, got %d", numBytes)
	}
	mac := hmac.New(sha512.New, []byte(Bip85HmacKey))
	mac.Write(privateKey)
	sum := mac.Sum(nil)
	out := make([]byte, numBytes)
	copy(out, sum[:numBytes])
	return out, nil
}

// Bip85DeriveEntropy derives a BIP-32 path from master and applies BIP-85 HMAC-SHA512 extraction.
func Bip85DeriveEntropy(master *ExtendedKey, path string, numBytes int) ([]byte, error) {
	derived, err := master.DerivePath(path)
	if err != nil {
		return nil, err
	}
	return Bip85EntropyFromKey(derived.Key, numBytes)
}

// Bip85DefaultLeafTail returns the BIP-85 hex-entropy leaf tail for the given hardened index:
// "83696968'/128169'/32'/<index>'".
func Bip85DefaultLeafTail(index uint32) string {
	return fmt.Sprintf("%d'/%d'/%d'/%d'", Bip85Purpose, Bip85HexApp, Bip85SeedBytes, index)
}

// IsBip85AbsolutePath reports whether path is an absolute BIP-85 path starting with "m/83696968'" (or h/H).
func IsBip85AbsolutePath(path string) bool {
	clean := strings.TrimSpace(path)
	if !strings.HasPrefix(clean, "m/") && !strings.HasPrefix(clean, "M/") {
		return false
	}
	rest := clean[2:]
	return strings.HasPrefix(rest, "83696968'") ||
		strings.HasPrefix(rest, "83696968h") ||
		strings.HasPrefix(rest, "83696968H")
}

// IsUnderBip85Purpose reports whether path (absolute or relative) is under the BIP-85 purpose 83696968'.
func IsUnderBip85Purpose(path string) bool {
	clean := strings.TrimSpace(path)
	clean = strings.TrimPrefix(clean, "m/")
	clean = strings.TrimPrefix(clean, "M/")
	return strings.HasPrefix(clean, "83696968'") ||
		strings.HasPrefix(clean, "83696968h") ||
		strings.HasPrefix(clean, "83696968H")
}

func isBip85Path(path string) bool {
	return IsUnderBip85Purpose(path)
}
