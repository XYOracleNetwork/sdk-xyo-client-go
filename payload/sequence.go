package payload

import (
	"fmt"
	"strings"
)

const (
	// LocalSequenceHexLength is 32 lowercase hex chars (16 bytes: 8B epoch + 4B index + 4B hash tail).
	LocalSequenceHexLength = 32
	// QualifiedSequenceHexLength is 72 lowercase hex chars (36 bytes: 16B local + 20B address).
	QualifiedSequenceHexLength = 72
)

// LocalSequence constructs a 32-character lowercase hex LocalSequence:
// [epochMs: 16 hex chars][index: 8 hex chars][last 4 bytes of hashHex: 8 hex chars].
func LocalSequence(epochMs uint64, index uint32, hashHex string) (string, error) {
	clean := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(hashHex), "0x"), "0X"))
	if len(clean) < 8 || !isHexLower(clean) {
		return "", fmt.Errorf("hash must be at least 8 valid hex chars for sequence, got %q", hashHex)
	}
	nonce := clean[len(clean)-8:]
	return fmt.Sprintf("%016x%08x%s", epochMs, index, nonce), nil
}

// QualifiedSequence constructs a 72-character lowercase hex QualifiedSequence:
// [LocalSequence: 32 hex chars][addressHex: 40 hex chars].
func QualifiedSequence(epochMs uint64, index uint32, hashHex, addressHex string) (string, error) {
	local, err := LocalSequence(epochMs, index, hashHex)
	if err != nil {
		return "", err
	}
	addr := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(addressHex), "0x"), "0X"))
	if len(addr) != 40 || !isHexLower(addr) {
		return "", fmt.Errorf("address must be 40 valid hex chars for qualified sequence, got %q", addressHex)
	}
	return local + addr, nil
}

// CompareSequence performs lexicographical comparison of two sequence strings, returning -1, 0, or +1.
func CompareSequence(a, b string) int {
	return strings.Compare(strings.ToLower(a), strings.ToLower(b))
}

// IsValidLocalSequence reports whether s is a valid 32-char lowercase hex LocalSequence.
func IsValidLocalSequence(s string) bool {
	return len(s) == LocalSequenceHexLength && isHexLower(s)
}

// IsValidQualifiedSequence reports whether s is a valid 72-char lowercase hex QualifiedSequence.
func IsValidQualifiedSequence(s string) bool {
	return len(s) == QualifiedSequenceHexLength && isHexLower(s)
}

func isHexLower(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
