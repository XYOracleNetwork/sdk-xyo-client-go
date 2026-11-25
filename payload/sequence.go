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
	if len(clean) < 8 {
		return "", fmt.Errorf("hash must be at least 8 hex chars for sequence, got %d", len(clean))
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
	if len(addr) != 40 {
		return "", fmt.Errorf("address must be 40 hex chars for qualified sequence, got %d", len(addr))
	}
	return local + addr, nil
}
