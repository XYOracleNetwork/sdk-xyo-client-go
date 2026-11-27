package payload

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Huri represents a Hash Uniform Resource Identifier (HURI), pointing to an XYO payload by hash
// with optional protocol, host/domain, and archivist path.
type Huri struct {
	Protocol string
	Host     string
	Path     string
	Hash     string
}

// ParseHuri parses a HURI string such as:
//   - "<64-char-hash>"
//   - "https://api.archivist.xyo.network/Archivist/<64-char-hash>"
//   - "xyo://api.archivist.xyo.network/<64-char-hash>"
func ParseHuri(raw string) (*Huri, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("HURI cannot be empty")
	}

	// Bare 64-char hex hash
	if !strings.Contains(trimmed, "://") && !strings.Contains(trimmed, "/") {
		h := strings.ToLower(trimmed)
		if len(h) != 64 || !isHexLower(h) {
			return nil, fmt.Errorf("invalid bare HURI hash: %q", trimmed)
		}
		return &Huri{Hash: h}, nil
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("parse HURI %q: %w", raw, err)
	}
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segments) == 0 || segments[len(segments)-1] == "" {
		return nil, fmt.Errorf("HURI %q missing hash segment", raw)
	}
	hashPart := strings.ToLower(segments[len(segments)-1])
	if len(hashPart) != 64 || !isHexLower(hashPart) {
		return nil, fmt.Errorf("HURI %q hash segment must be 64 hex chars, got %q", raw, hashPart)
	}
	var pathPart string
	if len(segments) > 1 {
		pathPart = strings.Join(segments[:len(segments)-1], "/")
	}
	return &Huri{
		Protocol: u.Scheme,
		Host:     u.Host,
		Path:     pathPart,
		Hash:     hashPart,
	}, nil
}

// String formats the Huri back to its URI string representation.
func (h *Huri) String() string {
	if h == nil {
		return ""
	}
	if h.Host == "" {
		return h.Hash
	}
	proto := h.Protocol
	if proto == "" {
		proto = "https"
	}
	if h.Path != "" {
		return fmt.Sprintf("%s://%s/%s/%s", proto, h.Host, strings.Trim(h.Path, "/"), h.Hash)
	}
	return fmt.Sprintf("%s://%s/%s", proto, h.Host, h.Hash)
}
