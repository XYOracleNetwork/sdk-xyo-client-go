package payload

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// MetaExclusion controls which top-level (depth == 0) metadata prefixes are stripped
// during XYO canonical JSON serialization.
type MetaExclusion int

const (
	// MetaExclusionNone retains all keys at all depths.
	MetaExclusionNone MetaExclusion = iota
	// MetaExclusionStorageMeta strips top-level "_" keys (storage metadata) and retains "$" keys (client metadata).
	// Used by PayloadBuilder.hash() / root hash.
	MetaExclusionStorageMeta
	// MetaExclusionAllMeta strips both top-level "_" and "$" keys.
	// Used by PayloadBuilder.dataHash() and BoundWitness signing.
	MetaExclusionAllMeta
)

// CanonicalJSON serializes any JSON-compatible Go value into XYO Protocol 2.0 canonical JSON bytes:
//   - Top-level meta fields are excluded per excl (nested "_" and "$" keys are preserved).
//   - All object keys at every depth (including inside arrays) are sorted in UTF-16 code-unit order.
//   - Explicit null values are preserved everywhere.
//   - Strings are emitted as raw UTF-8 without HTML escaping (<, >, & are not escaped).
//   - Compact output with no insignificant whitespace.
func CanonicalJSON(v any, excl MetaExclusion) ([]byte, error) {
	norm, err := toGenericJSONValue(v)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, norm, 0, excl); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// SHA256Bytes computes the 32-byte SHA-256 digest of the canonical JSON serialization of v.
func SHA256Bytes(v any, excl MetaExclusion) ([]byte, error) {
	canon, err := CanonicalJSON(v, excl)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canon)
	return sum[:], nil
}

// SHA256Hex computes the 64-char lowercase hex SHA-256 digest of the canonical JSON of v.
func SHA256Hex(v any, excl MetaExclusion) (string, error) {
	sum, err := SHA256Bytes(v, excl)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sum), nil
}

// Hash computes the XYO root hash (stripping top-level "_" storage meta, keeping "$" client meta).
func Hash(v any) (string, error) {
	return SHA256Hex(v, MetaExclusionStorageMeta)
}

// HashBytes computes the 32-byte XYO root hash.
func HashBytes(v any) ([]byte, error) {
	return SHA256Bytes(v, MetaExclusionStorageMeta)
}

// DataHash computes the XYO dataHash (stripping both top-level "_" and "$" meta fields).
func DataHash(v any) (string, error) {
	return SHA256Hex(v, MetaExclusionAllMeta)
}

// DataHashBytes computes the 32-byte XYO dataHash.
func DataHashBytes(v any) ([]byte, error) {
	return SHA256Bytes(v, MetaExclusionAllMeta)
}

func toGenericJSONValue(v any) (any, error) {
	switch val := v.(type) {
	case nil:
		return nil, nil
	case json.RawMessage:
		return decodeGenericJSON(val)
	case []byte:
		return decodeGenericJSON(val)
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("marshal for canonicalization: %w", err)
		}
		return decodeGenericJSON(raw)
	}
}

func decodeGenericJSON(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("decode for canonicalization: %w", err)
	}
	return out, nil
}

func shouldExcludeKey(key string, depth int, excl MetaExclusion) bool {
	if depth != 0 {
		return false
	}
	switch excl {
	case MetaExclusionStorageMeta:
		return strings.HasPrefix(key, "_")
	case MetaExclusionAllMeta:
		return strings.HasPrefix(key, "_") || strings.HasPrefix(key, "$")
	default:
		return false
	}
}

func writeCanonical(buf *bytes.Buffer, v any, depth int, excl MetaExclusion) error {
	switch val := v.(type) {
	case nil:
		buf.WriteString("null")
		return nil
	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil
	case string:
		writeJSONString(buf, val)
		return nil
	case json.Number:
		return writeCanonicalNumber(buf, val)
	case float64:
		return writeCanonicalFloat(buf, val)
	case int:
		buf.WriteString(strconv.Itoa(val))
		return nil
	case int64:
		buf.WriteString(strconv.FormatInt(val, 10))
		return nil
	case uint64:
		buf.WriteString(strconv.FormatUint(val, 10))
		return nil
	case []any:
		buf.WriteByte('[')
		for i, item := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item, depth+1, excl); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			if shouldExcludeKey(k, depth, excl) {
				continue
			}
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			return compareUTF16(keys[i], keys[j]) < 0
		})
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeJSONString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonical(buf, val[k], depth+1, excl); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	default:
		return fmt.Errorf("unsupported canonical JSON value type %T", v)
	}
}

func writeCanonicalNumber(buf *bytes.Buffer, n json.Number) error {
	s := n.String()
	// Exact integer path (preserves int64 precision beyond 2^53 if present)
	if !strings.ContainsAny(s, ".eE") {
		if iv, err := strconv.ParseInt(s, 10, 64); err == nil {
			buf.WriteString(strconv.FormatInt(iv, 10))
			return nil
		}
		if uv, err := strconv.ParseUint(s, 10, 64); err == nil {
			buf.WriteString(strconv.FormatUint(uv, 10))
			return nil
		}
	}
	fv, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("invalid JSON number %q: %w", s, err)
	}
	return writeCanonicalFloat(buf, fv)
}

func writeCanonicalFloat(buf *bytes.Buffer, f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return errors.New("NaN and Inf are not valid JSON numbers")
	}
	if f == 0 {
		buf.WriteByte('0')
		return nil
	}
	// Whole numbers strictly within int64 range [-2^63, 2^63) format as plain integers (no .0).
	// Note: float64(math.MaxInt64) rounds up to 2^63 (9223372036854775808.0), so strict '<' avoids int64 overflow.
	if math.Trunc(f) == f && f >= -9223372036854775808.0 && f < 9223372036854775808.0 {
		buf.WriteString(strconv.FormatInt(int64(f), 10))
		return nil
	}
	// Shortest IEEE-754 representation matching ECMAScript Number::toString
	buf.WriteString(formatJSFloat(f))
	return nil
}

// formatJSFloat formats a finite non-zero float64 to match JavaScript JSON.stringify output.
func formatJSFloat(f float64) string {
	abs := math.Abs(f)
	if abs >= 1e-6 && abs < 1e21 {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	s := strconv.FormatFloat(f, 'e', -1, 64)
	// Go formats exponents like e+05 or e-07; JS strips leading zero in 2-digit exponents (e+5 / e-7).
	if idx := strings.IndexByte(s, 'e'); idx != -1 && idx+2 < len(s) {
		sign := s[idx+1]
		exp := strings.TrimLeft(s[idx+2:], "0")
		if exp == "" {
			exp = "0"
		}
		return s[:idx+1] + string(sign) + exp
	}
	return s
}

func writeJSONString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r >= 0 && r < 0x20 {
				buf.WriteString(fmt.Sprintf(`\u%04x`, r))
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// compareUTF16 compares two UTF-8 strings in UTF-16 code unit order (matching JS Array.prototype.sort).
func compareUTF16(a, b string) int {
	// Fast path: if both strings are pure ASCII / BMP without surrogates, UTF-8 byte order matches UTF-16
	// for code points <= 0xFFFF EXCEPT between 0xE000..0xFFFF and >0xFFFF.
	if isASCII(a) && isASCII(b) {
		return strings.Compare(a, b)
	}
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	n := len(ua)
	if len(ub) < n {
		n = len(ub)
	}
	for i := 0; i < n; i++ {
		if ua[i] != ub[i] {
			if ua[i] < ub[i] {
				return -1
			}
			return 1
		}
	}
	if len(ua) < len(ub) {
		return -1
	}
	if len(ua) > len(ub) {
		return 1
	}
	return 0
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
