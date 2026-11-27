package payload

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Payload is the minimal interface implemented by all XYO Protocol 2.0 payloads.
type Payload interface {
	GetSchema() string
}

// BasePayload provides the required "schema" field for typed payload structs.
type BasePayload struct {
	Schema string `json:"schema"`
}

// NewBasePayload constructs a BasePayload with a lowercased schema name.
func NewBasePayload(schema string) BasePayload {
	return BasePayload{Schema: strings.ToLower(strings.TrimSpace(schema))}
}

// GetSchema returns the payload's schema string.
func (p BasePayload) GetSchema() string {
	return p.Schema
}

// AnyPayload is a dynamic payload backed by a JSON object map, useful for arbitrary
// payloads, query responses, and payloads containing custom/meta fields.
type AnyPayload map[string]any

// NewAnyPayload creates an AnyPayload with the given lowercased schema and optional initial fields.
func NewAnyPayload(schema string, fields map[string]any) AnyPayload {
	p := make(AnyPayload, len(fields)+1)
	for k, v := range fields {
		p[k] = v
	}
	p["schema"] = strings.ToLower(strings.TrimSpace(schema))
	return p
}

// GetSchema returns the "schema" field from the payload map.
func (p AnyPayload) GetSchema() string {
	if v, ok := p["schema"].(string); ok {
		return v
	}
	return ""
}

// Hash computes the root hash of this payload (excluding top-level "_" storage meta).
func (p AnyPayload) Hash() (string, error) {
	return Hash(map[string]any(p))
}

// DataHash computes the dataHash of this payload (excluding top-level "_" and "$" meta).
func (p AnyPayload) DataHash() (string, error) {
	return DataHash(map[string]any(p))
}

// String returns the string value at key if present and of type string.
func (p AnyPayload) String(key string) (string, bool) {
	v, ok := p[key].(string)
	return v, ok
}

// Int64 returns the int64 value at key if present and numeric.
func (p AnyPayload) Int64(key string) (int64, bool) {
	switch v := p[key].(type) {
	case int:
		return int64(v), true
	case int64:
		return v, true
	case float64:
		return int64(v), true
	case json.Number:
		iv, err := v.Int64()
		return iv, err == nil
	default:
		return 0, false
	}
}

// Bool returns the bool value at key if present and of type bool.
func (p AnyPayload) Bool(key string) (bool, bool) {
	v, ok := p[key].(bool)
	return v, ok
}

// DecodeInto decodes this AnyPayload into a typed Go struct pointer.
func (p AnyPayload) DecodeInto(dst any) error {
	raw, err := json.Marshal(map[string]any(p))
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, dst)
}

// ToAnyPayload converts any Payload or JSON-serializable object into an AnyPayload.
func ToAnyPayload(v any) (AnyPayload, error) {
	if ap, ok := v.(AnyPayload); ok {
		cp := make(AnyPayload, len(ap))
		for k, val := range ap {
			cp[k] = val
		}
		return cp, nil
	}
	if m, ok := v.(map[string]any); ok {
		cp := make(AnyPayload, len(m))
		for k, val := range m {
			cp[k] = val
		}
		return cp, nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	norm, err := decodeGenericJSON(raw)
	if err != nil {
		return nil, err
	}
	m, ok := norm.(map[string]any)
	if !ok {
		return nil, errors.New("payload must serialize to a JSON object")
	}
	return AnyPayload(m), nil
}

// PayloadBuilder constructs dynamic AnyPayload values and provides payload meta/hashing utilities.
type PayloadBuilder struct {
	schema string
	fields map[string]any
}

// NewBuilder creates a PayloadBuilder for the given schema.
func NewBuilder(schema string) *PayloadBuilder {
	return &PayloadBuilder{
		schema: strings.ToLower(strings.TrimSpace(schema)),
		fields: make(map[string]any),
	}
}

// Field sets a single key/value pair on the payload.
func (b *PayloadBuilder) Field(key string, value any) *PayloadBuilder {
	b.fields[key] = value
	return b
}

// Fields merges a map of fields into the payload.
func (b *PayloadBuilder) Fields(fields map[string]any) *PayloadBuilder {
	for k, v := range fields {
		b.fields[k] = v
	}
	return b
}

// Build constructs the AnyPayload, validating that schema is set.
func (b *PayloadBuilder) Build() (AnyPayload, error) {
	if b.schema == "" {
		return nil, errors.New("payload schema is required")
	}
	return NewAnyPayload(b.schema, b.fields), nil
}

// BuildWithHashMeta builds the payload and attaches _hash and _dataHash storage metadata.
func (b *PayloadBuilder) BuildWithHashMeta() (AnyPayload, error) {
	p, err := b.Build()
	if err != nil {
		return nil, err
	}
	return AddHashMeta(p)
}

// AddHashMeta returns a copy of p with _hash and _dataHash storage metadata populated.
func AddHashMeta(p any) (AnyPayload, error) {
	ap, err := ToAnyPayload(p)
	if err != nil {
		return nil, err
	}
	h, err := Hash(ap)
	if err != nil {
		return nil, err
	}
	dh, err := DataHash(ap)
	if err != nil {
		return nil, err
	}
	ap["_hash"] = h
	ap["_dataHash"] = dh
	return ap, nil
}

// OmitStorageMeta returns a shallow copy of p with top-level "_" keys removed.
func OmitStorageMeta(p AnyPayload) AnyPayload {
	out := make(AnyPayload, len(p))
	for k, v := range p {
		if !strings.HasPrefix(k, "_") {
			out[k] = v
		}
	}
	return out
}

// OmitClientMeta returns a shallow copy of p with top-level "$" keys removed.
func OmitClientMeta(p AnyPayload) AnyPayload {
	out := make(AnyPayload, len(p))
	for k, v := range p {
		if !strings.HasPrefix(k, "$") {
			out[k] = v
		}
	}
	return out
}

// OmitMeta returns a shallow copy of p with both top-level "_" and "$" keys removed.
func OmitMeta(p AnyPayload) AnyPayload {
	out := make(AnyPayload, len(p))
	for k, v := range p {
		if !strings.HasPrefix(k, "_") && !strings.HasPrefix(k, "$") {
			out[k] = v
		}
	}
	return out
}

// Hashes computes root hashes for a slice of payloads.
func Hashes[T any](payloads []T) ([]string, error) {
	out := make([]string, len(payloads))
	for i, p := range payloads {
		h, err := Hash(p)
		if err != nil {
			return nil, fmt.Errorf("hash payload[%d]: %w", i, err)
		}
		out[i] = h
	}
	return out, nil
}

// QueryFields represents optional query economics/routing fields shared by XYO query payloads.
type QueryFields struct {
	Address      string `json:"address,omitempty"`
	Budget       *int64 `json:"budget,omitempty"`
	MaxFrequency string `json:"maxFrequency,omitempty"`
	MinBid       *int64 `json:"minBid,omitempty"`
}

// HashPair associates a payload with its computed hash (root hash or dataHash).
type HashPair[T any] struct {
	Payload T
	Hash    string
}

// HashPairs returns (payload, rootHash) pairs for a slice of payloads.
func HashPairs[T any](payloads []T) ([]HashPair[T], error) {
	out := make([]HashPair[T], len(payloads))
	for i, p := range payloads {
		h, err := Hash(p)
		if err != nil {
			return nil, fmt.Errorf("hash payload[%d]: %w", i, err)
		}
		out[i] = HashPair[T]{Payload: p, Hash: h}
	}
	return out, nil
}

// DataHashPairs returns (payload, dataHash) pairs for a slice of payloads.
func DataHashPairs[T any](payloads []T) ([]HashPair[T], error) {
	out := make([]HashPair[T], len(payloads))
	for i, p := range payloads {
		h, err := DataHash(p)
		if err != nil {
			return nil, fmt.Errorf("dataHash payload[%d]: %w", i, err)
		}
		out[i] = HashPair[T]{Payload: p, Hash: h}
	}
	return out, nil
}

// ToHashMap indexes payloads by their root hash.
func ToHashMap[T any](payloads []T) (map[string]T, error) {
	out := make(map[string]T, len(payloads))
	for i, p := range payloads {
		h, err := Hash(p)
		if err != nil {
			return nil, fmt.Errorf("hash payload[%d]: %w", i, err)
		}
		out[h] = p
	}
	return out, nil
}

// ToDataHashMap indexes payloads by their dataHash.
func ToDataHashMap[T any](payloads []T) (map[string]T, error) {
	out := make(map[string]T, len(payloads))
	for i, p := range payloads {
		h, err := DataHash(p)
		if err != nil {
			return nil, fmt.Errorf("dataHash payload[%d]: %w", i, err)
		}
		out[h] = p
	}
	return out, nil
}

// FilterExcludeByHash returns payloads whose root hash is NOT in excludeHashes.
func FilterExcludeByHash[T any](payloads []T, excludeHashes []string) ([]T, error) {
	set := make(map[string]struct{}, len(excludeHashes))
	for _, h := range excludeHashes {
		set[strings.ToLower(h)] = struct{}{}
	}
	var out []T
	for i, p := range payloads {
		h, err := Hash(p)
		if err != nil {
			return nil, fmt.Errorf("hash payload[%d]: %w", i, err)
		}
		if _, found := set[h]; !found {
			out = append(out, p)
		}
	}
	return out, nil
}

// FilterExcludeByDataHash returns payloads whose dataHash is NOT in excludeHashes.
func FilterExcludeByDataHash[T any](payloads []T, excludeHashes []string) ([]T, error) {
	set := make(map[string]struct{}, len(excludeHashes))
	for _, h := range excludeHashes {
		set[strings.ToLower(h)] = struct{}{}
	}
	var out []T
	for i, p := range payloads {
		h, err := DataHash(p)
		if err != nil {
			return nil, fmt.Errorf("dataHash payload[%d]: %w", i, err)
		}
		if _, found := set[h]; !found {
			out = append(out, p)
		}
	}
	return out, nil
}

// FilterIncludeByHash returns payloads whose root hash IS in includeHashes.
func FilterIncludeByHash[T any](payloads []T, includeHashes []string) ([]T, error) {
	set := make(map[string]struct{}, len(includeHashes))
	for _, h := range includeHashes {
		set[strings.ToLower(h)] = struct{}{}
	}
	var out []T
	for i, p := range payloads {
		h, err := Hash(p)
		if err != nil {
			return nil, fmt.Errorf("hash payload[%d]: %w", i, err)
		}
		if _, found := set[h]; found {
			out = append(out, p)
		}
	}
	return out, nil
}

// FilterIncludeByDataHash returns payloads whose dataHash IS in includeHashes.
func FilterIncludeByDataHash[T any](payloads []T, includeHashes []string) ([]T, error) {
	set := make(map[string]struct{}, len(includeHashes))
	for _, h := range includeHashes {
		set[strings.ToLower(h)] = struct{}{}
	}
	var out []T
	for i, p := range payloads {
		h, err := DataHash(p)
		if err != nil {
			return nil, fmt.Errorf("dataHash payload[%d]: %w", i, err)
		}
		if _, found := set[h]; found {
			out = append(out, p)
		}
	}
	return out, nil
}

// FindByHash finds the first payload whose root hash matches targetHash.
func FindByHash[T any](payloads []T, targetHash string) (T, bool, error) {
	target := strings.ToLower(targetHash)
	for i, p := range payloads {
		h, err := Hash(p)
		if err != nil {
			var zero T
			return zero, false, fmt.Errorf("hash payload[%d]: %w", i, err)
		}
		if h == target {
			return p, true, nil
		}
	}
	var zero T
	return zero, false, nil
}

// FindByDataHash finds the first payload whose dataHash matches targetHash.
func FindByDataHash[T any](payloads []T, targetHash string) (T, bool, error) {
	target := strings.ToLower(targetHash)
	for i, p := range payloads {
		h, err := DataHash(p)
		if err != nil {
			var zero T
			return zero, false, fmt.Errorf("dataHash payload[%d]: %w", i, err)
		}
		if h == target {
			return p, true, nil
		}
	}
	var zero T
	return zero, false, nil
}

// DataHashes computes dataHashes for a slice of payloads.
func DataHashes[T any](payloads []T) ([]string, error) {
	out := make([]string, len(payloads))
	for i, p := range payloads {
		h, err := DataHash(p)
		if err != nil {
			return nil, fmt.Errorf("dataHash payload[%d]: %w", i, err)
		}
		out[i] = h
	}
	return out, nil
}
