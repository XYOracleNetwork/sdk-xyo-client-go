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
