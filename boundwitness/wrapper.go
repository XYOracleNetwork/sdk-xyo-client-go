package boundwitness

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/XYOracleNetwork/sdk-xyo-client-go/account"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/payload"
)

// BoundWitnessWrapper wraps a BoundWitness with its accompanying payloads and module errors,
// providing lookup maps, missing payload detection, chain traversal, and validation.
type BoundWitnessWrapper struct {
	BoundWitness *BoundWitness
	Payloads     []payload.AnyPayload
	Errors       []payload.ModuleErrorPayload

	hashMap     map[string]payload.AnyPayload
	dataHashMap map[string]payload.AnyPayload
}

// Wrap constructs a BoundWitnessWrapper from a BoundWitness and accompanying payloads.
func Wrap(bw *BoundWitness, payloads []any, errs ...payload.ModuleErrorPayload) (*BoundWitnessWrapper, error) {
	if bw == nil {
		return nil, errors.New("bound witness is nil")
	}
	converted := make([]payload.AnyPayload, 0, len(payloads))
	for _, p := range payloads {
		ap, err := payload.ToAnyPayload(p)
		if err != nil {
			return nil, err
		}
		converted = append(converted, ap)
	}
	return &BoundWitnessWrapper{
		BoundWitness: bw,
		Payloads:     converted,
		Errors:       errs,
	}, nil
}

// ParseTuple parses a JSON wire tuple [boundWitness, payloads] or [boundWitness, payloads, errors].
func ParseTuple(raw []byte) (*BoundWitnessWrapper, error) {
	var tuple []json.RawMessage
	if err := json.Unmarshal(raw, &tuple); err != nil {
		return nil, err
	}
	if len(tuple) < 2 {
		return nil, errors.New("bound witness tuple must have at least 2 elements")
	}
	var bw BoundWitness
	if err := json.Unmarshal(tuple[0], &bw); err != nil {
		return nil, err
	}
	var payloads []payload.AnyPayload
	if len(tuple[1]) > 0 && string(tuple[1]) != "null" {
		if err := json.Unmarshal(tuple[1], &payloads); err != nil {
			return nil, err
		}
	}
	var modErrs []payload.ModuleErrorPayload
	if len(tuple) >= 3 && len(tuple[2]) > 0 && string(tuple[2]) != "null" {
		if err := json.Unmarshal(tuple[2], &modErrs); err != nil {
			return nil, fmt.Errorf("unmarshal tuple errors: %w", err)
		}
	}
	return &BoundWitnessWrapper{
		BoundWitness: &bw,
		Payloads:     payloads,
		Errors:       modErrs,
	}, nil
}

// Hash computes the root hash of the wrapped BoundWitness.
func (w *BoundWitnessWrapper) Hash() (string, error) {
	return w.BoundWitness.Hash()
}

// DataHash computes the dataHash of the wrapped BoundWitness.
func (w *BoundWitnessWrapper) DataHash() (string, error) {
	return w.BoundWitness.DataHash()
}

// PayloadsHashMap returns a map from payload root hash to AnyPayload.
func (w *BoundWitnessWrapper) PayloadsHashMap() (map[string]payload.AnyPayload, error) {
	if w.hashMap != nil {
		return w.hashMap, nil
	}
	m := make(map[string]payload.AnyPayload, len(w.Payloads))
	for _, p := range w.Payloads {
		h, err := p.Hash()
		if err != nil {
			return nil, err
		}
		m[h] = p
	}
	w.hashMap = m
	return m, nil
}

// PayloadsDataHashMap returns a map from payload dataHash to AnyPayload.
func (w *BoundWitnessWrapper) PayloadsDataHashMap() (map[string]payload.AnyPayload, error) {
	if w.dataHashMap != nil {
		return w.dataHashMap, nil
	}
	m := make(map[string]payload.AnyPayload, len(w.Payloads))
	for _, p := range w.Payloads {
		dh, err := p.DataHash()
		if err != nil {
			return nil, err
		}
		m[dh] = p
	}
	w.dataHashMap = m
	return m, nil
}

// MissingPayloads returns all hashes listed in payload_hashes that are not matched by any payload
// in w.Payloads (checking both root hash and dataHash).
func (w *BoundWitnessWrapper) MissingPayloads() ([]string, error) {
	hm, err := w.PayloadsHashMap()
	if err != nil {
		return nil, err
	}
	dhm, err := w.PayloadsDataHashMap()
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, h := range w.BoundWitness.PayloadHashes {
		if _, ok := hm[h]; ok {
			continue
		}
		if _, ok := dhm[h]; ok {
			continue
		}
		missing = append(missing, h)
	}
	return missing, nil
}

// HashesBySchema returns all payload_hashes whose parallel payload_schemas entry matches schema.
func (w *BoundWitnessWrapper) HashesBySchema(schema string) []string {
	var out []string
	for i, s := range w.BoundWitness.PayloadSchemas {
		if s == schema && i < len(w.BoundWitness.PayloadHashes) {
			out = append(out, w.BoundWitness.PayloadHashes[i])
		}
	}
	return out
}

// PayloadsBySchema returns all accompanying payloads matching schema.
func (w *BoundWitnessWrapper) PayloadsBySchema(schema string) []payload.AnyPayload {
	var out []payload.AnyPayload
	for _, p := range w.Payloads {
		if p.GetSchema() == schema {
			out = append(out, p)
		}
	}
	return out
}

// PayloadsByHashes returns accompanying payloads matching any of the given root hashes (in request order).
func (w *BoundWitnessWrapper) PayloadsByHashes(hashes []string) ([]payload.AnyPayload, error) {
	hm, err := w.PayloadsHashMap()
	if err != nil {
		return nil, err
	}
	var out []payload.AnyPayload
	for _, h := range hashes {
		if p, ok := hm[strings.ToLower(account.StripHexPrefix(h))]; ok {
			out = append(out, p)
		}
	}
	return out, nil
}

// PayloadsByDataHashes returns accompanying payloads matching any of the given dataHashes (in request order).
func (w *BoundWitnessWrapper) PayloadsByDataHashes(dataHashes []string) ([]payload.AnyPayload, error) {
	dhm, err := w.PayloadsDataHashMap()
	if err != nil {
		return nil, err
	}
	var out []payload.AnyPayload
	for _, h := range dataHashes {
		if p, ok := dhm[strings.ToLower(account.StripHexPrefix(h))]; ok {
			out = append(out, p)
		}
	}
	return out, nil
}

// WrappedPayloads wraps each accompanying payload in a payload.PayloadWrapper.
func (w *BoundWitnessWrapper) WrappedPayloads() ([]*payload.PayloadWrapper, error) {
	out := make([]*payload.PayloadWrapper, 0, len(w.Payloads))
	for _, p := range w.Payloads {
		pw, err := payload.Wrap(p)
		if err != nil {
			return nil, err
		}
		out = append(out, pw)
	}
	return out, nil
}

// Prev returns the previous_hash recorded for address in this BoundWitness, or nil if absent/genesis.
func (w *BoundWitnessWrapper) Prev(address string) *string {
	return w.PreviousHashForAddress(address)
}

// PreviousHashForAddress returns the previous_hash recorded for address (normalized), or nil if absent/genesis.
func (w *BoundWitnessWrapper) PreviousHashForAddress(address string) *string {
	target, err := account.NormalizeAddress(address)
	if err != nil {
		target = strings.ToLower(account.StripHexPrefix(address))
	}
	for i, a := range w.BoundWitness.Addresses {
		norm, normErr := account.NormalizeAddress(a)
		if normErr != nil {
			norm = strings.ToLower(account.StripHexPrefix(a))
		}
		if norm == target && i < len(w.BoundWitness.PreviousHashes) {
			return w.BoundWitness.PreviousHashes[i]
		}
	}
	return nil
}

// ToResult returns the canonical 3-element tuple [boundWitness, payloads, errors] as a slice for wire encoding.
func (w *BoundWitnessWrapper) ToResult() []any {
	return []any{w.BoundWitness, w.Payloads, w.Errors}
}

// Dig extracts nested BoundWitnesses recursively up to the requested depth
// (depth <= 0 returns [w.BoundWitness]; depth 1 returns immediate nested BWs; depth > 1 traverses deeper).
func (w *BoundWitnessWrapper) Dig(depth int) []*BoundWitness {
	if depth <= 0 {
		return []*BoundWitness{w.BoundWitness}
	}
	hm, err := w.PayloadsHashMap()
	if err != nil {
		return nil
	}
	dhm, err := w.PayloadsDataHashMap()
	if err != nil {
		return nil
	}
	visited := make(map[string]struct{})
	if rootHash, err := w.Hash(); err == nil {
		visited[rootHash] = struct{}{}
	}
	var out []*BoundWitness
	var walk func(cur *BoundWitness, remaining int)
	walk = func(cur *BoundWitness, remaining int) {
		if remaining <= 0 || cur == nil {
			return
		}
		for i, schema := range cur.PayloadSchemas {
			if schema != SchemaBoundWitness || i >= len(cur.PayloadHashes) {
				continue
			}
			h := cur.PayloadHashes[i]
			p, ok := hm[h]
			if !ok {
				p, ok = dhm[h]
			}
			if !ok {
				continue
			}
			var nested BoundWitness
			if err := p.DecodeInto(&nested); err != nil {
				continue
			}
			if _, seen := visited[h]; seen {
				continue
			}
			visited[h] = struct{}{}
			out = append(out, &nested)
			if remaining > 1 {
				walk(&nested, remaining-1)
			}
		}
	}
	walk(w.BoundWitness, depth)
	return out
}

// Validate runs ValidateBoundWitness on the wrapped BoundWitness.
func (w *BoundWitnessWrapper) Validate() []error {
	return ValidateBoundWitness(w.BoundWitness)
}
