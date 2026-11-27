package boundwitness

import (
	"bytes"
	"encoding/json"

	"github.com/XYOracleNetwork/sdk-xyo-client-go/payload"
)

// SchemaBoundWitness is the canonical schema string for XYO BoundWitnesses.
const SchemaBoundWitness = payload.SchemaBoundWitness

// BoundWitness represents an XYO Protocol 2.0 BoundWitness.
// Core fields (addresses, payload_hashes, payload_schemas, previous_hashes, schema, optional timestamp)
// are included in dataHash and signed by all signers.
// Client metadata fields ($signatures, $destination, $sourceQuery, $version) are excluded from dataHash
// and included in the root hash.
// Unknown or custom JSON fields encountered during unmarshaling are preserved in Extra so cryptographic
// hashing and signature verification remain lossless across wire round-trips.
type BoundWitness struct {
	Addresses      []string  `json:"addresses"`
	PayloadHashes  []string  `json:"payload_hashes"`
	PayloadSchemas []string  `json:"payload_schemas"`
	PreviousHashes []*string `json:"previous_hashes"`
	Schema         string    `json:"schema"`
	Timestamp      *int64    `json:"timestamp,omitempty"`

	Signatures  []*string `json:"$signatures,omitempty"`
	Destination string    `json:"$destination,omitempty"`
	SourceQuery string    `json:"$sourceQuery,omitempty"`
	Version     *int      `json:"$version,omitempty"`

	Extra map[string]any `json:"-"`
}

type boundWitnessAlias BoundWitness

var knownBoundWitnessKeys = map[string]struct{}{
	"addresses":       {},
	"payload_hashes":  {},
	"payload_schemas": {},
	"previous_hashes": {},
	"schema":          {},
	"timestamp":       {},
	"$signatures":     {},
	"$destination":    {},
	"$sourceQuery":    {},
	"$version":        {},
}

// MarshalJSON serializes BoundWitness including any preserved Extra fields.
func (bw BoundWitness) MarshalJSON() ([]byte, error) {
	base, err := json.Marshal(boundWitnessAlias(bw))
	if err != nil {
		return nil, err
	}
	if len(bw.Extra) == 0 {
		return base, nil
	}
	return mergeExtraJSON(base, bw.Extra)
}

// UnmarshalJSON deserializes BoundWitness while preserving any unknown fields in Extra.
func (bw *BoundWitness) UnmarshalJSON(data []byte) error {
	var alias boundWitnessAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	extra, err := extractExtraFields(data, knownBoundWitnessKeys)
	if err != nil {
		return err
	}
	*bw = BoundWitness(alias)
	bw.Extra = extra
	return nil
}

// GetSchema implements payload.Payload.
func (bw *BoundWitness) GetSchema() string {
	if bw == nil {
		return ""
	}
	return bw.Schema
}

// Hash computes the root hash (stripping "_" storage meta, keeping "$" client meta).
func (bw *BoundWitness) Hash() (string, error) {
	return payload.Hash(bw)
}

// DataHash computes the signing dataHash (stripping both "_" and "$" meta fields).
func (bw *BoundWitness) DataHash() (string, error) {
	return payload.DataHash(bw)
}

// DataHashBytes computes the 32-byte signing dataHash.
func (bw *BoundWitness) DataHashBytes() ([]byte, error) {
	return payload.DataHashBytes(bw)
}

// IsSigned reports whether every address slot has a non-empty signature.
func (bw *BoundWitness) IsSigned() bool {
	if bw == nil || len(bw.Addresses) == 0 || len(bw.Signatures) != len(bw.Addresses) {
		return false
	}
	for _, s := range bw.Signatures {
		if s == nil || *s == "" {
			return false
		}
	}
	return true
}

// Clone returns a deep copy of the BoundWitness.
func (bw *BoundWitness) Clone() *BoundWitness {
	if bw == nil {
		return nil
	}
	cp := &BoundWitness{
		Addresses:      append([]string(nil), bw.Addresses...),
		PayloadHashes:  append([]string(nil), bw.PayloadHashes...),
		PayloadSchemas: append([]string(nil), bw.PayloadSchemas...),
		PreviousHashes: cloneStringPtrSlice(bw.PreviousHashes),
		Schema:         bw.Schema,
		Signatures:     cloneStringPtrSlice(bw.Signatures),
		Destination:    bw.Destination,
		SourceQuery:    bw.SourceQuery,
		Extra:          cloneExtraMap(bw.Extra),
	}
	if bw.Timestamp != nil {
		t := *bw.Timestamp
		cp.Timestamp = &t
	}
	if bw.Version != nil {
		v := *bw.Version
		cp.Version = &v
	}
	return cp
}

// QueryBoundWitness extends BoundWitness with the signed "query" hash and optional "error_hashes".
type QueryBoundWitness struct {
	BoundWitness
	Query       string   `json:"query"`
	ErrorHashes []string `json:"error_hashes,omitempty"`
}

var knownQueryBoundWitnessKeys = map[string]struct{}{
	"addresses":       {},
	"payload_hashes":  {},
	"payload_schemas": {},
	"previous_hashes": {},
	"schema":          {},
	"timestamp":       {},
	"$signatures":     {},
	"$destination":    {},
	"$sourceQuery":    {},
	"$version":        {},
	"query":           {},
	"error_hashes":    {},
}

// MarshalJSON serializes QueryBoundWitness including all BoundWitness fields, query/error_hashes, and Extra.
func (qbw QueryBoundWitness) MarshalJSON() ([]byte, error) {
	type qbwWire struct {
		Addresses      []string  `json:"addresses"`
		PayloadHashes  []string  `json:"payload_hashes"`
		PayloadSchemas []string  `json:"payload_schemas"`
		PreviousHashes []*string `json:"previous_hashes"`
		Schema         string    `json:"schema"`
		Timestamp      *int64    `json:"timestamp,omitempty"`
		Signatures     []*string `json:"$signatures,omitempty"`
		Destination    string    `json:"$destination,omitempty"`
		SourceQuery    string    `json:"$sourceQuery,omitempty"`
		Version        *int      `json:"$version,omitempty"`
		Query          string    `json:"query"`
		ErrorHashes    []string  `json:"error_hashes,omitempty"`
	}
	w := qbwWire{
		Addresses:      qbw.Addresses,
		PayloadHashes:  qbw.PayloadHashes,
		PayloadSchemas: qbw.PayloadSchemas,
		PreviousHashes: qbw.PreviousHashes,
		Schema:         qbw.Schema,
		Timestamp:      qbw.Timestamp,
		Signatures:     qbw.Signatures,
		Destination:    qbw.Destination,
		SourceQuery:    qbw.SourceQuery,
		Version:        qbw.Version,
		Query:          qbw.Query,
		ErrorHashes:    qbw.ErrorHashes,
	}
	base, err := json.Marshal(w)
	if err != nil {
		return nil, err
	}
	if len(qbw.Extra) == 0 {
		return base, nil
	}
	return mergeExtraJSON(base, qbw.Extra)
}

// UnmarshalJSON deserializes QueryBoundWitness while preserving unknown fields in Extra.
func (qbw *QueryBoundWitness) UnmarshalJSON(data []byte) error {
	var bwAlias boundWitnessAlias
	if err := json.Unmarshal(data, &bwAlias); err != nil {
		return err
	}
	var qFields struct {
		Query       string   `json:"query"`
		ErrorHashes []string `json:"error_hashes,omitempty"`
	}
	if err := json.Unmarshal(data, &qFields); err != nil {
		return err
	}
	extra, err := extractExtraFields(data, knownQueryBoundWitnessKeys)
	if err != nil {
		return err
	}
	qbw.BoundWitness = BoundWitness(bwAlias)
	qbw.Extra = extra
	qbw.Query = qFields.Query
	qbw.ErrorHashes = qFields.ErrorHashes
	return nil
}

// Clone returns a deep copy of the QueryBoundWitness.
func (qbw *QueryBoundWitness) Clone() *QueryBoundWitness {
	if qbw == nil {
		return nil
	}
	return &QueryBoundWitness{
		BoundWitness: *qbw.BoundWitness.Clone(),
		Query:        qbw.Query,
		ErrorHashes:  append([]string(nil), qbw.ErrorHashes...),
	}
}

// Hash computes the root hash of the QueryBoundWitness.
func (qbw *QueryBoundWitness) Hash() (string, error) {
	return payload.Hash(qbw)
}

// DataHash computes the signing dataHash of the QueryBoundWitness (including "query" and "error_hashes").
func (qbw *QueryBoundWitness) DataHash() (string, error) {
	return payload.DataHash(qbw)
}

// DataHashBytes computes the 32-byte signing dataHash of the QueryBoundWitness.
func (qbw *QueryBoundWitness) DataHashBytes() ([]byte, error) {
	return payload.DataHashBytes(qbw)
}

func cloneStringPtrSlice(in []*string) []*string {
	if in == nil {
		return nil
	}
	out := make([]*string, len(in))
	for i, p := range in {
		if p != nil {
			s := *p
			out[i] = &s
		}
	}
	return out
}

func cloneExtraMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func mergeExtraJSON(base []byte, extra map[string]any) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(base))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	for k, v := range extra {
		if _, exists := m[k]; !exists {
			m[k] = v
		}
	}
	return json.Marshal(m)
}

func extractExtraFields(data []byte, known map[string]struct{}) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	var extra map[string]any
	for k, v := range raw {
		if _, ok := known[k]; !ok {
			if extra == nil {
				extra = make(map[string]any)
			}
			extra[k] = v
		}
	}
	return extra, nil
}
