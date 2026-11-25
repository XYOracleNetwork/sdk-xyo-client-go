package boundwitness

import (
	"github.com/XYOracleNetwork/sdk-xyo-client-go/payload"
)

// SchemaBoundWitness is the canonical schema string for XYO BoundWitnesses.
const SchemaBoundWitness = payload.SchemaBoundWitness

// BoundWitness represents an XYO Protocol 2.0 BoundWitness.
// Core fields (addresses, payload_hashes, payload_schemas, previous_hashes, schema, optional timestamp)
// are included in dataHash and signed by all signers.
// Client metadata fields ($signatures, $destination, $sourceQuery, $version) are excluded from dataHash
// and included in the root hash.
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

func strPtr(s string) *string {
	return &s
}
