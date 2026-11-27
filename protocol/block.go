package protocol

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/XYOracleNetwork/sdk-xyo-client-go/boundwitness"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/payload"
)

// BlockBoundWitness represents an XL1 Block BoundWitness ("network.xyo.boundwitness").
// Unknown JSON fields encountered during unmarshaling are preserved in BoundWitness.Extra
// so DataHash/Hash and signature verification remain lossless across wire round-trips.
type BlockBoundWitness struct {
	boundwitness.BoundWitness
	Block      int64    `json:"block"`
	Chain      ChainID  `json:"chain"`
	Previous   *string  `json:"previous"`
	Protocol   *int     `json:"protocol,omitempty"`
	StepHashes []string `json:"step_hashes,omitempty"`
	Epoch      *int64   `json:"$epoch,omitempty"`

	// Optional storage metadata read from RPC responses
	StoredHash     string `json:"_hash,omitempty"`
	StoredDataHash string `json:"_dataHash,omitempty"`
}

var knownBlockBWKeys = map[string]struct{}{
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
	"block":           {},
	"chain":           {},
	"previous":        {},
	"protocol":        {},
	"step_hashes":     {},
	"$epoch":          {},
	"_hash":           {},
	"_dataHash":       {},
}

// MarshalJSON encodes BlockBoundWitness including all base BoundWitness fields, block fields, and Extra.
func (b BlockBoundWitness) MarshalJSON() ([]byte, error) {
	type blockWire struct {
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
		Block          int64     `json:"block"`
		Chain          ChainID   `json:"chain"`
		Previous       *string   `json:"previous"`
		Protocol       *int      `json:"protocol,omitempty"`
		StepHashes     []string  `json:"step_hashes,omitempty"`
		Epoch          *int64    `json:"$epoch,omitempty"`
		StoredHash     string    `json:"_hash,omitempty"`
		StoredDataHash string    `json:"_dataHash,omitempty"`
	}
	w := blockWire{
		Addresses:      b.Addresses,
		PayloadHashes:  b.PayloadHashes,
		PayloadSchemas: b.PayloadSchemas,
		PreviousHashes: b.PreviousHashes,
		Schema:         b.Schema,
		Timestamp:      b.Timestamp,
		Signatures:     b.Signatures,
		Destination:    b.Destination,
		SourceQuery:    b.SourceQuery,
		Version:        b.Version,
		Block:          b.Block,
		Chain:          b.Chain,
		Previous:       b.Previous,
		Protocol:       b.Protocol,
		StepHashes:     b.StepHashes,
		Epoch:          b.Epoch,
		StoredHash:     b.StoredHash,
		StoredDataHash: b.StoredDataHash,
	}
	base, err := json.Marshal(w)
	if err != nil {
		return nil, err
	}
	if len(b.Extra) == 0 {
		return base, nil
	}
	return mergeExtraJSON(base, b.Extra)
}

// UnmarshalJSON decodes BlockBoundWitness while preserving any unknown fields in Extra.
func (b *BlockBoundWitness) UnmarshalJSON(data []byte) error {
	var baseBW boundwitness.BoundWitness
	if err := json.Unmarshal(data, &baseBW); err != nil {
		return err
	}
	var blockFields struct {
		Block          int64    `json:"block"`
		Chain          ChainID  `json:"chain"`
		Previous       *string  `json:"previous"`
		Protocol       *int     `json:"protocol,omitempty"`
		StepHashes     []string `json:"step_hashes,omitempty"`
		Epoch          *int64   `json:"$epoch,omitempty"`
		StoredHash     string   `json:"_hash,omitempty"`
		StoredDataHash string   `json:"_dataHash,omitempty"`
	}
	if err := json.Unmarshal(data, &blockFields); err != nil {
		return err
	}
	extra, err := extractExtraJSON(data, knownBlockBWKeys)
	if err != nil {
		return err
	}
	b.BoundWitness = baseBW
	b.Extra = extra
	b.Block = blockFields.Block
	b.Chain = blockFields.Chain
	b.Previous = blockFields.Previous
	b.Protocol = blockFields.Protocol
	b.StepHashes = blockFields.StepHashes
	b.Epoch = blockFields.Epoch
	b.StoredHash = blockFields.StoredHash
	b.StoredDataHash = blockFields.StoredDataHash
	return nil
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

func extractExtraJSON(data []byte, known map[string]struct{}) (map[string]any, error) {
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

// BlockNumber returns the block height as XL1BlockNumber.
func (b *BlockBoundWitness) BlockNumber() XL1BlockNumber {
	return XL1BlockNumber(b.Block)
}

// Hash computes the root hash of this BlockBoundWitness (excluding "_" storage meta).
func (b *BlockBoundWitness) Hash() (string, error) {
	return payload.Hash(b)
}

// DataHash computes the signing dataHash of this BlockBoundWitness (excluding "_" and "$" meta).
func (b *BlockBoundWitness) DataHash() (string, error) {
	return payload.DataHash(b)
}

// DataHashBytes computes the 32-byte signing dataHash of this BlockBoundWitness.
func (b *BlockBoundWitness) DataHashBytes() ([]byte, error) {
	return payload.DataHashBytes(b)
}

// HydratedBlock pairs a BlockBoundWitness with its accompanying payloads and hash metadata.
// Marshals and unmarshals as the standard XL1 RPC 2-element wire tuple [BlockBoundWitness, Payloads].
type HydratedBlock struct {
	BoundWitness *BlockBoundWitness   `json:"boundWitness"`
	Payloads     []payload.AnyPayload `json:"payloads"`
	Hash         string               `json:"hash,omitempty"`
}

// MarshalJSON encodes HydratedBlock as the 2-element XL1 wire tuple [boundWitness, payloads].
func (hb HydratedBlock) MarshalJSON() ([]byte, error) {
	payloads := hb.Payloads
	if payloads == nil {
		payloads = []payload.AnyPayload{}
	}
	return json.Marshal([]any{hb.BoundWitness, payloads})
}

// UnmarshalJSON decodes a 2-element XL1 wire tuple [boundWitness, payloads] into HydratedBlock.
func (hb *HydratedBlock) UnmarshalJSON(data []byte) error {
	var tuple []json.RawMessage
	if err := json.Unmarshal(data, &tuple); err != nil {
		return err
	}
	if len(tuple) < 2 {
		return errors.New("hydrated block tuple must have at least 2 elements")
	}
	var bw BlockBoundWitness
	if err := json.Unmarshal(tuple[0], &bw); err != nil {
		return err
	}
	var payloads []payload.AnyPayload
	if len(tuple[1]) > 0 && string(tuple[1]) != "null" {
		if err := json.Unmarshal(tuple[1], &payloads); err != nil {
			return err
		}
	}
	hb.BoundWitness = &bw
	hb.Payloads = payloads
	if bw.StoredHash != "" {
		hb.Hash = bw.StoredHash
	} else if h, err := bw.Hash(); err == nil {
		hb.Hash = h
	}
	return nil
}

// EpochOfBlock returns the authoritative epoch milliseconds for a HydratedBlock:
// prefers a signed network.xyo.time payload's epoch field, falling back to unsigned $epoch client meta.
func EpochOfBlock(hb *HydratedBlock) *int64 {
	if hb == nil {
		return nil
	}
	for _, p := range hb.Payloads {
		if p.GetSchema() == payload.SchemaTime {
			var tp TimePayload
			if err := p.DecodeInto(&tp); err == nil && tp.Epoch != nil {
				v := *tp.Epoch
				return &v
			}
		}
	}
	if hb.BoundWitness != nil && hb.BoundWitness.Epoch != nil {
		v := *hb.BoundWitness.Epoch
		return &v
	}
	return nil
}
