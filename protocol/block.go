package protocol

import (
	"encoding/json"
	"errors"

	"github.com/XYOracleNetwork/sdk-xyo-client-go/boundwitness"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/payload"
)

// BlockBoundWitness represents an XL1 Block BoundWitness ("network.xyo.boundwitness").
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
