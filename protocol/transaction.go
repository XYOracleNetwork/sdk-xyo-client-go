package protocol

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/XYOracleNetwork/sdk-xyo-client-go/account"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/boundwitness"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/payload"
)

// TransactionFeesHex holds hex-encoded transaction fee components on the XL1 wire.
// Per XL1 protocol, signable/on-wire fee hex strings have NO "0x" prefix (see Normalized()).
type TransactionFeesHex struct {
	Base     string `json:"base"`
	GasLimit string `json:"gasLimit"`
	GasPrice string `json:"gasPrice"`
	Priority string `json:"priority"`
}

// Normalized returns a copy with any leading "0x"/"0X" prefixes stripped and lowercased.
func (f TransactionFeesHex) Normalized() TransactionFeesHex {
	return TransactionFeesHex{
		Base:     strings.ToLower(account.StripHexPrefix(strings.TrimSpace(f.Base))),
		GasLimit: strings.ToLower(account.StripHexPrefix(strings.TrimSpace(f.GasLimit))),
		GasPrice: strings.ToLower(account.StripHexPrefix(strings.TrimSpace(f.GasPrice))),
		Priority: strings.ToLower(account.StripHexPrefix(strings.TrimSpace(f.Priority))),
	}
}

// ToBigInt converts TransactionFeesHex to TransactionFeesBigInt.
func (f TransactionFeesHex) ToBigInt() (TransactionFeesBigInt, error) {
	base, err := AttoXL1FromHex(f.Base)
	if err != nil {
		return TransactionFeesBigInt{}, fmt.Errorf("invalid base fee: %w", err)
	}
	gasLimit, err := AttoXL1FromHex(f.GasLimit)
	if err != nil {
		return TransactionFeesBigInt{}, fmt.Errorf("invalid gasLimit fee: %w", err)
	}
	gasPrice, err := AttoXL1FromHex(f.GasPrice)
	if err != nil {
		return TransactionFeesBigInt{}, fmt.Errorf("invalid gasPrice fee: %w", err)
	}
	priority, err := AttoXL1FromHex(f.Priority)
	if err != nil {
		return TransactionFeesBigInt{}, fmt.Errorf("invalid priority fee: %w", err)
	}
	return TransactionFeesBigInt{
		Base:     base,
		GasLimit: gasLimit,
		GasPrice: gasPrice,
		Priority: priority,
	}, nil
}

// TransactionFeesBigInt holds strongly typed AttoXL1 transaction fee components.
type TransactionFeesBigInt struct {
	Base     AttoXL1
	GasLimit AttoXL1
	GasPrice AttoXL1
	Priority AttoXL1
}

// DefaultTransactionFees returns the canonical XL1 minimum/default transaction fees:
// base=1000 nano, gasLimit=1,000,000 nano, gasPrice=10 nano, priority=0.
func DefaultTransactionFees() TransactionFeesBigInt {
	base, _ := NewNanoXL1(big.NewInt(1_000))
	gasLimit, _ := NewNanoXL1(big.NewInt(1_000_000))
	gasPrice, _ := NewNanoXL1(big.NewInt(10))
	priority, _ := NewAttoXL1Int64(0)
	return TransactionFeesBigInt{
		Base:     base.ToAtto(),
		GasLimit: gasLimit.ToAtto(),
		GasPrice: gasPrice.ToAtto(),
		Priority: priority,
	}
}

// ToHex converts fees to bare lowercase hex TransactionFeesHex (matching XL1 wire format).
func (f TransactionFeesBigInt) ToHex() TransactionFeesHex {
	return TransactionFeesHex{
		Base:     f.Base.BareHex(),
		GasLimit: f.GasLimit.BareHex(),
		GasPrice: f.GasPrice.BareHex(),
		Priority: f.Priority.BareHex(),
	}
}

// Total computes base + (gasLimit * gasPrice) + priority.
func (f TransactionFeesBigInt) Total() *big.Int {
	gasCost := new(big.Int).Mul(f.GasLimit.BigInt(), f.GasPrice.BigInt())
	total := new(big.Int).Add(f.Base.BigInt(), gasCost)
	return total.Add(total, f.Priority.BigInt())
}

// TransactionBoundWitness represents an XL1 Transaction BoundWitness ("network.xyo.boundwitness").
// Unknown JSON fields encountered during unmarshaling are preserved in BoundWitness.Extra
// so DataHash/Hash and signature verification remain lossless across wire round-trips.
type TransactionBoundWitness struct {
	boundwitness.BoundWitness
	From   string             `json:"from"`
	Chain  ChainID            `json:"chain"`
	Nbf    int64              `json:"nbf"`
	Exp    int64              `json:"exp"`
	Fees   TransactionFeesHex `json:"fees"`
	Script []string           `json:"script,omitempty"`

	// Optional storage metadata read from RPC responses
	StoredHash     string `json:"_hash,omitempty"`
	StoredDataHash string `json:"_dataHash,omitempty"`
}

var knownTxBWKeys = map[string]struct{}{
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
	"from":            {},
	"chain":           {},
	"nbf":             {},
	"exp":             {},
	"fees":            {},
	"script":          {},
	"_hash":           {},
	"_dataHash":       {},
}

// MarshalJSON encodes TransactionBoundWitness including all base BoundWitness fields, tx fields, and Extra.
func (tx TransactionBoundWitness) MarshalJSON() ([]byte, error) {
	type txWire struct {
		Addresses      []string           `json:"addresses"`
		PayloadHashes  []string           `json:"payload_hashes"`
		PayloadSchemas []string           `json:"payload_schemas"`
		PreviousHashes []*string          `json:"previous_hashes"`
		Schema         string             `json:"schema"`
		Timestamp      *int64             `json:"timestamp,omitempty"`
		Signatures     []*string          `json:"$signatures,omitempty"`
		Destination    string             `json:"$destination,omitempty"`
		SourceQuery    string             `json:"$sourceQuery,omitempty"`
		Version        *int               `json:"$version,omitempty"`
		From           string             `json:"from"`
		Chain          ChainID            `json:"chain"`
		Nbf            int64              `json:"nbf"`
		Exp            int64              `json:"exp"`
		Fees           TransactionFeesHex `json:"fees"`
		Script         []string           `json:"script,omitempty"`
		StoredHash     string             `json:"_hash,omitempty"`
		StoredDataHash string             `json:"_dataHash,omitempty"`
	}
	w := txWire{
		Addresses:      tx.Addresses,
		PayloadHashes:  tx.PayloadHashes,
		PayloadSchemas: tx.PayloadSchemas,
		PreviousHashes: tx.PreviousHashes,
		Schema:         tx.Schema,
		Timestamp:      tx.Timestamp,
		Signatures:     tx.Signatures,
		Destination:    tx.Destination,
		SourceQuery:    tx.SourceQuery,
		Version:        tx.Version,
		From:           tx.From,
		Chain:          tx.Chain,
		Nbf:            tx.Nbf,
		Exp:            tx.Exp,
		Fees:           tx.Fees,
		Script:         tx.Script,
		StoredHash:     tx.StoredHash,
		StoredDataHash: tx.StoredDataHash,
	}
	base, err := json.Marshal(w)
	if err != nil {
		return nil, err
	}
	if len(tx.Extra) == 0 {
		return base, nil
	}
	return mergeExtraJSON(base, tx.Extra)
}

// UnmarshalJSON decodes TransactionBoundWitness while preserving unknown fields in Extra.
func (tx *TransactionBoundWitness) UnmarshalJSON(data []byte) error {
	var baseBW boundwitness.BoundWitness
	if err := json.Unmarshal(data, &baseBW); err != nil {
		return err
	}
	var txFields struct {
		From           string             `json:"from"`
		Chain          ChainID            `json:"chain"`
		Nbf            int64              `json:"nbf"`
		Exp            int64              `json:"exp"`
		Fees           TransactionFeesHex `json:"fees"`
		Script         []string           `json:"script,omitempty"`
		StoredHash     string             `json:"_hash,omitempty"`
		StoredDataHash string             `json:"_dataHash,omitempty"`
	}
	if err := json.Unmarshal(data, &txFields); err != nil {
		return err
	}
	extra, err := extractExtraJSON(data, knownTxBWKeys)
	if err != nil {
		return err
	}
	tx.BoundWitness = baseBW
	tx.Extra = extra
	tx.From = txFields.From
	tx.Chain = txFields.Chain
	tx.Nbf = txFields.Nbf
	tx.Exp = txFields.Exp
	tx.Fees = txFields.Fees
	tx.Script = txFields.Script
	tx.StoredHash = txFields.StoredHash
	tx.StoredDataHash = txFields.StoredDataHash
	return nil
}

// Hash computes the root hash of this TransactionBoundWitness.
func (tx *TransactionBoundWitness) Hash() (string, error) {
	return payload.Hash(tx)
}

// DataHash computes the signing dataHash of this TransactionBoundWitness.
func (tx *TransactionBoundWitness) DataHash() (string, error) {
	return payload.DataHash(tx)
}

// DataHashBytes computes the 32-byte signing dataHash of this TransactionBoundWitness.
func (tx *TransactionBoundWitness) DataHashBytes() ([]byte, error) {
	return payload.DataHashBytes(tx)
}

// HydratedTransaction pairs a TransactionBoundWitness with its payloads.
// Marshals and unmarshals as the XL1 RPC 2-element wire tuple [TransactionBoundWitness, Payloads].
type HydratedTransaction struct {
	BoundWitness *TransactionBoundWitness `json:"boundWitness"`
	Payloads     []any                    `json:"payloads"`
	Hash         string                   `json:"hash,omitempty"`
}

// MarshalJSON encodes HydratedTransaction as the 2-element XL1 wire tuple [boundWitness, payloads].
func (ht HydratedTransaction) MarshalJSON() ([]byte, error) {
	payloads := ht.Payloads
	if payloads == nil {
		payloads = []any{}
	}
	return json.Marshal([]any{ht.BoundWitness, payloads})
}

// UnmarshalJSON decodes a 2-element XL1 wire tuple [boundWitness, payloads] into HydratedTransaction.
func (ht *HydratedTransaction) UnmarshalJSON(data []byte) error {
	var tuple []json.RawMessage
	if err := json.Unmarshal(data, &tuple); err != nil {
		return err
	}
	if len(tuple) < 2 {
		return errors.New("hydrated transaction tuple must have at least 2 elements")
	}
	var bw TransactionBoundWitness
	if err := json.Unmarshal(tuple[0], &bw); err != nil {
		return err
	}
	var anyPayloads []payload.AnyPayload
	if len(tuple[1]) > 0 && string(tuple[1]) != "null" {
		if err := json.Unmarshal(tuple[1], &anyPayloads); err != nil {
			return err
		}
	}
	out := make([]any, len(anyPayloads))
	for i, p := range anyPayloads {
		out[i] = p
	}
	ht.BoundWitness = &bw
	ht.Payloads = out
	if bw.StoredHash != "" {
		ht.Hash = bw.StoredHash
	} else if h, err := bw.Hash(); err == nil {
		ht.Hash = h
	}
	return nil
}

// TransactionBuilder builds and signs XL1 HydratedTransactions matching Android/Swift/JS.
type TransactionBuilder struct {
	chain     ChainID
	hasChain  bool
	fees      *TransactionFeesBigInt
	nbf       *XL1BlockNumber
	exp       *XL1BlockNumber
	from      string
	payloads  []any
	signers   []account.Account
	scripts   []string
	timestamp *int64
}

// NewTransactionBuilder creates a new fluent TransactionBuilder.
func NewTransactionBuilder() *TransactionBuilder {
	return &TransactionBuilder{}
}

func (b *TransactionBuilder) Chain(chain ChainID) *TransactionBuilder {
	b.chain = chain
	b.hasChain = true
	return b
}

func (b *TransactionBuilder) Fees(fees TransactionFeesBigInt) *TransactionBuilder {
	cp := fees
	b.fees = &cp
	return b
}

func (b *TransactionBuilder) Range(nbf, exp XL1BlockNumber) *TransactionBuilder {
	b.nbf = &nbf
	b.exp = &exp
	return b
}

func (b *TransactionBuilder) From(address string) *TransactionBuilder {
	b.from = address
	return b
}

func (b *TransactionBuilder) Payload(p any) *TransactionBuilder {
	if p != nil {
		b.payloads = append(b.payloads, p)
	}
	return b
}

func (b *TransactionBuilder) Payloads(ps ...any) *TransactionBuilder {
	for _, p := range ps {
		b.Payload(p)
	}
	return b
}

func (b *TransactionBuilder) Signer(acct account.Account) *TransactionBuilder {
	if acct != nil {
		b.signers = append(b.signers, acct)
	}
	return b
}

func (b *TransactionBuilder) Signers(accts ...account.Account) *TransactionBuilder {
	for _, a := range accts {
		b.Signer(a)
	}
	return b
}

func (b *TransactionBuilder) Script(script string) *TransactionBuilder {
	if script != "" {
		b.scripts = append(b.scripts, script)
	}
	return b
}

func (b *TransactionBuilder) Timestamp(ts int64) *TransactionBuilder {
	b.timestamp = &ts
	return b
}

// Build constructs, elevates, hashes, and signs the XL1 transaction.
func (b *TransactionBuilder) Build() (*HydratedTransaction, error) {
	if !b.hasChain || strings.TrimSpace(string(b.chain)) == "" {
		return nil, errors.New("chain must be set")
	}
	if b.fees == nil {
		return nil, errors.New("fees must be set")
	}
	if b.nbf == nil || b.exp == nil {
		return nil, errors.New("block range (nbf and exp) must be set")
	}
	if *b.nbf < 0 {
		return nil, fmt.Errorf("nbf must be non-negative, got %d", *b.nbf)
	}
	if *b.exp <= *b.nbf {
		return nil, fmt.Errorf("exp (%d) must be greater than nbf (%d)", *b.exp, *b.nbf)
	}

	from := strings.TrimSpace(b.from)
	if from == "" {
		if len(b.signers) == 0 {
			return nil, errors.New("from address or at least one signer must be provided")
		}
		from = b.signers[0].Address()
	} else {
		normFrom, err := account.NormalizeAddress(from)
		if err != nil {
			return nil, fmt.Errorf("invalid from address: %w", err)
		}
		from = normFrom
	}

	payloadHashes := make([]string, len(b.payloads))
	payloadSchemas := make([]string, len(b.payloads))
	autoScripts := make([]string, 0, len(b.payloads))

	for i, p := range b.payloads {
		ap, err := payload.ToAnyPayload(p)
		if err != nil {
			return nil, fmt.Errorf("payload[%d]: %w", i, err)
		}
		schema := ap.GetSchema()
		if err := payload.ValidateSchemaName(schema); err != nil {
			return nil, fmt.Errorf("payload[%d] schema: %w", i, err)
		}
		h, err := payload.Hash(p)
		if err != nil {
			return nil, fmt.Errorf("payload[%d] hash: %w", i, err)
		}
		payloadHashes[i] = h
		payloadSchemas[i] = schema
		autoScripts = append(autoScripts, "elevate|"+h)
	}

	// Merge explicit scripts + auto elevate scripts, preserving order & deduplicating
	mergedScripts := dedupeStrings(append(append([]string(nil), b.scripts...), autoScripts...))
	if len(mergedScripts) == 0 {
		mergedScripts = nil
	}

	addresses := make([]string, len(b.signers))
	prevHashes := make([]*string, len(b.signers))
	seenSigners := make(map[string]struct{}, len(b.signers))
	for i, s := range b.signers {
		addr := s.Address()
		norm, err := account.NormalizeAddress(addr)
		if err != nil {
			return nil, fmt.Errorf("signer[%d] invalid address: %w", i, err)
		}
		if _, dup := seenSigners[norm]; dup {
			return nil, fmt.Errorf("duplicate signer address: %s", norm)
		}
		seenSigners[norm] = struct{}{}
		addresses[i] = norm
		prevHashes[i] = s.PreviousHashHex()
	}

	normalizedFees := b.fees.ToHex().Normalized()

	txBW := &TransactionBoundWitness{
		BoundWitness: boundwitness.BoundWitness{
			Addresses:      addresses,
			PayloadHashes:  payloadHashes,
			PayloadSchemas: payloadSchemas,
			PreviousHashes: prevHashes,
			Schema:         payload.SchemaBoundWitness,
			Timestamp:      b.timestamp,
		},
		From:   from,
		Chain:  b.chain,
		Nbf:    int64(*b.nbf),
		Exp:    int64(*b.exp),
		Fees:   normalizedFees,
		Script: mergedScripts,
	}

	dataHashBytes, err := txBW.DataHashBytes()
	if err != nil {
		return nil, fmt.Errorf("compute transaction dataHash: %w", err)
	}

	type rollbackable interface {
		RollbackPreviousHash(expectedCurrent, restorePrev []byte) error
	}
	type snap struct {
		acct account.Account
		prev []byte
	}
	var signed []snap
	sigs := make([]*string, len(b.signers))
	for i, s := range b.signers {
		prevBefore := s.PreviousHash()
		sigBytes, err := s.Sign(dataHashBytes)
		if err != nil {
			for j := len(signed) - 1; j >= 0; j-- {
				if rb, ok := signed[j].acct.(rollbackable); ok {
					_ = rb.RollbackPreviousHash(dataHashBytes, signed[j].prev)
				}
			}
			return nil, fmt.Errorf("sign transaction for %s: %w", s.Address(), err)
		}
		signed = append(signed, snap{acct: s, prev: prevBefore})
		sigHex := hex.EncodeToString(sigBytes)
		sigs[i] = &sigHex
	}
	if len(sigs) > 0 {
		txBW.Signatures = sigs
	}

	rootHash, err := txBW.Hash()
	if err != nil {
		return nil, err
	}

	return &HydratedTransaction{
		BoundWitness: txBW,
		Payloads:     append([]any(nil), b.payloads...),
		Hash:         rootHash,
	}, nil
}

// ConfirmSubmittedTransaction polls TransactionViewer.ByHash until the transaction appears on chain
// or maxAttempts / ctx deadline is reached.
func ConfirmSubmittedTransaction(
	ctx context.Context,
	viewer *TransactionViewer,
	txHash string,
	pollInterval time.Duration,
	maxAttempts int,
) (*HydratedTransaction, error) {
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}
	if maxAttempts <= 0 {
		maxAttempts = 30
	}
	for attempt := 0; attempt < maxAttempts; attempt++ {
		tx, err := viewer.ByHash(ctx, txHash)
		if err == nil && tx != nil && tx.BoundWitness != nil {
			return tx, nil
		}
		if attempt+1 < maxAttempts {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(pollInterval):
			}
		}
	}
	return nil, fmt.Errorf("transaction %s not confirmed after %d attempts", txHash, maxAttempts)
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
