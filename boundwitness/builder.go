package boundwitness

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/XYOracleNetwork/sdk-xyo-client-go/account"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/payload"
)

// processBuildMutex serializes multi-signer BoundWitness builds within the process,
// mirroring sdk-protocol-js BoundWitnessBuilder._buildMutex.
var processBuildMutex sync.Mutex

// Participant represents a signing slot in a BoundWitness (either a local signer Account
// or a remote address-only participant for sequential cosigning).
type Participant struct {
	Account      account.Account
	Address      string
	PreviousHash *string
}

// BoundWitnessBuilder constructs and signs XYO Protocol 2.0 BoundWitnesses.
type BoundWitnessBuilder struct {
	participants []Participant
	payloads     []any
	timestamp    *int64
	destination  string
	sourceQuery  string
	version      *int
}

// NewBuilder creates a new BoundWitnessBuilder.
func NewBuilder() *BoundWitnessBuilder {
	return &BoundWitnessBuilder{}
}

// Signer adds a local signing Account to the BoundWitness.
func (b *BoundWitnessBuilder) Signer(acct account.Account) *BoundWitnessBuilder {
	if acct != nil {
		b.participants = append(b.participants, Participant{Account: acct})
	}
	return b
}

// Signers adds multiple local signing Accounts to the BoundWitness.
func (b *BoundWitnessBuilder) Signers(accts ...account.Account) *BoundWitnessBuilder {
	for _, a := range accts {
		b.Signer(a)
	}
	return b
}

// Participant adds an address-only participant slot (left unsigned as null in $signatures
// for subsequent CosignBoundWitness).
func (b *BoundWitnessBuilder) Participant(address string, previousHash *string) *BoundWitnessBuilder {
	b.participants = append(b.participants, Participant{
		Address:      address,
		PreviousHash: previousHash,
	})
	return b
}

// Payload adds a single payload to the BoundWitness.
func (b *BoundWitnessBuilder) Payload(p any) *BoundWitnessBuilder {
	if p != nil {
		b.payloads = append(b.payloads, p)
	}
	return b
}

// Payloads adds multiple payloads to the BoundWitness.
func (b *BoundWitnessBuilder) Payloads(ps ...any) *BoundWitnessBuilder {
	for _, p := range ps {
		b.Payload(p)
	}
	return b
}

// Timestamp sets an optional explicit epoch millisecond timestamp on the BoundWitness.
func (b *BoundWitnessBuilder) Timestamp(ts int64) *BoundWitnessBuilder {
	b.timestamp = &ts
	return b
}

// Destination sets the $destination client metadata field.
func (b *BoundWitnessBuilder) Destination(address string) *BoundWitnessBuilder {
	b.destination = address
	return b
}

// SourceQuery sets the $sourceQuery client metadata field.
func (b *BoundWitnessBuilder) SourceQuery(hash string) *BoundWitnessBuilder {
	b.sourceQuery = hash
	return b
}

// Version sets the optional $version client metadata field.
func (b *BoundWitnessBuilder) Version(v int) *BoundWitnessBuilder {
	b.version = &v
	return b
}

// Build constructs and signs the BoundWitness with all local signers.
// Returns the signed BoundWitness and the list of payloads included in it.
func (b *BoundWitnessBuilder) Build() (*BoundWitness, []any, error) {
	return b.build(true)
}

// BuildUnsigned constructs the BoundWitness without signing (leaving all $signatures slots nil).
func (b *BoundWitnessBuilder) BuildUnsigned() (*BoundWitness, []any, error) {
	return b.build(false)
}

func (b *BoundWitnessBuilder) build(sign bool) (*BoundWitness, []any, error) {
	processBuildMutex.Lock()
	defer processBuildMutex.Unlock()

	bw, payloads, err := b.assembleFields()
	if err != nil {
		return nil, nil, err
	}

	sigs := make([]*string, len(b.participants))
	if sign {
		dataHashBytes, err := bw.DataHashBytes()
		if err != nil {
			return nil, nil, fmt.Errorf("compute bound witness dataHash: %w", err)
		}
		if err := signParticipantsAtomic(b.participants, dataHashBytes, sigs); err != nil {
			return nil, nil, fmt.Errorf("sign bound witness: %w", err)
		}
		if len(sigs) > 0 {
			bw.Signatures = sigs
		}
	}

	return bw, payloads, nil
}

type rollbackableAccount interface {
	RollbackPreviousHash(expectedCurrent, restorePrev []byte) error
}

type signedSnapshot struct {
	acct account.Account
	prev []byte
}

func signParticipantsAtomic(participants []Participant, dataHashBytes []byte, sigs []*string) error {
	var signed []signedSnapshot
	for i, part := range participants {
		if part.Account == nil {
			sigs[i] = nil
			continue
		}
		prevBefore := part.Account.PreviousHash()
		sigBytes, err := part.Account.Sign(dataHashBytes)
		if err != nil {
			for j := len(signed) - 1; j >= 0; j-- {
				if rb, ok := signed[j].acct.(rollbackableAccount); ok {
					_ = rb.RollbackPreviousHash(dataHashBytes, signed[j].prev)
				}
			}
			return fmt.Errorf("for %s: %w", part.Account.Address(), err)
		}
		signed = append(signed, signedSnapshot{acct: part.Account, prev: prevBefore})
		sigHex := hex.EncodeToString(sigBytes)
		sigs[i] = &sigHex
	}
	return nil
}

func (b *BoundWitnessBuilder) assembleFields() (*BoundWitness, []any, error) {
	addresses := make([]string, len(b.participants))
	prevHashes := make([]*string, len(b.participants))
	seen := make(map[string]struct{}, len(b.participants))

	for i, part := range b.participants {
		var addr string
		var prev *string
		if part.Account != nil {
			addr = part.Account.Address()
			prev = part.Account.PreviousHashHex()
		} else {
			norm, err := account.NormalizeAddress(part.Address)
			if err != nil {
				return nil, nil, fmt.Errorf("participant[%d] invalid address: %w", i, err)
			}
			addr = norm
			if part.PreviousHash != nil && *part.PreviousHash != "" {
				p := strings.ToLower(account.StripHexPrefix(*part.PreviousHash))
				prev = &p
			}
		}
		if _, dup := seen[addr]; dup {
			return nil, nil, fmt.Errorf("duplicate signer address: %s", addr)
		}
		seen[addr] = struct{}{}
		addresses[i] = addr
		prevHashes[i] = prev
	}

	payloadHashes := make([]string, len(b.payloads))
	payloadSchemas := make([]string, len(b.payloads))
	for i, p := range b.payloads {
		schema, err := extractSchema(p)
		if err != nil {
			return nil, nil, fmt.Errorf("payload[%d]: %w", i, err)
		}
		if err := payload.ValidateSchemaName(schema); err != nil {
			return nil, nil, fmt.Errorf("payload[%d] schema: %w", i, err)
		}
		// BoundWitness.payload_hashes stores each payload's root hash (STORAGE_META excluded)
		h, err := payload.Hash(p)
		if err != nil {
			return nil, nil, fmt.Errorf("payload[%d] hash: %w", i, err)
		}
		payloadHashes[i] = h
		payloadSchemas[i] = schema
	}

	bw := &BoundWitness{
		Addresses:      addresses,
		PayloadHashes:  payloadHashes,
		PayloadSchemas: payloadSchemas,
		PreviousHashes: prevHashes,
		Schema:         SchemaBoundWitness,
		Timestamp:      b.timestamp,
		Destination:    b.destination,
		SourceQuery:    b.sourceQuery,
		Version:        b.version,
	}

	outPayloads := make([]any, len(b.payloads))
	copy(outPayloads, b.payloads)
	return bw, outPayloads, nil
}

// CosignBoundWitness clones bw, locates signer.Address() in Addresses, verifies the slot is unsigned
// and its previous_hash matches signer.PreviousHashHex(), signs bw.DataHashBytes(), and populates
// $signatures[i] without mutating the original BoundWitness.
func CosignBoundWitness(bw *BoundWitness, signer account.Account) (*BoundWitness, error) {
	if bw == nil {
		return nil, errors.New("bound witness is nil")
	}
	if signer == nil {
		return nil, errors.New("signer is nil")
	}
	if len(bw.PreviousHashes) != len(bw.Addresses) {
		return nil, fmt.Errorf("previous_hashes length (%d) != addresses length (%d)", len(bw.PreviousHashes), len(bw.Addresses))
	}
	addr, err := account.NormalizeAddress(signer.Address())
	if err != nil {
		return nil, fmt.Errorf("invalid signer address: %w", err)
	}
	idx := -1
	for i, a := range bw.Addresses {
		if norm, normErr := account.NormalizeAddress(a); normErr == nil && norm == addr {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, fmt.Errorf("signer address %s not found in bound witness addresses", addr)
	}
	if idx < len(bw.Signatures) && bw.Signatures[idx] != nil && *bw.Signatures[idx] != "" {
		return nil, fmt.Errorf("address %s has already signed this bound witness", addr)
	}

	// Verify previous_hash expectation matches signer's current chain state
	signerPrev := signer.PreviousHashHex()
	bwPrev := bw.PreviousHashes[idx]
	if !stringPtrEqual(bwPrev, signerPrev) {
		return nil, fmt.Errorf("previous_hash mismatch for %s", addr)
	}

	dataHashBytes, err := bw.DataHashBytes()
	if err != nil {
		return nil, fmt.Errorf("compute dataHash for cosign: %w", err)
	}
	sigBytes, err := signer.Sign(dataHashBytes)
	if err != nil {
		return nil, fmt.Errorf("cosign failed: %w", err)
	}
	sigHex := hex.EncodeToString(sigBytes)

	out := bw.Clone()
	if len(out.Signatures) < len(out.Addresses) {
		expanded := make([]*string, len(out.Addresses))
		copy(expanded, out.Signatures)
		out.Signatures = expanded
	}
	out.Signatures[idx] = &sigHex
	return out, nil
}

// QueryBoundWitnessBuilder builds and signs a QueryBoundWitness for XYO module queries.
type QueryBoundWitnessBuilder struct {
	BoundWitnessBuilder
	queryPayload any
	errorHashes  []string
}

// NewQueryBuilder creates a new QueryBoundWitnessBuilder.
func NewQueryBuilder() *QueryBoundWitnessBuilder {
	return &QueryBoundWitnessBuilder{}
}

// Query sets the query payload (its dataHash becomes the signed "query" field,
// and the query payload is included in the BoundWitness payloads).
func (qb *QueryBoundWitnessBuilder) Query(q any) *QueryBoundWitnessBuilder {
	qb.queryPayload = q
	return qb
}

// ErrorHashes sets optional error payload hashes on the QueryBoundWitness.
func (qb *QueryBoundWitnessBuilder) ErrorHashes(hashes ...string) *QueryBoundWitnessBuilder {
	qb.errorHashes = append(qb.errorHashes, hashes...)
	return qb
}

// Signer adds a local signer account.
func (qb *QueryBoundWitnessBuilder) Signer(acct account.Account) *QueryBoundWitnessBuilder {
	qb.BoundWitnessBuilder.Signer(acct)
	return qb
}

// Signers adds multiple local signer accounts.
func (qb *QueryBoundWitnessBuilder) Signers(accts ...account.Account) *QueryBoundWitnessBuilder {
	qb.BoundWitnessBuilder.Signers(accts...)
	return qb
}

// Payload adds an attached payload (sent alongside the query payload).
func (qb *QueryBoundWitnessBuilder) Payload(p any) *QueryBoundWitnessBuilder {
	qb.BoundWitnessBuilder.Payload(p)
	return qb
}

// Payloads adds multiple attached payloads.
func (qb *QueryBoundWitnessBuilder) Payloads(ps ...any) *QueryBoundWitnessBuilder {
	qb.BoundWitnessBuilder.Payloads(ps...)
	return qb
}

// Destination sets the $destination client metadata field.
func (qb *QueryBoundWitnessBuilder) Destination(address string) *QueryBoundWitnessBuilder {
	qb.BoundWitnessBuilder.Destination(address)
	return qb
}

// SourceQuery sets the $sourceQuery client metadata field.
func (qb *QueryBoundWitnessBuilder) SourceQuery(hash string) *QueryBoundWitnessBuilder {
	qb.BoundWitnessBuilder.SourceQuery(hash)
	return qb
}

// Timestamp sets an optional explicit epoch millisecond timestamp on the QueryBoundWitness.
func (qb *QueryBoundWitnessBuilder) Timestamp(ts int64) *QueryBoundWitnessBuilder {
	qb.BoundWitnessBuilder.Timestamp(ts)
	return qb
}

// Version sets the optional $version client metadata field.
func (qb *QueryBoundWitnessBuilder) Version(v int) *QueryBoundWitnessBuilder {
	qb.BoundWitnessBuilder.Version(v)
	return qb
}

// Participant adds an address-only participant slot for sequential cosigning.
func (qb *QueryBoundWitnessBuilder) Participant(address string, previousHash *string) *QueryBoundWitnessBuilder {
	qb.BoundWitnessBuilder.Participant(address, previousHash)
	return qb
}

// Build constructs and signs the QueryBoundWitness and returns (qbw, payloadsIncludingQuery, err).
func (qb *QueryBoundWitnessBuilder) Build() (*QueryBoundWitness, []any, error) {
	if qb.queryPayload == nil {
		return nil, nil, errors.New("query payload is required")
	}
	processBuildMutex.Lock()
	defer processBuildMutex.Unlock()

	queryDataHash, err := payload.DataHash(qb.queryPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("compute query payload dataHash: %w", err)
	}

	// Build copy of payloads ending with queryPayload (matches Android/Swift/JS wire convention)
	inner := qb.BoundWitnessBuilder
	inner.payloads = append(append([]any(nil), qb.payloads...), qb.queryPayload)

	bw, payloads, err := inner.assembleFields()
	if err != nil {
		return nil, nil, err
	}

	qbw := &QueryBoundWitness{
		BoundWitness: *bw,
		Query:        queryDataHash,
		ErrorHashes:  append([]string(nil), qb.errorHashes...),
	}

	dataHashBytes, err := qbw.DataHashBytes()
	if err != nil {
		return nil, nil, fmt.Errorf("compute QueryBoundWitness dataHash: %w", err)
	}

	sigs := make([]*string, len(inner.participants))
	if err := signParticipantsAtomic(inner.participants, dataHashBytes, sigs); err != nil {
		return nil, nil, fmt.Errorf("sign QueryBoundWitness: %w", err)
	}
	if len(sigs) > 0 {
		qbw.Signatures = sigs
	}

	return qbw, payloads, nil
}

func extractSchema(p any) (string, error) {
	if typed, ok := p.(payload.Payload); ok {
		s := typed.GetSchema()
		if s == "" {
			return "", errors.New("payload has empty schema")
		}
		return s, nil
	}
	ap, err := payload.ToAnyPayload(p)
	if err != nil {
		return "", err
	}
	s := ap.GetSchema()
	if s == "" {
		return "", errors.New("payload missing schema field")
	}
	return s, nil
}

func stringPtrEqual(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return strings.EqualFold(account.StripHexPrefix(*a), account.StripHexPrefix(*b))
}
