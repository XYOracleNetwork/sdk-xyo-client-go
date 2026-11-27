package protocol

import (
	"errors"
	"fmt"
	"strings"

	"github.com/XYOracleNetwork/sdk-xyo-client-go/account"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/boundwitness"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/payload"
)

// ValidationError is a structured XL1 protocol validation error with a machine-readable Code
// (matching Android network.xyo.chain.protocol.validation.ValidationError).
type ValidationError struct {
	Code    string
	Message string
}

func (e ValidationError) Error() string {
	if e.Code == "" {
		return e.Message
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// BlockValidator validates an XL1 BlockBoundWitness and returns any ValidationErrors.
type BlockValidator func(block *BlockBoundWitness) []ValidationError

// TransactionValidator validates an XL1 TransactionBoundWitness and returns any ValidationErrors.
type TransactionValidator func(tx *TransactionBoundWitness) []ValidationError

// BlockCumulativeBalanceValidator validates core XL1 block invariants (non-negative block number,
// chain presence, genesis vs non-genesis previous hash, and signer addresses).
func BlockCumulativeBalanceValidator(block *BlockBoundWitness) []ValidationError {
	if block == nil {
		return []ValidationError{{Code: "NIL_BLOCK", Message: "block bound witness is nil"}}
	}
	var errs []ValidationError
	if block.Block < 0 {
		errs = append(errs, ValidationError{Code: "INVALID_BLOCK_NUMBER", Message: fmt.Sprintf("block number must be non-negative: %d", block.Block)})
	}
	if strings.TrimSpace(string(block.Chain)) == "" {
		errs = append(errs, ValidationError{Code: "MISSING_CHAIN", Message: "block must specify a chain"})
	}
	if block.Block == 0 && block.Previous != nil && *block.Previous != "" {
		errs = append(errs, ValidationError{Code: "INVALID_GENESIS_PREVIOUS", Message: "genesis block (block 0) must not specify a previous hash"})
	}
	if block.Block > 0 {
		if block.Previous == nil || *block.Previous == "" {
			errs = append(errs, ValidationError{Code: "MISSING_PREVIOUS", Message: "non-genesis block must specify previous block hash"})
		} else if !isHex64(*block.Previous) {
			errs = append(errs, ValidationError{Code: "INVALID_PREVIOUS", Message: fmt.Sprintf("invalid previous block hash: %q", *block.Previous)})
		}
	}
	if len(block.Addresses) == 0 {
		errs = append(errs, ValidationError{Code: "MISSING_ADDRESSES", Message: "block must have at least one signer address"})
	}
	return errs
}

// TransactionDurationValidator validates nbf >= 0, exp >= 0, and exp > nbf.
func TransactionDurationValidator(tx *TransactionBoundWitness) []ValidationError {
	if tx == nil {
		return []ValidationError{{Code: "NIL_TRANSACTION", Message: "transaction bound witness is nil"}}
	}
	var errs []ValidationError
	if tx.Nbf < 0 {
		errs = append(errs, ValidationError{Code: "INVALID_NBF", Message: fmt.Sprintf("nbf (not before block) must be non-negative: %d", tx.Nbf)})
	}
	if tx.Exp < 0 {
		errs = append(errs, ValidationError{Code: "INVALID_EXP", Message: fmt.Sprintf("exp (expiration block) must be non-negative: %d", tx.Exp)})
	}
	if tx.Exp <= tx.Nbf {
		errs = append(errs, ValidationError{Code: "INVALID_DURATION", Message: fmt.Sprintf("exp (%d) must be greater than nbf (%d)", tx.Exp, tx.Nbf)})
	}
	return errs
}

// TransactionFromValidator validates that from is a valid XYO address (legacy or quant)
// and that at least one signer address is present and matches from.
func TransactionFromValidator(tx *TransactionBoundWitness) []ValidationError {
	if tx == nil {
		return []ValidationError{{Code: "NIL_TRANSACTION", Message: "transaction bound witness is nil"}}
	}
	var errs []ValidationError
	var normFrom string
	if strings.TrimSpace(tx.From) == "" {
		errs = append(errs, ValidationError{Code: "MISSING_FROM", Message: "transaction must have a 'from' address"})
	} else {
		nf, err := account.NormalizeAddress(tx.From)
		if err != nil {
			errs = append(errs, ValidationError{Code: "INVALID_FROM", Message: fmt.Sprintf("invalid 'from' address format: %q", tx.From)})
		} else {
			normFrom = nf
		}
	}
	if len(tx.Addresses) == 0 {
		errs = append(errs, ValidationError{Code: "MISSING_ADDRESSES", Message: "transaction must have at least one signer address"})
	} else if normFrom != "" {
		foundFrom := false
		for _, a := range tx.Addresses {
			if na, err := account.NormalizeAddress(a); err == nil && na == normFrom {
				foundFrom = true
				break
			}
		}
		if !foundFrom {
			errs = append(errs, ValidationError{Code: "FROM_NOT_SIGNER", Message: fmt.Sprintf("'from' address %s must be present in transaction signer addresses", normFrom)})
		}
	}
	return errs
}

// TransactionGasValidator validates transaction fee hex formatting and gasLimit > 0.
func TransactionGasValidator(tx *TransactionBoundWitness) []ValidationError {
	if tx == nil {
		return []ValidationError{{Code: "NIL_TRANSACTION", Message: "transaction bound witness is nil"}}
	}
	fees, err := tx.Fees.ToBigInt()
	if err != nil {
		return []ValidationError{{Code: "INVALID_FEES", Message: fmt.Sprintf("invalid fee hex format: %v", err)}}
	}
	var errs []ValidationError
	if fees.GasLimit.BigInt().Sign() <= 0 {
		errs = append(errs, ValidationError{Code: "INVALID_GAS_LIMIT", Message: "gasLimit must be positive"})
	}
	return errs
}

// TransactionTransfersValidator validates payload hash/schema alignment and chain presence.
func TransactionTransfersValidator(tx *TransactionBoundWitness) []ValidationError {
	if tx == nil {
		return []ValidationError{{Code: "NIL_TRANSACTION", Message: "transaction bound witness is nil"}}
	}
	var errs []ValidationError
	if len(tx.PayloadHashes) != len(tx.PayloadSchemas) {
		errs = append(errs, ValidationError{
			Code:    "PAYLOAD_MISMATCH",
			Message: fmt.Sprintf("payload_hashes length (%d) must match payload_schemas length (%d)", len(tx.PayloadHashes), len(tx.PayloadSchemas)),
		})
	}
	if strings.TrimSpace(string(tx.Chain)) == "" {
		errs = append(errs, ValidationError{Code: "MISSING_CHAIN", Message: "transaction must specify a chain"})
	}
	return errs
}

// ValidateBlockWith runs cryptographic bound-witness validation plus the provided modular BlockValidators.
func ValidateBlockWith(block *BlockBoundWitness, validators ...BlockValidator) []ValidationError {
	if block == nil {
		return []ValidationError{{Code: "NIL_BLOCK", Message: "block bound witness is nil"}}
	}
	var out []ValidationError
	for _, err := range validateSignedChainBoundWitness(&block.BoundWitness, block) {
		out = append(out, ValidationError{Code: "BOUND_WITNESS_INVALID", Message: err.Error()})
	}
	for _, v := range validators {
		if v != nil {
			out = append(out, v(block)...)
		}
	}
	return out
}

// ValidateTransactionWith runs cryptographic bound-witness validation plus the provided modular TransactionValidators.
func ValidateTransactionWith(tx *TransactionBoundWitness, validators ...TransactionValidator) []ValidationError {
	if tx == nil {
		return []ValidationError{{Code: "NIL_TRANSACTION", Message: "transaction bound witness is nil"}}
	}
	var out []ValidationError
	for _, err := range validateSignedChainBoundWitness(&tx.BoundWitness, tx) {
		out = append(out, ValidationError{Code: "BOUND_WITNESS_INVALID", Message: err.Error()})
	}
	for _, v := range validators {
		if v != nil {
			out = append(out, v(tx)...)
		}
	}
	return out
}

// ValidateBlock validates an XL1 HydratedBlock structurally and cryptographically.
func ValidateBlock(hb *HydratedBlock) []error {
	if hb == nil || hb.BoundWitness == nil {
		return []error{errors.New("hydrated block or bound witness is nil")}
	}
	bw := hb.BoundWitness
	var errs []error
	for _, ve := range BlockCumulativeBalanceValidator(bw) {
		errs = append(errs, ve)
	}
	errs = append(errs, validateSignedChainBoundWitness(&bw.BoundWitness, bw)...)
	if len(hb.Payloads) > 0 {
		errs = append(errs, validateHydratedPayloadsMatch(&bw.BoundWitness, anyPayloadSliceToAny(hb.Payloads))...)
	}
	return errs
}

// ValidateTransaction validates an XL1 HydratedTransaction (from address, block range duration,
// gas/fees, transfer amounts, payload integrity, and cryptographic signatures).
func ValidateTransaction(ht *HydratedTransaction) []error {
	if ht == nil || ht.BoundWitness == nil {
		return []error{errors.New("hydrated transaction or bound witness is nil")}
	}
	tx := ht.BoundWitness
	var errs []error

	for _, ve := range TransactionFromValidator(tx) {
		errs = append(errs, ve)
	}
	for _, ve := range TransactionDurationValidator(tx) {
		errs = append(errs, ve)
	}
	for _, ve := range TransactionGasValidator(tx) {
		errs = append(errs, ve)
	}
	for _, ve := range TransactionTransfersValidator(tx) {
		errs = append(errs, ve)
	}

	// Transfer payloads validation
	for i, p := range ht.Payloads {
		ap, err := payload.ToAnyPayload(p)
		if err != nil {
			errs = append(errs, fmt.Errorf("payload[%d]: %w", i, err))
			continue
		}
		if ap.GetSchema() == payload.SchemaTransfer {
			var tp TransferPayload
			if err := ap.DecodeInto(&tp); err != nil {
				errs = append(errs, fmt.Errorf("transfer payload[%d]: %w", i, err))
				continue
			}
			if tp.From != "" && !account.IsAddress(tp.From) {
				errs = append(errs, fmt.Errorf("transfer payload[%d] invalid from address: %q", i, tp.From))
			}
			for recipient, amt := range tp.Transfers {
				if !account.IsAddress(recipient) {
					errs = append(errs, fmt.Errorf("transfer payload[%d] invalid recipient: %q", i, recipient))
				}
				if _, err := AttoXL1FromHex(amt); err != nil {
					errs = append(errs, fmt.Errorf("transfer payload[%d] invalid hex amount for %s: %w", i, recipient, err))
				}
			}
		}
	}

	if len(ht.Payloads) > 0 {
		errs = append(errs, validateHydratedPayloadsMatch(&tx.BoundWitness, ht.Payloads)...)
	}

	// BoundWitness structure & cryptographic signature validation
	errs = append(errs, validateSignedChainBoundWitness(&tx.BoundWitness, tx)...)
	return errs
}

func validateHydratedPayloadsMatch(base *boundwitness.BoundWitness, payloads []any) []error {
	if len(base.PayloadHashes) == 0 {
		return nil
	}
	present := make(map[string]string, len(payloads)*2)
	for _, p := range payloads {
		ap, err := payload.ToAnyPayload(p)
		if err != nil {
			continue
		}
		schema := ap.GetSchema()
		if h, err := payload.Hash(p); err == nil {
			present[h] = schema
		}
		if dh, err := payload.DataHash(p); err == nil {
			if _, exists := present[dh]; !exists {
				present[dh] = schema
			}
		}
	}
	var errs []error
	for i, h := range base.PayloadHashes {
		if gotSchema, ok := present[strings.ToLower(account.StripHexPrefix(h))]; ok {
			if i < len(base.PayloadSchemas) && gotSchema != base.PayloadSchemas[i] {
				errs = append(errs, fmt.Errorf("payload[%d] schema mismatch: payload has %q, bound witness declares %q", i, gotSchema, base.PayloadSchemas[i]))
			}
		}
	}
	return errs
}

func validateSignedChainBoundWitness(base *boundwitness.BoundWitness, fullTarget any) []error {
	var errs []error
	if base.Schema != payload.SchemaBoundWitness {
		errs = append(errs, fmt.Errorf("invalid bound witness schema: %q", base.Schema))
	}
	if len(base.Addresses) == 0 {
		errs = append(errs, errors.New("bound witness must have at least one signer address"))
		return errs
	}
	seenAddr := make(map[string]struct{}, len(base.Addresses))
	for i, addr := range base.Addresses {
		norm, err := account.NormalizeAddress(addr)
		if err != nil {
			errs = append(errs, fmt.Errorf("addresses[%d] invalid XYO address: %q", i, addr))
			continue
		}
		if _, dup := seenAddr[norm]; dup {
			errs = append(errs, fmt.Errorf("duplicate signer address: %s", addr))
		}
		seenAddr[norm] = struct{}{}
	}
	if len(base.PreviousHashes) != len(base.Addresses) {
		errs = append(errs, fmt.Errorf("previous_hashes length (%d) != addresses length (%d)", len(base.PreviousHashes), len(base.Addresses)))
	}
	if len(base.PayloadHashes) != len(base.PayloadSchemas) {
		errs = append(errs, fmt.Errorf("payload_hashes length (%d) != payload_schemas length (%d)", len(base.PayloadHashes), len(base.PayloadSchemas)))
	}
	for i, s := range base.PayloadSchemas {
		if err := payload.ValidateSchemaName(s); err != nil {
			errs = append(errs, fmt.Errorf("payload_schemas[%d]: %w", i, err))
		}
	}
	if len(base.Signatures) != len(base.Addresses) {
		errs = append(errs, fmt.Errorf("$signatures length (%d) != addresses length (%d)", len(base.Signatures), len(base.Addresses)))
		return errs
	}
	dataHashHex, err := payload.DataHash(fullTarget)
	if err != nil {
		errs = append(errs, fmt.Errorf("compute dataHash: %w", err))
		return errs
	}
	for i, addr := range base.Addresses {
		sig := base.Signatures[i]
		if sig == nil || *sig == "" {
			errs = append(errs, fmt.Errorf("missing signature at index %d", i))
			continue
		}
		if !account.VerifySignatureHex(addr, dataHashHex, *sig) {
			errs = append(errs, fmt.Errorf("invalid signature at index %d for address %s", i, addr))
		}
	}
	return errs
}

func isHex64(s string) bool {
	clean := account.StripHexPrefix(strings.TrimSpace(s))
	if len(clean) != 64 {
		return false
	}
	for i := 0; i < len(clean); i++ {
		c := clean[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func anyPayloadSliceToAny(in []payload.AnyPayload) []any {
	out := make([]any, len(in))
	for i, p := range in {
		out[i] = p
	}
	return out
}
