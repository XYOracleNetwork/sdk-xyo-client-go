package boundwitness

import (
	"errors"
	"fmt"

	"github.com/XYOracleNetwork/sdk-xyo-client-go/account"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/payload"
)

// ValidateBoundWitness performs full structural and cryptographic validation of a BoundWitness,
// supporting both secp256k1 (40-char hex) and ML-DSA-65 (qm65 Bech32m) addresses and signatures.
func ValidateBoundWitness(bw *BoundWitness) []error {
	if bw == nil {
		return []error{errors.New("bound witness is nil")}
	}
	return validateBoundWitnessCore(bw, bw)
}

// ValidateQueryBoundWitness validates a QueryBoundWitness including its "query" field and signatures
// over the QueryBoundWitness's full dataHash.
func ValidateQueryBoundWitness(qbw *QueryBoundWitness) []error {
	if qbw == nil {
		return []error{errors.New("query bound witness is nil")}
	}
	errs := validateBoundWitnessCore(&qbw.BoundWitness, qbw)
	if qbw.Query == "" {
		errs = append(errs, errors.New("query bound witness missing query hash"))
	} else if !isValidHashHex(qbw.Query) {
		errs = append(errs, fmt.Errorf("invalid query hash: %q", qbw.Query))
	}
	for i, eh := range qbw.ErrorHashes {
		if !isValidHashHex(eh) {
			errs = append(errs, fmt.Errorf("invalid error_hashes[%d]: %q", i, eh))
		}
	}
	return errs
}

func validateBoundWitnessCore(bw *BoundWitness, hashTarget any) []error {
	var errs []error

	if bw.Schema != SchemaBoundWitness {
		errs = append(errs, fmt.Errorf("invalid bound witness schema: got %q, want %q", bw.Schema, SchemaBoundWitness))
	}

	if len(bw.Addresses) == 0 {
		errs = append(errs, errors.New("bound witness must have at least one address"))
	}

	seenAddr := make(map[string]struct{}, len(bw.Addresses))
	for i, addr := range bw.Addresses {
		norm, err := account.NormalizeAddress(addr)
		if err != nil {
			errs = append(errs, fmt.Errorf("addresses[%d] invalid XYO address: %q", i, addr))
			continue
		}
		if _, dup := seenAddr[norm]; dup {
			errs = append(errs, fmt.Errorf("duplicate address in bound witness: %s", addr))
		}
		seenAddr[norm] = struct{}{}
	}

	if len(bw.PreviousHashes) != len(bw.Addresses) {
		errs = append(errs, fmt.Errorf("previous_hashes length (%d) != addresses length (%d)", len(bw.PreviousHashes), len(bw.Addresses)))
	}
	for i, ph := range bw.PreviousHashes {
		if ph != nil && !isValidHashHex(*ph) {
			errs = append(errs, fmt.Errorf("invalid previous_hashes[%d]: %q", i, *ph))
		}
	}

	if len(bw.PayloadHashes) != len(bw.PayloadSchemas) {
		errs = append(errs, fmt.Errorf("payload_hashes length (%d) != payload_schemas length (%d)", len(bw.PayloadHashes), len(bw.PayloadSchemas)))
	}
	for i, h := range bw.PayloadHashes {
		if !isValidHashHex(h) {
			errs = append(errs, fmt.Errorf("invalid payload_hashes[%d]: %q", i, h))
		}
	}

	for i, s := range bw.PayloadSchemas {
		if err := payload.ValidateSchemaName(s); err != nil {
			errs = append(errs, fmt.Errorf("payload_schemas[%d]: %w", i, err))
		}
	}

	if len(bw.Signatures) != len(bw.Addresses) {
		errs = append(errs, fmt.Errorf("$signatures length (%d) != addresses length (%d)", len(bw.Signatures), len(bw.Addresses)))
		return errs
	}

	dataHashHex, err := payload.DataHash(hashTarget)
	if err != nil {
		errs = append(errs, fmt.Errorf("compute bound witness dataHash: %w", err))
		return errs
	}

	for i, addr := range bw.Addresses {
		sigPtr := bw.Signatures[i]
		if sigPtr == nil || *sigPtr == "" {
			errs = append(errs, fmt.Errorf("missing signature at index %d for address %s", i, addr))
			continue
		}
		if !account.VerifySignatureHex(addr, dataHashHex, *sigPtr) {
			errs = append(errs, fmt.Errorf("invalid signature at index %d for address %s", i, addr))
		}
	}

	return errs
}

func isValidHashHex(h string) bool {
	clean := account.StripHexPrefix(h)
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
