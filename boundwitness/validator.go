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
	} else {
		found := false
		for _, h := range qbw.PayloadHashes {
			if h == qbw.Query {
				found = true
				break
			}
		}
		if !found {
			// Note: Query is dataHash while payload_hashes contains root hash; they match when query has no $ meta.
			// We only require Query to be a 64-char hex string.
			if len(qbw.Query) != 64 {
				errs = append(errs, fmt.Errorf("invalid query hash length: %d", len(qbw.Query)))
			}
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
		if !account.IsAddress(addr) {
			errs = append(errs, fmt.Errorf("addresses[%d] invalid XYO address: %q", i, addr))
		}
		if _, dup := seenAddr[addr]; dup {
			errs = append(errs, fmt.Errorf("duplicate address in bound witness: %s", addr))
		}
		seenAddr[addr] = struct{}{}
	}

	if len(bw.PreviousHashes) != len(bw.Addresses) {
		errs = append(errs, fmt.Errorf("previous_hashes length (%d) != addresses length (%d)", len(bw.PreviousHashes), len(bw.Addresses)))
	}

	if len(bw.PayloadHashes) != len(bw.PayloadSchemas) {
		errs = append(errs, fmt.Errorf("payload_hashes length (%d) != payload_schemas length (%d)", len(bw.PayloadHashes), len(bw.PayloadSchemas)))
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
