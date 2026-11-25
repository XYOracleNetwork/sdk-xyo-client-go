package protocol

import (
	"errors"
	"fmt"

	"github.com/XYOracleNetwork/sdk-xyo-client-go/account"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/boundwitness"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/payload"
)

// ValidateBlock validates an XL1 HydratedBlock structurally and cryptographically.
func ValidateBlock(hb *HydratedBlock) []error {
	if hb == nil || hb.BoundWitness == nil {
		return []error{errors.New("hydrated block or bound witness is nil")}
	}
	bw := hb.BoundWitness
	var errs []error
	if bw.Schema != payload.SchemaBoundWitness {
		errs = append(errs, fmt.Errorf("invalid block schema: %q", bw.Schema))
	}
	if bw.Block < 0 {
		errs = append(errs, fmt.Errorf("block number cannot be negative: %d", bw.Block))
	}
	if bw.Chain == "" {
		errs = append(errs, errors.New("block chain ID is required"))
	}
	if bw.Block > 0 && (bw.Previous == nil || *bw.Previous == "") {
		errs = append(errs, errors.New("non-genesis block must specify previous block hash"))
	}
	errs = append(errs, validateSignedChainBoundWitness(&bw.BoundWitness, bw)...)
	return errs
}

// ValidateTransaction validates an XL1 HydratedTransaction (from address, block range duration,
// gas/fees, transfer amounts, and cryptographic signatures over the TransactionBoundWitness).
func ValidateTransaction(ht *HydratedTransaction) []error {
	if ht == nil || ht.BoundWitness == nil {
		return []error{errors.New("hydrated transaction or bound witness is nil")}
	}
	tx := ht.BoundWitness
	var errs []error

	// From address validation (supports both legacy hex and post-quantum qm65 Bech32m)
	if !account.IsAddress(tx.From) {
		errs = append(errs, fmt.Errorf("invalid transaction from address: %q", tx.From))
	}

	// Chain ID
	if tx.Chain == "" {
		errs = append(errs, errors.New("transaction chain ID is required"))
	}

	// Duration validation: nbf >= 0 and exp > nbf
	if tx.Nbf < 0 {
		errs = append(errs, fmt.Errorf("transaction nbf cannot be negative: %d", tx.Nbf))
	}
	if tx.Exp <= tx.Nbf {
		errs = append(errs, fmt.Errorf("transaction exp (%d) must be greater than nbf (%d)", tx.Exp, tx.Nbf))
	}

	// Fees / Gas validation
	if _, err := tx.Fees.ToBigInt(); err != nil {
		errs = append(errs, fmt.Errorf("invalid transaction fees: %w", err))
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
				if _, err := AttoXL1FromString(amt); err != nil {
					errs = append(errs, fmt.Errorf("transfer payload[%d] invalid amount for %s: %w", i, recipient, err))
				}
			}
		}
	}

	// BoundWitness structure & cryptographic signature validation
	errs = append(errs, validateSignedChainBoundWitness(&tx.BoundWitness, tx)...)
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
	if len(base.PreviousHashes) != len(base.Addresses) {
		errs = append(errs, fmt.Errorf("previous_hashes length (%d) != addresses length (%d)", len(base.PreviousHashes), len(base.Addresses)))
	}
	if len(base.PayloadHashes) != len(base.PayloadSchemas) {
		errs = append(errs, fmt.Errorf("payload_hashes length (%d) != payload_schemas length (%d)", len(base.PayloadHashes), len(base.PayloadSchemas)))
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
