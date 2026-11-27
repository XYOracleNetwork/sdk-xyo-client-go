package protocol

import (
	"fmt"
	"math/big"

	"github.com/XYOracleNetwork/sdk-xyo-client-go/account"
)

// AddressWrapper wraps an XYO address with validation and normalization helpers
// (matching Android protocol/wrapper/AddressWrapper).
type AddressWrapper struct {
	raw string
}

// WrapAddress creates an AddressWrapper for raw.
func WrapAddress(raw string) AddressWrapper {
	return AddressWrapper{raw: raw}
}

// Raw returns the original unnormalized address string.
func (w AddressWrapper) Raw() string { return w.raw }

// IsValid reports whether the wrapped address is a valid legacy hex or quant Bech32m address.
func (w AddressWrapper) IsValid() bool { return account.IsAddress(w.raw) }

// IsLegacy reports whether the wrapped address is a 40-char hex secp256k1 address.
func (w AddressWrapper) IsLegacy() bool { return account.IsLegacyAddress(w.raw) }

// IsQuant reports whether the wrapped address is a lowercase Bech32m qm65 address.
func (w AddressWrapper) IsQuant() bool { return account.IsQuantAddress(w.raw) }

// Normalized returns the canonical lowercase address string (without 0x prefix).
func (w AddressWrapper) Normalized() (string, error) { return account.NormalizeAddress(w.raw) }

// Bytes returns the 20-byte address payload.
func (w AddressWrapper) Bytes() ([]byte, error) { return account.AddressBytes(w.raw) }

// FeesWrapper wraps TransactionFeesBigInt with AttoXL1 accessors and total fee computation
// (matching Android protocol/wrapper/FeesWrapper).
type FeesWrapper struct {
	Fees TransactionFeesBigInt
}

// WrapFees wraps a TransactionFeesBigInt.
func WrapFees(fees TransactionFeesBigInt) FeesWrapper {
	return FeesWrapper{Fees: fees}
}

// FeesWrapperFromBigInts constructs a FeesWrapper from four *big.Int values.
func FeesWrapperFromBigInts(base, gasLimit, gasPrice, priority *big.Int) (FeesWrapper, error) {
	b, err := NewAttoXL1(base)
	if err != nil {
		return FeesWrapper{}, fmt.Errorf("base fee: %w", err)
	}
	gl, err := NewAttoXL1(gasLimit)
	if err != nil {
		return FeesWrapper{}, fmt.Errorf("gasLimit: %w", err)
	}
	gp, err := NewAttoXL1(gasPrice)
	if err != nil {
		return FeesWrapper{}, fmt.Errorf("gasPrice: %w", err)
	}
	pr, err := NewAttoXL1(priority)
	if err != nil {
		return FeesWrapper{}, fmt.Errorf("priority fee: %w", err)
	}
	return FeesWrapper{
		Fees: TransactionFeesBigInt{
			Base:     b,
			GasLimit: gl,
			GasPrice: gp,
			Priority: pr,
		},
	}, nil
}

func (w FeesWrapper) Base() AttoXL1     { return w.Fees.Base }
func (w FeesWrapper) GasLimit() AttoXL1 { return w.Fees.GasLimit }
func (w FeesWrapper) GasPrice() AttoXL1 { return w.Fees.GasPrice }
func (w FeesWrapper) Priority() AttoXL1 { return w.Fees.Priority }

// Total returns base + (gasLimit * gasPrice) + priority as an AttoXL1.
func (w FeesWrapper) Total() (AttoXL1, error) {
	return NewAttoXL1(w.Fees.Total())
}

func (w FeesWrapper) String() string {
	return fmt.Sprintf("Fees(base=%s, gasLimit=%s, gasPrice=%s, priority=%s, total=%s)",
		w.Fees.Base.String(),
		w.Fees.GasLimit.String(),
		w.Fees.GasPrice.String(),
		w.Fees.Priority.String(),
		w.Fees.Total().String(),
	)
}

// HydratedTransactionWrapper wraps a HydratedTransaction with block-range validity checks
// and convenient field accessors (matching Android protocol/wrapper/HydratedTransactionWrapper).
type HydratedTransactionWrapper struct {
	Transaction *HydratedTransaction
}

// WrapTransaction wraps a HydratedTransaction.
func WrapTransaction(tx *HydratedTransaction) HydratedTransactionWrapper {
	return HydratedTransactionWrapper{Transaction: tx}
}

func (w HydratedTransactionWrapper) BoundWitness() *TransactionBoundWitness {
	if w.Transaction == nil {
		return nil
	}
	return w.Transaction.BoundWitness
}

func (w HydratedTransactionWrapper) Payloads() []any {
	if w.Transaction == nil {
		return nil
	}
	return w.Transaction.Payloads
}

func (w HydratedTransactionWrapper) From() string {
	if bw := w.BoundWitness(); bw != nil {
		return bw.From
	}
	return ""
}

func (w HydratedTransactionWrapper) Chain() ChainID {
	if bw := w.BoundWitness(); bw != nil {
		return bw.Chain
	}
	return ""
}

func (w HydratedTransactionWrapper) Nbf() XL1BlockNumber {
	if bw := w.BoundWitness(); bw != nil {
		return XL1BlockNumber(bw.Nbf)
	}
	return 0
}

func (w HydratedTransactionWrapper) Exp() XL1BlockNumber {
	if bw := w.BoundWitness(); bw != nil {
		return XL1BlockNumber(bw.Exp)
	}
	return 0
}

func (w HydratedTransactionWrapper) Fees() (FeesWrapper, error) {
	bw := w.BoundWitness()
	if bw == nil {
		return FeesWrapper{}, fmt.Errorf("transaction bound witness is nil")
	}
	bigFees, err := bw.Fees.ToBigInt()
	if err != nil {
		return FeesWrapper{}, err
	}
	return WrapFees(bigFees), nil
}

// IsExpiredAt reports whether the transaction has expired at block (block >= exp).
func (w HydratedTransactionWrapper) IsExpiredAt(block XL1BlockNumber) bool {
	bw := w.BoundWitness()
	if bw == nil {
		return true
	}
	return int64(block) >= bw.Exp
}

// IsValidAt reports whether the transaction is within its active block window [nbf, exp) at block.
func (w HydratedTransactionWrapper) IsValidAt(block XL1BlockNumber) bool {
	bw := w.BoundWitness()
	if bw == nil {
		return false
	}
	return int64(block) >= bw.Nbf && !w.IsExpiredAt(block)
}
