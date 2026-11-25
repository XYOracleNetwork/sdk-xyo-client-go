package protocol

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// ChainID identifies an XL1 blockchain (40-character lowercase hex address).
type ChainID string

// XL1BlockNumber represents a non-negative XL1 block height.
type XL1BlockNumber int64

// XL1BlockRange represents an inclusive [Start, End] range of XL1 block numbers.
type XL1BlockRange struct {
	Start XL1BlockNumber `json:"start"`
	End   XL1BlockNumber `json:"end"`
}

// Key formats the block range as "start|end".
func (r XL1BlockRange) Key() string {
	return fmt.Sprintf("%d|%d", r.Start, r.End)
}

// ParseBlockRange parses a "start|end" block range key.
func ParseBlockRange(key string) (XL1BlockRange, error) {
	parts := strings.Split(key, "|")
	if len(parts) != 2 {
		return XL1BlockRange{}, fmt.Errorf("invalid block range key %q", key)
	}
	start, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return XL1BlockRange{}, err
	}
	end, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return XL1BlockRange{}, err
	}
	return XL1BlockRange{Start: XL1BlockNumber(start), End: XL1BlockNumber(end)}, nil
}

// StepSizesValues holds the canonical XL1 primorial+1 step sizes.
var StepSizesValues = []int64{
	7,
	31,
	211,
	2311,
	30031,
	510511,
	9699691,
	223092871,
	6469693231,
}

// StepRewardFraction represents a rational reward fraction Numerator / Denominator.
type StepRewardFraction struct {
	Numerator   int64
	Denominator int64
}

// StepRewardFractions holds the canonical XL1 step reward fractions per step tier.
var StepRewardFractions = []StepRewardFraction{
	{0, 1},
	{0, 1},
	{0, 1},
	{1, 10000},
	{2, 1000},
	{3, 100},
	{45, 100},
}

// Stake represents a staking position on XL1.
type Stake struct {
	ID            int64  `json:"id"`
	Staker        string `json:"staker"`
	Staked        string `json:"staked"`
	Amount        string `json:"amount"`
	AddBlock      int64  `json:"addBlock"`
	RemoveBlock   *int64 `json:"removeBlock,omitempty"`
	WithdrawBlock *int64 `json:"withdrawBlock,omitempty"`
}

// Position represents a staking position with lifecycle helpers.
type Position struct {
	Stake
}

func (p Position) IsRemoved() bool   { return p.RemoveBlock != nil && *p.RemoveBlock > 0 }
func (p Position) IsWithdrawn() bool { return p.WithdrawBlock != nil && *p.WithdrawBlock > 0 }
func (p Position) IsActive() bool    { return !p.IsRemoved() && !p.IsWithdrawn() }

// ChainQualification carries the head block hash and block range qualifying an account balance query.
type ChainQualification struct {
	Head  string  `json:"head"`
	Range []int64 `json:"range,omitempty"`
}

// ChainQualified pairs a result payload with its ChainQualification metadata.
type ChainQualified[T any] struct {
	Data          T                  `json:"data"`
	Qualification ChainQualification `json:"qualification"`
}

// AccountBalanceConfig configures qualified account balance RPC queries.
type AccountBalanceConfig struct {
	Range []int64 `json:"range,omitempty"`
	Head  string  `json:"head,omitempty"`
}

// AccountBalanceHistoryItem represents a single entry in a qualified account balance history.
type AccountBalanceHistoryItem struct {
	Block   int64   `json:"block"`
	Balance AttoXL1 `json:"balance"`
	Raw     any     `json:"raw,omitempty"`
}

// BlockRate describes observed block production cadence.
type BlockRate struct {
	BlocksPerSecond float64 `json:"blocksPerSecond"`
	SecondsPerBlock float64 `json:"secondsPerBlock"`
}

// Caveat restricts a Permission scope.
type Caveat struct {
	Type  string `json:"type"`
	Value any    `json:"value,omitempty"`
}

// Permission represents a wallet/chain permission grant.
type Permission struct {
	ParentCapability string   `json:"parentCapability"`
	Invoker          string   `json:"invoker,omitempty"`
	Caveats          []Caveat `json:"caveats,omitempty"`
}

// ParseFlexibleAtto parses a balance value encoded as decimal string, 0x-hex string,
// bare hex string, or JSON number into an AttoXL1.
func ParseFlexibleAtto(raw any) (AttoXL1, error) {
	switch v := raw.(type) {
	case string:
		return AttoXL1FromString(v)
	case float64:
		return NewAttoXL1(big.NewInt(int64(v)))
	case int64:
		return NewAttoXL1Int64(v)
	case int:
		return NewAttoXL1Int64(int64(v))
	default:
		return AttoXL1FromString(fmt.Sprintf("%v", raw))
	}
}
