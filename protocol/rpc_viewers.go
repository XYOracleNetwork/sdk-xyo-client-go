package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/XYOracleNetwork/sdk-xyo-client-go/payload"
)

// BlockViewer queries XL1 blocks and block payloads over JSON-RPC.
type BlockViewer struct {
	transport RPCTransport
}

func NewBlockViewer(t RPCTransport) *BlockViewer { return &BlockViewer{transport: t} }

func (v *BlockViewer) CurrentBlock(ctx context.Context) (*HydratedBlock, error) {
	raw, err := v.transport.CallRaw(ctx, RPCMethodBlockViewerCurrentBlock)
	if err != nil || isJSONNull(raw) {
		return nil, err
	}
	var out HydratedBlock
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (v *BlockViewer) BlocksByHash(ctx context.Context, hash string, limit ...int) ([]HydratedBlock, error) {
	params := []any{hash}
	if len(limit) > 0 {
		params = append(params, limit[0])
	}
	var out []HydratedBlock
	if err := v.transport.Call(ctx, RPCMethodBlockViewerBlocksByHash, &out, params...); err != nil {
		return nil, err
	}
	return out, nil
}

func (v *BlockViewer) BlocksByNumber(ctx context.Context, blockNumber XL1BlockNumber, limit ...int) ([]HydratedBlock, error) {
	params := []any{int64(blockNumber)}
	if len(limit) > 0 {
		params = append(params, limit[0])
	}
	var out []HydratedBlock
	if err := v.transport.Call(ctx, RPCMethodBlockViewerBlocksByNumber, &out, params...); err != nil {
		return nil, err
	}
	return out, nil
}

func (v *BlockViewer) PayloadsByHash(ctx context.Context, hashes []string) ([]payload.AnyPayload, error) {
	var out []payload.AnyPayload
	if err := v.transport.Call(ctx, RPCMethodBlockViewerPayloadsByHash, &out, hashes); err != nil {
		return nil, err
	}
	return out, nil
}

// TransactionViewer queries XL1 transactions by hash or block position.
type TransactionViewer struct {
	transport RPCTransport
}

func NewTransactionViewer(t RPCTransport) *TransactionViewer { return &TransactionViewer{transport: t} }

func (v *TransactionViewer) ByHash(ctx context.Context, hash string) (*HydratedTransaction, error) {
	raw, err := v.transport.CallRaw(ctx, RPCMethodTransactionViewerByHash, hash)
	if err != nil || len(raw) == 0 || string(raw) == "null" {
		return nil, err
	}
	var out HydratedTransaction
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (v *TransactionViewer) TransactionByHash(ctx context.Context, hash string) (*HydratedTransaction, error) {
	raw, err := v.transport.CallRaw(ctx, RPCMethodTransactionViewerTransactionByHash, hash)
	if err != nil || len(raw) == 0 || string(raw) == "null" {
		return nil, err
	}
	var out HydratedTransaction
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (v *TransactionViewer) TransactionByBlockHashAndIndex(ctx context.Context, blockHash string, index int) (*HydratedTransaction, error) {
	raw, err := v.transport.CallRaw(ctx, RPCMethodTransactionViewerTransactionByBlockHashAndIndex, blockHash, index)
	if err != nil || len(raw) == 0 || string(raw) == "null" {
		return nil, err
	}
	var out HydratedTransaction
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (v *TransactionViewer) TransactionByBlockNumberAndIndex(ctx context.Context, blockNumber XL1BlockNumber, index int) (*HydratedTransaction, error) {
	raw, err := v.transport.CallRaw(ctx, RPCMethodTransactionViewerTransactionByBlockNumAndIndex, int64(blockNumber), index)
	if err != nil || len(raw) == 0 || string(raw) == "null" {
		return nil, err
	}
	var out HydratedTransaction
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AccountBalanceViewer queries qualified XL1 account balances and histories.
type AccountBalanceViewer struct {
	transport RPCTransport
}

func NewAccountBalanceViewer(t RPCTransport) *AccountBalanceViewer {
	return &AccountBalanceViewer{transport: t}
}

func (v *AccountBalanceViewer) QualifiedAccountBalances(
	ctx context.Context,
	addresses []string,
	config *AccountBalanceConfig,
) (*ChainQualified[map[string]AttoXL1], error) {
	params := []any{addresses}
	if config != nil {
		params = append(params, config)
	}
	raw, err := v.transport.CallRaw(ctx, RPCMethodAccountBalanceViewerQualifiedBalances, params...)
	if err != nil {
		return nil, err
	}
	// Wire format is 2-element tuple: [ { addr: "0x..." | "123" }, { head: "...", range: [start, end] } ]
	var tuple []json.RawMessage
	if err := json.Unmarshal(raw, &tuple); err != nil {
		return nil, fmt.Errorf("decode qualifiedAccountBalances tuple: %w", err)
	}
	if len(tuple) < 2 {
		return nil, errors.New("qualifiedAccountBalances response must be a 2-element tuple")
	}
	var rawBalances map[string]any
	if err := decodeJSONUseNumber(tuple[0], &rawBalances); err != nil {
		return nil, fmt.Errorf("decode balances map: %w", err)
	}
	balances := make(map[string]AttoXL1, len(rawBalances))
	for addr, val := range rawBalances {
		atto, err := ParseFlexibleAtto(val)
		if err != nil {
			return nil, fmt.Errorf("parse balance for %s: %w", addr, err)
		}
		balances[addr] = atto
	}
	var qual ChainQualification
	if err := json.Unmarshal(tuple[1], &qual); err != nil {
		return nil, fmt.Errorf("decode balance qualification: %w", err)
	}
	return &ChainQualified[map[string]AttoXL1]{
		Data:          balances,
		Qualification: qual,
	}, nil
}

func (v *AccountBalanceViewer) QualifiedAccountBalanceHistories(
	ctx context.Context,
	addresses []string,
	config *AccountBalanceConfig,
) (*ChainQualified[map[string][]AccountBalanceHistoryItem], error) {
	params := []any{addresses}
	if config != nil {
		params = append(params, config)
	}
	raw, err := v.transport.CallRaw(ctx, RPCMethodAccountBalanceViewerQualifiedBalanceHistories, params...)
	if err != nil {
		return nil, err
	}
	var tuple []json.RawMessage
	if err := json.Unmarshal(raw, &tuple); err != nil {
		return nil, err
	}
	if len(tuple) < 2 {
		return nil, errors.New("qualifiedAccountBalanceHistories response must be a 2-element tuple")
	}
	var rawHistories map[string][]json.RawMessage
	if err := json.Unmarshal(tuple[0], &rawHistories); err != nil {
		return nil, err
	}
	histories := make(map[string][]AccountBalanceHistoryItem, len(rawHistories))
	for addr, entries := range rawHistories {
		items := make([]AccountBalanceHistoryItem, 0, len(entries))
		for _, entry := range entries {
			var item AccountBalanceHistoryItem
			if uErr := json.Unmarshal(entry, &item); uErr == nil && (item.Block != 0 || item.Balance.BigInt().Sign() != 0) {
				items = append(items, item)
			} else {
				var anyVal any
				_ = decodeJSONUseNumber(entry, &anyVal)
				items = append(items, AccountBalanceHistoryItem{Raw: anyVal})
			}
		}
		histories[addr] = items
	}
	var qual ChainQualification
	if err := json.Unmarshal(tuple[1], &qual); err != nil {
		return nil, err
	}
	return &ChainQualified[map[string][]AccountBalanceHistoryItem]{
		Data:          histories,
		Qualification: qual,
	}, nil
}

// FinalizationViewer queries the finalized head block.
type FinalizationViewer struct {
	transport RPCTransport
}

func NewFinalizationViewer(t RPCTransport) *FinalizationViewer {
	return &FinalizationViewer{transport: t}
}

func (v *FinalizationViewer) Head(ctx context.Context) (*HydratedBlock, error) {
	raw, err := v.transport.CallRaw(ctx, RPCMethodFinalizationViewerHead)
	if err != nil || isJSONNull(raw) {
		return nil, err
	}
	var out HydratedBlock
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// MempoolViewer queries pending transactions and blocks in the mempool.
type MempoolViewer struct {
	transport RPCTransport
}

func NewMempoolViewer(t RPCTransport) *MempoolViewer { return &MempoolViewer{transport: t} }

func (v *MempoolViewer) PendingTransactions(ctx context.Context, options ...any) ([]HydratedTransaction, error) {
	var out []HydratedTransaction
	if err := v.transport.Call(ctx, RPCMethodMempoolViewerPendingTransactions, &out, options...); err != nil {
		return nil, err
	}
	return out, nil
}

func (v *MempoolViewer) PendingBlocks(ctx context.Context, options ...any) ([]HydratedBlock, error) {
	var out []HydratedBlock
	if err := v.transport.Call(ctx, RPCMethodMempoolViewerPendingBlocks, &out, options...); err != nil {
		return nil, err
	}
	return out, nil
}

// TimeSyncViewer converts and queries time across XL1, epoch, and Ethereum domains.
type TimeSyncViewer struct {
	transport RPCTransport
}

func NewTimeSyncViewer(t RPCTransport) *TimeSyncViewer { return &TimeSyncViewer{transport: t} }

func (v *TimeSyncViewer) ConvertTime(ctx context.Context, fromDomain, toDomain string, value int64) (int64, error) {
	var out int64
	if err := v.transport.Call(ctx, RPCMethodTimeSyncViewerConvertTime, &out, fromDomain, toDomain, value); err != nil {
		return 0, err
	}
	return out, nil
}

func (v *TimeSyncViewer) CurrentTime(ctx context.Context, domain string) (string, int64, error) {
	var tuple []json.RawMessage
	if err := v.transport.Call(ctx, RPCMethodTimeSyncViewerCurrentTime, &tuple, domain); err != nil {
		return "", 0, err
	}
	if len(tuple) < 2 {
		return "", 0, errors.New("currentTime response must be a 2-element tuple [domain, value]")
	}
	var dom string
	var val int64
	if err := json.Unmarshal(tuple[0], &dom); err != nil {
		return "", 0, err
	}
	if err := json.Unmarshal(tuple[1], &val); err != nil {
		return "", 0, err
	}
	return dom, val, nil
}

func (v *TimeSyncViewer) CurrentTimeAndHash(ctx context.Context, domain string) (int64, string, error) {
	var tuple []json.RawMessage
	if err := v.transport.Call(ctx, RPCMethodTimeSyncViewerCurrentTimeAndHash, &tuple, domain); err != nil {
		return 0, "", err
	}
	if len(tuple) < 2 {
		return 0, "", errors.New("currentTimeAndHash response must be a 2-element tuple [value, hash]")
	}
	var val int64
	var hash string
	if err := json.Unmarshal(tuple[0], &val); err != nil {
		return 0, "", err
	}
	if err := json.Unmarshal(tuple[1], &hash); err != nil {
		return 0, "", err
	}
	return val, hash, nil
}

func (v *TimeSyncViewer) CurrentTimePayload(ctx context.Context) (*TimePayload, error) {
	raw, err := v.transport.CallRaw(ctx, RPCMethodTimeSyncViewerCurrentTimePayload)
	if err != nil || isJSONNull(raw) {
		return nil, err
	}
	var out TimePayload
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// StakeViewer queries staking positions and contract parameters.
type StakeViewer struct {
	transport RPCTransport
}

func NewStakeViewer(t RPCTransport) *StakeViewer { return &StakeViewer{transport: t} }

func (v *StakeViewer) StakeByID(ctx context.Context, id int64) (*Stake, error) {
	raw, err := v.transport.CallRaw(ctx, RPCMethodStakeViewerStakeByID, id)
	if err != nil || isJSONNull(raw) {
		return nil, err
	}
	var out Stake
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (v *StakeViewer) StakeByStaker(ctx context.Context, staker string, slot int64) (*Stake, error) {
	raw, err := v.transport.CallRaw(ctx, RPCMethodStakeViewerStakeByStaker, staker, slot)
	if err != nil || isJSONNull(raw) {
		return nil, err
	}
	var out Stake
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (v *StakeViewer) StakesByStaked(ctx context.Context, staked string) ([]Stake, error) {
	var out []Stake
	if err := v.transport.Call(ctx, RPCMethodStakeViewerStakesByStaked, &out, staked); err != nil {
		return nil, err
	}
	return out, nil
}

func (v *StakeViewer) StakesByStaker(ctx context.Context, staker string) ([]Stake, error) {
	var out []Stake
	if err := v.transport.Call(ctx, RPCMethodStakeViewerStakesByStaker, &out, staker); err != nil {
		return nil, err
	}
	return out, nil
}

func (v *StakeViewer) MinWithdrawalBlocks(ctx context.Context) (int64, error) {
	var out int64
	if err := v.transport.Call(ctx, RPCMethodStakeViewerMinWithdrawalBlocks, &out); err != nil {
		return 0, err
	}
	return out, nil
}

func (v *StakeViewer) RewardsContract(ctx context.Context) (string, error) {
	var out string
	if err := v.transport.Call(ctx, RPCMethodStakeViewerRewardsContract, &out); err != nil {
		return "", err
	}
	return out, nil
}

func (v *StakeViewer) StakingTokenAddress(ctx context.Context) (string, error) {
	var out string
	if err := v.transport.Call(ctx, RPCMethodStakeViewerStakingTokenAddress, &out); err != nil {
		return "", err
	}
	return out, nil
}

// StakeTotalsViewer queries aggregate active, pending, and withdrawn stake totals.
type StakeTotalsViewer struct {
	transport RPCTransport
}

func NewStakeTotalsViewer(t RPCTransport) *StakeTotalsViewer { return &StakeTotalsViewer{transport: t} }

func (v *StakeTotalsViewer) callAtto(ctx context.Context, method string, params ...any) (AttoXL1, error) {
	raw, err := v.transport.CallRaw(ctx, method, params...)
	if err != nil {
		return AttoXL1{}, err
	}
	return decodeRawAtto(raw)
}

func (v *StakeTotalsViewer) Active(ctx context.Context, time ...int64) (AttoXL1, error) {
	var params []any
	if len(time) > 0 {
		params = append(params, time[0])
	}
	return v.callAtto(ctx, RPCMethodStakeTotalsViewerActive, params...)
}

func (v *StakeTotalsViewer) ActiveByStaked(ctx context.Context, staked string, time ...int64) (AttoXL1, error) {
	params := []any{staked}
	if len(time) > 0 {
		params = append(params, time[0])
	}
	return v.callAtto(ctx, RPCMethodStakeTotalsViewerActiveByStaked, params...)
}

func (v *StakeTotalsViewer) ActiveByStaker(ctx context.Context, staker string, time ...int64) (AttoXL1, error) {
	params := []any{staker}
	if len(time) > 0 {
		params = append(params, time[0])
	}
	return v.callAtto(ctx, RPCMethodStakeTotalsViewerActiveByStaker, params...)
}

func (v *StakeTotalsViewer) Pending(ctx context.Context, time ...int64) (AttoXL1, error) {
	var params []any
	if len(time) > 0 {
		params = append(params, time[0])
	}
	return v.callAtto(ctx, RPCMethodStakeTotalsViewerPending, params...)
}

func (v *StakeTotalsViewer) PendingByStaker(ctx context.Context, staker string, time ...int64) (AttoXL1, error) {
	params := []any{staker}
	if len(time) > 0 {
		params = append(params, time[0])
	}
	return v.callAtto(ctx, RPCMethodStakeTotalsViewerPendingByStaker, params...)
}

func (v *StakeTotalsViewer) Withdrawn(ctx context.Context, time ...int64) (AttoXL1, error) {
	var params []any
	if len(time) > 0 {
		params = append(params, time[0])
	}
	return v.callAtto(ctx, RPCMethodStakeTotalsViewerWithdrawn, params...)
}

func (v *StakeTotalsViewer) WithdrawnByStaker(ctx context.Context, staker string, time ...int64) (AttoXL1, error) {
	params := []any{staker}
	if len(time) > 0 {
		params = append(params, time[0])
	}
	return v.callAtto(ctx, RPCMethodStakeTotalsViewerWithdrawnByStaker, params...)
}

// NetworkStakeViewer queries total active network stake.
type NetworkStakeViewer struct {
	transport RPCTransport
}

func NewNetworkStakeViewer(t RPCTransport) *NetworkStakeViewer {
	return &NetworkStakeViewer{transport: t}
}

func (v *NetworkStakeViewer) Active(ctx context.Context, blockNumber ...XL1BlockNumber) (json.RawMessage, error) {
	var params []any
	if len(blockNumber) > 0 {
		params = append(params, int64(blockNumber[0]))
	}
	return v.transport.CallRaw(ctx, RPCMethodNetworkStakeViewerActive, params...)
}

// StepViewer queries staking step details (positions, randomizer, stake, stakers, weight).
type StepViewer struct {
	transport RPCTransport
}

func NewStepViewer(t RPCTransport) *StepViewer { return &StepViewer{transport: t} }

func (v *StepViewer) PositionCount(ctx context.Context, step any) (int64, error) {
	var out int64
	err := v.transport.Call(ctx, RPCMethodStepViewerPositionCount, &out, step)
	return out, err
}

func (v *StepViewer) Positions(ctx context.Context, step any, opts ...any) ([]Position, error) {
	params := append([]any{step}, opts...)
	var out []Position
	err := v.transport.Call(ctx, RPCMethodStepViewerPositions, &out, params...)
	return out, err
}

func (v *StepViewer) Randomizer(ctx context.Context, step any) (string, error) {
	var out string
	err := v.transport.Call(ctx, RPCMethodStepViewerRandomizer, &out, step)
	return out, err
}

func (v *StepViewer) Stake(ctx context.Context, step any) (AttoXL1, error) {
	raw, err := v.transport.CallRaw(ctx, RPCMethodStepViewerStake, step)
	if err != nil {
		return AttoXL1{}, err
	}
	return decodeRawAtto(raw)
}

func (v *StepViewer) StakerCount(ctx context.Context, step any) (int64, error) {
	var out int64
	err := v.transport.Call(ctx, RPCMethodStepViewerStakerCount, &out, step)
	return out, err
}

func (v *StepViewer) Stakers(ctx context.Context, step any, opts ...any) ([]string, error) {
	params := append([]any{step}, opts...)
	var out []string
	err := v.transport.Call(ctx, RPCMethodStepViewerStakers, &out, params...)
	return out, err
}

func (v *StepViewer) Weight(ctx context.Context, step any) (AttoXL1, error) {
	raw, err := v.transport.CallRaw(ctx, RPCMethodStepViewerWeight, step)
	if err != nil {
		return AttoXL1{}, err
	}
	return decodeRawAtto(raw)
}

// DataLakeViewer queries payloads from the XL1 DataLake.
type DataLakeViewer struct {
	transport RPCTransport
}

func NewDataLakeViewer(t RPCTransport) *DataLakeViewer { return &DataLakeViewer{transport: t} }

func (v *DataLakeViewer) Get(ctx context.Context, hashes []string) ([]payload.AnyPayload, error) {
	var out []payload.AnyPayload
	err := v.transport.Call(ctx, RPCMethodDataLakeViewerGet, &out, hashes)
	return out, err
}

func (v *DataLakeViewer) Next(ctx context.Context, options ...any) ([]payload.AnyPayload, error) {
	var out []payload.AnyPayload
	err := v.transport.Call(ctx, RPCMethodDataLakeViewerNext, &out, options...)
	return out, err
}

// NetworkStakingStepRewardsViewer queries v1.26 split-per-dimension staking step rewards
// (ByPosition, ByStaker, ByStep, or Total).
type NetworkStakingStepRewardsViewer struct {
	transport RPCTransport
	prefix    string
}

func NewRewardsByPositionViewer(t RPCTransport) *NetworkStakingStepRewardsViewer {
	return &NetworkStakingStepRewardsViewer{transport: t, prefix: RPCMethodRewardsByPositionPrefix}
}

func NewRewardsByStakerViewer(t RPCTransport) *NetworkStakingStepRewardsViewer {
	return &NetworkStakingStepRewardsViewer{transport: t, prefix: RPCMethodRewardsByStakerPrefix}
}

func NewRewardsByStepViewer(t RPCTransport) *NetworkStakingStepRewardsViewer {
	return &NetworkStakingStepRewardsViewer{transport: t, prefix: RPCMethodRewardsByStepPrefix}
}

func NewRewardsTotalViewer(t RPCTransport) *NetworkStakingStepRewardsViewer {
	return &NetworkStakingStepRewardsViewer{transport: t, prefix: RPCMethodRewardsTotalPrefix}
}

func (v *NetworkStakingStepRewardsViewer) callRewardsMap(ctx context.Context, suffix string, opts ...any) (map[string]AttoXL1, error) {
	rawBytes, err := v.transport.CallRaw(ctx, v.prefix+suffix, opts...)
	if err != nil || isJSONNull(rawBytes) {
		return nil, err
	}
	var raw map[string]any
	if err := decodeJSONUseNumber(rawBytes, &raw); err != nil {
		return nil, err
	}
	out := make(map[string]AttoXL1, len(raw))
	for k, val := range raw {
		atto, err := ParseFlexibleAtto(val)
		if err != nil {
			return nil, fmt.Errorf("parse reward %s: %w", k, err)
		}
		out[k] = atto
	}
	return out, nil
}

func (v *NetworkStakingStepRewardsViewer) Bonus(ctx context.Context, opts ...any) (map[string]AttoXL1, error) {
	return v.callRewardsMap(ctx, "bonus", opts...)
}

func (v *NetworkStakingStepRewardsViewer) Claimed(ctx context.Context, opts ...any) (map[string]AttoXL1, error) {
	return v.callRewardsMap(ctx, "claimed", opts...)
}

func (v *NetworkStakingStepRewardsViewer) Earned(ctx context.Context, opts ...any) (map[string]AttoXL1, error) {
	return v.callRewardsMap(ctx, "earned", opts...)
}

func (v *NetworkStakingStepRewardsViewer) Total(ctx context.Context, opts ...any) (map[string]AttoXL1, error) {
	return v.callRewardsMap(ctx, "total", opts...)
}

func (v *NetworkStakingStepRewardsViewer) Unclaimed(ctx context.Context, opts ...any) (map[string]AttoXL1, error) {
	return v.callRewardsMap(ctx, "unclaimed", opts...)
}

// LegacyNetworkStakeStepRewardsViewer queries legacy networkStakeStepRewardsViewer_* RPC methods.
type LegacyNetworkStakeStepRewardsViewer struct {
	transport RPCTransport
}

func NewLegacyNetworkStakeStepRewardsViewer(t RPCTransport) *LegacyNetworkStakeStepRewardsViewer {
	return &LegacyNetworkStakeStepRewardsViewer{transport: t}
}

func (v *LegacyNetworkStakeStepRewardsViewer) ByPosition(ctx context.Context, opts ...any) (json.RawMessage, error) {
	return v.transport.CallRaw(ctx, RPCMethodLegacyNetworkStakeRewardsByPosition, opts...)
}

func (v *LegacyNetworkStakeStepRewardsViewer) ByStaker(ctx context.Context, opts ...any) (json.RawMessage, error) {
	return v.transport.CallRaw(ctx, RPCMethodLegacyNetworkStakeRewardsByStaker, opts...)
}

func (v *LegacyNetworkStakeStepRewardsViewer) ByStep(ctx context.Context, opts ...any) (json.RawMessage, error) {
	return v.transport.CallRaw(ctx, RPCMethodLegacyNetworkStakeRewardsByStep, opts...)
}

func (v *LegacyNetworkStakeStepRewardsViewer) Total(ctx context.Context, opts ...any) (json.RawMessage, error) {
	return v.transport.CallRaw(ctx, RPCMethodLegacyNetworkStakeRewardsTotal, opts...)
}

// TransferBalanceViewer queries transfer balances and histories.
type TransferBalanceViewer struct {
	transport RPCTransport
}

func NewTransferBalanceViewer(t RPCTransport) *TransferBalanceViewer {
	return &TransferBalanceViewer{transport: t}
}

func (v *TransferBalanceViewer) TransferBalance(ctx context.Context, address string) (AttoXL1, error) {
	raw, err := v.transport.CallRaw(ctx, RPCMethodTransferBalanceViewerBalance, address)
	if err != nil {
		return AttoXL1{}, err
	}
	return decodeRawAtto(raw)
}

func (v *TransferBalanceViewer) TransferBalances(ctx context.Context, addresses []string) (map[string]AttoXL1, error) {
	rawBytes, err := v.transport.CallRaw(ctx, RPCMethodTransferBalanceViewerBalances, addresses)
	if err != nil || isJSONNull(rawBytes) {
		return nil, err
	}
	var raw map[string]any
	if err := decodeJSONUseNumber(rawBytes, &raw); err != nil {
		return nil, err
	}
	out := make(map[string]AttoXL1, len(raw))
	for k, val := range raw {
		a, err := ParseFlexibleAtto(val)
		if err != nil {
			return nil, err
		}
		out[k] = a
	}
	return out, nil
}

func (v *TransferBalanceViewer) TransferBalanceHistory(ctx context.Context, address string) (json.RawMessage, error) {
	return v.transport.CallRaw(ctx, RPCMethodTransferBalanceViewerBalanceHistory, address)
}

func (v *TransferBalanceViewer) TransferPairBalance(ctx context.Context, from, to string) (AttoXL1, error) {
	raw, err := v.transport.CallRaw(ctx, RPCMethodTransferBalanceViewerPairBalance, from, to)
	if err != nil {
		return AttoXL1{}, err
	}
	return decodeRawAtto(raw)
}

func (v *TransferBalanceViewer) TransferPairBalanceHistory(ctx context.Context, from, to string) (json.RawMessage, error) {
	return v.transport.CallRaw(ctx, RPCMethodTransferBalanceViewerPairBalanceHistory, from, to)
}

func (v *TransferBalanceViewer) TransferPairBalances(ctx context.Context, pairs [][]string) (json.RawMessage, error) {
	return v.transport.CallRaw(ctx, RPCMethodTransferBalanceViewerPairBalances, pairs)
}

// BlockRewardViewer queries allowed block rewards.
type BlockRewardViewer struct {
	transport RPCTransport
}

func NewBlockRewardViewer(t RPCTransport) *BlockRewardViewer {
	return &BlockRewardViewer{transport: t}
}

func (v *BlockRewardViewer) AllowedRewardForBlock(ctx context.Context, blockNumber XL1BlockNumber) (AttoXL1, error) {
	raw, err := v.transport.CallRaw(ctx, RPCMethodBlockRewardViewerAllowedRewardForBlock, int64(blockNumber))
	if err != nil {
		return AttoXL1{}, err
	}
	return decodeRawAtto(raw)
}

// ForkViewer queries fork history.
type ForkViewer struct {
	transport RPCTransport
}

func NewForkViewer(t RPCTransport) *ForkViewer { return &ForkViewer{transport: t} }

func (v *ForkViewer) ForkHistory(ctx context.Context) (json.RawMessage, error) {
	return v.transport.CallRaw(ctx, RPCMethodForkViewerForkHistory)
}

func isJSONNull(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null"))
}
