package protocol

import (
	"context"
	"encoding/json"
)

// MempoolRunner submits signed HydratedTransactions and HydratedBlocks to an XL1 node mempool.
type MempoolRunner struct {
	transport RPCTransport
}

func NewMempoolRunner(t RPCTransport) *MempoolRunner { return &MempoolRunner{transport: t} }

// SubmitTransactions submits hydrated transactions via mempoolRunner_submitTransactions.
// Per XL1 RPC spec, params is a single-element array wrapping the list of [bw, payloads] tuples.
func (r *MempoolRunner) SubmitTransactions(ctx context.Context, txs []HydratedTransaction) ([]string, error) {
	var out []string
	if err := r.transport.Call(ctx, RPCMethodMempoolRunnerSubmitTransactions, &out, txs); err != nil {
		return nil, err
	}
	return out, nil
}

// SubmitBlocks submits hydrated blocks via mempoolRunner_submitBlocks.
func (r *MempoolRunner) SubmitBlocks(ctx context.Context, blocks []HydratedBlock) ([]string, error) {
	var out []string
	if err := r.transport.Call(ctx, RPCMethodMempoolRunnerSubmitBlocks, &out, blocks); err != nil {
		return nil, err
	}
	return out, nil
}

// StakeRunner submits staking lifecycle actions over JSON-RPC.
type StakeRunner struct {
	transport RPCTransport
}

func NewStakeRunner(t RPCTransport) *StakeRunner { return &StakeRunner{transport: t} }

func (r *StakeRunner) AddStake(ctx context.Context, staked string, amount AttoXL1) (json.RawMessage, error) {
	return r.transport.CallRaw(ctx, RPCMethodStakeRunnerAddStake, staked, amount.Hex())
}

func (r *StakeRunner) RemoveStake(ctx context.Context, slot int64) (json.RawMessage, error) {
	return r.transport.CallRaw(ctx, RPCMethodStakeRunnerRemoveStake, slot)
}

func (r *StakeRunner) WithdrawStake(ctx context.Context, slot int64) (json.RawMessage, error) {
	return r.transport.CallRaw(ctx, RPCMethodStakeRunnerWithdrawStake, slot)
}

// XyoViewer is the aggregate XL1 Chain Protocol client facade composing all viewers and runners
// over a shared RPCTransport (matching Android & Swift XyoViewer).
type XyoViewer struct {
	Transport         RPCTransport
	Block             *BlockViewer
	Transaction       *TransactionViewer
	AccountBalance    *AccountBalanceViewer
	Finalization      *FinalizationViewer
	Mempool           *MempoolViewer
	MempoolRunner     *MempoolRunner
	TimeSync          *TimeSyncViewer
	Stake             *StakeViewer
	StakeTotals       *StakeTotalsViewer
	StakeRunner       *StakeRunner
	NetworkStake      *NetworkStakeViewer
	Step              *StepViewer
	DataLake          *DataLakeViewer
	RewardsByPosition *NetworkStakingStepRewardsViewer
	RewardsByStaker   *NetworkStakingStepRewardsViewer
	RewardsByStep     *NetworkStakingStepRewardsViewer
	RewardsTotal      *NetworkStakingStepRewardsViewer
	TransferBalance   *TransferBalanceViewer
	BlockReward       *BlockRewardViewer
	Fork              *ForkViewer
}

// NewXyoViewer constructs an XyoViewer over the given RPCTransport.
func NewXyoViewer(t RPCTransport) *XyoViewer {
	return &XyoViewer{
		Transport:         t,
		Block:             NewBlockViewer(t),
		Transaction:       NewTransactionViewer(t),
		AccountBalance:    NewAccountBalanceViewer(t),
		Finalization:      NewFinalizationViewer(t),
		Mempool:           NewMempoolViewer(t),
		MempoolRunner:     NewMempoolRunner(t),
		TimeSync:          NewTimeSyncViewer(t),
		Stake:             NewStakeViewer(t),
		StakeTotals:       NewStakeTotalsViewer(t),
		StakeRunner:       NewStakeRunner(t),
		NetworkStake:      NewNetworkStakeViewer(t),
		Step:              NewStepViewer(t),
		DataLake:          NewDataLakeViewer(t),
		RewardsByPosition: NewRewardsByPositionViewer(t),
		RewardsByStaker:   NewRewardsByStakerViewer(t),
		RewardsByStep:     NewRewardsByStepViewer(t),
		RewardsTotal:      NewRewardsTotalViewer(t),
		TransferBalance:   NewTransferBalanceViewer(t),
		BlockReward:       NewBlockRewardViewer(t),
		Fork:              NewForkViewer(t),
	}
}

// NewXyoViewerHTTP constructs an XyoViewer backed by an HTTPRPCTransport.
func NewXyoViewerHTTP(endpoint string, opts ...HTTPRPCTransportOption) (*XyoViewer, error) {
	t, err := NewHTTPRPCTransport(endpoint, opts...)
	if err != nil {
		return nil, err
	}
	return NewXyoViewer(t), nil
}

// Call invokes any JSON-RPC method directly on the underlying transport.
func (v *XyoViewer) Call(ctx context.Context, method string, out any, params ...any) error {
	return v.Transport.Call(ctx, method, out, params...)
}

// Convenience pass-through methods matching Swift/Android XyoViewer.

func (v *XyoViewer) CurrentBlock(ctx context.Context) (*HydratedBlock, error) {
	return v.Block.CurrentBlock(ctx)
}

func (v *XyoViewer) FinalizedHead(ctx context.Context) (*HydratedBlock, error) {
	return v.Finalization.Head(ctx)
}

func (v *XyoViewer) TransactionByHash(ctx context.Context, hash string) (*HydratedTransaction, error) {
	return v.Transaction.ByHash(ctx, hash)
}

func (v *XyoViewer) SubmitTransactions(ctx context.Context, txs []HydratedTransaction) ([]string, error) {
	return v.MempoolRunner.SubmitTransactions(ctx, txs)
}
