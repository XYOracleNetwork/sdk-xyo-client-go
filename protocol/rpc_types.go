package protocol

import (
	"encoding/json"
	"fmt"
)

// Standard JSON-RPC 2.0 error codes.
const (
	RPCErrParseError     = -32700
	RPCErrInvalidRequest = -32600
	RPCErrMethodNotFound = -32601
	RPCErrInvalidParams  = -32602
	RPCErrInternalError  = -32603
)

// JSONRPCRequest represents a JSON-RPC 2.0 request envelope.
type JSONRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// JSONRPCError represents a JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *JSONRPCError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("json-rpc error %d: %s", e.Code, e.Message)
}

// JSONRPCResponse represents a JSON-RPC 2.0 response envelope.
// ID intentionally omits "omitempty" so "id": 0 and "id": null are serialized per JSON-RPC 2.0.
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

// XL1 JSON-RPC 2.0 method name constants (matching Android 3.3 & Swift 3.1 / @xyo-network/xl1-rpc).
const (
	// BlockViewer
	RPCMethodBlockViewerBlocksByHash   = "blockViewer_blocksByHash"
	RPCMethodBlockViewerBlocksByNumber = "blockViewer_blocksByNumber"
	RPCMethodBlockViewerCurrentBlock   = "blockViewer_currentBlock"
	RPCMethodBlockViewerPayloadsByHash = "blockViewer_payloadsByHash"

	// TransactionViewer
	RPCMethodTransactionViewerByHash                         = "transactionViewer_byHash"
	RPCMethodTransactionViewerTransactionByHash              = "transactionViewer_transactionByHash"
	RPCMethodTransactionViewerTransactionByBlockHashAndIndex = "transactionViewer_transactionByBlockHashAndIndex"
	RPCMethodTransactionViewerTransactionByBlockNumAndIndex  = "transactionViewer_transactionByBlockNumberAndIndex"

	// AccountBalanceViewer
	RPCMethodAccountBalanceViewerQualifiedBalances         = "accountBalanceViewer_qualifiedAccountBalances"
	RPCMethodAccountBalanceViewerQualifiedBalanceHistories = "accountBalanceViewer_qualifiedAccountBalanceHistories"

	// FinalizationViewer
	RPCMethodFinalizationViewerHead = "finalizationViewer_head"

	// MempoolViewer & MempoolRunner
	RPCMethodMempoolViewerPendingTransactions = "mempoolViewer_pendingTransactions"
	RPCMethodMempoolViewerPendingBlocks       = "mempoolViewer_pendingBlocks"
	RPCMethodMempoolRunnerSubmitTransactions  = "mempoolRunner_submitTransactions"
	RPCMethodMempoolRunnerSubmitBlocks        = "mempoolRunner_submitBlocks"

	// TimeSyncViewer
	RPCMethodTimeSyncViewerConvertTime        = "timeSyncViewer_convertTime"
	RPCMethodTimeSyncViewerCurrentTime        = "timeSyncViewer_currentTime"
	RPCMethodTimeSyncViewerCurrentTimeAndHash = "timeSyncViewer_currentTimeAndHash"
	RPCMethodTimeSyncViewerCurrentTimePayload = "timeSyncViewer_currentTimePayload"

	// StakeViewer
	RPCMethodStakeViewerStakeByID           = "stakeViewer_stakeById"
	RPCMethodStakeViewerStakeByStaker       = "stakeViewer_stakeByStaker"
	RPCMethodStakeViewerStakesByStaked      = "stakeViewer_stakesByStaked"
	RPCMethodStakeViewerStakesByStaker      = "stakeViewer_stakesByStaker"
	RPCMethodStakeViewerMinWithdrawalBlocks = "stakeViewer_minWithdrawalBlocks"
	RPCMethodStakeViewerRewardsContract     = "stakeViewer_rewardsContract"
	RPCMethodStakeViewerStakingTokenAddress = "stakeViewer_stakingTokenAddress"

	// StakeTotalsViewer
	RPCMethodStakeTotalsViewerActive            = "stakeTotalsViewer_active"
	RPCMethodStakeTotalsViewerActiveByStaked    = "stakeTotalsViewer_activeByStaked"
	RPCMethodStakeTotalsViewerActiveByStaker    = "stakeTotalsViewer_activeByStaker"
	RPCMethodStakeTotalsViewerPending           = "stakeTotalsViewer_pending"
	RPCMethodStakeTotalsViewerPendingByStaker   = "stakeTotalsViewer_pendingByStaker"
	RPCMethodStakeTotalsViewerWithdrawn         = "stakeTotalsViewer_withdrawn"
	RPCMethodStakeTotalsViewerWithdrawnByStaker = "stakeTotalsViewer_withdrawnByStaker"

	// StakeRunner
	RPCMethodStakeRunnerAddStake      = "stakeRunner_addStake"
	RPCMethodStakeRunnerRemoveStake   = "stakeRunner_removeStake"
	RPCMethodStakeRunnerWithdrawStake = "stakeRunner_withdrawStake"

	// NetworkStakeViewer
	RPCMethodNetworkStakeViewerActive = "networkStakeViewer_active"

	// StepViewer
	RPCMethodStepViewerPositionCount = "stepViewer_positionCount"
	RPCMethodStepViewerPositions     = "stepViewer_positions"
	RPCMethodStepViewerRandomizer    = "stepViewer_randomizer"
	RPCMethodStepViewerStake         = "stepViewer_stake"
	RPCMethodStepViewerStakerCount   = "stepViewer_stakerCount"
	RPCMethodStepViewerStakers       = "stepViewer_stakers"
	RPCMethodStepViewerWeight        = "stepViewer_weight"

	// DataLakeViewer
	RPCMethodDataLakeViewerGet  = "dataLakeViewer_get"
	RPCMethodDataLakeViewerNext = "dataLakeViewer_next"

	// TransferBalanceViewer
	RPCMethodTransferBalanceViewerBalance            = "transferBalanceViewer_transferBalance"
	RPCMethodTransferBalanceViewerBalanceHistory     = "transferBalanceViewer_transferBalanceHistory"
	RPCMethodTransferBalanceViewerBalances           = "transferBalanceViewer_transferBalances"
	RPCMethodTransferBalanceViewerPairBalance        = "transferBalanceViewer_transferPairBalance"
	RPCMethodTransferBalanceViewerPairBalanceHistory = "transferBalanceViewer_transferPairBalanceHistory"
	RPCMethodTransferBalanceViewerPairBalances       = "transferBalanceViewer_transferPairBalances"

	// BlockRewardViewer
	RPCMethodBlockRewardViewerAllowedRewardForBlock = "blockRewardViewer_allowedRewardForBlock"

	// ForkViewer
	RPCMethodForkViewerForkHistory = "forkViewer_forkHistory"

	// Legacy NetworkStake StepRewardsViewer
	RPCMethodLegacyNetworkStakeRewardsByPosition = "networkStakeStepRewardsViewer_byPosition"
	RPCMethodLegacyNetworkStakeRewardsByStaker   = "networkStakeStepRewardsViewer_byStaker"
	RPCMethodLegacyNetworkStakeRewardsByStep     = "networkStakeStepRewardsViewer_byStep"
	RPCMethodLegacyNetworkStakeRewardsTotal      = "networkStakeStepRewardsViewer_total"

	// NetworkStakingStepRewards (v1.26 split-per-dimension)
	RPCMethodRewardsByPositionPrefix = "networkStakingStepRewardsByPositionViewer_"
	RPCMethodRewardsByStakerPrefix   = "networkStakingStepRewardsByStakerViewer_"
	RPCMethodRewardsByStepPrefix     = "networkStakingStepRewardsByStepViewer_"
	RPCMethodRewardsTotalPrefix      = "networkStakingStepRewardsTotalViewer_"

	RPCMethodRewardsByPositionBonus     = "networkStakingStepRewardsByPositionViewer_bonus"
	RPCMethodRewardsByPositionClaimed   = "networkStakingStepRewardsByPositionViewer_claimed"
	RPCMethodRewardsByPositionEarned    = "networkStakingStepRewardsByPositionViewer_earned"
	RPCMethodRewardsByPositionTotal     = "networkStakingStepRewardsByPositionViewer_total"
	RPCMethodRewardsByPositionUnclaimed = "networkStakingStepRewardsByPositionViewer_unclaimed"

	RPCMethodRewardsByStakerBonus     = "networkStakingStepRewardsByStakerViewer_bonus"
	RPCMethodRewardsByStakerClaimed   = "networkStakingStepRewardsByStakerViewer_claimed"
	RPCMethodRewardsByStakerEarned    = "networkStakingStepRewardsByStakerViewer_earned"
	RPCMethodRewardsByStakerTotal     = "networkStakingStepRewardsByStakerViewer_total"
	RPCMethodRewardsByStakerUnclaimed = "networkStakingStepRewardsByStakerViewer_unclaimed"

	RPCMethodRewardsByStepBonus     = "networkStakingStepRewardsByStepViewer_bonus"
	RPCMethodRewardsByStepClaimed   = "networkStakingStepRewardsByStepViewer_claimed"
	RPCMethodRewardsByStepEarned    = "networkStakingStepRewardsByStepViewer_earned"
	RPCMethodRewardsByStepTotal     = "networkStakingStepRewardsByStepViewer_total"
	RPCMethodRewardsByStepUnclaimed = "networkStakingStepRewardsByStepViewer_unclaimed"

	RPCMethodRewardsTotalBonus     = "networkStakingStepRewardsTotalViewer_bonus"
	RPCMethodRewardsTotalClaimed   = "networkStakingStepRewardsTotalViewer_claimed"
	RPCMethodRewardsTotalEarned    = "networkStakingStepRewardsTotalViewer_earned"
	RPCMethodRewardsTotalTotal     = "networkStakingStepRewardsTotalViewer_total"
	RPCMethodRewardsTotalUnclaimed = "networkStakingStepRewardsTotalViewer_unclaimed"
)
