package protocol

import "github.com/XYOracleNetwork/sdk-xyo-client-go/payload"

// TransferPayload represents an XL1 "network.xyo.transfer" transaction payload.
type TransferPayload struct {
	payload.BasePayload
	From      string            `json:"from,omitempty"`
	Transfers map[string]string `json:"transfers,omitempty"`
	Epoch     *int64            `json:"epoch,omitempty"`
	Context   map[string]any    `json:"context,omitempty"`
}

// NewTransferPayload creates a TransferPayload mapping recipient address -> amount string (hex or decimal).
func NewTransferPayload(from string, transfers map[string]string, epoch *int64) TransferPayload {
	return TransferPayload{
		BasePayload: payload.BasePayload{Schema: payload.SchemaTransfer},
		From:        from,
		Transfers:   transfers,
		Epoch:       epoch,
	}
}

// TimePayload represents an elevatable "network.xyo.time" payload.
type TimePayload struct {
	payload.BasePayload
	Epoch        *int64 `json:"epoch,omitempty"`
	XL1          *int64 `json:"xl1,omitempty"`
	XL1Hash      string `json:"xl1Hash,omitempty"`
	Ethereum     *int64 `json:"ethereum,omitempty"`
	EthereumHash string `json:"ethereumHash,omitempty"`
}

// NewTimePayload creates a TimePayload with the given epoch milliseconds.
func NewTimePayload(epochMs int64) TimePayload {
	return TimePayload{
		BasePayload: payload.BasePayload{Schema: payload.SchemaTime},
		Epoch:       &epochMs,
	}
}

// ChainStakeIntentPayload represents an elevatable "network.xyo.chain.stake.intent" payload.
type ChainStakeIntentPayload struct {
	payload.BasePayload
	Staked string `json:"staked"`
	Amount string `json:"amount"`
}

// NewChainStakeIntentPayload creates a ChainStakeIntentPayload.
func NewChainStakeIntentPayload(staked, amount string) ChainStakeIntentPayload {
	return ChainStakeIntentPayload{
		BasePayload: payload.BasePayload{Schema: payload.SchemaChainStakeIntent},
		Staked:      staked,
		Amount:      amount,
	}
}

// HashPayload represents an elevatable "network.xyo.hash" payload.
type HashPayload struct {
	payload.BasePayload
	Hash string `json:"hash"`
}

// NewHashPayload creates a HashPayload.
func NewHashPayload(hash string) HashPayload {
	return HashPayload{
		BasePayload: payload.BasePayload{Schema: payload.SchemaHash},
		Hash:        hash,
	}
}

// StepCompletePayload represents an elevatable "network.xyo.step.complete" payload.
type StepCompletePayload struct {
	payload.BasePayload
	Step  int64 `json:"step"`
	Block int64 `json:"block"`
}

// NewStepCompletePayload creates a StepCompletePayload.
func NewStepCompletePayload(step, block int64) StepCompletePayload {
	return StepCompletePayload{
		BasePayload: payload.BasePayload{Schema: payload.SchemaStepComplete},
		Step:        step,
		Block:       block,
	}
}
