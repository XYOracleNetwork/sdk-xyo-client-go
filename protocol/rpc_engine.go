package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
)

const defaultRPCMaxBodyBytes = 16 << 20 // 16 MiB

// RPCMethodHandler handles a single JSON-RPC 2.0 method invocation.
type RPCMethodHandler func(ctx context.Context, params []json.RawMessage) (any, error)

// RPCEngine is a server-side JSON-RPC 2.0 dispatcher implementing standard error codes
// (-32700..-32603), notifications, batch requests, and http.Handler for hosting XL1 RPC endpoints.
type RPCEngine struct {
	mu           sync.RWMutex
	handlers     map[string]RPCMethodHandler
	maxBodyBytes int64
}

// NewRPCEngine creates an empty RPCEngine.
func NewRPCEngine() *RPCEngine {
	return &RPCEngine{
		handlers:     make(map[string]RPCMethodHandler),
		maxBodyBytes: defaultRPCMaxBodyBytes,
	}
}

// Register registers a handler for the given JSON-RPC method name.
func (e *RPCEngine) Register(method string, handler RPCMethodHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.handlers[method] = handler
}

// Methods returns a list of all registered JSON-RPC method names.
func (e *RPCEngine) Methods() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]string, 0, len(e.handlers))
	for m := range e.handlers {
		out = append(out, m)
	}
	return out
}

// HandleRaw processes a single raw JSON-RPC 2.0 request object and returns a JSONRPCResponse.
func (e *RPCEngine) HandleRaw(ctx context.Context, raw []byte) JSONRPCResponse {
	resp, _ := e.handleSingle(ctx, raw)
	return resp
}

// HandleRawBytes processes either a single JSON-RPC 2.0 request or a JSON-RPC 2.0 batch array.
// Returns (nil, false) for notifications where no response should be sent per JSON-RPC 2.0 spec.
func (e *RPCEngine) HandleRawBytes(ctx context.Context, raw []byte) ([]byte, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		out, _ := json.Marshal(JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      nil,
			Error:   &JSONRPCError{Code: RPCErrParseError, Message: "Parse error: empty request"},
		})
		return out, true
	}

	// JSON-RPC 2.0 batch request
	if trimmed[0] == '[' {
		var batch []json.RawMessage
		if err := json.Unmarshal(trimmed, &batch); err != nil {
			out, _ := json.Marshal(JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      nil,
				Error:   &JSONRPCError{Code: RPCErrParseError, Message: "Parse error: " + err.Error()},
			})
			return out, true
		}
		if len(batch) == 0 {
			out, _ := json.Marshal(JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      nil,
				Error:   &JSONRPCError{Code: RPCErrInvalidRequest, Message: "Invalid Request: empty batch"},
			})
			return out, true
		}
		responses := make([]JSONRPCResponse, 0, len(batch))
		for _, item := range batch {
			resp, shouldReply := e.handleSingle(ctx, item)
			if shouldReply {
				responses = append(responses, resp)
			}
		}
		if len(responses) == 0 {
			return nil, false
		}
		out, _ := json.Marshal(responses)
		return out, true
	}

	resp, shouldReply := e.handleSingle(ctx, trimmed)
	if !shouldReply {
		return nil, false
	}
	out, _ := json.Marshal(resp)
	return out, true
}

func (e *RPCEngine) handleSingle(ctx context.Context, raw []byte) (JSONRPCResponse, bool) {
	// Parse top-level map to detect notification (absence of "id" key vs explicit "id": null)
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rawMap); err != nil {
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      nil,
			Error:   &JSONRPCError{Code: RPCErrParseError, Message: "Parse error: " + err.Error()},
		}, true
	}

	_, hasID := rawMap["id"]
	var id any
	if hasID {
		if err := decodeJSONUseNumber(rawMap["id"], &id); err != nil {
			return JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      nil,
				Error:   &JSONRPCError{Code: RPCErrInvalidRequest, Message: "Invalid Request: invalid id"},
			}, true
		}
	}

	var jsonrpcVer string
	if v, ok := rawMap["jsonrpc"]; ok {
		_ = json.Unmarshal(v, &jsonrpcVer)
	}
	var method string
	if v, ok := rawMap["method"]; ok {
		_ = json.Unmarshal(v, &method)
	}
	if jsonrpcVer != "2.0" || method == "" {
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: RPCErrInvalidRequest, Message: "Invalid Request"},
		}, true
	}

	var params []json.RawMessage
	if rawParams, ok := rawMap["params"]; ok {
		pt := bytes.TrimSpace(rawParams)
		if len(pt) > 0 && !bytes.Equal(pt, []byte("null")) {
			switch pt[0] {
			case '[':
				if err := json.Unmarshal(pt, &params); err != nil {
					return JSONRPCResponse{
						JSONRPC: "2.0",
						ID:      id,
						Error:   &JSONRPCError{Code: RPCErrInvalidParams, Message: "Invalid params: " + err.Error()},
					}, hasID
				}
			case '{':
				// Object-style named params passed as single raw JSON object
				params = []json.RawMessage{pt}
			default:
				return JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      id,
					Error:   &JSONRPCError{Code: RPCErrInvalidParams, Message: "Invalid params: must be array or object"},
				}, hasID
			}
		}
	}

	e.mu.RLock()
	handler, ok := e.handlers[method]
	e.mu.RUnlock()
	if !ok {
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: RPCErrMethodNotFound, Message: "Method not found: " + method},
		}, hasID
	}

	res, err := handler(ctx, params)
	if !hasID {
		return JSONRPCResponse{}, false
	}
	if err != nil {
		var rpcErr *JSONRPCError
		if errors.As(err, &rpcErr) {
			return JSONRPCResponse{JSONRPC: "2.0", ID: id, Error: rpcErr}, true
		}
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: RPCErrInternalError, Message: err.Error()},
		}, true
	}

	resBytes, err := json.Marshal(res)
	if err != nil {
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &JSONRPCError{Code: RPCErrInternalError, Message: "marshal result: " + err.Error()},
		}, true
	}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  resBytes,
	}, true
}

// ServeHTTP implements http.Handler for JSON-RPC 2.0 over HTTP POST (single, batch, and notifications).
func (e *RPCEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit := e.maxBodyBytes
	if limit <= 0 {
		limit = defaultRPCMaxBodyBytes
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	out, shouldReply := e.HandleRawBytes(r.Context(), body)
	if !shouldReply {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

// RPCConnection aggregates optional server-side handler implementations for wiring an RPCEngine
// (mirroring Android protocol/rpc/engine/RpcConnection and xl1-protocol XyoConnection).
type RPCConnection struct {
	Handlers map[string]RPCMethodHandler
	Viewer   *XyoViewer // Optional proxy backend: forwards standard viewer/runner RPC methods
}

// RPCEngineFromConnection constructs an RPCEngine wired from conn.
// If conn.Viewer is set, standard XL1 viewer/runner methods are wired to proxy through conn.Viewer;
// any explicit entries in conn.Handlers override them.
func RPCEngineFromConnection(conn RPCConnection) *RPCEngine {
	engine := NewRPCEngine()
	if conn.Viewer != nil && conn.Viewer.Transport != nil {
		proxy := func(method string) RPCMethodHandler {
			return func(ctx context.Context, params []json.RawMessage) (any, error) {
				anyParams := make([]any, len(params))
				for i, p := range params {
					anyParams[i] = p
				}
				return conn.Viewer.Transport.CallRaw(ctx, method, anyParams...)
			}
		}
		standardMethods := []string{
			RPCMethodBlockViewerBlocksByHash,
			RPCMethodBlockViewerBlocksByNumber,
			RPCMethodBlockViewerCurrentBlock,
			RPCMethodBlockViewerPayloadsByHash,
			RPCMethodTransactionViewerByHash,
			RPCMethodTransactionViewerTransactionByHash,
			RPCMethodTransactionViewerTransactionByBlockHashAndIndex,
			RPCMethodTransactionViewerTransactionByBlockNumAndIndex,
			RPCMethodAccountBalanceViewerQualifiedBalances,
			RPCMethodAccountBalanceViewerQualifiedBalanceHistories,
			RPCMethodFinalizationViewerHead,
			RPCMethodMempoolViewerPendingTransactions,
			RPCMethodMempoolViewerPendingBlocks,
			RPCMethodMempoolRunnerSubmitTransactions,
			RPCMethodMempoolRunnerSubmitBlocks,
			RPCMethodTimeSyncViewerConvertTime,
			RPCMethodTimeSyncViewerCurrentTime,
			RPCMethodTimeSyncViewerCurrentTimeAndHash,
			RPCMethodTimeSyncViewerCurrentTimePayload,
			RPCMethodStakeViewerStakeByID,
			RPCMethodStakeViewerStakeByStaker,
			RPCMethodStakeViewerStakesByStaked,
			RPCMethodStakeViewerStakesByStaker,
			RPCMethodStakeViewerMinWithdrawalBlocks,
			RPCMethodStakeViewerRewardsContract,
			RPCMethodStakeViewerStakingTokenAddress,
			RPCMethodStakeTotalsViewerActive,
			RPCMethodStakeTotalsViewerActiveByStaked,
			RPCMethodStakeTotalsViewerActiveByStaker,
			RPCMethodStakeTotalsViewerPending,
			RPCMethodStakeTotalsViewerPendingByStaker,
			RPCMethodStakeTotalsViewerWithdrawn,
			RPCMethodStakeTotalsViewerWithdrawnByStaker,
			RPCMethodStakeRunnerAddStake,
			RPCMethodStakeRunnerRemoveStake,
			RPCMethodStakeRunnerWithdrawStake,
			RPCMethodNetworkStakeViewerActive,
			RPCMethodStepViewerPositionCount,
			RPCMethodStepViewerPositions,
			RPCMethodStepViewerRandomizer,
			RPCMethodStepViewerStake,
			RPCMethodStepViewerStakerCount,
			RPCMethodStepViewerStakers,
			RPCMethodStepViewerWeight,
			RPCMethodDataLakeViewerGet,
			RPCMethodDataLakeViewerNext,
			RPCMethodTransferBalanceViewerBalance,
			RPCMethodTransferBalanceViewerBalanceHistory,
			RPCMethodTransferBalanceViewerBalances,
			RPCMethodTransferBalanceViewerPairBalance,
			RPCMethodTransferBalanceViewerPairBalanceHistory,
			RPCMethodTransferBalanceViewerPairBalances,
			RPCMethodBlockRewardViewerAllowedRewardForBlock,
			RPCMethodForkViewerForkHistory,
			RPCMethodLegacyNetworkStakeRewardsByPosition,
			RPCMethodLegacyNetworkStakeRewardsByStaker,
			RPCMethodLegacyNetworkStakeRewardsByStep,
			RPCMethodLegacyNetworkStakeRewardsTotal,
			RPCMethodRewardsByPositionBonus,
			RPCMethodRewardsByPositionClaimed,
			RPCMethodRewardsByPositionEarned,
			RPCMethodRewardsByPositionTotal,
			RPCMethodRewardsByPositionUnclaimed,
			RPCMethodRewardsByStakerBonus,
			RPCMethodRewardsByStakerClaimed,
			RPCMethodRewardsByStakerEarned,
			RPCMethodRewardsByStakerTotal,
			RPCMethodRewardsByStakerUnclaimed,
			RPCMethodRewardsByStepBonus,
			RPCMethodRewardsByStepClaimed,
			RPCMethodRewardsByStepEarned,
			RPCMethodRewardsByStepTotal,
			RPCMethodRewardsByStepUnclaimed,
			RPCMethodRewardsTotalBonus,
			RPCMethodRewardsTotalClaimed,
			RPCMethodRewardsTotalEarned,
			RPCMethodRewardsTotalTotal,
			RPCMethodRewardsTotalUnclaimed,
		}
		for _, m := range standardMethods {
			engine.Register(m, proxy(m))
		}
	}
	for method, h := range conn.Handlers {
		if h != nil {
			engine.Register(method, h)
		}
	}
	return engine
}
