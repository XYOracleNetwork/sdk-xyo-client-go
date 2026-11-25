package protocol

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
)

// RPCMethodHandler handles a single JSON-RPC 2.0 method invocation.
type RPCMethodHandler func(ctx context.Context, params []json.RawMessage) (any, error)

// RPCEngine is a server-side JSON-RPC 2.0 dispatcher implementing standard error codes
// (-32700..-32603) and http.Handler for hosting XL1 RPC endpoints or local test stubs.
type RPCEngine struct {
	mu       sync.RWMutex
	handlers map[string]RPCMethodHandler
}

// NewRPCEngine creates an empty RPCEngine.
func NewRPCEngine() *RPCEngine {
	return &RPCEngine{
		handlers: make(map[string]RPCMethodHandler),
	}
}

// Register registers a handler for the given JSON-RPC method name.
func (e *RPCEngine) Register(method string, handler RPCMethodHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.handlers[method] = handler
}

// HandleRaw processes a raw JSON-RPC 2.0 request payload and returns a JSONRPCResponse.
func (e *RPCEngine) HandleRaw(ctx context.Context, raw []byte) JSONRPCResponse {
	var req struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      any             `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return JSONRPCResponse{
			JSONRPC: "2.0",
			Error:   &JSONRPCError{Code: RPCErrParseError, Message: "Parse error: " + err.Error()},
		}
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &JSONRPCError{Code: RPCErrInvalidRequest, Message: "Invalid Request"},
		}
	}

	var params []json.RawMessage
	if len(req.Params) > 0 && string(req.Params) != "null" {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &JSONRPCError{Code: RPCErrInvalidParams, Message: "Invalid params: " + err.Error()},
			}
		}
	}

	e.mu.RLock()
	handler, ok := e.handlers[req.Method]
	e.mu.RUnlock()
	if !ok {
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &JSONRPCError{Code: RPCErrMethodNotFound, Message: "Method not found: " + req.Method},
		}
	}

	res, err := handler(ctx, params)
	if err != nil {
		var rpcErr *JSONRPCError
		if errors.As(err, &rpcErr) {
			return JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Error: rpcErr}
		}
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &JSONRPCError{Code: RPCErrInternalError, Message: err.Error()},
		}
	}

	resBytes, err := json.Marshal(res)
	if err != nil {
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &JSONRPCError{Code: RPCErrInternalError, Message: "marshal result: " + err.Error()},
		}
	}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  resBytes,
	}
}

// ServeHTTP implements http.Handler for JSON-RPC 2.0 over HTTP POST.
func (e *RPCEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp := e.HandleRaw(r.Context(), body)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
