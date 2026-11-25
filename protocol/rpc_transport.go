package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

// RPCTransport abstracts JSON-RPC 2.0 request/response execution for XL1 viewers and runners.
type RPCTransport interface {
	CallRaw(ctx context.Context, method string, params ...any) (json.RawMessage, error)
	Call(ctx context.Context, method string, out any, params ...any) error
}

// HTTPRPCTransport sends JSON-RPC 2.0 requests over HTTP POST using net/http.
type HTTPRPCTransport struct {
	endpoint   string
	httpClient *http.Client
	headers    map[string]string
	nextID     atomic.Uint64
}

// HTTPRPCTransportOption configures an HTTPRPCTransport.
type HTTPRPCTransportOption func(*HTTPRPCTransport)

// WithRPCHTTPClient overrides the http.Client used by HTTPRPCTransport.
func WithRPCHTTPClient(c *http.Client) HTTPRPCTransportOption {
	return func(t *HTTPRPCTransport) {
		if c != nil {
			t.httpClient = c
		}
	}
}

// WithRPCHeader adds a custom HTTP header to every JSON-RPC request.
func WithRPCHeader(key, value string) HTTPRPCTransportOption {
	return func(t *HTTPRPCTransport) {
		t.headers[key] = value
	}
}

// NewHTTPRPCTransport creates an HTTPRPCTransport targeting endpoint.
func NewHTTPRPCTransport(endpoint string, opts ...HTTPRPCTransportOption) (*HTTPRPCTransport, error) {
	if endpoint == "" {
		return nil, errors.New("RPC endpoint URL is required")
	}
	t := &HTTPRPCTransport{
		endpoint:   endpoint,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		headers:    make(map[string]string),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(t)
		}
	}
	return t, nil
}

// Endpoint returns the configured JSON-RPC endpoint URL.
func (t *HTTPRPCTransport) Endpoint() string {
	return t.endpoint
}

// CallRaw executes a JSON-RPC 2.0 call and returns the raw JSON result bytes.
func (t *HTTPRPCTransport) CallRaw(ctx context.Context, method string, params ...any) (json.RawMessage, error) {
	if params == nil {
		params = []any{}
	}
	id := t.nextID.Add(1)
	reqObj := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      fmt.Sprintf("%d", id),
		Method:  method,
		Params:  params,
	}
	bodyBytes, err := json.Marshal(reqObj)
	if err != nil {
		return nil, fmt.Errorf("marshal JSON-RPC request %s: %w", method, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("build HTTP request %s: %w", method, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	for k, v := range t.headers {
		httpReq.Header.Set(k, v)
	}

	httpResp, err := t.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP POST %s (%s): %w", t.endpoint, method, err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read HTTP response (%s): %w", method, err)
	}
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d from %s (%s): %s", httpResp.StatusCode, t.endpoint, method, string(respBody))
	}

	var rpcResp JSONRPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("decode JSON-RPC response (%s): %w", method, err)
	}
	if rpcResp.Error != nil {
		return nil, rpcResp.Error
	}
	return rpcResp.Result, nil
}

// Call executes a JSON-RPC 2.0 call and unmarshals the result into out (if out != nil).
func (t *HTTPRPCTransport) Call(ctx context.Context, method string, out any, params ...any) error {
	raw, err := t.CallRaw(ctx, method, params...)
	if err != nil {
		return err
	}
	if out == nil || len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("unmarshal JSON-RPC result for %s: %w", method, err)
	}
	return nil
}
