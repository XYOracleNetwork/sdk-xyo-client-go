package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/XYOracleNetwork/sdk-xyo-client-go/account"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/boundwitness"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/payload"
)

const (
	// DefaultAPIDomain is the default production XYO Archivist domain.
	DefaultAPIDomain = "https://api.archivist.xyo.network"
	// DefaultAPIModule is the default target module name.
	DefaultAPIModule = "Archivist"
)

// APIConfig configures an HTTP connection to an XYO Node/Archivist endpoint.
type APIConfig struct {
	Domain     string
	Module     string
	Token      string
	HTTPClient *http.Client
}

// EndpointURL returns the combined endpoint URL "<Domain>/<Module>" (or "<Domain>" if Module is empty).
func (c APIConfig) EndpointURL() string {
	domain := strings.TrimRight(c.Domain, "/")
	if domain == "" {
		domain = DefaultAPIDomain
	}
	mod := strings.Trim(c.Module, "/")
	if mod == "" {
		return domain
	}
	return domain + "/" + mod
}

// NodeClient sends signed XYO Protocol 2.0 module queries over HTTP POST using the wire format
// [QueryBoundWitness, payloads] and parses { "data": [BoundWitness, Payloads, Errors?] }.
type NodeClient struct {
	url        string
	account    account.Account
	token      string
	httpClient *http.Client
}

// NodeClientOption configures a NodeClient.
type NodeClientOption func(*NodeClient)

// WithHTTPClient overrides the default http.Client on NodeClient.
func WithHTTPClient(hc *http.Client) NodeClientOption {
	return func(nc *NodeClient) {
		if hc != nil {
			nc.httpClient = hc
		}
	}
}

// WithToken sets an optional Bearer token for HTTP requests.
func WithToken(token string) NodeClientOption {
	return func(nc *NodeClient) {
		nc.token = token
	}
}

// NewNodeClient creates a NodeClient targeting url with the given signing Account.
// If acct is nil, a fresh random secp256k1 account is created.
func NewNodeClient(url string, acct account.Account, opts ...NodeClientOption) (*NodeClient, error) {
	if strings.TrimSpace(url) == "" {
		return nil, errors.New("node client url is required")
	}
	if acct == nil {
		var err error
		acct, err = account.RandomAccount()
		if err != nil {
			return nil, fmt.Errorf("create random account for NodeClient: %w", err)
		}
	}
	nc := &NodeClient{
		url:        strings.TrimSpace(url),
		account:    acct,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(nc)
		}
	}
	return nc, nil
}

// NewNodeClientFromConfig creates a NodeClient from an APIConfig and signing Account.
func NewNodeClientFromConfig(cfg APIConfig, acct account.Account) (*NodeClient, error) {
	opts := []NodeClientOption{WithToken(cfg.Token)}
	if cfg.HTTPClient != nil {
		opts = append(opts, WithHTTPClient(cfg.HTTPClient))
	}
	return NewNodeClient(cfg.EndpointURL(), acct, opts...)
}

// URL returns the target HTTP endpoint URL.
func (c *NodeClient) URL() string {
	return c.url
}

// Account returns the signing account used for outgoing queries.
func (c *NodeClient) Account() account.Account {
	return c.account
}

// Query builds a signed QueryBoundWitness for queryPayload + attached payloads, POSTs
// [QueryBoundWitness, payloads] to the node endpoint, and returns the parsed ModuleQueryResult.
func (c *NodeClient) Query(ctx context.Context, queryPayload any, payloads ...any) (*ModuleQueryResult, error) {
	qbw, allPayloads, err := boundwitness.NewQueryBuilder().
		Query(queryPayload).
		Payloads(payloads...).
		Signer(c.account).
		Build()
	if err != nil {
		return nil, fmt.Errorf("build query bound witness: %w", err)
	}

	wireTuple := []any{qbw, allPayloads}
	bodyBytes, err := json.Marshal(wireTuple)
	if err != nil {
		return nil, fmt.Errorf("marshal query tuple: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP POST %s: %w", c.url, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read HTTP response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d from %s: %s", resp.StatusCode, c.url, string(respBody))
	}

	return parseQueryResponse(respBody)
}

func parseQueryResponse(raw []byte) (*ModuleQueryResult, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return &ModuleQueryResult{}, nil
	}

	// Standard envelope: { "data": [bw, payloads, errors?], "errors": [...] }
	if trimmed[0] == '{' {
		var envelope struct {
			Data   json.RawMessage   `json:"data"`
			Errors []json.RawMessage `json:"errors"`
		}
		if err := json.Unmarshal(trimmed, &envelope); err != nil {
			return nil, fmt.Errorf("decode query response envelope: %w", err)
		}
		if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
			if len(envelope.Errors) > 0 {
				return nil, fmt.Errorf("node query returned errors: %s", string(trimmed))
			}
			return &ModuleQueryResult{}, nil
		}
		res, err := parseResultTuple(envelope.Data)
		if err != nil {
			return nil, err
		}
		for _, rawErr := range envelope.Errors {
			var modErr payload.ModuleErrorPayload
			if uErr := json.Unmarshal(rawErr, &modErr); uErr == nil && (modErr.Message != "" || modErr.Name != "") {
				if modErr.Schema == "" {
					modErr.Schema = payload.SchemaModuleError
				}
				res.Errors = append(res.Errors, modErr)
			} else {
				res.Errors = append(res.Errors, payload.NewModuleErrorPayload("EnvelopeError", string(rawErr), ""))
			}
		}
		return res, nil
	}

	// Direct tuple response: [bw, payloads, errors?]
	if trimmed[0] == '[' {
		return parseResultTuple(trimmed)
	}

	return nil, fmt.Errorf("unexpected query response format: %s", string(trimmed))
}

func parseResultTuple(raw []byte) (*ModuleQueryResult, error) {
	wrapper, err := boundwitness.ParseTuple(raw)
	if err != nil {
		return nil, fmt.Errorf("parse query response tuple: %w", err)
	}
	return &ModuleQueryResult{
		BoundWitness: wrapper.BoundWitness,
		Payloads:     wrapper.Payloads,
		Errors:       wrapper.Errors,
	}, nil
}

// RemoteModule implements ModuleInstance backed by a NodeClient.
type RemoteModule struct {
	node    *NodeClient
	address string
	name    string
	queries []string
}

// NewRemoteModule creates a RemoteModule backed by node.
func NewRemoteModule(node *NodeClient, address, name string, queries []string) *RemoteModule {
	return &RemoteModule{
		node:    node,
		address: address,
		name:    name,
		queries: append([]string(nil), queries...),
	}
}

func (m *RemoteModule) Address() string   { return m.address }
func (m *RemoteModule) ModName() string   { return m.name }
func (m *RemoteModule) Queries() []string { return append([]string(nil), m.queries...) }

func (m *RemoteModule) Query(ctx context.Context, queryPayload any, payloads ...any) (*ModuleQueryResult, error) {
	return m.node.Query(ctx, queryPayload, payloads...)
}

func (m *RemoteModule) Describe(ctx context.Context) (*ModuleDescription, error) {
	q := payload.NewBasePayload(QuerySchemaModuleDescribe)
	res, err := m.node.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	for _, p := range res.Payloads {
		if p.GetSchema() == payload.SchemaModuleDescription {
			var desc ModuleDescription
			if err := p.DecodeInto(&desc); err == nil {
				return &desc, nil
			}
		}
	}
	return &ModuleDescription{
		Address: m.address,
		Name:    m.name,
		Queries: m.Queries(),
	}, nil
}
