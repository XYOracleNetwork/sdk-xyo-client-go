package client

import (
	"context"
	"fmt"
	"sync"

	"github.com/XYOracleNetwork/sdk-xyo-client-go/account"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/boundwitness"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/payload"
)

// Archivist query payload types (matching sdk-xyo-client-swift, sdk-xyo-client-android & sdk-xyo-client-js).

type ArchivistGetQueryPayload struct {
	payload.BasePayload
	Hashes []string `json:"hashes"`
}

type ArchivistInsertQueryPayload struct {
	payload.BasePayload
}

type ArchivistDeleteQueryPayload struct {
	payload.BasePayload
	Hashes []string `json:"hashes"`
}

type ArchivistAllQueryPayload struct {
	payload.BasePayload
}

type ArchivistClearQueryPayload struct {
	payload.BasePayload
}

type ArchivistNextQueryPayload struct {
	payload.BasePayload
	Cursor string `json:"cursor,omitempty"`
	Limit  *int   `json:"limit,omitempty"`
	Open   *bool  `json:"open,omitempty"`
	Order  string `json:"order,omitempty"`
}

type ArchivistCommitQueryPayload struct {
	payload.BasePayload
}

type ArchivistSnapshotQueryPayload struct {
	payload.BasePayload
}

// ArchivistWrapper wraps a NodeClient to provide strongly typed XYO Archivist operations
// over the standard QueryBoundWitness HTTP protocol.
type ArchivistWrapper struct {
	node *NodeClient
}

// NewArchivistWrapper wraps an existing NodeClient.
func NewArchivistWrapper(node *NodeClient) *ArchivistWrapper {
	return &ArchivistWrapper{node: node}
}

// NewArchivistClient constructs a NodeClient from APIConfig and wraps it as an ArchivistWrapper.
func NewArchivistClient(cfg APIConfig, acct account.Account) (*ArchivistWrapper, error) {
	node, err := NewNodeClientFromConfig(cfg, acct)
	if err != nil {
		return nil, err
	}
	return NewArchivistWrapper(node), nil
}

// Node returns the underlying NodeClient.
func (a *ArchivistWrapper) Node() *NodeClient {
	return a.node
}

// Get fetches payloads by their hashes via network.xyo.query.archivist.get.
func (a *ArchivistWrapper) Get(ctx context.Context, hashes []string) ([]payload.AnyPayload, error) {
	q := ArchivistGetQueryPayload{
		BasePayload: payload.BasePayload{Schema: QuerySchemaArchivistGet},
		Hashes:      hashes,
	}
	res, err := a.node.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	return res.Payloads, nil
}

// Insert stores payloads via network.xyo.query.archivist.insert and returns the inserted payloads.
func (a *ArchivistWrapper) Insert(ctx context.Context, payloads ...any) ([]payload.AnyPayload, error) {
	q := ArchivistInsertQueryPayload{
		BasePayload: payload.BasePayload{Schema: QuerySchemaArchivistInsert},
	}
	res, err := a.node.Query(ctx, q, payloads...)
	if err != nil {
		return nil, err
	}
	return res.Payloads, nil
}

// InsertQuery sends an insert query and returns the full ModuleQueryResult.
func (a *ArchivistWrapper) InsertQuery(ctx context.Context, payloads ...any) (*ModuleQueryResult, error) {
	q := ArchivistInsertQueryPayload{
		BasePayload: payload.BasePayload{Schema: QuerySchemaArchivistInsert},
	}
	return a.node.Query(ctx, q, payloads...)
}

// Delete removes payloads by hash via network.xyo.query.archivist.delete.
func (a *ArchivistWrapper) Delete(ctx context.Context, hashes []string) ([]string, error) {
	q := ArchivistDeleteQueryPayload{
		BasePayload: payload.BasePayload{Schema: QuerySchemaArchivistDelete},
		Hashes:      hashes,
	}
	res, err := a.node.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	var deleted []string
	for _, p := range res.Payloads {
		if h, err := p.Hash(); err == nil {
			deleted = append(deleted, h)
		}
	}
	return deleted, nil
}

// All returns all payloads stored in the archivist via network.xyo.query.archivist.all.
func (a *ArchivistWrapper) All(ctx context.Context) ([]payload.AnyPayload, error) {
	q := ArchivistAllQueryPayload{
		BasePayload: payload.BasePayload{Schema: QuerySchemaArchivistAll},
	}
	res, err := a.node.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	return res.Payloads, nil
}

// Clear empties the archivist via network.xyo.query.archivist.clear.
func (a *ArchivistWrapper) Clear(ctx context.Context) error {
	q := ArchivistClearQueryPayload{
		BasePayload: payload.BasePayload{Schema: QuerySchemaArchivistClear},
	}
	_, err := a.node.Query(ctx, q)
	return err
}

// Next pages through payloads via network.xyo.query.archivist.next.
func (a *ArchivistWrapper) Next(ctx context.Context, opts *ArchivistNextOptions) ([]payload.AnyPayload, error) {
	q := ArchivistNextQueryPayload{
		BasePayload: payload.BasePayload{Schema: QuerySchemaArchivistNext},
	}
	if opts != nil {
		q.Cursor = opts.Cursor
		q.Limit = opts.Limit
		q.Open = opts.Open
		q.Order = opts.Order
	}
	res, err := a.node.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	return res.Payloads, nil
}

// Commit commits pending payloads via network.xyo.query.archivist.commit.
func (a *ArchivistWrapper) Commit(ctx context.Context) ([]*boundwitness.BoundWitness, error) {
	q := ArchivistCommitQueryPayload{
		BasePayload: payload.BasePayload{Schema: QuerySchemaArchivistCommit},
	}
	res, err := a.node.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	var out []*boundwitness.BoundWitness
	for _, p := range res.Payloads {
		if p.GetSchema() == payload.SchemaBoundWitness {
			var bw boundwitness.BoundWitness
			if err := p.DecodeInto(&bw); err == nil {
				out = append(out, &bw)
			}
		}
	}
	return out, nil
}

// Snapshot requests a snapshot bound witness via network.xyo.query.archivist.snapshot.
func (a *ArchivistWrapper) Snapshot(ctx context.Context) (*boundwitness.BoundWitness, error) {
	q := ArchivistSnapshotQueryPayload{
		BasePayload: payload.BasePayload{Schema: QuerySchemaArchivistSnapshot},
	}
	res, err := a.node.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	return res.BoundWitness, nil
}

// MemoryArchivist is a concurrency-safe in-memory ArchivistInstance for local use and testing.
type MemoryArchivist struct {
	mu      sync.RWMutex
	account account.Account
	order   []string
	byHash  map[string]payload.AnyPayload
	byData  map[string]string // dataHash -> rootHash
}

// NewMemoryArchivist creates a new in-memory Archivist.
func NewMemoryArchivist(acct account.Account) (*MemoryArchivist, error) {
	if acct == nil {
		var err error
		acct, err = account.RandomAccount()
		if err != nil {
			return nil, err
		}
	}
	return &MemoryArchivist{
		account: acct,
		byHash:  make(map[string]payload.AnyPayload),
		byData:  make(map[string]string),
	}, nil
}

func (m *MemoryArchivist) Get(_ context.Context, hashes []string) ([]payload.AnyPayload, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []payload.AnyPayload
	for _, h := range hashes {
		if p, ok := m.byHash[h]; ok {
			out = append(out, p)
			continue
		}
		if rootHash, ok := m.byData[h]; ok {
			if p, ok := m.byHash[rootHash]; ok {
				out = append(out, p)
			}
		}
	}
	return out, nil
}

func (m *MemoryArchivist) Insert(_ context.Context, payloads ...any) ([]payload.AnyPayload, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inserted := make([]payload.AnyPayload, 0, len(payloads))
	for _, raw := range payloads {
		withMeta, err := payload.AddHashMeta(raw)
		if err != nil {
			return nil, fmt.Errorf("insert payload: %w", err)
		}
		h, _ := withMeta.String("_hash")
		dh, _ := withMeta.String("_dataHash")
		if _, exists := m.byHash[h]; !exists {
			m.order = append(m.order, h)
		}
		m.byHash[h] = withMeta
		m.byData[dh] = h
		inserted = append(inserted, withMeta)
	}
	return inserted, nil
}

func (m *MemoryArchivist) Delete(_ context.Context, hashes []string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var deleted []string
	for _, h := range hashes {
		target := h
		p, ok := m.byHash[target]
		if !ok {
			if rootHash, found := m.byData[h]; found {
				target = rootHash
				p, ok = m.byHash[target]
			}
		}
		if ok {
			delete(m.byHash, target)
			if dh, hasDH := p.String("_dataHash"); hasDH && m.byData[dh] == target {
				delete(m.byData, dh)
			}
			deleted = append(deleted, target)
		}
	}
	if len(deleted) > 0 {
		nextOrder := make([]string, 0, len(m.order))
		for _, h := range m.order {
			if _, ok := m.byHash[h]; ok {
				nextOrder = append(nextOrder, h)
			}
		}
		m.order = nextOrder
	}
	return deleted, nil
}

func (m *MemoryArchivist) All(_ context.Context) ([]payload.AnyPayload, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]payload.AnyPayload, 0, len(m.order))
	for _, h := range m.order {
		if p, ok := m.byHash[h]; ok {
			out = append(out, p)
		}
	}
	return out, nil
}

func (m *MemoryArchivist) Clear(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.order = nil
	m.byHash = make(map[string]payload.AnyPayload)
	m.byData = make(map[string]string)
	return nil
}

func (m *MemoryArchivist) Next(_ context.Context, opts *ArchivistNextOptions) ([]payload.AnyPayload, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	orderedHashes := make([]string, 0, len(m.order))
	if opts != nil && opts.Order == "desc" {
		for i := len(m.order) - 1; i >= 0; i-- {
			orderedHashes = append(orderedHashes, m.order[i])
		}
	} else {
		orderedHashes = append(orderedHashes, m.order...)
	}

	startIdx := 0
	if opts != nil && opts.Cursor != "" {
		cursorHash := opts.Cursor
		if mapped, ok := m.byData[cursorHash]; ok {
			cursorHash = mapped
		}
		found := false
		for i, h := range orderedHashes {
			if h == cursorHash {
				found = true
				if opts.Open != nil && !*opts.Open {
					startIdx = i
				} else {
					startIdx = i + 1
				}
				break
			}
		}
		if !found {
			return nil, nil
		}
	}

	if startIdx >= len(orderedHashes) {
		return nil, nil
	}
	sliceHashes := orderedHashes[startIdx:]
	if opts != nil && opts.Limit != nil && *opts.Limit >= 0 && *opts.Limit < len(sliceHashes) {
		sliceHashes = sliceHashes[:*opts.Limit]
	}

	out := make([]payload.AnyPayload, 0, len(sliceHashes))
	for _, h := range sliceHashes {
		if p, ok := m.byHash[h]; ok {
			out = append(out, p)
		}
	}
	return out, nil
}

func (m *MemoryArchivist) Commit(ctx context.Context) ([]*boundwitness.BoundWitness, error) {
	bw, err := m.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	return []*boundwitness.BoundWitness{bw}, nil
}

func (m *MemoryArchivist) Snapshot(_ context.Context) (*boundwitness.BoundWitness, error) {
	m.mu.RLock()
	items := make([]any, 0, len(m.order))
	for _, h := range m.order {
		items = append(items, m.byHash[h])
	}
	m.mu.RUnlock()
	bw, _, err := boundwitness.NewBuilder().Signer(m.account).Payloads(items...).Build()
	return bw, err
}
