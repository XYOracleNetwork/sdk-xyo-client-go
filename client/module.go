package client

import (
	"context"
	"strings"
	"sync"

	"github.com/XYOracleNetwork/sdk-xyo-client-go/account"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/boundwitness"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/payload"
)

// Yellow Paper Section 6.5 & 18.8 Module Query Schema Constants.
const (
	// Base module queries
	QuerySchemaModuleDiscover            = "network.xyo.query.module.discover"
	QuerySchemaModuleDescribe            = "network.xyo.query.module.describe"
	QuerySchemaModuleManifest            = "network.xyo.query.module.manifest"
	QuerySchemaModuleState               = "network.xyo.query.module.state"
	QuerySchemaModuleSubscribe           = "network.xyo.query.module.subscribe"
	QuerySchemaModuleAddressPreviousHash = "network.xyo.query.module.address.previousHash"

	// Archivist queries
	QuerySchemaArchivistGet      = "network.xyo.query.archivist.get"
	QuerySchemaArchivistInsert   = "network.xyo.query.archivist.insert"
	QuerySchemaArchivistDelete   = "network.xyo.query.archivist.delete"
	QuerySchemaArchivistAll      = "network.xyo.query.archivist.all"
	QuerySchemaArchivistClear    = "network.xyo.query.archivist.clear"
	QuerySchemaArchivistCommit   = "network.xyo.query.archivist.commit"
	QuerySchemaArchivistNext     = "network.xyo.query.archivist.next"
	QuerySchemaArchivistSnapshot = "network.xyo.query.archivist.snapshot"

	// Diviner queries
	QuerySchemaDivinerDivine = "network.xyo.query.diviner.divine"

	// Witness queries
	QuerySchemaWitnessObserve = "network.xyo.query.witness.observe"

	// Sentinel queries
	QuerySchemaSentinelReport = "network.xyo.query.sentinel.report"

	// Bridge queries
	QuerySchemaBridgeConnect    = "network.xyo.query.bridge.connect"
	QuerySchemaBridgeDisconnect = "network.xyo.query.bridge.disconnect"
	QuerySchemaBridgeExpose     = "network.xyo.query.bridge.expose"
	QuerySchemaBridgeUnexpose   = "network.xyo.query.bridge.unexpose"

	// Node queries
	QuerySchemaNodeAttach     = "network.xyo.query.node.attach"
	QuerySchemaNodeAttached   = "network.xyo.query.node.attached"
	QuerySchemaNodeDetach     = "network.xyo.query.node.detach"
	QuerySchemaNodeRegistered = "network.xyo.query.node.registered"
)

// ModuleQueryResult represents the canonical XYO 3-tuple [BoundWitness, Payloads, Errors].
type ModuleQueryResult struct {
	BoundWitness *boundwitness.BoundWitness   `json:"bw"`
	Payloads     []payload.AnyPayload         `json:"payloads"`
	Errors       []payload.ModuleErrorPayload `json:"errors,omitempty"`
}

// ModuleDescription describes an XYO module's identity and capabilities.
type ModuleDescription struct {
	Address  string   `json:"address"`
	Name     string   `json:"name,omitempty"`
	Queries  []string `json:"queries"`
	Children []string `json:"children,omitempty"`
}

// ModuleStatus represents a module lifecycle state.
type ModuleStatus string

const (
	ModuleStatusIdle     ModuleStatus = "idle"
	ModuleStatusStarting ModuleStatus = "starting"
	ModuleStatusStarted  ModuleStatus = "started"
	ModuleStatusStopping ModuleStatus = "stopping"
	ModuleStatusStopped  ModuleStatus = "stopped"
	ModuleStatusDead     ModuleStatus = "dead"
)

// ModuleInstance is the base interface for XYO Protocol 2.0 modules.
type ModuleInstance interface {
	Address() string
	ModName() string
	Queries() []string
	Describe(ctx context.Context) (*ModuleDescription, error)
	Query(ctx context.Context, queryPayload any, payloads ...any) (*ModuleQueryResult, error)
}

// ArchivistNextOptions configures cursor-based pagination for Archivist.Next.
type ArchivistNextOptions struct {
	Cursor string `json:"cursor,omitempty"`
	Limit  *int   `json:"limit,omitempty"`
	Open   *bool  `json:"open,omitempty"`
	Order  string `json:"order,omitempty"` // "asc" or "desc"
}

// ArchivistInstance defines the standard Archivist module operations.
type ArchivistInstance interface {
	Get(ctx context.Context, hashes []string) ([]payload.AnyPayload, error)
	Insert(ctx context.Context, payloads ...any) ([]payload.AnyPayload, error)
	Delete(ctx context.Context, hashes []string) ([]string, error)
	All(ctx context.Context) ([]payload.AnyPayload, error)
	Clear(ctx context.Context) error
	Next(ctx context.Context, opts *ArchivistNextOptions) ([]payload.AnyPayload, error)
	Commit(ctx context.Context) ([]*boundwitness.BoundWitness, error)
	Snapshot(ctx context.Context) (*boundwitness.BoundWitness, error)
}

// DivinerInstance defines the standard Diviner module operation.
type DivinerInstance interface {
	Divine(ctx context.Context, payloads ...any) ([]payload.AnyPayload, error)
}

// WitnessInstance defines the standard Witness module operation.
type WitnessInstance interface {
	Observe(ctx context.Context, payloads ...any) ([]any, error)
	Account() account.Account
}

// SentinelInstance defines the standard Sentinel module operation.
type SentinelInstance interface {
	Report(ctx context.Context, payloads ...any) ([]any, error)
}

// ModuleResolver resolves XYO modules by address, name, or supported query schema.
type ModuleResolver interface {
	ResolveByAddress(address string) ModuleInstance
	ResolveByName(name string) ModuleInstance
	ResolveByQuery(querySchema string) []ModuleInstance
	ResolveAll() []ModuleInstance
}

// StaticModuleResolver is a thread-safe in-memory ModuleResolver.
type StaticModuleResolver struct {
	mu      sync.RWMutex
	modules []ModuleInstance
}

// NewStaticModuleResolver creates a StaticModuleResolver populated with modules.
func NewStaticModuleResolver(modules ...ModuleInstance) *StaticModuleResolver {
	return &StaticModuleResolver{
		modules: append([]ModuleInstance(nil), modules...),
	}
}

// Add registers a module with the resolver.
func (r *StaticModuleResolver) Add(mod ModuleInstance) {
	if mod == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.modules = append(r.modules, mod)
}

func (r *StaticModuleResolver) ResolveByAddress(address string) ModuleInstance {
	r.mu.RLock()
	defer r.mu.RUnlock()
	target := strings.ToLower(account.StripHexPrefix(address))
	for _, m := range r.modules {
		if strings.ToLower(account.StripHexPrefix(m.Address())) == target {
			return m
		}
	}
	return nil
}

func (r *StaticModuleResolver) ResolveByName(name string) ModuleInstance {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, m := range r.modules {
		if m.ModName() == name {
			return m
		}
	}
	return nil
}

func (r *StaticModuleResolver) ResolveByQuery(querySchema string) []ModuleInstance {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []ModuleInstance
	for _, m := range r.modules {
		for _, q := range m.Queries() {
			if q == querySchema {
				out = append(out, m)
				break
			}
		}
	}
	return out
}

func (r *StaticModuleResolver) ResolveAll() []ModuleInstance {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ModuleInstance, len(r.modules))
	copy(out, r.modules)
	return out
}

// Manifest types (Yellow Paper Section 15)

type ConfigManifest struct {
	Schema   string         `json:"schema"`
	Name     string         `json:"name,omitempty"`
	Labels   map[string]any `json:"labels,omitempty"`
	Language string         `json:"language,omitempty"`
	OS       string         `json:"os,omitempty"`
}

type ModuleManifest struct {
	Config    ConfigManifest `json:"config"`
	LazyStart bool           `json:"lazyStart,omitempty"`
	Status    *ModuleStatus  `json:"status,omitempty"`
}

type NodeManifest struct {
	ModuleManifest
	Modules struct {
		Private []ModuleManifest `json:"private,omitempty"`
		Public  []ModuleManifest `json:"public,omitempty"`
	} `json:"modules"`
}

type PackageManifest struct {
	Schema      string         `json:"schema"`
	Description string         `json:"description,omitempty"`
	Nodes       []NodeManifest `json:"nodes,omitempty"`
}
