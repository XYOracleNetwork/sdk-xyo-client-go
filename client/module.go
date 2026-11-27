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
	QuerySchemaModuleAddress             = "network.xyo.query.module.address"
	QuerySchemaModuleState               = "network.xyo.query.module.state"
	QuerySchemaModuleSubscribe           = "network.xyo.query.module.subscribe"
	QuerySchemaModuleAddressPreviousHash = "network.xyo.query.module.address.previous"

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
	QuerySchemaNodeCertify    = "network.xyo.query.node.certify"
	QuerySchemaNodeDetach     = "network.xyo.query.node.detach"
	QuerySchemaNodeRegistered = "network.xyo.query.node.registered"
)

// ModuleQueryResult represents the canonical XYO 3-tuple [BoundWitness, Payloads, Errors].
type ModuleQueryResult struct {
	BoundWitness *boundwitness.BoundWitness   `json:"bw"`
	Payloads     []payload.AnyPayload         `json:"payloads"`
	Errors       []payload.ModuleErrorPayload `json:"errors,omitempty"`
}

// BWDataHash returns the dataHash of the response BoundWitness (or "" if BoundWitness is nil).
func (r *ModuleQueryResult) BWDataHash() (string, error) {
	if r == nil || r.BoundWitness == nil {
		return "", nil
	}
	return r.BoundWitness.DataHash()
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
	ModuleStatusCreating ModuleStatus = "creating"
	ModuleStatusCreated  ModuleStatus = "created"
	ModuleStatusIdle     ModuleStatus = "idle"
	ModuleStatusStarting ModuleStatus = "starting"
	ModuleStatusStarted  ModuleStatus = "started"
	ModuleStatusStopping ModuleStatus = "stopping"
	ModuleStatusStopped  ModuleStatus = "stopped"
	ModuleStatusError    ModuleStatus = "error"
	ModuleStatusWrapped  ModuleStatus = "wrapped"
	ModuleStatusProxy    ModuleStatus = "proxy"
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

// BridgeInstance defines the standard Bridge module operations (matching Android BridgeInstance).
type BridgeInstance interface {
	ModuleInstance
	Connect(ctx context.Context) (bool, error)
	Disconnect(ctx context.Context) (bool, error)
	Expose(ctx context.Context, id string) ([]string, error)
	Unexpose(ctx context.Context, id string) ([]string, error)
}

// NodeInstance defines the standard Node module operations (matching Android NodeInstance).
type NodeInstance interface {
	ModuleInstance
	Attach(ctx context.Context, nameOrAddress string, external bool) (string, error)
	Attached(ctx context.Context) ([]string, error)
	Detach(ctx context.Context, nameOrAddress string) (string, error)
	Registered(ctx context.Context) ([]string, error)
}

// ModuleConfig represents base configuration fields shared by XYO modules.
type ModuleConfig struct {
	payload.BasePayload
	Name     string            `json:"name,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
	Security map[string]any    `json:"security,omitempty"`
}

// ModuleParams encapsulates module creation parameters.
type ModuleParams struct {
	Account account.Account
	Config  *ModuleConfig
}

// ArchivistParents configures parent archivists for commit/read-through/write-through.
type ArchivistParents struct {
	Commit []string `json:"commit,omitempty"`
	Read   []string `json:"read,omitempty"`
	Write  []string `json:"write,omitempty"`
}

// ArchivistConfig represents an Archivist module configuration payload.
type ArchivistConfig struct {
	ModuleConfig
	Parents           *ArchivistParents `json:"parents,omitempty"`
	StoreParentReads  *bool             `json:"storeParentReads,omitempty"`
	RequireAllParents *bool             `json:"requireAllParents,omitempty"`
}

// SentinelTask describes a witness/archivist reporting task on a Sentinel.
type SentinelTask struct {
	Module string `json:"module"`
	Input  bool   `json:"input,omitempty"`
}

// SentinelConfig represents a Sentinel module configuration payload.
type SentinelConfig struct {
	ModuleConfig
	Synchronous *bool          `json:"synchronous,omitempty"`
	Tasks       []SentinelTask `json:"tasks,omitempty"`
}

// BridgeConfig represents a base Bridge module configuration payload.
type BridgeConfig struct {
	ModuleConfig
	MaxDepth *int `json:"maxDepth,omitempty"`
}

// BridgeClientConfig represents a client Bridge configuration targeting a remote host.
type BridgeClientConfig struct {
	BridgeConfig
	Host string `json:"host,omitempty"`
}

// BridgeHostConfig represents a host Bridge configuration exposing local modules.
type BridgeHostConfig struct {
	BridgeConfig
	Expose []string `json:"expose,omitempty"`
}

// Module type-check helpers (matching Android ModuleTypeChecks & Swift ModuleInstance.isSupportedQuery).

// IsSupportedQuery reports whether mod advertises querySchema in its Queries list.
func IsSupportedQuery(mod ModuleInstance, querySchema string) bool {
	if mod == nil {
		return false
	}
	for _, q := range mod.Queries() {
		if q == querySchema {
			return true
		}
	}
	return false
}

// IsArchivist reports whether mod advertises core Archivist query schemas.
func IsArchivist(mod ModuleInstance) bool {
	return IsSupportedQuery(mod, QuerySchemaArchivistGet) && IsSupportedQuery(mod, QuerySchemaArchivistInsert)
}

// IsDiviner reports whether mod advertises the Diviner divine query schema.
func IsDiviner(mod ModuleInstance) bool {
	return IsSupportedQuery(mod, QuerySchemaDivinerDivine)
}

// IsWitness reports whether mod advertises the Witness observe query schema.
func IsWitness(mod ModuleInstance) bool {
	return IsSupportedQuery(mod, QuerySchemaWitnessObserve)
}

// IsSentinel reports whether mod advertises the Sentinel report query schema.
func IsSentinel(mod ModuleInstance) bool {
	return IsSupportedQuery(mod, QuerySchemaSentinelReport)
}

// IsBridge reports whether mod advertises Bridge connect/disconnect query schemas.
func IsBridge(mod ModuleInstance) bool {
	return IsSupportedQuery(mod, QuerySchemaBridgeConnect) && IsSupportedQuery(mod, QuerySchemaBridgeDisconnect)
}

// IsNode reports whether mod advertises Node attach/attached query schemas.
func IsNode(mod ModuleInstance) bool {
	return IsSupportedQuery(mod, QuerySchemaNodeAttach) && IsSupportedQuery(mod, QuerySchemaNodeAttached)
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
