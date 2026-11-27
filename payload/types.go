package payload

// AddressPayload represents a "network.xyo.address" payload.
type AddressPayload struct {
	BasePayload
	Address string `json:"address,omitempty"`
	Name    string `json:"name,omitempty"`
}

func NewAddressPayload(address, name string) AddressPayload {
	return AddressPayload{
		BasePayload: BasePayload{Schema: SchemaAddress},
		Address:     address,
		Name:        name,
	}
}

// ConfigPayload represents a "network.xyo.config" payload.
type ConfigPayload struct {
	BasePayload
	Config any `json:"config,omitempty"`
}

func NewConfigPayload(cfg any) ConfigPayload {
	return ConfigPayload{
		BasePayload: BasePayload{Schema: SchemaConfig},
		Config:      cfg,
	}
}

// DomainPayload represents a "network.xyo.domain" payload.
type DomainPayload struct {
	BasePayload
	Domain  string `json:"domain,omitempty"`
	Aliases any    `json:"aliases,omitempty"`
}

func NewDomainPayload(domain string, aliases any) DomainPayload {
	return DomainPayload{
		BasePayload: BasePayload{Schema: SchemaDomain},
		Domain:      domain,
		Aliases:     aliases,
	}
}

// IdPayload represents a "network.xyo.id" payload.
type IdPayload struct {
	BasePayload
	Salt string `json:"salt"`
}

func NewIdPayload(salt string) IdPayload {
	return IdPayload{
		BasePayload: BasePayload{Schema: SchemaId},
		Salt:        salt,
	}
}

// ModuleErrorPayload represents a "network.xyo.error.module" payload.
type ModuleErrorPayload struct {
	BasePayload
	Message string   `json:"message,omitempty"`
	Name    string   `json:"name,omitempty"`
	Query   string   `json:"query,omitempty"`
	Sources []string `json:"$sources,omitempty"`
}

func NewModuleErrorPayload(name, message, queryHash string) ModuleErrorPayload {
	return ModuleErrorPayload{
		BasePayload: BasePayload{Schema: SchemaModuleError},
		Name:        name,
		Message:     message,
		Query:       queryHash,
	}
}

// PayloadBundle represents a "network.xyo.payload.bundle" payload.
type PayloadBundle struct {
	BasePayload
	Root string `json:"root,omitempty"`
}

func NewPayloadBundle(root string) PayloadBundle {
	return PayloadBundle{
		BasePayload: BasePayload{Schema: SchemaPayloadBundle},
		Root:        root,
	}
}

// SchemaPayload represents a "network.xyo.schema" payload.
type SchemaPayload struct {
	BasePayload
	Definition any `json:"definition,omitempty"`
}

func NewSchemaPayload(definition any) SchemaPayload {
	return SchemaPayload{
		BasePayload: BasePayload{Schema: SchemaSchema},
		Definition:  definition,
	}
}

// ValuePayload represents a "network.xyo.value" payload.
type ValuePayload struct {
	BasePayload
	Value any `json:"value,omitempty"`
}

func NewValuePayload(value any) ValuePayload {
	return ValuePayload{
		BasePayload: BasePayload{Schema: SchemaValue},
		Value:       value,
	}
}

// EventPayload represents a "network.xyo.event" payload.
type EventPayload struct {
	BasePayload
	Event     string `json:"event"`
	Timestamp int64  `json:"time_stamp"`
}

func NewEventPayload(event string, timestampMs int64) EventPayload {
	return EventPayload{
		BasePayload: BasePayload{Schema: SchemaEvent},
		Event:       event,
		Timestamp:   timestampMs,
	}
}

// NetworkNodePayload represents a "network.xyo.network.node" payload.
type NetworkNodePayload struct {
	BasePayload
	Name string `json:"name,omitempty"`
	Slug string `json:"slug,omitempty"`
	Type string `json:"type"`
	URI  string `json:"uri"`
	Web  string `json:"web,omitempty"`
}

// NetworkPayload represents a "network.xyo.network" payload.
type NetworkPayload struct {
	BasePayload
	Name  string               `json:"name,omitempty"`
	Slug  string               `json:"slug,omitempty"`
	Nodes []NetworkNodePayload `json:"nodes,omitempty"`
}

// Coordinates holds WGS-84 geographic coordinates for LocationPayload.
type Coordinates struct {
	Accuracy         *float64 `json:"accuracy,omitempty"`
	Altitude         *float64 `json:"altitude,omitempty"`
	AltitudeAccuracy *float64 `json:"altitudeAccuracy,omitempty"`
	Heading          *float64 `json:"heading,omitempty"`
	Latitude         float64  `json:"latitude"`
	Longitude        float64  `json:"longitude"`
	Speed            *float64 `json:"speed,omitempty"`
}

// CurrentLocation wraps coordinates and optional observation timestamp.
type CurrentLocation struct {
	Coords    Coordinates `json:"coords"`
	Timestamp *int64      `json:"timestamp,omitempty"`
}

// LocationPayload represents a "network.xyo.location.current" payload (matching Swift/Android LocationPayload).
type LocationPayload struct {
	BasePayload
	CurrentLocation CurrentLocation `json:"currentLocation"`
}

// NewLocationPayload creates a LocationPayload with the canonical "network.xyo.location.current" schema.
func NewLocationPayload(loc CurrentLocation) LocationPayload {
	return LocationPayload{
		BasePayload:     BasePayload{Schema: SchemaLocationCurrent},
		CurrentLocation: loc,
	}
}

// SystemInfoPayload represents a "network.xyo.system.info" payload (matching Swift/Android SystemInfoPayload).
type SystemInfoPayload struct {
	BasePayload
	Device  map[string]any `json:"device,omitempty"`
	Network map[string]any `json:"network,omitempty"`
	OS      map[string]any `json:"os,omitempty"`
}

// NewSystemInfoPayload creates a SystemInfoPayload with the canonical "network.xyo.system.info" schema.
func NewSystemInfoPayload(device, network, osInfo map[string]any) SystemInfoPayload {
	return SystemInfoPayload{
		BasePayload: BasePayload{Schema: SchemaSystemInfo},
		Device:      device,
		Network:     network,
		OS:          osInfo,
	}
}

// NetworkMain is the canonical Mainnet archivist network preset.
var NetworkMain = NetworkPayload{
	BasePayload: BasePayload{Schema: SchemaNetwork},
	Name:        "Main",
	Slug:        "main",
	Nodes: []NetworkNodePayload{
		{
			BasePayload: BasePayload{Schema: SchemaNetworkNode},
			Name:        "XYO Archivist",
			Slug:        "archivist",
			Type:        "archivist",
			URI:         "https://api.archivist.xyo.network",
		},
	},
}

// NetworkBeta is the canonical Beta archivist network preset.
var NetworkBeta = NetworkPayload{
	BasePayload: BasePayload{Schema: SchemaNetwork},
	Name:        "Beta",
	Slug:        "beta",
	Nodes: []NetworkNodePayload{
		{
			BasePayload: BasePayload{Schema: SchemaNetworkNode},
			Name:        "XYO Archivist Beta",
			Slug:        "archivist",
			Type:        "archivist",
			URI:         "https://beta.api.archivist.xyo.network",
		},
	},
}
