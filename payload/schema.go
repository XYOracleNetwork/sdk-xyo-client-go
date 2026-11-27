package payload

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Core XYO Protocol 2.0 and XL1 schema constants (Yellow Paper Section 7).
const (
	// Core protocol schemas - Section 7.1
	SchemaBasePayload   = "network.xyo.payload"
	SchemaBoundWitness  = "network.xyo.boundwitness"
	SchemaQuery         = "network.xyo.query"
	SchemaModuleError   = "network.xyo.error.module"
	SchemaPayloadBundle = "network.xyo.payload.bundle"
	SchemaPayloadSet    = "network.xyo.payload.set"

	// Core data schemas - Section 7.7
	SchemaAddress         = "network.xyo.address"
	SchemaAddressChild    = "network.xyo.address.child"
	SchemaAddressPrevious = "network.xyo.address.hash.previous"
	SchemaConfig          = "network.xyo.config"
	SchemaDomain          = "network.xyo.domain"
	SchemaId              = "network.xyo.id"
	SchemaSchema          = "network.xyo.schema"
	SchemaValue           = "network.xyo.value"
	SchemaRange           = "network.xyo.range"
	SchemaNumber          = "network.xyo.number"
	SchemaBigInt          = "network.xyo.bigint"
	SchemaEvent           = "network.xyo.event"
	SchemaNetwork         = "network.xyo.network"
	SchemaNetworkNode     = "network.xyo.network.node"
	SchemaLocationCurrent = "network.xyo.location.current"
	SchemaSystemInfo      = "network.xyo.system.info"
	SchemaDebug           = "network.xyo.debug"
	SchemaTest            = "network.xyo.test"

	// Module config schemas - Section 7.2
	SchemaModuleConfig    = "network.xyo.module.config"
	SchemaArchivistConfig = "network.xyo.archivist.config"
	SchemaBridgeConfig    = "network.xyo.bridge.config"
	SchemaDivinerConfig   = "network.xyo.diviner.config"
	SchemaNodeConfig      = "network.xyo.node.config"
	SchemaSentinelConfig  = "network.xyo.sentinel.config"
	SchemaWitnessConfig   = "network.xyo.witness.config"

	// Manifest schemas - Section 7.4
	SchemaPackageManifest     = "network.xyo.manifest.package"
	SchemaPackageDappManifest = "network.xyo.manifest.package.dapp"
	SchemaNodeManifest        = "network.xyo.manifest.node"
	SchemaModuleManifest      = "network.xyo.manifest.module"

	// Module payload & filter schemas - Section 7.3
	SchemaModuleState        = "network.xyo.module.state"
	SchemaModuleDescription  = "network.xyo.module.description"
	SchemaModuleFilter       = "network.xyo.module.filter"
	SchemaChildCertification = "network.xyo.child.certification"
	SchemaArchivistSnapshot  = "network.xyo.archivist.snapshot"
	SchemaArchivistStats     = "network.xyo.archivist.stats"

	// Diviner type schemas - Section 7.5
	SchemaDivinerPayload           = "network.xyo.diviner.payload"
	SchemaDivinerBoundWitness      = "network.xyo.diviner.boundwitness"
	SchemaDivinerAddressHistory    = "network.xyo.diviner.address.history"
	SchemaDivinerAddressChain      = "network.xyo.diviner.address.chain"
	SchemaDivinerAddressSpace      = "network.xyo.diviner.address.space"
	SchemaDivinerTransform         = "network.xyo.diviner.transform"
	SchemaDivinerForecasting       = "network.xyo.diviner.forecasting"
	SchemaDivinerJSONPath          = "network.xyo.diviner.jsonpath"
	SchemaDivinerJSONPathAggregate = "network.xyo.diviner.jsonpath.aggregate"
	SchemaDivinerJSONPatch         = "network.xyo.diviner.jsonpatch"
	SchemaDivinerIndexing          = "network.xyo.diviner.indexing"
	SchemaDivinerPayloadPointer    = "network.xyo.diviner.payload.pointer"
	SchemaDivinerSchemaList        = "network.xyo.diviner.schema.list"
	SchemaDivinerBoundWitnessStats = "network.xyo.diviner.boundwitness.stats"
	SchemaDivinerPayloadStats      = "network.xyo.diviner.payload.stats"
	SchemaDivinerSchemaStats       = "network.xyo.diviner.schema.stats"

	// Automation schemas - Section 7.6
	SchemaAutomation            = "network.xyo.automation"
	SchemaAutomationInterval    = "network.xyo.automation.interval"
	SchemaAutomationEventModule = "network.xyo.automation.event.module"

	// XL1 Chain Protocol schemas
	SchemaTransfer         = "network.xyo.transfer"
	SchemaTime             = "network.xyo.time"
	SchemaHash             = "network.xyo.hash"
	SchemaStepComplete     = "network.xyo.step.complete"
	SchemaChainStakeIntent = "network.xyo.chain.stake.intent"
)

var schemaLexicalRegex = regexp.MustCompile(`^(?:[a-z0-9]+\.)*[a-z0-9]+$`)

// ValidateSchemaName validates an XYO schema name per Yellow Paper / SchemaNameValidator:
// non-empty, lowercase ASCII alphanumeric segments separated by dots, and at least 3 levels
// (reverse-DNS format, e.g. "network.xyo.boundwitness").
func ValidateSchemaName(schema string) error {
	if schema == "" {
		return errors.New("schema cannot be empty")
	}
	if schema != strings.ToLower(schema) {
		return fmt.Errorf("schema %q must be lowercase", schema)
	}
	if !schemaLexicalRegex.MatchString(schema) {
		return fmt.Errorf("schema %q contains invalid characters", schema)
	}
	parts := strings.Split(schema, ".")
	if len(parts) < 3 {
		return fmt.Errorf("schema %q must have at least 3 dot-separated levels", schema)
	}
	return nil
}

// IsValidSchema reports whether schema passes ValidateSchemaName.
func IsValidSchema(schema string) bool {
	return ValidateSchemaName(schema) == nil
}

// SchemaRootDomain returns the reversed root domain from a valid reverse-DNS schema
// (e.g. "network.xyo.boundwitness" -> "xyo.network").
func SchemaRootDomain(schema string) (string, error) {
	if err := ValidateSchemaName(schema); err != nil {
		return "", err
	}
	parts := strings.Split(schema, ".")
	return parts[1] + "." + parts[0], nil
}

// SchemaNameLevels returns the number of dot-separated levels in schema (0 if empty).
func SchemaNameLevels(schema string) int {
	if strings.TrimSpace(schema) == "" {
		return 0
	}
	return len(strings.Split(schema, "."))
}
