package payload

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Core XYO Protocol 2.0 and XL1 schema constants (Yellow Paper Section 7).
const (
	// Core protocol schemas
	SchemaBasePayload   = "network.xyo.payload"
	SchemaBoundWitness  = "network.xyo.boundwitness"
	SchemaQuery         = "network.xyo.query"
	SchemaModuleError   = "network.xyo.error.module"
	SchemaPayloadBundle = "network.xyo.payload.bundle"

	// Core data schemas
	SchemaAddress         = "network.xyo.address"
	SchemaConfig          = "network.xyo.config"
	SchemaDomain          = "network.xyo.domain"
	SchemaId              = "network.xyo.id"
	SchemaSchema          = "network.xyo.schema"
	SchemaValue           = "network.xyo.value"
	SchemaEvent           = "network.xyo.event"
	SchemaNetwork         = "network.xyo.network"
	SchemaNetworkNode     = "network.xyo.network.node"
	SchemaLocationCurrent = "network.xyo.location.current"
	SchemaSystemInfo      = "network.xyo.system.info"
	SchemaDebug           = "network.xyo.debug"
	SchemaTest            = "network.xyo.test"

	// Module config schemas
	SchemaModuleConfig    = "network.xyo.module.config"
	SchemaArchivistConfig = "network.xyo.archivist.config"
	SchemaBridgeConfig    = "network.xyo.bridge.config"
	SchemaDivinerConfig   = "network.xyo.diviner.config"
	SchemaNodeConfig      = "network.xyo.node.config"
	SchemaSentinelConfig  = "network.xyo.sentinel.config"
	SchemaWitnessConfig   = "network.xyo.witness.config"

	// Manifest schemas
	SchemaPackageManifest = "network.xyo.manifest.package"
	SchemaNodeManifest    = "network.xyo.manifest.node"
	SchemaModuleManifest  = "network.xyo.manifest.module"

	// Module payload schemas
	SchemaModuleState       = "network.xyo.module.state"
	SchemaModuleDescription = "network.xyo.module.description"

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
