package payload

import (
	"errors"
	"fmt"
)

// ValidatePayload validates a Payload's schema name.
func ValidatePayload(p Payload) []error {
	if p == nil {
		return []error{errors.New("payload is nil")}
	}
	if err := ValidateSchemaName(p.GetSchema()); err != nil {
		return []error{err}
	}
	return nil
}

// PayloadWrapper wraps a payload with cached hashing and validation helpers.
type PayloadWrapper struct {
	payload  any
	schema   string
	hash     string
	dataHash string
}

// Wrap wraps any Payload or JSON object into a PayloadWrapper.
func Wrap(p any) (*PayloadWrapper, error) {
	if p == nil {
		return nil, errors.New("cannot wrap nil payload")
	}
	var schema string
	if typed, ok := p.(Payload); ok {
		schema = typed.GetSchema()
	} else {
		ap, err := ToAnyPayload(p)
		if err != nil {
			return nil, err
		}
		schema = ap.GetSchema()
	}
	if schema == "" {
		return nil, errors.New("payload missing schema field")
	}
	return &PayloadWrapper{
		payload: p,
		schema:  schema,
	}, nil
}

// Payload returns the underlying wrapped payload value.
func (w *PayloadWrapper) Payload() any {
	return w.payload
}

// Schema returns the wrapped payload's schema string.
func (w *PayloadWrapper) Schema() string {
	return w.schema
}

// Hash computes (and caches) the root hash of the wrapped payload.
func (w *PayloadWrapper) Hash() (string, error) {
	if w.hash != "" {
		return w.hash, nil
	}
	h, err := Hash(w.payload)
	if err != nil {
		return "", err
	}
	w.hash = h
	return h, nil
}

// DataHash computes (and caches) the dataHash of the wrapped payload.
func (w *PayloadWrapper) DataHash() (string, error) {
	if w.dataHash != "" {
		return w.dataHash, nil
	}
	dh, err := DataHash(w.payload)
	if err != nil {
		return "", err
	}
	w.dataHash = dh
	return dh, nil
}

// Validate checks the schema and any embedded _hash / _dataHash storage metadata consistency.
func (w *PayloadWrapper) Validate() []error {
	var errs []error
	if err := ValidateSchemaName(w.schema); err != nil {
		errs = append(errs, err)
	}
	ap, err := ToAnyPayload(w.payload)
	if err != nil {
		errs = append(errs, err)
		return errs
	}
	if storedHash, ok := ap.String("_hash"); ok && storedHash != "" {
		actual, err := w.Hash()
		if err != nil {
			errs = append(errs, fmt.Errorf("compute _hash: %w", err))
		} else if actual != storedHash {
			errs = append(errs, fmt.Errorf("_hash mismatch: stored %s != computed %s", storedHash, actual))
		}
	}
	if storedDataHash, ok := ap.String("_dataHash"); ok && storedDataHash != "" {
		actual, err := w.DataHash()
		if err != nil {
			errs = append(errs, fmt.Errorf("compute _dataHash: %w", err))
		} else if actual != storedDataHash {
			errs = append(errs, fmt.Errorf("_dataHash mismatch: stored %s != computed %s", storedDataHash, actual))
		}
	}
	return errs
}
