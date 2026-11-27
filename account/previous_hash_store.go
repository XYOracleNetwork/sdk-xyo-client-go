package account

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ErrPreviousHashConflict is returned by SetItemIfMatch when the stored previous hash
// does not match the caller's expected value.
var ErrPreviousHashConflict = errors.New("previous hash compare-and-swap conflict")

// PreviousHashStore persists the latest signed bound witness dataHash per account address
// to maintain the XYO previous-hash anti-replay chain across sessions.
type PreviousHashStore interface {
	GetItem(address string) (string, bool, error)
	SetItem(address string, hash string) error
	SetItemIfMatch(address string, expected *string, next string) (bool, error)
	RemoveItem(address string) error
}

// MemoryPreviousHashStore is a concurrency-safe in-memory PreviousHashStore.
type MemoryPreviousHashStore struct {
	mu    sync.RWMutex
	items map[string]string
}

// NewMemoryPreviousHashStore creates a new empty in-memory previous hash store.
func NewMemoryPreviousHashStore() *MemoryPreviousHashStore {
	return &MemoryPreviousHashStore{
		items: make(map[string]string),
	}
}

func normalizeStoreKey(address string) string {
	return strings.ToLower(StripHexPrefix(address))
}

func (s *MemoryPreviousHashStore) GetItem(address string) (string, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.items[normalizeStoreKey(address)]
	return v, ok, nil
}

func (s *MemoryPreviousHashStore) SetItem(address string, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[normalizeStoreKey(address)] = strings.ToLower(StripHexPrefix(hash))
	return nil
}

func (s *MemoryPreviousHashStore) SetItemIfMatch(address string, expected *string, next string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := normalizeStoreKey(address)
	cur, exists := s.items[key]
	if expected == nil {
		if exists {
			return false, nil
		}
	} else {
		exp := strings.ToLower(StripHexPrefix(*expected))
		if !exists || cur != exp {
			return false, nil
		}
	}
	s.items[key] = strings.ToLower(StripHexPrefix(next))
	return true, nil
}

func (s *MemoryPreviousHashStore) RemoveItem(address string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, normalizeStoreKey(address))
	return nil
}

// FilePreviousHashStore persists previous hashes as a JSON map on disk with atomic writes.
type FilePreviousHashStore struct {
	mu    sync.Mutex
	path  string
	items map[string]string
}

// NewFilePreviousHashStore loads or initializes a JSON-backed PreviousHashStore at path.
func NewFilePreviousHashStore(path string) (*FilePreviousHashStore, error) {
	s := &FilePreviousHashStore{
		path:  path,
		items: make(map[string]string),
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return nil, err
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &s.items); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *FilePreviousHashStore) persistLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.items, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (s *FilePreviousHashStore) GetItem(address string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.items[normalizeStoreKey(address)]
	return v, ok, nil
}

func (s *FilePreviousHashStore) SetItem(address string, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := normalizeStoreKey(address)
	oldVal, existed := s.items[key]
	s.items[key] = strings.ToLower(StripHexPrefix(hash))
	if err := s.persistLocked(); err != nil {
		if existed {
			s.items[key] = oldVal
		} else {
			delete(s.items, key)
		}
		return err
	}
	return nil
}

func (s *FilePreviousHashStore) SetItemIfMatch(address string, expected *string, next string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := normalizeStoreKey(address)
	cur, exists := s.items[key]
	if expected == nil {
		if exists {
			return false, nil
		}
	} else {
		exp := strings.ToLower(StripHexPrefix(*expected))
		if !exists || cur != exp {
			return false, nil
		}
	}
	s.items[key] = strings.ToLower(StripHexPrefix(next))
	if err := s.persistLocked(); err != nil {
		if exists {
			s.items[key] = cur
		} else {
			delete(s.items, key)
		}
		return false, err
	}
	return true, nil
}

func (s *FilePreviousHashStore) RemoveItem(address string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := normalizeStoreKey(address)
	oldVal, existed := s.items[key]
	delete(s.items, key)
	if err := s.persistLocked(); err != nil {
		if existed {
			s.items[key] = oldVal
		}
		return err
	}
	return nil
}
