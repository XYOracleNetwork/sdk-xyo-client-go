package account

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

const (
	// PrivateKeySize is the secp256k1 private key length in bytes.
	PrivateKeySize = 32
	// HashSize is the SHA-256 hash length in bytes.
	HashSize = 32
	// Secp256k1SignatureSize is the compact r||s signature length in bytes (no recovery ID).
	Secp256k1SignatureSize = 64
	// Secp256k1UncompressedPubKeySize is the 64-byte X||Y uncompressed public key without 0x04 prefix.
	Secp256k1UncompressedPubKeySize = 64
	// Secp256k1CompressedPubKeySize is the 33-byte compressed public key.
	Secp256k1CompressedPubKeySize = 33
)

// Account is the common interface implemented by both classical secp256k1 accounts
// and post-quantum ML-DSA-65 QuantAccounts.
type Account interface {
	// Algorithm returns the account's cryptographic algorithm ("secp256k1" or "ml-dsa-65").
	Algorithm() Algorithm
	// Address returns the canonical address string (40-char lowercase hex or qm65 Bech32m).
	Address() string
	// AddressBytes returns a copy of the raw 20-byte address payload.
	AddressBytes() []byte
	// PublicKey returns the primary public key bytes (33B compressed for secp256k1, 1952B for ML-DSA-65).
	PublicKey() []byte
	// PublicKeyUncompressed returns the uncompressed public key bytes
	// (64B X||Y without 0x04 prefix for secp256k1, 1952B for ML-DSA-65).
	PublicKeyUncompressed() []byte
	// PreviousHash returns a copy of the 32-byte previous hash, or nil if none.
	PreviousHash() []byte
	// PreviousHashHex returns the lowercase 64-char hex previous hash, or nil if none.
	PreviousHashHex() *string
	// Sign signs the given 32-byte hash and advances the previous-hash chain.
	Sign(hash []byte) ([]byte, error)
	// SignDetached signs the given hash without advancing the previous-hash chain.
	SignDetached(hash []byte) ([]byte, error)
	// Verify verifies a signature against the given hash for this account.
	Verify(hash []byte, signature []byte) bool
}

// AccountOption configures an Account or QuantAccount upon construction.
type AccountOption func(*accountConfig)

type accountConfig struct {
	previousHash      []byte
	previousHashStore PreviousHashStore
}

// WithPreviousHash initializes an account with a known 32-byte previous hash.
func WithPreviousHash(hash []byte) AccountOption {
	return func(c *accountConfig) {
		if len(hash) > 0 {
			cp := make([]byte, len(hash))
			copy(cp, hash)
			c.previousHash = cp
		}
	}
}

// WithPreviousHashHex initializes an account with a known hex-encoded previous hash.
func WithPreviousHashHex(hashHex string) AccountOption {
	return func(c *accountConfig) {
		if hashHex == "" {
			return
		}
		if b, err := DecodeHex(hashHex); err == nil {
			c.previousHash = b
		}
	}
}

// WithPreviousHashStore attaches a PreviousHashStore to persist chain state.
func WithPreviousHashStore(store PreviousHashStore) AccountOption {
	return func(c *accountConfig) {
		c.previousHashStore = store
	}
}

// Secp256k1Account implements XYO Protocol 2.0 classical secp256k1 accounts.
// Signatures are 64-byte RFC 6979 deterministic low-S compact r||s values.
type Secp256k1Account struct {
	mu                sync.Mutex
	privKey           *secp256k1.PrivateKey
	pubKey            *secp256k1.PublicKey
	pubCompressed     []byte
	pubUncompressed64 []byte
	addressBytes      []byte
	addressHex        string
	previousHash      []byte
	previousHashStore PreviousHashStore
}

// RandomAccount generates a new random secp256k1 Account using crypto/rand.
func RandomAccount(opts ...AccountOption) (*Secp256k1Account, error) {
	priv, err := secp256k1.GeneratePrivateKeyFromRand(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate secp256k1 key: %w", err)
	}
	return fromSecp256k1PrivKey(priv, opts...)
}

// AccountFromPrivateKey creates a secp256k1 Account from a 32-byte private key.
func AccountFromPrivateKey(key []byte, opts ...AccountOption) (*Secp256k1Account, error) {
	if len(key) != PrivateKeySize {
		return nil, fmt.Errorf("private key must be %d bytes, got %d", PrivateKeySize, len(key))
	}
	var scalar secp256k1.ModNScalar
	if overflow := scalar.SetByteSlice(key); overflow || scalar.IsZero() {
		return nil, errors.New("private key out of valid secp256k1 scalar range (0, n)")
	}
	priv := secp256k1.NewPrivateKey(&scalar)
	return fromSecp256k1PrivKey(priv, opts...)
}

// AccountFromPrivateKeyHex creates a secp256k1 Account from a 64-char hex string (optional 0x prefix).
func AccountFromPrivateKeyHex(hexKey string, opts ...AccountOption) (*Secp256k1Account, error) {
	clean := StripHexPrefix(strings.TrimSpace(hexKey))
	if len(clean) != PrivateKeySize*2 {
		return nil, fmt.Errorf("private key hex must be %d chars, got %d", PrivateKeySize*2, len(clean))
	}
	raw, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("decode private key hex: %w", err)
	}
	return AccountFromPrivateKey(raw, opts...)
}

func fromSecp256k1PrivKey(priv *secp256k1.PrivateKey, opts ...AccountOption) (*Secp256k1Account, error) {
	var cfg accountConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	pub := priv.PubKey()
	uncompressed65 := pub.SerializeUncompressed()
	pub64 := make([]byte, Secp256k1UncompressedPubKeySize)
	copy(pub64, uncompressed65[1:])

	addrBytes := AddressFromPublicKey(pub64)
	acct := &Secp256k1Account{
		privKey:           priv,
		pubKey:            pub,
		pubCompressed:     pub.SerializeCompressed(),
		pubUncompressed64: pub64,
		addressBytes:      addrBytes,
		addressHex:        hex.EncodeToString(addrBytes),
		previousHashStore: cfg.previousHashStore,
	}

	if len(cfg.previousHash) > 0 {
		if len(cfg.previousHash) != HashSize {
			return nil, fmt.Errorf("previous hash must be %d bytes, got %d", HashSize, len(cfg.previousHash))
		}
		acct.previousHash = append([]byte(nil), cfg.previousHash...)
		if acct.previousHashStore != nil {
			if err := acct.previousHashStore.SetItem(acct.addressHex, hex.EncodeToString(acct.previousHash)); err != nil {
				return nil, err
			}
		}
	} else if acct.previousHashStore != nil {
		if stored, ok, err := acct.previousHashStore.GetItem(acct.addressHex); err != nil {
			return nil, err
		} else if ok {
			if b, decErr := DecodeHex(stored); decErr == nil && len(b) == HashSize {
				acct.previousHash = b
			}
		}
	}

	return acct, nil
}

func (a *Secp256k1Account) Algorithm() Algorithm {
	return AlgorithmSecp256k1
}

func (a *Secp256k1Account) Address() string {
	return a.addressHex
}

func (a *Secp256k1Account) AddressBytes() []byte {
	out := make([]byte, len(a.addressBytes))
	copy(out, a.addressBytes)
	return out
}

// PrivateKey returns a copy of the 32-byte private key.
func (a *Secp256k1Account) PrivateKey() []byte {
	return a.privKey.Serialize()
}

// PrivateKeyHex returns the lowercase 64-character hex private key.
func (a *Secp256k1Account) PrivateKeyHex() string {
	return hex.EncodeToString(a.privKey.Serialize())
}

func (a *Secp256k1Account) PublicKey() []byte {
	out := make([]byte, len(a.pubCompressed))
	copy(out, a.pubCompressed)
	return out
}

func (a *Secp256k1Account) PublicKeyUncompressed() []byte {
	out := make([]byte, len(a.pubUncompressed64))
	copy(out, a.pubUncompressed64)
	return out
}

// PublicKeyUncompressedHex returns the 128-char lowercase hex uncompressed public key (X||Y, no 0x04).
func (a *Secp256k1Account) PublicKeyUncompressedHex() string {
	return hex.EncodeToString(a.pubUncompressed64)
}

func (a *Secp256k1Account) PreviousHash() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.previousHash) == 0 {
		return nil
	}
	out := make([]byte, len(a.previousHash))
	copy(out, a.previousHash)
	return out
}

func (a *Secp256k1Account) PreviousHashHex() *string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.previousHash) == 0 {
		return nil
	}
	s := hex.EncodeToString(a.previousHash)
	return &s
}

// LoadPreviousHash loads or explicitly sets the account's previous hash under its signing mutex.
func (a *Secp256k1Account) LoadPreviousHash(explicit []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(explicit) > 0 {
		if len(explicit) != HashSize {
			return fmt.Errorf("previous hash must be %d bytes, got %d", HashSize, len(explicit))
		}
		a.previousHash = append([]byte(nil), explicit...)
		if a.previousHashStore != nil {
			return a.previousHashStore.SetItem(a.addressHex, hex.EncodeToString(a.previousHash))
		}
		return nil
	}
	if a.previousHashStore != nil {
		stored, ok, err := a.previousHashStore.GetItem(a.addressHex)
		if err != nil {
			return err
		}
		if ok {
			b, err := DecodeHex(stored)
			if err != nil || len(b) != HashSize {
				return fmt.Errorf("invalid stored previous hash: %q", stored)
			}
			a.previousHash = b
		}
	}
	return nil
}

// Sign computes a deterministic RFC 6979 low-S 64-byte compact ECDSA signature over the 32-byte hash
// and advances the previous-hash chain (updating the configured PreviousHashStore with CAS).
func (a *Secp256k1Account) Sign(hash []byte) ([]byte, error) {
	if len(hash) != HashSize {
		return nil, fmt.Errorf("hash must be %d bytes, got %d", HashSize, len(hash))
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	sig64 := signSecp256k1Raw(a.privKey, hash)
	nextHex := hex.EncodeToString(hash)

	if a.previousHashStore != nil {
		var expected *string
		if len(a.previousHash) > 0 {
			prev := hex.EncodeToString(a.previousHash)
			expected = &prev
		}
		ok, err := a.previousHashStore.SetItemIfMatch(a.addressHex, expected, nextHex)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrPreviousHashConflict
		}
	}

	a.previousHash = append([]byte(nil), hash...)
	return sig64, nil
}

// SignDetached computes a 64-byte compact ECDSA signature without advancing previousHash.
func (a *Secp256k1Account) SignDetached(hash []byte) ([]byte, error) {
	if len(hash) != HashSize {
		return nil, fmt.Errorf("hash must be %d bytes, got %d", HashSize, len(hash))
	}
	return signSecp256k1Raw(a.privKey, hash), nil
}

// Verify checks whether signature is a valid canonical low-S 64-byte secp256k1 signature over hash
// produced by this account.
func (a *Secp256k1Account) Verify(hash []byte, signature []byte) bool {
	return VerifySecp256k1Signature(a.addressBytes, hash, signature)
}

func signSecp256k1Raw(priv *secp256k1.PrivateKey, hash []byte) []byte {
	// ecdsa.SignCompact produces 65 bytes: [header || r(32) || s(32)] using RFC 6979 + BIP 0062 low-S.
	compact := ecdsa.SignCompact(priv, hash, false)
	sig64 := make([]byte, Secp256k1SignatureSize)
	copy(sig64, compact[1:65])
	return sig64
}
