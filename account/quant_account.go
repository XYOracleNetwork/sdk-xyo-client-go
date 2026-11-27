package account

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	// MLDSA65SeedSize is the 32-byte deterministic seed length for FIPS 204 ML-DSA-65.
	MLDSA65SeedSize = mldsa65.SeedSize
	// MLDSA65PublicKeySize is the 1952-byte ML-DSA-65 public key length.
	MLDSA65PublicKeySize = mldsa65.PublicKeySize
	// MLDSA65PrivateKeySize is the 4032-byte ML-DSA-65 expanded secret key length.
	MLDSA65PrivateKeySize = mldsa65.PrivateKeySize
	// MLDSA65SignatureSize is the 3309-byte raw ML-DSA-65 signature length.
	MLDSA65SignatureSize = mldsa65.SignatureSize
	// MLDSA65BundleSize is the 5261-byte XYO wire bundle length: publicKey (1952B) || signature (3309B).
	MLDSA65BundleSize = MLDSA65PublicKeySize + MLDSA65SignatureSize
)

// QuantAccount implements an XYO Protocol 2.0 post-quantum ML-DSA-65 (FIPS 204) identity.
// Addresses are lowercase Bech32m strings with HRP "qm65" over the last 20 bytes of keccak256(publicKey).
// Sign returns the canonical 5261-byte wire bundle (publicKey || signature) matching @xyo-network/sdk-protocol v9,
// enabling self-contained address verification without out-of-band public key distribution.
type QuantAccount struct {
	mu                sync.Mutex
	seed              []byte
	pubKey            *mldsa65.PublicKey
	privKey           *mldsa65.PrivateKey
	pubKeyBytes       []byte
	addressBytes      []byte
	addressStr        string
	previousHash      []byte
	previousHashStore PreviousHashStore
}

// RandomQuantAccount generates a new ML-DSA-65 QuantAccount from 32 random bytes.
func RandomQuantAccount(opts ...AccountOption) (*QuantAccount, error) {
	seed := make([]byte, MLDSA65SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("generate ML-DSA-65 seed: %w", err)
	}
	return QuantAccountFromSeed(seed, opts...)
}

// QuantAccountFromSeed deterministically derives an ML-DSA-65 QuantAccount from a 32-byte seed.
func QuantAccountFromSeed(seed []byte, opts ...AccountOption) (*QuantAccount, error) {
	if len(seed) != MLDSA65SeedSize {
		return nil, fmt.Errorf("ML-DSA-65 seed must be %d bytes, got %d", MLDSA65SeedSize, len(seed))
	}
	var cfg accountConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.initErr != nil {
		return nil, cfg.initErr
	}

	var seedArr [mldsa65.SeedSize]byte
	copy(seedArr[:], seed)
	pk, sk := mldsa65.NewKeyFromSeed(&seedArr)
	pkBytes := pk.Bytes()
	addrBytes := AddressFromPublicKey(pkBytes)
	addrStr, err := EncodeQuantAddress(QuantHRPMLDSA65, addrBytes)
	if err != nil {
		return nil, err
	}

	acct := &QuantAccount{
		seed:              append([]byte(nil), seed...),
		pubKey:            pk,
		privKey:           sk,
		pubKeyBytes:       pkBytes,
		addressBytes:      addrBytes,
		addressStr:        addrStr,
		previousHashStore: cfg.previousHashStore,
	}

	if len(cfg.previousHash) > 0 {
		if len(cfg.previousHash) != HashSize {
			return nil, fmt.Errorf("previous hash must be %d bytes, got %d", HashSize, len(cfg.previousHash))
		}
		acct.previousHash = append([]byte(nil), cfg.previousHash...)
		if acct.previousHashStore != nil {
			if err := acct.previousHashStore.SetItem(acct.addressStr, hex.EncodeToString(acct.previousHash)); err != nil {
				return nil, err
			}
		}
	} else if acct.previousHashStore != nil {
		if stored, ok, err := acct.previousHashStore.GetItem(acct.addressStr); err != nil {
			return nil, err
		} else if ok {
			b, decErr := DecodeHex(stored)
			if decErr != nil || len(b) != HashSize {
				return nil, fmt.Errorf("invalid stored previous hash: %q", stored)
			}
			acct.previousHash = b
		}
	}

	return acct, nil
}

// QuantAccountFromSeedHex creates a QuantAccount from a 64-character hex seed string.
func QuantAccountFromSeedHex(seedHex string, opts ...AccountOption) (*QuantAccount, error) {
	clean := StripHexPrefix(strings.TrimSpace(seedHex))
	if len(clean) != MLDSA65SeedSize*2 {
		return nil, fmt.Errorf("ML-DSA-65 seed hex must be %d chars, got %d", MLDSA65SeedSize*2, len(clean))
	}
	raw, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("decode ML-DSA-65 seed hex: %w", err)
	}
	return QuantAccountFromSeed(raw, opts...)
}

func (a *QuantAccount) Algorithm() Algorithm {
	return AlgorithmMLDSA65
}

func (a *QuantAccount) Address() string {
	return a.addressStr
}

func (a *QuantAccount) AddressBytes() []byte {
	out := make([]byte, len(a.addressBytes))
	copy(out, a.addressBytes)
	return out
}

// Seed returns a copy of the 32-byte ML-DSA-65 private seed.
func (a *QuantAccount) Seed() []byte {
	out := make([]byte, len(a.seed))
	copy(out, a.seed)
	return out
}

func (a *QuantAccount) PublicKey() []byte {
	out := make([]byte, len(a.pubKeyBytes))
	copy(out, a.pubKeyBytes)
	return out
}

func (a *QuantAccount) PublicKeyUncompressed() []byte {
	return a.PublicKey()
}

// KeccakBytes returns the 32-byte Keccak-256 hash of the ML-DSA-65 public key.
func (a *QuantAccount) KeccakBytes() []byte {
	return Keccak256(a.pubKeyBytes)
}

func (a *QuantAccount) PreviousHash() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.previousHash) == 0 {
		return nil
	}
	out := make([]byte, len(a.previousHash))
	copy(out, a.previousHash)
	return out
}

func (a *QuantAccount) PreviousHashHex() *string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.previousHash) == 0 {
		return nil
	}
	s := hex.EncodeToString(a.previousHash)
	return &s
}

// LoadPreviousHash loads or explicitly sets the account's previous hash under its signing mutex.
func (a *QuantAccount) LoadPreviousHash(explicit []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(explicit) > 0 {
		if len(explicit) != HashSize {
			return fmt.Errorf("previous hash must be %d bytes, got %d", HashSize, len(explicit))
		}
		a.previousHash = append([]byte(nil), explicit...)
		if a.previousHashStore != nil {
			return a.previousHashStore.SetItem(a.addressStr, hex.EncodeToString(a.previousHash))
		}
		return nil
	}
	if a.previousHashStore != nil {
		stored, ok, err := a.previousHashStore.GetItem(a.addressStr)
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

// RollbackPreviousHash reverts the account's previous hash from expectedCurrent back to restorePrev
// if the account's current previous hash still matches expectedCurrent.
func (a *QuantAccount) RollbackPreviousHash(expectedCurrent, restorePrev []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if hex.EncodeToString(a.previousHash) != hex.EncodeToString(expectedCurrent) {
		return nil
	}
	if a.previousHashStore != nil {
		if len(restorePrev) == 0 {
			if err := a.previousHashStore.RemoveItem(a.addressStr); err != nil {
				return err
			}
		} else {
			curHex := hex.EncodeToString(expectedCurrent)
			if _, err := a.previousHashStore.SetItemIfMatch(a.addressStr, &curHex, hex.EncodeToString(restorePrev)); err != nil {
				return err
			}
		}
	}
	if len(restorePrev) == 0 {
		a.previousHash = nil
	} else {
		a.previousHash = append([]byte(nil), restorePrev...)
	}
	return nil
}

// Sign signs the 32-byte hash with ML-DSA-65, returning the 5261-byte XYO wire bundle
// (publicKey || signature) and advancing the previous-hash chain.
func (a *QuantAccount) Sign(hash []byte) ([]byte, error) {
	if len(hash) != HashSize {
		return nil, fmt.Errorf("hash must be %d bytes, got %d", HashSize, len(hash))
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	sig := make([]byte, MLDSA65SignatureSize)
	if err := mldsa65.SignTo(a.privKey, hash, nil, true, sig); err != nil {
		return nil, fmt.Errorf("ML-DSA-65 sign: %w", err)
	}
	bundle := BundleMLDSA65Signature(a.pubKeyBytes, sig)
	nextHex := hex.EncodeToString(hash)

	if a.previousHashStore != nil {
		var expected *string
		if len(a.previousHash) > 0 {
			prev := hex.EncodeToString(a.previousHash)
			expected = &prev
		}
		ok, err := a.previousHashStore.SetItemIfMatch(a.addressStr, expected, nextHex)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrPreviousHashConflict
		}
	}

	a.previousHash = append([]byte(nil), hash...)
	return bundle, nil
}

// SignDetached signs msg without advancing the previous-hash chain, returning the 5261-byte wire bundle.
func (a *QuantAccount) SignDetached(msg []byte) ([]byte, error) {
	sig := make([]byte, MLDSA65SignatureSize)
	if err := mldsa65.SignTo(a.privKey, msg, nil, true, sig); err != nil {
		return nil, fmt.Errorf("ML-DSA-65 sign: %w", err)
	}
	return BundleMLDSA65Signature(a.pubKeyBytes, sig), nil
}

// SignRaw signs msg and returns the raw 3309-byte ML-DSA-65 signature (without prepended public key)
// without advancing previousHash.
func (a *QuantAccount) SignRaw(msg []byte) ([]byte, error) {
	sig := make([]byte, MLDSA65SignatureSize)
	if err := mldsa65.SignTo(a.privKey, msg, nil, true, sig); err != nil {
		return nil, fmt.Errorf("ML-DSA-65 sign: %w", err)
	}
	return sig, nil
}

// Verify checks either a 5261-byte wire bundle (publicKey || signature) or a raw 3309-byte
// ML-DSA-65 signature against msg for this account.
func (a *QuantAccount) Verify(msg []byte, signature []byte) bool {
	switch len(signature) {
	case MLDSA65BundleSize:
		return VerifyMLDSA65Bundle(a.addressBytes, msg, signature)
	case MLDSA65SignatureSize:
		return mldsa65.Verify(a.pubKey, msg, nil, signature)
	default:
		return false
	}
}

// BundleMLDSA65Signature concatenates publicKey (1952B) || signature (3309B) into the 5261B wire format.
func BundleMLDSA65Signature(publicKey, signature []byte) []byte {
	out := make([]byte, len(publicKey)+len(signature))
	copy(out, publicKey)
	copy(out[len(publicKey):], signature)
	return out
}

// UnbundleMLDSA65Signature splits a 5261-byte wire bundle into (publicKey, signature).
func UnbundleMLDSA65Signature(bundle []byte) (publicKey, signature []byte, err error) {
	if len(bundle) != MLDSA65BundleSize {
		return nil, nil, fmt.Errorf("invalid ML-DSA-65 bundle length: got %d, want %d", len(bundle), MLDSA65BundleSize)
	}
	return bundle[:MLDSA65PublicKeySize], bundle[MLDSA65PublicKeySize:], nil
}
