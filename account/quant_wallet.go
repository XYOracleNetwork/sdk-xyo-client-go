package account

import (
	"errors"
	"fmt"
	"strings"

	bip39 "github.com/tyler-smith/go-bip39"
)

// QuantHDWallet derives post-quantum ML-DSA-65 QuantAccounts from a BIP-39/BIP-32 master seed
// using BIP-85 HMAC-SHA512 entropy extraction (matching sdk-protocol-js v9 & sdk-xyo-client-android 3.3).
type QuantHDWallet struct {
	*QuantAccount
	node   *ExtendedKey
	master *ExtendedKey
	path   string
	opts   []AccountOption
}

// QuantWalletFromMnemonic derives a QuantHDWallet from a BIP-39 mnemonic and optional derivation path.
// If path is empty, Bip85DefaultQuantPath ("m/83696968'/128169'/32'/0'") is used.
// If a classical path is supplied (not starting with 83696968'), Bip85DefaultQuantLeafPath is appended
// before applying BIP-85 HMAC-SHA512 extraction.
func QuantWalletFromMnemonic(mnemonic string, path string, opts ...AccountOption) (*QuantHDWallet, error) {
	return QuantWalletFromMnemonicWithPassphrase(mnemonic, "", path, opts...)
}

// QuantWalletFromMnemonicWithPassphrase derives a QuantHDWallet with an optional BIP-39 passphrase.
func QuantWalletFromMnemonicWithPassphrase(mnemonic, passphrase, path string, opts ...AccountOption) (*QuantHDWallet, error) {
	normalized := strings.Join(strings.Fields(strings.ToLower(mnemonic)), " ")
	if !bip39.IsMnemonicValid(normalized) {
		return nil, errors.New("invalid BIP-39 mnemonic")
	}
	seed := bip39.NewSeed(normalized, passphrase)
	master, err := NewMasterKey(seed)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(path) == "" {
		path = Bip85DefaultQuantPath
	}
	normPath := normalizeWalletPath(path)
	target, err := master.DerivePath(normPath)
	if err != nil {
		return nil, err
	}
	return quantWalletFromNodeAndPath(target, normPath, master, opts...)
}

// QuantWalletFromExtendedKey creates a QuantHDWallet from an existing BIP-32 ExtendedKey.
func QuantWalletFromExtendedKey(key *ExtendedKey, opts ...AccountOption) (*QuantHDWallet, error) {
	if key == nil {
		return nil, errors.New("extended key must not be nil")
	}
	cloned := key.Clone()
	var master *ExtendedKey
	var path string
	if cloned.Depth == 0 {
		master = cloned
		path = "m"
	}
	return quantWalletFromNodeAndPath(cloned, path, master, opts...)
}

// QuantWalletFromExtendedKeyString creates a QuantHDWallet from a Base58Check BIP-32 xprv string.
func QuantWalletFromExtendedKeyString(xprv string, opts ...AccountOption) (*QuantHDWallet, error) {
	key, err := ParseExtendedKey(xprv)
	if err != nil {
		return nil, err
	}
	return QuantWalletFromExtendedKey(key, opts...)
}

// QuantWalletFromSeed creates a root QuantHDWallet from raw BIP-32 seed bytes.
func QuantWalletFromSeed(seed []byte, opts ...AccountOption) (*QuantHDWallet, error) {
	master, err := NewMasterKey(seed)
	if err != nil {
		return nil, err
	}
	return quantWalletFromNodeAndPath(master, "m", master, opts...)
}

// QuantWalletFromSeedHex creates a root QuantHDWallet from a hex-encoded seed.
func QuantWalletFromSeedHex(seedHex string, opts ...AccountOption) (*QuantHDWallet, error) {
	raw, err := DecodeHex(seedHex)
	if err != nil {
		return nil, fmt.Errorf("decode seed hex: %w", err)
	}
	return QuantWalletFromSeed(raw, opts...)
}

// Path returns the derivation path of this QuantHDWallet node.
func (w *QuantHDWallet) Path() string {
	return w.path
}

// ExtendedKey returns a copy of this wallet's underlying BIP-32 ExtendedKey.
func (w *QuantHDWallet) ExtendedKey() *ExtendedKey {
	return w.node.Clone()
}

// DerivePath derives a descendant QuantHDWallet along path.
// Matches sdk-xyo-client-android QuantHDWallet.derivePath semantics:
//   - Absolute BIP-85 paths ("m/83696968'/...") derive directly from the master node.
//   - Other absolute paths ("m/...") derive from the current node (if extending Path()) or master.
//   - Relative paths derive from the current node.
//   - Nodes under BIP-85 purpose apply BIP-85 extraction directly; other nodes append Bip85DefaultQuantLeafPath.
func (w *QuantHDWallet) DerivePath(path string) (*QuantHDWallet, error) {
	trimmed := strings.TrimSpace(path)
	if strings.HasPrefix(trimmed, "m/") || strings.HasPrefix(trimmed, "M/") || trimmed == "m" || trimmed == "M" {
		normAbs := normalizeWalletPath(trimmed)
		if IsBip85AbsolutePath(normAbs) {
			if w.master == nil {
				return nil, errors.New("cannot derive BIP-85 absolute path: wallet has no master node")
			}
			childNode, err := w.master.DerivePath(normAbs)
			if err != nil {
				return nil, err
			}
			return quantWalletFromNodeAndPath(childNode, normAbs, w.master, w.opts...)
		}
		if w.path != "" && normAbs == w.path {
			return quantWalletFromNodeAndPath(w.node.Clone(), w.path, w.master, w.opts...)
		}
		if w.path != "" && strings.HasPrefix(normAbs, w.path+"/") {
			rel := strings.TrimPrefix(normAbs, w.path+"/")
			childNode, err := w.node.DerivePath(rel)
			if err != nil {
				return nil, err
			}
			return quantWalletFromNodeAndPath(childNode, normAbs, w.master, w.opts...)
		}
		if w.master != nil {
			childNode, err := w.master.DerivePath(normAbs)
			if err != nil {
				return nil, err
			}
			return quantWalletFromNodeAndPath(childNode, normAbs, w.master, w.opts...)
		}
		return nil, fmt.Errorf("invalid absolute path %q for quant wallet with path %q", path, w.path)
	}

	childNode, err := w.node.DerivePath(trimmed)
	if err != nil {
		return nil, err
	}
	var newPath string
	if w.path != "" && trimmed != "" {
		newPath = w.path + "/" + trimmed
	} else if w.path == "" && trimmed != "" && IsUnderBip85Purpose(trimmed) {
		newPath = trimmed
	}
	return quantWalletFromNodeAndPath(childNode, newPath, w.master, w.opts...)
}

func quantWalletFromNodeAndPath(node *ExtendedKey, path string, master *ExtendedKey, opts ...AccountOption) (*QuantHDWallet, error) {
	leaf := node
	if !IsUnderBip85Purpose(path) {
		var err error
		leaf, err = node.DerivePath(Bip85DefaultQuantLeafPath)
		if err != nil {
			return nil, err
		}
	}
	entropy, err := Bip85EntropyFromKey(leaf.Key, Bip85SeedBytes)
	if err != nil {
		return nil, err
	}
	acct, err := QuantAccountFromSeed(entropy, opts...)
	if err != nil {
		return nil, err
	}
	return &QuantHDWallet{
		QuantAccount: acct,
		node:         node,
		master:       master,
		path:         path,
		opts:         opts,
	}, nil
}
