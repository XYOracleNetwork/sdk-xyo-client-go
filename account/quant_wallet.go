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
	node *ExtendedKey
	opts []AccountOption
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
	root, err := QuantWalletFromSeed(seed, opts...)
	if err != nil {
		return nil, err
	}
	if path == "" {
		path = Bip85DefaultQuantPath
	}
	return root.DerivePath(path)
}

// QuantWalletFromSeed creates a root QuantHDWallet from raw BIP-32 seed bytes.
func QuantWalletFromSeed(seed []byte, opts ...AccountOption) (*QuantHDWallet, error) {
	master, err := NewMasterKey(seed)
	if err != nil {
		return nil, err
	}
	return quantWalletFromNode(master, opts...)
}

// QuantWalletFromSeedHex creates a root QuantHDWallet from a hex-encoded seed.
func QuantWalletFromSeedHex(seedHex string, opts ...AccountOption) (*QuantHDWallet, error) {
	raw, err := DecodeHex(seedHex)
	if err != nil {
		return nil, fmt.Errorf("decode seed hex: %w", err)
	}
	return QuantWalletFromSeed(raw, opts...)
}

// DerivePath derives a descendant QuantHDWallet along path.
// If path is already under BIP-85 (starts with 83696968'), it derives directly and applies BIP-85 extraction.
// Otherwise it derives the given path and appends Bip85DefaultQuantLeafPath ("83696968'/128169'/32'/0'").
func (w *QuantHDWallet) DerivePath(path string) (*QuantHDWallet, error) {
	target, err := w.node.DerivePath(path)
	if err != nil {
		return nil, err
	}
	if isBip85Path(path) {
		return quantWalletFromBip85Leaf(target, w.opts...)
	}
	return quantWalletFromNode(target, w.opts...)
}

func quantWalletFromNode(node *ExtendedKey, opts ...AccountOption) (*QuantHDWallet, error) {
	leaf, err := node.DerivePath(Bip85DefaultQuantLeafPath)
	if err != nil {
		return nil, err
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
		opts:         opts,
	}, nil
}

func quantWalletFromBip85Leaf(leaf *ExtendedKey, opts ...AccountOption) (*QuantHDWallet, error) {
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
		node:         leaf,
		opts:         opts,
	}, nil
}
