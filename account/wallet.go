package account

import (
	"errors"
	"fmt"
	"strings"

	bip39 "github.com/tyler-smith/go-bip39"
)

// DefaultDerivationPath is the standard BIP-44 Ethereum/XYO derivation path.
const DefaultDerivationPath = "m/44'/60'/0'/0/0"

// HDWallet is a BIP-32/BIP-39/BIP-44 hierarchical deterministic secp256k1 wallet
// that also embeds a Secp256k1Account at its current node.
type HDWallet struct {
	*Secp256k1Account
	node *ExtendedKey
	opts []AccountOption
}

// GenerateMnemonic generates a new BIP-39 English mnemonic with the given bit size
// (128 = 12 words, 160 = 15, 192 = 18, 224 = 21, 256 = 24).
func GenerateMnemonic(bitSize int) (string, error) {
	if bitSize == 0 {
		bitSize = 256
	}
	entropy, err := bip39.NewEntropy(bitSize)
	if err != nil {
		return "", fmt.Errorf("generate BIP-39 entropy: %w", err)
	}
	return bip39.NewMnemonic(entropy)
}

// IsValidMnemonic reports whether mnemonic is a valid BIP-39 English phrase.
func IsValidMnemonic(mnemonic string) bool {
	return bip39.IsMnemonicValid(strings.TrimSpace(mnemonic))
}

// WalletFromMnemonic derives an HDWallet from a BIP-39 mnemonic and optional derivation path.
// If path is empty, DefaultDerivationPath ("m/44'/60'/0'/0/0") is used.
func WalletFromMnemonic(mnemonic string, path string, opts ...AccountOption) (*HDWallet, error) {
	return WalletFromMnemonicWithPassphrase(mnemonic, "", path, opts...)
}

// WalletFromMnemonicWithPassphrase derives an HDWallet using a BIP-39 mnemonic and passphrase.
func WalletFromMnemonicWithPassphrase(mnemonic, passphrase, path string, opts ...AccountOption) (*HDWallet, error) {
	normalized := strings.Join(strings.Fields(strings.ToLower(mnemonic)), " ")
	if !bip39.IsMnemonicValid(normalized) {
		return nil, errors.New("invalid BIP-39 mnemonic")
	}
	seed := bip39.NewSeed(normalized, passphrase)
	root, err := WalletFromSeed(seed, opts...)
	if err != nil {
		return nil, err
	}
	if path == "" {
		path = DefaultDerivationPath
	}
	return root.DerivePath(path)
}

// WalletFromSeed creates a root HDWallet (at "m") from raw seed bytes (16..64 bytes).
func WalletFromSeed(seed []byte, opts ...AccountOption) (*HDWallet, error) {
	master, err := NewMasterKey(seed)
	if err != nil {
		return nil, err
	}
	acct, err := AccountFromPrivateKey(master.Key, opts...)
	if err != nil {
		return nil, err
	}
	return &HDWallet{
		Secp256k1Account: acct,
		node:             master,
		opts:             opts,
	}, nil
}

// WalletFromSeedHex creates a root HDWallet from a hex-encoded seed.
func WalletFromSeedHex(seedHex string, opts ...AccountOption) (*HDWallet, error) {
	raw, err := DecodeHex(seedHex)
	if err != nil {
		return nil, fmt.Errorf("decode seed hex: %w", err)
	}
	return WalletFromSeed(raw, opts...)
}

// RandomWallet generates a new random 24-word mnemonic and returns the wallet at DefaultDerivationPath
// along with the mnemonic phrase.
func RandomWallet(opts ...AccountOption) (*HDWallet, string, error) {
	mnemonic, err := GenerateMnemonic(256)
	if err != nil {
		return nil, "", err
	}
	w, err := WalletFromMnemonic(mnemonic, DefaultDerivationPath, opts...)
	if err != nil {
		return nil, "", err
	}
	return w, mnemonic, nil
}

// DerivePath derives a descendant HDWallet relative to this wallet node.
func (w *HDWallet) DerivePath(path string) (*HDWallet, error) {
	childNode, err := w.node.DerivePath(path)
	if err != nil {
		return nil, err
	}
	acct, err := AccountFromPrivateKey(childNode.Key, w.opts...)
	if err != nil {
		return nil, err
	}
	return &HDWallet{
		Secp256k1Account: acct,
		node:             childNode,
		opts:             w.opts,
	}, nil
}

// ExtendedKey returns a copy of this wallet's BIP-32 extended key.
func (w *HDWallet) ExtendedKey() *ExtendedKey {
	return &ExtendedKey{
		Key:       append([]byte(nil), w.node.Key...),
		ChainCode: append([]byte(nil), w.node.ChainCode...),
		Depth:     w.node.Depth,
		ChildNum:  w.node.ChildNum,
	}
}
