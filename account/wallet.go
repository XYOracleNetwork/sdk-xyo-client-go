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
	node   *ExtendedKey
	master *ExtendedKey
	path   string
	opts   []AccountOption
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
	normalized := strings.Join(strings.Fields(strings.ToLower(mnemonic)), " ")
	return bip39.IsMnemonicValid(normalized)
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
	master, err := NewMasterKey(seed)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(path) == "" {
		path = DefaultDerivationPath
	}
	target, err := master.DerivePath(path)
	if err != nil {
		return nil, err
	}
	acct, err := AccountFromPrivateKey(target.Key, opts...)
	if err != nil {
		return nil, err
	}
	return &HDWallet{
		Secp256k1Account: acct,
		node:             target,
		master:           master,
		path:             normalizeWalletPath(path),
		opts:             opts,
	}, nil
}

// WalletFromExtendedKey creates an HDWallet from an existing BIP-32 ExtendedKey.
func WalletFromExtendedKey(key *ExtendedKey, opts ...AccountOption) (*HDWallet, error) {
	if key == nil {
		return nil, errors.New("extended key must not be nil")
	}
	cloned := key.Clone()
	acct, err := AccountFromPrivateKey(cloned.Key, opts...)
	if err != nil {
		return nil, err
	}
	var master *ExtendedKey
	var path string
	if cloned.Depth == 0 {
		master = cloned
		path = "m"
	}
	return &HDWallet{
		Secp256k1Account: acct,
		node:             cloned,
		master:           master,
		path:             path,
		opts:             opts,
	}, nil
}

// WalletFromExtendedKeyString creates an HDWallet from a Base58Check BIP-32 xprv string.
func WalletFromExtendedKeyString(xprv string, opts ...AccountOption) (*HDWallet, error) {
	key, err := ParseExtendedKey(xprv)
	if err != nil {
		return nil, err
	}
	return WalletFromExtendedKey(key, opts...)
}

// WalletFromSeed creates a root HDWallet (at "m") from raw seed bytes (16..64 bytes).
func WalletFromSeed(seed []byte, opts ...AccountOption) (*HDWallet, error) {
	master, err := NewMasterKey(seed)
	if err != nil {
		return nil, err
	}
	return WalletFromExtendedKey(master, opts...)
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

// Path returns the BIP-32 derivation path of this wallet node (or "" if derived from a non-root ExtendedKey).
func (w *HDWallet) Path() string {
	return w.path
}

// DerivePath derives a descendant HDWallet along path.
// Absolute paths starting with "m/" derive from the master node (or from the current node if path extends Path());
// relative paths derive from the current node.
func (w *HDWallet) DerivePath(path string) (*HDWallet, error) {
	trimmed := strings.TrimSpace(path)
	var childNode *ExtendedKey
	var newPath string
	var err error

	if strings.HasPrefix(trimmed, "m/") || strings.HasPrefix(trimmed, "M/") || trimmed == "m" || trimmed == "M" {
		normAbs := normalizeWalletPath(trimmed)
		if w.path != "" && normAbs == w.path {
			childNode = w.node.Clone()
			newPath = w.path
		} else if w.path != "" && strings.HasPrefix(normAbs, w.path+"/") {
			rel := strings.TrimPrefix(normAbs, w.path+"/")
			childNode, err = w.node.DerivePath(rel)
			newPath = normAbs
		} else if w.master != nil {
			childNode, err = w.master.DerivePath(normAbs)
			newPath = normAbs
		} else {
			return nil, fmt.Errorf("cannot derive absolute path %q on non-root wallet without master key", path)
		}
	} else {
		childNode, err = w.node.DerivePath(trimmed)
		if w.path != "" && trimmed != "" {
			newPath = w.path + "/" + trimmed
		}
	}
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
		master:           w.master,
		path:             newPath,
		opts:             w.opts,
	}, nil
}

// ExtendedKey returns a copy of this wallet's BIP-32 extended key.
func (w *HDWallet) ExtendedKey() *ExtendedKey {
	return w.node.Clone()
}

func normalizeWalletPath(path string) string {
	trimmed := strings.TrimSpace(path)
	trimmed = strings.TrimSuffix(trimmed, "/")
	if trimmed == "" || trimmed == "m" || trimmed == "M" {
		return "m"
	}
	if strings.HasPrefix(trimmed, "M/") {
		return "m/" + trimmed[2:]
	}
	if strings.HasPrefix(trimmed, "m/") {
		return trimmed
	}
	return "m/" + trimmed
}
