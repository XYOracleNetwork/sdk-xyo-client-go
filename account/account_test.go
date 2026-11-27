package account_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/XYOracleNetwork/sdk-xyo-client-go/account"
)

type jsCompatVectors struct {
	Accounts []struct {
		PrivateKey            string `json:"private_key"`
		PublicKeyUncompressed string `json:"public_key_uncompressed"`
		Address               string `json:"address"`
		Signatures            []struct {
			MessageHash string `json:"message_hash"`
			Signature   string `json:"signature"`
		} `json:"signatures"`
	} `json:"accounts"`
	HDWallets []struct {
		Mnemonic    string `json:"mnemonic"`
		Derivations []struct {
			Path                  string `json:"path"`
			PrivateKey            string `json:"private_key"`
			PublicKeyUncompressed string `json:"public_key_uncompressed"`
			Address               string `json:"address"`
		} `json:"derivations"`
	} `json:"hd_wallets"`
}

func loadVectors(t *testing.T) jsCompatVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "jsCompatVectors.json"))
	if err != nil {
		t.Fatalf("read jsCompatVectors.json: %v", err)
	}
	var v jsCompatVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshal jsCompatVectors.json: %v", err)
	}
	return v
}

func TestJsCompatAccounts(t *testing.T) {
	v := loadVectors(t)
	if len(v.Accounts) == 0 {
		t.Fatal("expected account vectors")
	}

	for i, tc := range v.Accounts {
		acct, err := account.AccountFromPrivateKeyHex(tc.PrivateKey)
		if err != nil {
			t.Fatalf("account[%d]: %v", i, err)
		}
		if got := acct.PublicKeyUncompressedHex(); got != tc.PublicKeyUncompressed {
			t.Errorf("account[%d] pubkey:\n got  %s\n want %s", i, got, tc.PublicKeyUncompressed)
		}
		if got := acct.Address(); got != tc.Address {
			t.Errorf("account[%d] address: got %s, want %s", i, got, tc.Address)
		}

		for j, sigTC := range tc.Signatures {
			fresh, err := account.AccountFromPrivateKeyHex(tc.PrivateKey)
			if err != nil {
				t.Fatalf("account[%d] fresh: %v", i, err)
			}
			hashBytes, err := hex.DecodeString(sigTC.MessageHash)
			if err != nil {
				t.Fatalf("decode hash: %v", err)
			}
			sig, err := fresh.Sign(hashBytes)
			if err != nil {
				t.Fatalf("account[%d] sig[%d]: %v", i, j, err)
			}
			gotSig := hex.EncodeToString(sig)
			if gotSig != sigTC.Signature {
				t.Errorf("account[%d] sig[%d] RFC6979 mismatch:\n got  %s\n want %s", i, j, gotSig, sigTC.Signature)
			}
			if !fresh.Verify(hashBytes, sig) {
				t.Errorf("account[%d] sig[%d] verify failed", i, j)
			}
			if !account.VerifySignatureHex(tc.Address, sigTC.MessageHash, gotSig) {
				t.Errorf("account[%d] sig[%d] VerifySignatureHex failed", i, j)
			}
		}
	}
}

func TestYellowPaperVerifyVectors(t *testing.T) {
	// Section 8.1.1 Key Derivation
	acct, err := account.AccountFromPrivateKeyHex("7f71bc5644f8f521f7e9b73f7a391e82c05432f8a9d36c44d6b1edbf1d8db62f")
	if err != nil {
		t.Fatal(err)
	}
	if acct.PublicKeyUncompressedHex() != "ed6f3b86542f45aab88ec48ab1366b462bd993fec83e234054afd8f2311fba774800fdb40c04918463b463a6044b83413a604550bfba8f8911beb65475d6528e" {
		t.Fatal("section 8.1.1 pubkey mismatch")
	}
	if acct.Address() != "5e7a847447e7fec41011ae7d32d768f86605ba03" {
		t.Fatal("section 8.1.1 address mismatch")
	}

	// AddressValue.spec.ts / Yellow Paper Section 8.1.3: [messageHash, signature, address]
	verifyCases := []struct {
		msg  string
		sig  string
		addr string
	}{
		{"b35238cf5a1c52915b2149741d6841ee6a36bf59ec545928d68ec4b0036faa48", "e5c4d459c64b38b95c6b8d3597d4085b2f88c87e1b653351fd278c9092ebe1cb2e96ba28c80b61699f2dafd9f5cbe0aeb93078c4e8b246165a599310ab7b10e2", "336c46e57d17f4f9e2a5c85171027fe0e8993225"},
		{"28cf6d3952fd24095a5e9ade3a0ce5d0789219a536d275657eb9816a92cf3ea8", "664e0b587c653fd0bbb533f5a6bdd27d68e96494fcd7657fbf2e6b6281b2b75502498ba7e64d6f149edff674cb9fe81c99a6870e65e39e4a7307eb8363e9f65e", "57359a536a343f957ad6c73108f9452df9b2d726"},
		{"4cce5a4abefc91d0e93d2b3e39123ceb6de15e4f383d77078785fbfd78ea4301", "bb8c13260c43058e0238db8fd91c6e35f65331f6d237eff933fe3a879eca74e4137d47337cd86e7fdb4dd9c7548e83fb795e7a4d94691b406992be97bbe765a2", "6e20a2da9b94bd77e04834acc5a630a98d14bd3c"},
		{"43f9941e762ccc9a037f8c1dadecf578937f265ecaf85ca8a73c85d467791632", "898c8b1388f49b3d433ff1fdc25d0789e2133ab1cdc1c5461058377d96f039595fa6c923268337da10afd303b97139930ba2ce846b1829d5db3ef37c5433efcc", "c6a675fb92d6c496158a2e4ec6fbb50837a89057"},
		{"f54fe3a9663f5259241024ea20fc296937ae2a8149256744cec7f515f9c0bf68", "7380b85fb0e9e46e55ead4d34fa66167fb7745d202865f524ab3a1b3728786db455a7bfd0b2aa3a6e76a6c0020464075889aa2e2d26b13c8589562a0aa535ff1", "ca8acb608446f3a5c89b74754ef30fdb7fc2591c"},
		{"538d1aadd8e1c45feff63c66ca397ff21a7feff969f4967ad64b1b22f5fbac9b", "bf00f704cbfae145726a358fc59cc6df1ec9965bc28f020c27673e57ca371eb1102e1990618760141e49825ac33bfa66ecb0a5597f6b4d50736242390f723722", "83e7596cd6551205c33ae76cda0fb619d9bb5932"},
		{"87bc867209fa430152381b6c13724f3cf5e4b6e62d44cb2332042d279f3bb300", "9a77619f71e41a0acf5a00ba057c8092140ff247aeb28e13d0ee6f5ee6280a3d5b78841913fa434a92730ed739ceed28f398556f164f4d95f5ee8148acaf71ce", "81a0951a8d8cf3127b18577453fba372925e89c5"},
		{"5266f8ffd5f45cef6611db587d07cab2119dfa09714d84e7966ca2eb28711e6f", "6e083eea0828613facee06186169ca785aff665e3890f3640bab1418f504ab9642a52bfd64fdc498329beeba77a3ab78ad2e7c9a04d0db534f06e8adc831d025", "a6e47b18e0a7d14a62d43443cc1ee44b733ca3e1"},
		{"668e0e656311430d886d08b494e174556a25336347774d275f95fe4d12e00aab", "b052751b5c3c8f3fa1616a5cbcaecfcadaeb253e9e460000897b53262366a2fb23cd044aaa713b61a2841ffd2bb5fc97e96d5c7e85a552cd9e5572d42e4783ac", "6bb02a7b148dbf399010bb0836cb395d7cab3171"},
		{"99ef40dddb13ef73de51ebee7a297d78ccf3390838efa704489bf03e27e50da1", "3ec5fc9ab65ae0219ea516a34f6bf5dd1f461c81a83cfe025a6ebae86df35ca37fb384f450f2681e461cd0d364610afabb98e70fddd39d028488e830fab0f936", "1294e0310e421ec1937d475c11ac6952b054b1be"},
	}

	for i, tc := range verifyCases {
		if !account.VerifySignatureHex(tc.addr, tc.msg, tc.sig) {
			t.Errorf("verifyCase[%d] failed for address %s", i, tc.addr)
		}
	}
}

func TestHighSMalleabilityRejected(t *testing.T) {
	acct, err := account.AccountFromPrivateKeyHex("7f71bc5644f8f521f7e9b73f7a391e82c05432f8a9d36c44d6b1edbf1d8db62f")
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := hex.DecodeString("4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a")
	sig, err := acct.SignDetached(hash)
	if err != nil {
		t.Fatal(err)
	}
	if !acct.Verify(hash, sig) {
		t.Fatal("low-S signature should verify")
	}

	// Construct malleable twin (r, n - s)
	secpN, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	sVal := new(big.Int).SetBytes(sig[32:])
	highS := new(big.Int).Sub(secpN, sVal)
	malleated := make([]byte, 64)
	copy(malleated[:32], sig[:32])
	highS.FillBytes(malleated[32:])

	if account.IsCanonicalSecp256k1Signature(malleated) {
		t.Fatal("high-S signature must not be canonical")
	}
	if acct.Verify(hash, malleated) {
		t.Fatal("high-S signature must be rejected")
	}
}

func TestJsCompatHDWallets(t *testing.T) {
	v := loadVectors(t)
	if len(v.HDWallets) == 0 {
		t.Fatal("expected hd_wallet vectors")
	}

	for wi, wv := range v.HDWallets {
		for di, dv := range wv.Derivations {
			w, err := account.WalletFromMnemonic(wv.Mnemonic, dv.Path)
			if err != nil {
				t.Fatalf("wallet[%d][%d] (%s): %v", wi, di, dv.Path, err)
			}
			if got := w.PrivateKeyHex(); got != dv.PrivateKey {
				t.Errorf("wallet[%d][%d] priv: got %s want %s", wi, di, got, dv.PrivateKey)
			}
			if got := w.PublicKeyUncompressedHex(); got != dv.PublicKeyUncompressed {
				t.Errorf("wallet[%d][%d] pub: got %s want %s", wi, di, got, dv.PublicKeyUncompressed)
			}
			if got := w.Address(); got != dv.Address {
				t.Errorf("wallet[%d][%d] addr: got %s want %s", wi, di, got, dv.Address)
			}
		}
	}
}

func TestBech32mQuantAddressVector(t *testing.T) {
	payload := make([]byte, 20)
	for i := 0; i < 20; i++ {
		payload[i] = byte((i*7 + 1) & 0xff)
	}
	encoded, err := account.EncodeQuantAddress("qm65", payload)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "qm651qyyq79says4nyw2qga892hrrdfchsluxleee2j"
	if encoded != expected {
		t.Fatalf("bech32m encode: got %s, want %s", encoded, expected)
	}
	if !account.IsQuantAddress(encoded) || !account.IsAddress(encoded) {
		t.Fatal("expected valid quant address")
	}
	hrp, decoded, err := account.DecodeQuantAddress(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if hrp != "qm65" || !bytes.Equal(decoded, payload) {
		t.Fatalf("decoded mismatch: hrp=%s payload=%x", hrp, decoded)
	}
	// Uppercase must be rejected for quant addresses
	if account.IsQuantAddress("QM651QYYQ79SAYS4NYW2QGA892HRRDFCHSLUXLEEE2J") {
		t.Fatal("uppercase quant address must be rejected")
	}
}

func TestQuantAccountNistAcvpVector(t *testing.T) {
	seedHex := "1bd67dc782b2958e189e315c040dd1f64c8ab232a6a170e1a7a52c33f10851b1"
	acct, err := account.QuantAccountFromSeedHex(seedHex)
	if err != nil {
		t.Fatal(err)
	}
	pk := acct.PublicKey()
	if len(pk) != account.MLDSA65PublicKeySize {
		t.Fatalf("pk len: got %d want %d", len(pk), account.MLDSA65PublicKeySize)
	}
	wantHead := "43ad6560d3bb684667a559ee6ec7c816020e5b65671f270f2353a8c912b6c26b"
	wantTail := "486432b090f0cce86aa84b661ff22d4a56035e821a1ce30f33afeb6c7b8fa9ce"
	if got := hex.EncodeToString(pk[:32]); got != wantHead {
		t.Errorf("pk head mismatch:\n got  %s\n want %s", got, wantHead)
	}
	if got := hex.EncodeToString(pk[1920:1952]); got != wantTail {
		t.Errorf("pk tail mismatch:\n got  %s\n want %s", got, wantTail)
	}
	if !account.IsQuantAddress(acct.Address()) {
		t.Errorf("invalid quant address: %s", acct.Address())
	}

	hash, _ := hex.DecodeString("4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a")
	bundle, err := acct.Sign(hash)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle) != account.MLDSA65BundleSize {
		t.Fatalf("bundle len: got %d want %d", len(bundle), account.MLDSA65BundleSize)
	}
	if !acct.Verify(hash, bundle) {
		t.Fatal("QuantAccount.Verify(bundle) failed")
	}
	if !account.VerifySignature(acct.Address(), hash, bundle) {
		t.Fatal("VerifySignature(quantAddr, hash, bundle) failed")
	}
	// Raw 3309B signature verification also supported on QuantAccount.Verify
	rawSig, err := acct.SignRaw(hash)
	if err != nil {
		t.Fatal(err)
	}
	if !acct.Verify(hash, rawSig) {
		t.Fatal("QuantAccount.Verify(rawSig) failed")
	}
	// Tampered hash must fail
	badHash := append([]byte(nil), hash...)
	badHash[0] ^= 0xff
	if account.VerifySignature(acct.Address(), badHash, bundle) {
		t.Fatal("tampered hash must fail verification")
	}
}

func TestBip85AndQuantHDWallet(t *testing.T) {
	// BIP-85 spec test vectors (matching Android Bip85Test.kt & QuantHDWalletTest.kt)
	const bip85MasterXprv = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"

	// BIP-85 path helpers
	if got := account.Bip85DefaultLeafTail(0); got != "83696968'/128169'/32'/0'" {
		t.Fatalf("Bip85DefaultLeafTail(0) = %q", got)
	}
	if got := account.Bip85DefaultLeafTail(5); got != "83696968'/128169'/32'/5'" {
		t.Fatalf("Bip85DefaultLeafTail(5) = %q", got)
	}
	if !account.IsBip85AbsolutePath("m/83696968'/128169'") || account.IsBip85AbsolutePath("m/44'/60'/0'/0/0") {
		t.Fatal("IsBip85AbsolutePath mismatch")
	}
	if !account.IsUnderBip85Purpose("m/83696968'") || !account.IsUnderBip85Purpose("83696968'/128169'") || account.IsUnderBip85Purpose("m/44'/60'/0'/0/0") {
		t.Fatal("IsUnderBip85Purpose mismatch")
	}

	master, err := account.ParseExtendedKey(bip85MasterXprv)
	if err != nil {
		t.Fatalf("ParseExtendedKey: %v", err)
	}
	// Serialize round-trip check
	if roundTripped, err := account.ParseExtendedKey(master.Serialize()); err != nil || !bytes.Equal(roundTripped.Key, master.Key) || !bytes.Equal(roundTripped.ChainCode, master.ChainCode) {
		t.Fatalf("ExtendedKey serialize/parse round-trip failed: %v", err)
	}

	bip85Vectors := []struct {
		name string
		path string
		want string
	}{
		{"spec-hmac-case-1", "m/83696968'/0'/0'", "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f0"},
		{"spec-hmac-case-2", "m/83696968'/0'/1'", "70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872"},
		{"spec-hex-entropy-app", "m/83696968'/128169'/64'/0'", "492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f8785"},
	}
	for _, tc := range bip85Vectors {
		t.Run(tc.name, func(t *testing.T) {
			ent, err := account.Bip85DeriveEntropy(master, tc.path, 32)
			if err != nil {
				t.Fatalf("Bip85DeriveEntropy(%s): %v", tc.path, err)
			}
			if got := hex.EncodeToString(ent); got != tc.want {
				t.Errorf("BIP-85 %s:\n got  %s\n want %s", tc.path, got, tc.want)
			}
		})
	}

	// QuantHDWallet from xprv (matching Android QuantHDWalletTest.kt)
	testHash, _ := hex.DecodeString("4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a")
	rootQW, err := account.QuantWalletFromExtendedKeyString(bip85MasterXprv)
	if err != nil {
		t.Fatalf("QuantWalletFromExtendedKeyString: %v", err)
	}
	if len(rootQW.AddressBytes()) != 20 || len(rootQW.Address()) != 43 || !account.IsQuantAddress(rootQW.Address()) {
		t.Fatalf("unexpected quant root address: %q", rootQW.Address())
	}
	sig, err := rootQW.Sign(testHash)
	if err != nil || !rootQW.Verify(testHash, sig) {
		t.Fatalf("rootQW sign/verify failed: err=%v", err)
	}

	child5, err := rootQW.DerivePath("m/83696968'/128169'/32'/5'")
	if err != nil {
		t.Fatalf("DerivePath bip85 explicit: %v", err)
	}
	if child5.Address() == rootQW.Address() || len(child5.Address()) != 43 {
		t.Fatalf("unexpected child5 address: %q", child5.Address())
	}
	if sig5, err := child5.Sign(testHash); err != nil || !child5.Verify(testHash, sig5) {
		t.Fatalf("child5 sign/verify failed: %v", err)
	}

	childBase, err := rootQW.DerivePath("m/83696968'/0'/0'")
	if err != nil || !account.IsQuantAddress(childBase.Address()) {
		t.Fatalf("DerivePath bip85 base case failed: %v", err)
	}

	childClassical, err := rootQW.DerivePath("m/44'/60'/0'/0/7")
	if err != nil || !account.IsQuantAddress(childClassical.Address()) {
		t.Fatalf("DerivePath classical auto-leaf failed: %v", err)
	}

	// Determinism across separate master loads
	rootQW2, err := account.QuantWalletFromExtendedKeyString(bip85MasterXprv)
	if err != nil {
		t.Fatal(err)
	}
	a42, err := rootQW.DerivePath("m/83696968'/128169'/32'/42'")
	if err != nil {
		t.Fatal(err)
	}
	b42, err := rootQW2.DerivePath("m/83696968'/128169'/32'/42'")
	if err != nil {
		t.Fatal(err)
	}
	if a42.Address() != b42.Address() {
		t.Fatalf("non-deterministic derivation: %s vs %s", a42.Address(), b42.Address())
	}

	// Verify BIP-39 mnemonic -> QuantHDWallet determinism
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	qw1, err := account.QuantWalletFromMnemonic(mnemonic, "")
	if err != nil {
		t.Fatal(err)
	}
	qw2, err := account.QuantWalletFromMnemonic(mnemonic, account.Bip85DefaultQuantPath)
	if err != nil {
		t.Fatal(err)
	}
	if qw1.Address() != qw2.Address() {
		t.Fatalf("quant wallet default path mismatch: %s vs %s", qw1.Address(), qw2.Address())
	}
	qwClassical, err := account.QuantWalletFromMnemonic(mnemonic, "m/44'/60'/0'/0/0")
	if err != nil {
		t.Fatal(err)
	}
	if qwClassical.Address() == qw1.Address() {
		t.Fatal("different derivation paths should yield different quant addresses")
	}
}

func TestSwiftWalletVectorAndEdgeCases(t *testing.T) {
	// Swift WalletVectors.swift reference vector (compressed + uncompressed + address)
	phrase := "later puppy sound rebuild rebuild noise ozone amazing hope broccoli crystal grief"
	if !account.IsValidMnemonic("  LATER   PUPPY sound rebuild rebuild noise ozone amazing hope broccoli crystal grief  ") {
		t.Fatal("IsValidMnemonic should normalize case and whitespace")
	}
	w, err := account.WalletFromMnemonic(phrase, account.DefaultDerivationPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := w.PrivateKeyHex(); got != "96a7705eedbb701a03ee235911253fd3eb80e48a06106c0bf957d42b72bd8efa" {
		t.Errorf("privKey: got %s", got)
	}
	if got := w.Address(); got != "e46c258c74c7c1df33d7caa4c2c664dc0843ab3f" {
		t.Errorf("address: got %s", got)
	}
	if got := hex.EncodeToString(w.PublicKey()); got != "03a9f10779cb44e73a1983b8225ce9de96ff63cbc8a2900db102fa55a38a14b206" {
		t.Errorf("compressed pubKey: got %s", got)
	}
	if got := "04" + w.PublicKeyUncompressedHex(); got != "04a9f10779cb44e73a1983b8225ce9de96ff63cbc8a2900db102fa55a38a14b206f850a6decf0d0277c8ea237d865a06b6237f07eaf4273217ed6b2ed830161bef" {
		t.Errorf("uncompressed pubKey: got %s", got)
	}
	if len(w.KeccakBytes()) != 32 {
		t.Fatalf("expected 32-byte KeccakBytes, got %d", len(w.KeccakBytes()))
	}

	// Absolute path derivation from child wallet uses master
	sibling, err := w.DerivePath("m/44'/60'/0'/0/1")
	if err != nil {
		t.Fatalf("derive sibling absolute path: %v", err)
	}
	direct1, err := account.WalletFromMnemonic(phrase, "m/44'/60'/0'/0/1")
	if err != nil {
		t.Fatal(err)
	}
	if sibling.Address() != direct1.Address() {
		t.Fatalf("sibling address mismatch: %s vs %s", sibling.Address(), direct1.Address())
	}

	// Non-root ExtendedKey without master rejects unrelated absolute path
	nonRoot, err := account.WalletFromExtendedKey(w.ExtendedKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nonRoot.DerivePath("m/44'/60'/0'/0/1"); err == nil {
		t.Fatal("expected error deriving absolute path on non-root wallet without master")
	}

	// WithPreviousHashHex rejects invalid hex
	if _, err := account.RandomAccount(account.WithPreviousHashHex("not-valid-hex!!!")); err == nil {
		t.Fatal("expected error for invalid WithPreviousHashHex")
	}
	if _, err := account.RandomQuantAccount(account.WithPreviousHashHex("not-valid-hex!!!")); err == nil {
		t.Fatal("expected error for invalid WithPreviousHashHex on QuantAccount")
	}

	// Bech32m 90-char limit & checksum tamper (matching Android XyoAddressTest)
	if _, err := account.EncodeBech32m("qm65", make([]byte, 60)); err == nil {
		t.Fatal("expected BIP-350 >90 char error from EncodeBech32m")
	}
	const validQuant = "qm651qyyq79says4nyw2qga892hrrdfchsluxleee2j"
	if decoded := account.TryDecodeQuantAddress(validQuant); decoded == nil || decoded.HRP != "qm65" || len(decoded.Bytes) != 20 {
		t.Fatalf("TryDecodeQuantAddress failed: %+v", decoded)
	}
	tampered := validQuant[:len(validQuant)-1] + "q"
	if account.IsQuantAddress(tampered) || account.TryDecodeQuantAddress(tampered) != nil {
		t.Fatal("tampered quant address checksum must be rejected")
	}
}

func TestFilePreviousHashStoreRollbackOnPersistError(t *testing.T) {
	// Point FilePreviousHashStore at a directory path so os.Rename(tmp, dir) fails
	dir := t.TempDir()
	badTarget := filepath.Join(dir, "blocker")
	if err := os.Mkdir(badTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := account.NewFilePreviousHashStore(filepath.Join(dir, "nonexistent.json"))
	if err != nil {
		t.Fatal(err)
	}
	_ = store

	// Create a file store whose path is an existing non-empty directory so persist fails on write/rename
	nonEmptyDir := filepath.Join(dir, "dir_as_file")
	if err := os.Mkdir(nonEmptyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nonEmptyDir, "child"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Make a normal store first, verify rollback when parent is read-only
	roDir := filepath.Join(dir, "ro")
	if err := os.Mkdir(roDir, 0o700); err != nil {
		t.Fatal(err)
	}
	storePath := filepath.Join(roDir, "hashes.json")
	fs, err := account.NewFilePreviousHashStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	addr := "5e7a847447e7fec41011ae7d32d768f86605ba03"
	h1 := "1111111111111111111111111111111111111111111111111111111111111111"
	h2 := "2222222222222222222222222222222222222222222222222222222222222222"
	if err := fs.SetItem(addr, h1); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(roDir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(roDir, 0o700) }()

	// Attempt SetItem/SetItemIfMatch/RemoveItem while dir is read-only (non-root)
	if os.Geteuid() != 0 {
		if err := fs.SetItem(addr, h2); err == nil {
			t.Fatal("expected SetItem error on read-only dir")
		}
		if got, ok, _ := fs.GetItem(addr); !ok || got != h1 {
			t.Fatalf("SetItem failed to rollback in-memory state: got=%q ok=%v", got, ok)
		}
		if _, err := fs.SetItemIfMatch(addr, &h1, h2); err == nil {
			t.Fatal("expected SetItemIfMatch error on read-only dir")
		}
		if got, ok, _ := fs.GetItem(addr); !ok || got != h1 {
			t.Fatalf("SetItemIfMatch failed to rollback in-memory state: got=%q ok=%v", got, ok)
		}
		if err := fs.RemoveItem(addr); err == nil {
			t.Fatal("expected RemoveItem error on read-only dir")
		}
		if got, ok, _ := fs.GetItem(addr); !ok || got != h1 {
			t.Fatalf("RemoveItem failed to rollback in-memory state: got=%q ok=%v", got, ok)
		}
	}
}

func TestPreviousHashStoreAndConcurrency(t *testing.T) {
	store := account.NewMemoryPreviousHashStore()
	acct, err := account.RandomAccount(account.WithPreviousHashStore(store))
	if err != nil {
		t.Fatal(err)
	}
	if acct.PreviousHash() != nil {
		t.Fatal("fresh account should have nil previousHash")
	}

	const N = 16
	var wg sync.WaitGroup
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			h := make([]byte, 32)
			h[0] = byte(idx + 1)
			if _, err := acct.Sign(h); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent sign failed: %v", err)
	}

	stored, ok, err := store.GetItem(acct.Address())
	if err != nil || !ok {
		t.Fatalf("expected previousHash in store: ok=%v err=%v", ok, err)
	}
	if acct.PreviousHashHex() == nil || *acct.PreviousHashHex() != stored {
		t.Fatalf("account previousHash mismatch with store")
	}

	// FilePreviousHashStore round-trip
	tmpPath := filepath.Join(t.TempDir(), "prev_hashes.json")
	fstore, err := account.NewFilePreviousHashStore(tmpPath)
	if err != nil {
		t.Fatal(err)
	}
	h1 := make([]byte, 32)
	h1[31] = 0xab
	acct2, err := account.AccountFromPrivateKey(acct.PrivateKey(), account.WithPreviousHashStore(fstore))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acct2.Sign(h1); err != nil {
		t.Fatal(err)
	}
	fstore2, err := account.NewFilePreviousHashStore(tmpPath)
	if err != nil {
		t.Fatal(err)
	}
	acct3, err := account.AccountFromPrivateKey(acct.PrivateKey(), account.WithPreviousHashStore(fstore2))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(acct3.PreviousHash(), h1) {
		t.Fatalf("reloaded previous hash mismatch: got %x want %x", acct3.PreviousHash(), h1)
	}
}
