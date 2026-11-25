package boundwitness_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/XYOracleNetwork/sdk-xyo-client-go/account"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/boundwitness"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/payload"
)

type jsBoundWitnessVectors struct {
	BoundWitnesses []struct {
		ID                string    `json:"id"`
		SignerPrivateKeys []string  `json:"signer_private_keys"`
		PayloadsRawJSON   []string  `json:"payloads_raw_json"`
		Addresses         []string  `json:"addresses"`
		PayloadHashes     []string  `json:"payload_hashes"`
		PayloadSchemas    []string  `json:"payload_schemas"`
		PreviousHashes    []*string `json:"previous_hashes"`
		DataHash          string    `json:"data_hash"`
		Signatures        []string  `json:"signatures"`
		RootHash          string    `json:"root_hash"`
	} `json:"bound_witnesses"`
}

func TestJsCompatBoundWitnesses(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "jsCompatVectors.json"))
	if err != nil {
		t.Fatalf("read jsCompatVectors.json: %v", err)
	}
	var v jsBoundWitnessVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshal vectors: %v", err)
	}
	if len(v.BoundWitnesses) == 0 {
		t.Fatal("expected bound_witnesses vectors")
	}

	for _, tc := range v.BoundWitnesses {
		t.Run(tc.ID, func(t *testing.T) {
			b := boundwitness.NewBuilder()
			for _, pk := range tc.SignerPrivateKeys {
				acct, err := account.AccountFromPrivateKeyHex(pk)
				if err != nil {
					t.Fatalf("account: %v", err)
				}
				b.Signer(acct)
			}
			for _, pJSON := range tc.PayloadsRawJSON {
				b.Payload(json.RawMessage(pJSON))
			}

			bw, payloads, err := b.Build()
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			if len(payloads) != len(tc.PayloadsRawJSON) {
				t.Fatalf("payloads len: got %d want %d", len(payloads), len(tc.PayloadsRawJSON))
			}

			dh, err := bw.DataHash()
			if err != nil {
				t.Fatal(err)
			}
			if dh != tc.DataHash {
				t.Errorf("data_hash:\n got  %s\n want %s", dh, tc.DataHash)
			}

			rh, err := bw.Hash()
			if err != nil {
				t.Fatal(err)
			}
			if tc.RootHash != "" && rh != tc.RootHash {
				t.Errorf("root_hash:\n got  %s\n want %s", rh, tc.RootHash)
			}

			if len(bw.Signatures) != len(tc.Signatures) {
				t.Fatalf("signatures len: got %d want %d", len(bw.Signatures), len(tc.Signatures))
			}
			for i, wantSig := range tc.Signatures {
				if bw.Signatures[i] == nil || *bw.Signatures[i] != wantSig {
					t.Errorf("sig[%d]:\n got  %v\n want %s", i, bw.Signatures[i], wantSig)
				}
			}

			if errs := boundwitness.ValidateBoundWitness(bw); len(errs) != 0 {
				t.Errorf("ValidateBoundWitness failed: %v", errs)
			}
		})
	}
}

func TestYellowPaper4StepChainedSequence(t *testing.T) {
	w1, err := account.WalletFromMnemonic(
		"report door cry include salad horn recipe luxury access pledge husband maple busy double olive",
		account.DefaultDerivationPath,
	)
	if err != nil {
		t.Fatal(err)
	}
	w2, err := account.WalletFromMnemonic(
		"turn you orphan sauce act patient village entire lava transfer height sense enroll quit idle",
		account.DefaultDerivationPath,
	)
	if err != nil {
		t.Fatal(err)
	}
	if w1.Address() != "25524ca99764d76ca27604bb9727f6e2f27c4533" {
		t.Fatalf("wallet1 addr: got %s", w1.Address())
	}
	if w2.Address() != "fdced2c3549289049bebf743fb721df211633fbf" {
		t.Fatalf("wallet2 addr: got %s", w2.Address())
	}

	// Step 1: Wallet 1 + IdPayload("0")
	bw1, _, err := boundwitness.NewBuilder().Signer(w1).Payload(payload.NewIdPayload("0")).Build()
	if err != nil {
		t.Fatal(err)
	}
	dh1, _ := bw1.DataHash()
	rh1, _ := bw1.Hash()
	if dh1 != "750113b9826ba94b622667b06cd8467f1330837581c28907c16160fec20d0a4b" {
		t.Fatalf("step1 dataHash: got %s", dh1)
	}
	if rh1 != "66fffbe36ad8af17f00fe76b40dd7e6df3d1637b5bb1f90253db17f86a242956" {
		t.Fatalf("step1 rootHash: got %s", rh1)
	}

	// Step 2: Wallet 2 + IdPayload("1")
	bw2, _, err := boundwitness.NewBuilder().Signer(w2).Payload(payload.NewIdPayload("1")).Build()
	if err != nil {
		t.Fatal(err)
	}
	dh2, _ := bw2.DataHash()
	rh2, _ := bw2.Hash()
	if dh2 != "bacd010d79126a154339e59c11c5b46be032c3bef65626f83bcafe968dc6dd1b" {
		t.Fatalf("step2 dataHash: got %s", dh2)
	}
	if rh2 != "133ccc6cfea0c7ba2adeb21f24adf6557683871e7b9a89eea72ec3f0078e8e33" {
		t.Fatalf("step2 rootHash: got %s", rh2)
	}

	// Step 3: Wallet 1 + Wallet 2 + IdPayload("2"), IdPayload("3")
	bw3, _, err := boundwitness.NewBuilder().
		Signers(w1, w2).
		Payloads(payload.NewIdPayload("2"), payload.NewIdPayload("3")).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	dh3, _ := bw3.DataHash()
	rh3, _ := bw3.Hash()
	if dh3 != "73245ef73517913f4b57c12d56d81199968ecd8fbefea9ddc474f43dd6cfa8c8" {
		t.Fatalf("step3 dataHash: got %s", dh3)
	}
	if rh3 != "930c5b01d2659b5e098da093d5e83f2f99ed9b2536af9d309cf980da8d3a6c25" {
		t.Fatalf("step3 rootHash: got %s", rh3)
	}

	// Step 4: Wallet 1 + Wallet 2 + IdPayload("4"), IdPayload("5")
	bw4, payloads4, err := boundwitness.NewBuilder().
		Signers(w1, w2).
		Payloads(payload.NewIdPayload("4"), payload.NewIdPayload("5")).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	dh4, _ := bw4.DataHash()
	rh4, _ := bw4.Hash()
	if dh4 != "210d86ea43d82b85a49b77959a8ee4e6016ff7036254cfa39953befc66073010" {
		t.Fatalf("step4 dataHash: got %s", dh4)
	}
	if rh4 != "62830e4dd1f40625faca1da3c678d0ac57e73006706f4ef3a87d1c6f2656e223" {
		t.Fatalf("step4 rootHash: got %s", rh4)
	}

	wrapper, err := boundwitness.Wrap(bw4, payloads4)
	if err != nil {
		t.Fatal(err)
	}
	if errs := wrapper.Validate(); len(errs) != 0 {
		t.Fatalf("wrapper.Validate failed: %v", errs)
	}
	missing, err := wrapper.MissingPayloads()
	if err != nil || len(missing) != 0 {
		t.Fatalf("expected 0 missing payloads, got %v (err=%v)", missing, err)
	}
	if prev := wrapper.Prev(w1.Address()); prev == nil || *prev != dh3 {
		t.Fatalf("wrapper.Prev(w1) mismatch: %v", prev)
	}
}

func TestCosignAndHybridSecp256k1PlusMLDSA65(t *testing.T) {
	classical, err := account.RandomAccount()
	if err != nil {
		t.Fatal(err)
	}
	quant, err := account.RandomQuantAccount()
	if err != nil {
		t.Fatal(err)
	}

	// Build partially signed BW: classical signs locally, quant is a remote participant slot
	partial, payloads, err := boundwitness.NewBuilder().
		Signer(classical).
		Participant(quant.Address(), quant.PreviousHashHex()).
		Payload(payload.NewIdPayload("hybrid-cosign")).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	if partial.IsSigned() {
		t.Fatal("partial BW should not be fully signed yet")
	}
	if len(boundwitness.ValidateBoundWitness(partial)) == 0 {
		t.Fatal("partial BW must fail validation until cosigned")
	}

	// Quant account cosigns without mutating partial
	signed, err := boundwitness.CosignBoundWitness(partial, quant)
	if err != nil {
		t.Fatalf("CosignBoundWitness: %v", err)
	}
	if partial.IsSigned() {
		t.Fatal("original partial BW must not be mutated")
	}
	if !signed.IsSigned() {
		t.Fatal("cosigned BW must be fully signed")
	}
	if errs := boundwitness.ValidateBoundWitness(signed); len(errs) != 0 {
		t.Fatalf("hybrid classical+ML-DSA-65 BW validation failed: %v", errs)
	}

	// Verify dataHash did not change during cosigning
	dhPartial, _ := partial.DataHash()
	dhSigned, _ := signed.DataHash()
	if dhPartial != dhSigned {
		t.Fatalf("cosign altered dataHash: %s vs %s", dhPartial, dhSigned)
	}

	// Wrapper roundtrip
	w, err := boundwitness.Wrap(signed, payloads)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.PayloadsBySchema(payload.SchemaId)) != 1 {
		t.Fatal("expected 1 id payload")
	}
}

func TestQueryBoundWitnessBuilder(t *testing.T) {
	acct, err := account.RandomAccount()
	if err != nil {
		t.Fatal(err)
	}
	q := payload.NewAnyPayload("network.xyo.query.archivist.get", map[string]any{
		"hashes": []string{"ada56ff753c0c9b2ce5e1f823eda9ac53501db2843d8883d6cf6869c18ef7f65"},
	})
	qbw, payloads, err := boundwitness.NewQueryBuilder().
		Query(q).
		Signer(acct).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 1 {
		t.Fatalf("expected 1 payload (the query), got %d", len(payloads))
	}
	if errs := boundwitness.ValidateQueryBoundWitness(qbw); len(errs) != 0 {
		t.Fatalf("ValidateQueryBoundWitness failed: %v", errs)
	}
}
