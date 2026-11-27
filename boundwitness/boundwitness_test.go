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
		Timestamp(1700000000000).
		Version(2).
		Destination("5e7a847447e7fec41011ae7d32d768f86605ba03").
		SourceQuery("ada56ff753c0c9b2ce5e1f823eda9ac53501db2843d8883d6cf6869c18ef7f65").
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

	// Verify $sourceQuery and $destination do NOT alter DataHash (Swift QueryBoundWitnessTests parity)
	qbwClone := qbw.Clone()
	qbwClone.SourceQuery = ""
	qbwClone.Destination = ""
	dh1, _ := qbw.DataHash()
	dh2, _ := qbwClone.DataHash()
	if dh1 != dh2 {
		t.Fatalf("client meta altered QueryBoundWitness dataHash: %s vs %s", dh1, dh2)
	}
	// Root hash DOES change because $sourceQuery/$destination are included in Hash()
	rh1, _ := qbw.Hash()
	rh2, _ := qbwClone.Hash()
	if rh1 == rh2 {
		t.Fatal("expected different root hashes when $sourceQuery/$destination differ")
	}
}

func TestExtraFieldsPreservationAndValidatorEdgeCases(t *testing.T) {
	// Unknown JSON fields (like $epoch1, $meta, custom_field) must survive JSON round-trip & hashing
	rawWire := `{
		"$epoch1": "1234567890",
		"$meta": {
			"client": "ios",
			"signatures": ["fad86c98252b937a65be61f2307ce6d427a08425b4aee1c90fea0b446e9c862f46b6a36fea69450f83dadf9a2409c4f9ddc2e39a3dc222ae06f81b19eb2a17e6"]
		},
		"addresses": ["e3b3bb3cdc49e13f9ac5f48d52915368de43afec"],
		"payload_hashes": ["c915c56dd93b5e0db509d1a63ca540cfb211e11f03039b05e19712267bb8b6db"],
		"payload_schemas": ["network.xyo.test"],
		"previous_hashes": [null],
		"schema": "network.xyo.boundwitness"
	}`
	var bw boundwitness.BoundWitness
	if err := json.Unmarshal([]byte(rawWire), &bw); err != nil {
		t.Fatal(err)
	}
	dh, err := bw.DataHash()
	if err != nil {
		t.Fatal(err)
	}
	if dh != "6f731b3956114fd0d18820dbbe1116f9e36dc8d803b0bb049302f7109037468f" {
		t.Fatalf("dataHash mismatch after unmarshal: %s", dh)
	}
	rh, err := bw.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if rh != "6dc6e662a75fad55451d5a488f5687f90a93174c17359404945b392a37f70e07" {
		t.Fatalf("rootHash mismatch (Extra $ fields dropped?): got %s", rh)
	}

	// Case-variant duplicate addresses must be caught by validator
	badHash := "not-hex-hash"
	dupBW := &boundwitness.BoundWitness{
		Schema:         boundwitness.SchemaBoundWitness,
		Addresses:      []string{"5e7a847447e7fec41011ae7d32d768f86605ba03", "0x5E7A847447E7FEC41011AE7D32D768F86605BA03"},
		PreviousHashes: []*string{nil, &badHash},
		PayloadHashes:  []string{"zzzz"},
		PayloadSchemas: []string{"BadSchema"},
	}
	errs := boundwitness.ValidateBoundWitness(dupBW)
	if len(errs) < 4 {
		t.Fatalf("expected >=4 validation errors (dup addr, bad prev hash, bad payload hash, bad schema, sig len), got %d: %v", len(errs), errs)
	}
}

func TestMultiSignerAtomicRollbackOnFailure(t *testing.T) {
	store := account.NewMemoryPreviousHashStore()
	a1, err := account.RandomAccount(account.WithPreviousHashStore(store))
	if err != nil {
		t.Fatal(err)
	}
	a2, err := account.RandomAccount(account.WithPreviousHashStore(store))
	if err != nil {
		t.Fatal(err)
	}

	// Simulate an external concurrent writer advancing a2 in the store so a2.Sign() fails CAS!
	staleHash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := store.SetItem(a2.Address(), staleHash); err != nil {
		t.Fatal(err)
	}

	_, _, err = boundwitness.NewBuilder().
		Signers(a1, a2).
		Payload(payload.NewIdPayload("rollback-test")).
		Build()
	if err == nil {
		t.Fatal("expected build failure when signer 2 hits CAS conflict")
	}
	// a1 MUST have been rolled back cleanly (both in-memory and in PreviousHashStore)
	if a1.PreviousHash() != nil {
		t.Fatalf("expected a1 previousHash rolled back to nil, got %x", a1.PreviousHash())
	}
	if _, ok, _ := store.GetItem(a1.Address()); ok {
		t.Fatal("expected a1 entry removed from store after rollback")
	}
}

func TestWrapperRecursiveDigAndHelpers(t *testing.T) {
	acct, err := account.RandomAccount()
	if err != nil {
		t.Fatal(err)
	}
	// Build 3-level nested BoundWitness chain: outer -> mid -> inner
	inner, innerPayloads, err := boundwitness.NewBuilder().Signer(acct).Payload(payload.NewIdPayload("leaf")).Build()
	if err != nil {
		t.Fatal(err)
	}
	mid, _, err := boundwitness.NewBuilder().Signer(acct).Payload(inner).Build()
	if err != nil {
		t.Fatal(err)
	}
	outer, _, err := boundwitness.NewBuilder().Signer(acct).Payload(mid).Build()
	if err != nil {
		t.Fatal(err)
	}

	w, err := boundwitness.Wrap(outer, []any{mid, inner, innerPayloads[0]})
	if err != nil {
		t.Fatal(err)
	}
	d1 := w.Dig(1)
	if len(d1) != 1 {
		t.Fatalf("Dig(1): expected 1 nested BW, got %d", len(d1))
	}
	d2 := w.Dig(2)
	if len(d2) != 2 {
		t.Fatalf("Dig(2): expected 2 nested BWs (mid + inner), got %d", len(d2))
	}

	// PayloadsByHashes, PayloadsByDataHashes, WrappedPayloads, ToResult
	midHash, _ := mid.Hash()
	byH, err := w.PayloadsByHashes([]string{midHash})
	if err != nil || len(byH) != 1 {
		t.Fatalf("PayloadsByHashes failed: len=%d err=%v", len(byH), err)
	}
	midDH, _ := mid.DataHash()
	byDH, err := w.PayloadsByDataHashes([]string{midDH})
	if err != nil || len(byDH) != 1 {
		t.Fatalf("PayloadsByDataHashes failed: len=%d err=%v", len(byDH), err)
	}
	wrapped, err := w.WrappedPayloads()
	if err != nil || len(wrapped) != 3 {
		t.Fatalf("WrappedPayloads failed: len=%d err=%v", len(wrapped), err)
	}
	res := w.ToResult()
	if len(res) != 3 {
		t.Fatalf("ToResult len: got %d want 3", len(res))
	}

	// ParseTuple propagates malformed error tuple
	if _, err := boundwitness.ParseTuple([]byte(`[{}, [], "not-an-array"]`)); err == nil {
		t.Fatal("expected ParseTuple to reject malformed tuple[2]")
	}
}
