package payload_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/XYOracleNetwork/sdk-xyo-client-go/payload"
)

type jsPayloadVectors struct {
	PayloadHashes []struct {
		ID       string `json:"id"`
		RawJSON  string `json:"raw_json"`
		Hash     string `json:"hash"`
		DataHash string `json:"data_hash"`
	} `json:"payload_hashes"`
}

func TestJsCompatPayloadHashes(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "jsCompatVectors.json"))
	if err != nil {
		t.Fatalf("read jsCompatVectors.json: %v", err)
	}
	var v jsPayloadVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshal vectors: %v", err)
	}
	if len(v.PayloadHashes) == 0 {
		t.Fatal("expected payload_hashes vectors")
	}

	for _, tc := range v.PayloadHashes {
		t.Run(tc.ID, func(t *testing.T) {
			rawMsg := json.RawMessage(tc.RawJSON)
			gotHash, err := payload.Hash(rawMsg)
			if err != nil {
				t.Fatalf("Hash error: %v", err)
			}
			if gotHash != tc.Hash {
				canon, _ := payload.CanonicalJSON(rawMsg, payload.MetaExclusionStorageMeta)
				t.Errorf("hash mismatch:\n canon: %s\n got:   %s\n want:  %s", string(canon), gotHash, tc.Hash)
			}

			gotDataHash, err := payload.DataHash(rawMsg)
			if err != nil {
				t.Fatalf("DataHash error: %v", err)
			}
			if gotDataHash != tc.DataHash {
				canon, _ := payload.CanonicalJSON(rawMsg, payload.MetaExclusionAllMeta)
				t.Errorf("dataHash mismatch:\n canon: %s\n got:   %s\n want:  %s", string(canon), gotDataHash, tc.DataHash)
			}
		})
	}
}

func TestYellowPaperPayloadVectors(t *testing.T) {
	// Section 8.2.1 Location Payload with $meta_field
	locJSON := json.RawMessage(`{
		"$meta_field": "yo",
		"currentLocation": {
			"coords": {
				"accuracy": 5,
				"altitude": 15,
				"altitudeAccuracy": 15,
				"heading": 90,
				"latitude": 37.7749,
				"longitude": -122.4194,
				"speed": 2.5
			},
			"timestamp": 1609459200000
		},
		"schema": "network.xyo.location.current"
	}`)
	dh, err := payload.DataHash(locJSON)
	if err != nil {
		t.Fatal(err)
	}
	if dh != "0c1f0c80481b0f391a677eab542a594a192081325b6416acc3dc99db23355ee2" {
		t.Errorf("location dataHash: got %s", dh)
	}
	h, err := payload.Hash(locJSON)
	if err != nil {
		t.Fatal(err)
	}
	if h != "d1685b23bbc87c0260620fa6ff3581ffd48574bd326cb472425d4db787af487f" {
		t.Errorf("location hash: got %s", h)
	}

	// Builder.spec.ts iOS BoundWitness Payload with $meta and $epoch1
	bwJSON := json.RawMessage(`{
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
	}`)
	dh, err = payload.DataHash(bwJSON)
	if err != nil {
		t.Fatal(err)
	}
	if dh != "6f731b3956114fd0d18820dbbe1116f9e36dc8d803b0bb049302f7109037468f" {
		t.Errorf("bw dataHash: got %s", dh)
	}
	h, err = payload.Hash(bwJSON)
	if err != nil {
		t.Fatal(err)
	}
	if h != "6dc6e662a75fad55451d5a488f5687f90a93174c17359404945b392a37f70e07" {
		t.Errorf("bw hash: got %s", h)
	}

	// Builder.spec.ts Kotlin Cross-Platform Test (with $meta)
	kotlinJSON := json.RawMessage(`{
		"$meta": {
			"client": "android",
			"signatures": ["493178d0b896818e2185ca424738cd6d4cac94990af9c1a238c02e51baa387b3354058c32ef0e601c8e6201ff677bf97885169140e6e36778dc41ecd6bf362d7"]
		},
		"addresses": ["9858effd232b4033e47d90003d41ec34ecaeda94"],
		"payload_hashes": ["4ca087085f26a7c3961b450457a8e44307f331ecf2580bb952fdacdcb7be4cd7"],
		"payload_schemas": ["network.xyo.test"],
		"previous_hashes": [null],
		"schema": "network.xyo.boundwitness"
	}`)
	h, err = payload.Hash(kotlinJSON)
	if err != nil {
		t.Fatal(err)
	}
	if h != "79f9ff8083f5b1dde361d48b583821bd2b78723a29b422c8d6aefaed5bcba981" {
		t.Errorf("kotlin hash: got %s", h)
	}

	// Section 8.3.2 IdPayloads salt 0..5
	expectedIdHashes := []string{
		"ada56ff753c0c9b2ce5e1f823eda9ac53501db2843d8883d6cf6869c18ef7f65",
		"3a3b8deca568ff820b0b7c8714fbdf82b40fb54f4b15aca8745e06b81291558e",
		"1a40207fab71fc184e88557d5bee6196cbbb49f11f73cda85000555a628a8f0a",
		"c4bce9b4d3239fcc9a248251d1bef1ba7677e3c0c2c43ce909a6668885b519e6",
		"59c0374dd801ae64ddddba27320ca028d7bd4b3d460f6674c7da1b4aa9c956d6",
		"5d9b8e84bc824280fcbb6290904c2edbb401d626ad9789717c0a23d1cab937b0",
	}
	for i, want := range expectedIdHashes {
		p := payload.NewIdPayload(string(rune('0' + i)))
		got, err := payload.Hash(p)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("IdPayload(%d): got %s want %s", i, got, want)
		}
	}
}

func TestCanonicalNoHTMLEscapeAndArraySort(t *testing.T) {
	p := payload.NewAnyPayload("network.xyo.test", map[string]any{
		"expr":  "a < b && c > d",
		"items": []any{map[string]any{"z": 1, "a": 2}, nil},
	})
	canon, err := payload.CanonicalJSON(p, payload.MetaExclusionAllMeta)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"expr":"a < b && c > d","items":[{"a":2,"z":1},null],"schema":"network.xyo.test"}`
	if string(canon) != want {
		t.Errorf("canonical JSON:\n got  %s\n want %s", string(canon), want)
	}
}

func TestSchemaValidationSequenceAndHuri(t *testing.T) {
	if !payload.IsValidSchema("network.xyo.boundwitness") {
		t.Error("expected valid schema")
	}
	if payload.IsValidSchema("network.xyo") {
		t.Error("2-level schema should be invalid")
	}
	if payload.IsValidSchema("Network.Xyo.Test") {
		t.Error("uppercase schema should be invalid")
	}
	root, err := payload.SchemaRootDomain("network.xyo.boundwitness")
	if err != nil || root != "xyo.network" {
		t.Errorf("SchemaRootDomain: got %q err=%v", root, err)
	}

	hash := "ada56ff753c0c9b2ce5e1f823eda9ac53501db2843d8883d6cf6869c18ef7f65"
	addr := "5e7a847447e7fec41011ae7d32d768f86605ba03"
	locSeq, err := payload.LocalSequence(1700000000000, 1, hash)
	if err != nil || len(locSeq) != payload.LocalSequenceHexLength {
		t.Fatalf("LocalSequence: %q err=%v", locSeq, err)
	}
	qualSeq, err := payload.QualifiedSequence(1700000000000, 1, hash, addr)
	if err != nil || len(qualSeq) != payload.QualifiedSequenceHexLength {
		t.Fatalf("QualifiedSequence: %q err=%v", qualSeq, err)
	}

	huri, err := payload.ParseHuri("https://api.archivist.xyo.network/Archivist/" + hash)
	if err != nil {
		t.Fatal(err)
	}
	if huri.Host != "api.archivist.xyo.network" || huri.Path != "Archivist" || huri.Hash != hash {
		t.Fatalf("unexpected parsed HURI: %+v", huri)
	}
	if huri.String() != "https://api.archivist.xyo.network/Archivist/"+hash {
		t.Fatalf("unexpected HURI string: %s", huri.String())
	}

	// Wrapper validation
	withMeta, err := payload.NewBuilder("network.xyo.id").Field("salt", "0").BuildWithHashMeta()
	if err != nil {
		t.Fatal(err)
	}
	w, err := payload.Wrap(withMeta)
	if err != nil {
		t.Fatal(err)
	}
	if errs := w.Validate(); len(errs) != 0 {
		t.Fatalf("expected no validation errors, got %v", errs)
	}

	// Non-hex HURI and Sequence must be rejected
	if _, err := payload.ParseHuri("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"); err == nil {
		t.Error("expected non-hex bare HURI to fail")
	}
	if _, err := payload.ParseHuri("https://api.archivist.xyo.network/Archivist/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"); err == nil {
		t.Error("expected non-hex URL HURI to fail")
	}
	if _, err := payload.LocalSequence(1, 0, "zzzzzzzz"); err == nil {
		t.Error("expected non-hex hash in LocalSequence to fail")
	}
	if _, err := payload.QualifiedSequence(1, 0, hash, "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"); err == nil {
		t.Error("expected non-hex address in QualifiedSequence to fail")
	}
	if !payload.IsValidLocalSequence(locSeq) || !payload.IsValidQualifiedSequence(qualSeq) {
		t.Error("expected generated sequences to validate")
	}
	locSeq2, _ := payload.LocalSequence(1700000000001, 0, hash)
	if payload.CompareSequence(locSeq, locSeq2) >= 0 {
		t.Error("expected earlier sequence to compare less than later sequence")
	}
	if payload.SchemaNameLevels("network.xyo.boundwitness") != 3 {
		t.Error("expected 3 schema levels")
	}
}

func TestJsCompatTypedPluginPayloads(t *testing.T) {
	// Mirrors Swift/Android JsVectorPluginPayloadTest: verify typed Go payload structs
	// hash identically to the JS reference vectors in jsCompatVectors.json.
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "jsCompatVectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v jsPayloadVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	byID := make(map[string]struct{ hash, dataHash string }, len(v.PayloadHashes))
	for _, tc := range v.PayloadHashes {
		byID[tc.ID] = struct{ hash, dataHash string }{tc.Hash, tc.DataHash}
	}

	floatPtr := func(f float64) *float64 { return &f }
	int64Ptr := func(i int64) *int64 { return &i }

	cases := []struct {
		id string
		p  any
	}{
		{"plugin-address", payload.NewAddressPayload("1234567890abcdef1234567890abcdef12345678", "primary-signer")},
		{"plugin-config", payload.NewConfigPayload(map[string]any{"timeout": 30, "retries": 3, "enabled": true, "label": "test-config"})},
		{"plugin-domain", payload.NewDomainPayload("xyo.network", map[string]any{"primary": "xyo.network", "cdn": "cdn.xyo.network"})},
		{"plugin-id", payload.NewIdPayload("cross-sdk-id-vector")},
		{"plugin-schema", payload.NewSchemaPayload(map[string]any{"title": "test", "version": 1, "fields": []string{"a", "b", "c"}})},
		{"plugin-value-number", payload.NewValuePayload(42)},
		{"plugin-value-string", payload.NewValuePayload("hello-value-plugin")},
		{"plugin-value-object", payload.NewValuePayload(map[string]any{"key": "nested", "n": 99})},
		{"id-payload-salt-7", payload.NewIdPayload("7")},
		{"location", payload.NewLocationPayload(payload.CurrentLocation{
			Coords: payload.Coordinates{
				Accuracy:         floatPtr(5),
				Altitude:         floatPtr(15),
				AltitudeAccuracy: floatPtr(15),
				Heading:          floatPtr(90),
				Latitude:         37.7749,
				Longitude:        -122.4194,
				Speed:            floatPtr(2.5),
			},
			Timestamp: int64Ptr(1609459200000),
		})},
	}

	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			want, ok := byID[tc.id]
			if !ok {
				t.Fatalf("missing vector %q in jsCompatVectors.json", tc.id)
			}
			gotH, err := payload.Hash(tc.p)
			if err != nil {
				t.Fatal(err)
			}
			if gotH != want.hash {
				canon, _ := payload.CanonicalJSON(tc.p, payload.MetaExclusionStorageMeta)
				t.Errorf("hash mismatch:\n canon=%s\n got  %s\n want %s", canon, gotH, want.hash)
			}
			gotDH, err := payload.DataHash(tc.p)
			if err != nil {
				t.Fatal(err)
			}
			if gotDH != want.dataHash {
				t.Errorf("dataHash mismatch:\n got  %s\n want %s", gotDH, want.dataHash)
			}
		})
	}
}

func TestCanonicalLargeFloatAndBatchHelpers(t *testing.T) {
	// float64(1<<63) must NOT overflow int64 to negative; ECMAScript JSON.stringify(2**63) == "9223372036854776000".
	canon, err := payload.CanonicalJSON(map[string]any{
		"big":    float64(1 << 63),
		"schema": "network.xyo.test",
	}, payload.MetaExclusionAllMeta)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"big":9223372036854776000,"schema":"network.xyo.test"}`
	if string(canon) != want {
		t.Fatalf("2^63 float canonical mismatch:\n got  %s\n want %s", string(canon), want)
	}

	// PayloadHasher batch utilities
	p0 := payload.NewIdPayload("0")
	p1 := payload.NewIdPayload("1")
	p2 := payload.NewIdPayload("2")
	list := []payload.IdPayload{p0, p1, p2}

	pairs, err := payload.HashPairs(list)
	if err != nil || len(pairs) != 3 {
		t.Fatalf("HashPairs: %v", err)
	}
	hMap, err := payload.ToHashMap(list)
	if err != nil || hMap[pairs[1].Hash].Salt != "1" {
		t.Fatalf("ToHashMap failed: %v", err)
	}
	dhMap, err := payload.ToDataHashMap(list)
	if err != nil || dhMap[pairs[2].Hash].Salt != "2" {
		t.Fatalf("ToDataHashMap failed: %v", err)
	}
	excl, err := payload.FilterExcludeByHash(list, []string{pairs[1].Hash})
	if err != nil || len(excl) != 2 {
		t.Fatalf("FilterExcludeByHash: len=%d err=%v", len(excl), err)
	}
	incl, err := payload.FilterIncludeByDataHash(list, []string{pairs[0].Hash, pairs[2].Hash})
	if err != nil || len(incl) != 2 {
		t.Fatalf("FilterIncludeByDataHash: len=%d err=%v", len(incl), err)
	}
	found, ok, err := payload.FindByHash(list, pairs[2].Hash)
	if err != nil || !ok || found.Salt != "2" {
		t.Fatalf("FindByHash: found=%+v ok=%v err=%v", found, ok, err)
	}
	foundDH, ok, err := payload.FindByDataHash(list, pairs[0].Hash)
	if err != nil || !ok || foundDH.Salt != "0" {
		t.Fatalf("FindByDataHash: found=%+v ok=%v err=%v", foundDH, ok, err)
	}

	// PayloadWrapper.Validate propagates tampered _hash and _dataHash errors
	tampered, _ := payload.NewBuilder("network.xyo.id").Field("salt", "0").BuildWithHashMeta()
	tampered["_hash"] = "0000000000000000000000000000000000000000000000000000000000000000"
	tampered["_dataHash"] = "0000000000000000000000000000000000000000000000000000000000000000"
	tw, err := payload.Wrap(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if errs := tw.Validate(); len(errs) != 2 {
		t.Fatalf("expected 2 hash mismatch errors, got %d: %v", len(errs), errs)
	}
}
