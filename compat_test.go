package xyoclient_test

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/XYOracleNetwork/sdk-xyo-client-go/account"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/boundwitness"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/client"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/payload"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/protocol"
)

// TestSharedVectorsContractIntegrity verifies that testdata/jsCompatVectors.json contains the
// complete frozen cross-SDK contract matching sdk-xyo-client-swift and sdk-xyo-client-android.
func TestSharedVectorsContractIntegrity(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "jsCompatVectors.json"))
	if err != nil {
		t.Fatalf("read testdata/jsCompatVectors.json: %v", err)
	}
	var doc struct {
		Sources       map[string]string `json:"sources"`
		MessageHashes []string          `json:"message_hashes"`
		Accounts      []json.RawMessage `json:"accounts"`
		HDWallets     []struct {
			Derivations []json.RawMessage `json:"derivations"`
		} `json:"hd_wallets"`
		PayloadHashes  []json.RawMessage `json:"payload_hashes"`
		BoundWitnesses []struct {
			ID       string `json:"id"`
			RootHash string `json:"root_hash"`
		} `json:"bound_witnesses"`
		XL1Amounts []json.RawMessage `json:"xl1_amounts"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal jsCompatVectors.json: %v", err)
	}
	if len(doc.MessageHashes) != 3 {
		t.Errorf("message_hashes count: got %d want 3", len(doc.MessageHashes))
	}
	if len(doc.Accounts) != 5 {
		t.Errorf("accounts count: got %d want 5", len(doc.Accounts))
	}
	totalDerivations := 0
	for _, w := range doc.HDWallets {
		totalDerivations += len(w.Derivations)
	}
	if totalDerivations != 14 {
		t.Errorf("hd_wallets total derivations: got %d want 14", totalDerivations)
	}
	if len(doc.PayloadHashes) != 26 {
		t.Errorf("payload_hashes count: got %d want 26", len(doc.PayloadHashes))
	}
	if len(doc.BoundWitnesses) != 3 {
		t.Errorf("bound_witnesses count: got %d want 3", len(doc.BoundWitnesses))
	}
	for _, bw := range doc.BoundWitnesses {
		if len(bw.RootHash) != 64 {
			t.Errorf("bound_witness %q missing 64-char root_hash", bw.ID)
		}
	}
	if len(doc.XL1Amounts) != 13 {
		t.Errorf("xl1_amounts count: got %d want 13", len(doc.XL1Amounts))
	}
}

// TestEndToEndCrossPackageFlow exercises account + payload + boundwitness + client + protocol together.
func TestEndToEndCrossPackageFlow(t *testing.T) {
	ctx := context.Background()
	mnemonic := "later puppy sound rebuild rebuild noise ozone amazing hope broccoli crystal grief"

	classical, err := account.WalletFromMnemonic(mnemonic, account.DefaultDerivationPath)
	if err != nil {
		t.Fatal(err)
	}
	quant, err := account.QuantWalletFromMnemonic(mnemonic, account.Bip85DefaultQuantPath)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Observe payloads via Panel into MemoryArchivist
	mem, err := client.NewMemoryArchivist(classical)
	if err != nil {
		t.Fatal(err)
	}
	wit := client.NewBasicWitness(quant, func(_ context.Context, _ ...any) ([]any, error) {
		return []any{payload.NewIdPayload("e2e-flow")}, nil
	})
	panel, err := client.NewPanel(classical, []client.ArchivistInstance{mem}, wit)
	if err != nil {
		t.Fatal(err)
	}
	panelRes, err := panel.ReportQuery(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if errs := boundwitness.ValidateBoundWitness(panelRes.BoundWitness); len(errs) != 0 {
		t.Fatalf("panel BoundWitness invalid: %v", errs)
	}

	// 2. Build hybrid classical + ML-DSA-65 XL1 transfer transaction and submit over RPCEngine
	transfer := protocol.NewTransferPayload(
		classical.Address(),
		map[string]string{quant.Address(): protocol.AmountFromXL1(big.NewInt(2)).Atto().BareHex()},
		nil,
	)
	tx, err := protocol.NewTransactionBuilder().
		Chain("c5fe2e6f6841cbab12d8c0618be2df8c6156cc44").
		Fees(protocol.DefaultTransactionFees()).
		Range(10, 100).
		Payload(transfer).
		Signers(classical, quant).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	if errs := protocol.ValidateTransaction(tx); len(errs) != 0 {
		t.Fatalf("ValidateTransaction failed: %v", errs)
	}

	engine := protocol.NewRPCEngine()
	engine.Register(protocol.RPCMethodMempoolRunnerSubmitTransactions, func(_ context.Context, params []json.RawMessage) (any, error) {
		var txs []protocol.HydratedTransaction
		if err := json.Unmarshal(params[0], &txs); err != nil {
			return nil, err
		}
		for i := range txs {
			if errs := protocol.ValidateTransaction(&txs[i]); len(errs) != 0 {
				return nil, &protocol.JSONRPCError{Code: protocol.RPCErrInvalidParams, Message: errs[0].Error()}
			}
		}
		return []string{txs[0].Hash}, nil
	})
	srv := httptest.NewServer(engine)
	defer srv.Close()

	viewer, err := protocol.NewXyoViewerHTTP(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	hashes, err := viewer.SubmitTransactions(ctx, []protocol.HydratedTransaction{*tx})
	if err != nil || len(hashes) != 1 || hashes[0] != tx.Hash {
		t.Fatalf("SubmitTransactions: hashes=%v err=%v", hashes, err)
	}
}
