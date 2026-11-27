package protocol_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/XYOracleNetwork/sdk-xyo-client-go/account"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/boundwitness"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/payload"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/protocol"
)

type jsXL1Vectors struct {
	XL1Amounts []struct {
		Label string `json:"label"`
		Atto  string `json:"atto"`
		Femto string `json:"femto"`
		Pico  string `json:"pico"`
		Nano  string `json:"nano"`
		Micro string `json:"micro"`
		Milli string `json:"milli"`
		XL1   string `json:"xl1"`
	} `json:"xl1_amounts"`
}

func TestJsCompatXL1Amounts(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "jsCompatVectors.json"))
	if err != nil {
		t.Fatalf("read jsCompatVectors.json: %v", err)
	}
	var v jsXL1Vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshal vectors: %v", err)
	}
	if len(v.XL1Amounts) == 0 {
		t.Fatal("expected xl1_amounts vectors")
	}

	for _, tc := range v.XL1Amounts {
		t.Run(tc.Label, func(t *testing.T) {
			bigAtto, ok := new(big.Int).SetString(tc.Atto, 10)
			if !ok {
				t.Fatalf("invalid atto %q", tc.Atto)
			}
			amt := protocol.AmountFromAtto(bigAtto)
			if got := amt.Atto().String(); got != tc.Atto {
				t.Errorf("atto: got %s want %s", got, tc.Atto)
			}
			if got := amt.Femto().String(); got != tc.Femto {
				t.Errorf("femto: got %s want %s", got, tc.Femto)
			}
			if got := amt.Pico().String(); got != tc.Pico {
				t.Errorf("pico: got %s want %s", got, tc.Pico)
			}
			if got := amt.Nano().String(); got != tc.Nano {
				t.Errorf("nano: got %s want %s", got, tc.Nano)
			}
			if got := amt.Micro().String(); got != tc.Micro {
				t.Errorf("micro: got %s want %s", got, tc.Micro)
			}
			if got := amt.Milli().String(); got != tc.Milli {
				t.Errorf("milli: got %s want %s", got, tc.Milli)
			}
			if got := amt.XL1().String(); got != tc.XL1 {
				t.Errorf("xl1: got %s want %s", got, tc.XL1)
			}
		})
	}
}

func TestShiftedBigIntFormatting(t *testing.T) {
	oneXL1 := protocol.AmountFromXL1(big.NewInt(1))
	if got := oneXL1.ToFullString(protocol.PlacesXL1); got != "1.000000000000000000" {
		t.Errorf("1 XL1 full: got %q", got)
	}
	if got := oneXL1.ToShortString(); got != "1.0" {
		t.Errorf("1 XL1 short: got %q", got)
	}

	onePointFiveAtto := new(big.Int).Mul(big.NewInt(15), protocol.AttoConvertFactor(17))
	onePointFive := protocol.AmountFromAtto(onePointFiveAtto)
	if got := onePointFive.ToFullString(protocol.PlacesXL1); got != "1.500000000000000000" {
		t.Errorf("1.5 XL1 full: got %q", got)
	}
	if got := onePointFive.ToShortString(); got != "1.5" {
		t.Errorf("1.5 XL1 short: got %q", got)
	}

	bigXL1 := protocol.AmountFromXL1(big.NewInt(1234))
	if got := bigXL1.ToShortString(); got != "1,234.0" {
		t.Errorf("1234 XL1 short: got %q", got)
	}

	cfg0 := protocol.DefaultShiftedBigIntConfig()
	cfg0.Places = 0
	s0 := protocol.NewShiftedBigInt(big.NewInt(1_234_567), cfg0)
	if got := s0.ToShortString(); got != "1,234,567" {
		t.Errorf("places=0 short: got %q", got)
	}

	// Denomination bounds check
	if _, err := protocol.NewAttoXL1(big.NewInt(-1)); !errors.Is(err, protocol.ErrNegativeAmount) {
		t.Errorf("expected ErrNegativeAmount, got %v", err)
	}
	overMax := new(big.Int).Add(protocol.MaxValueForPlaces(protocol.PlacesAtto), big.NewInt(1))
	if _, err := protocol.NewAttoXL1(overMax); !errors.Is(err, protocol.ErrAmountOverflow) {
		t.Errorf("expected ErrAmountOverflow, got %v", err)
	}
}

func TestTransactionBuilderAndValidation(t *testing.T) {
	sender, err := account.RandomAccount()
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := account.RandomAccount()
	if err != nil {
		t.Fatal(err)
	}
	quantSigner, err := account.RandomQuantAccount()
	if err != nil {
		t.Fatal(err)
	}

	transfer := protocol.NewTransferPayload(
		sender.Address(),
		map[string]string{recipient.Address(): "0x64"},
		nil,
	)

	tx, err := protocol.NewTransactionBuilder().
		Chain("c5fe2e6f6841cbab12d8c0618be2df8c6156cc44").
		Fees(protocol.DefaultTransactionFees()).
		Range(100, 200).
		Payload(transfer).
		Signers(sender, quantSigner).
		Build()
	if err != nil {
		t.Fatalf("TransactionBuilder.Build: %v", err)
	}

	// Verify fees are bare hex (no 0x prefix)
	if strings.HasPrefix(tx.BoundWitness.Fees.Base, "0x") ||
		strings.HasPrefix(tx.BoundWitness.Fees.GasLimit, "0x") ||
		strings.HasPrefix(tx.BoundWitness.Fees.GasPrice, "0x") ||
		strings.HasPrefix(tx.BoundWitness.Fees.Priority, "0x") {
		t.Fatalf("expected bare-hex fees without 0x prefix, got %+v", tx.BoundWitness.Fees)
	}

	// Verify auto-generated elevate|<hash> script
	transferHash, _ := payload.Hash(transfer)
	if len(tx.BoundWitness.Script) != 1 || tx.BoundWitness.Script[0] != "elevate|"+transferHash {
		t.Fatalf("expected auto elevate script, got %v", tx.BoundWitness.Script)
	}

	// Validate structurally and cryptographically (verifies both secp256k1 & ML-DSA-65!)
	if errs := protocol.ValidateTransaction(tx); len(errs) != 0 {
		t.Fatalf("ValidateTransaction failed: %v", errs)
	}

	// Round-trip JSON wire tuple [bw, payloads]
	rawTuple, err := json.Marshal(tx)
	if err != nil {
		t.Fatalf("marshal hydrated tx: %v", err)
	}
	var decoded protocol.HydratedTransaction
	if err := json.Unmarshal(rawTuple, &decoded); err != nil {
		t.Fatalf("unmarshal hydrated tx: %v", err)
	}
	if errs := protocol.ValidateTransaction(&decoded); len(errs) != 0 {
		t.Fatalf("decoded HydratedTransaction failed validation: %v", errs)
	}
}

func TestBlockEpochAndRPCEngineWithXyoViewer(t *testing.T) {
	const (
		chainID = protocol.ChainID("c5fe2e6f6841cbab12d8c0618be2df8c6156cc44")
		headNum = 200_000
	)
	signer, err := account.RandomAccount()
	if err != nil {
		t.Fatal(err)
	}

	makeBlock := func(num int64) protocol.HydratedBlock {
		tp := protocol.NewTimePayload(1700000000000 + num*60000)
		tpAny, _ := payload.ToAnyPayload(tp)
		tpHash, _ := tpAny.Hash()
		prev := strings.Repeat("0", 63) + "1"
		bw := &protocol.BlockBoundWitness{
			BoundWitness: boundwitness.BoundWitness{
				Addresses:      []string{signer.Address()},
				PayloadHashes:  []string{tpHash},
				PayloadSchemas: []string{payload.SchemaTime},
				PreviousHashes: []*string{nil},
				Schema:         payload.SchemaBoundWitness,
			},
			Block:      num,
			Chain:      chainID,
			Previous:   &prev,
			StepHashes: []string{},
		}
		dh, _ := bw.DataHashBytes()
		sigBytes, _ := signer.SignDetached(dh)
		sigHex := strings.ToLower(string(encodeHex(sigBytes)))
		bw.Signatures = []*string{&sigHex}
		h, _ := bw.Hash()
		bw.StoredHash = h
		return protocol.HydratedBlock{
			BoundWitness: bw,
			Payloads:     []payload.AnyPayload{tpAny},
			Hash:         h,
		}
	}

	headBlock := makeBlock(headNum)
	finalizedBlock := makeBlock(headNum - 6)
	if errs := protocol.ValidateBlock(&headBlock); len(errs) != 0 {
		t.Fatalf("ValidateBlock failed: %v", errs)
	}
	if ep := protocol.EpochOfBlock(&headBlock); ep == nil || *ep != 1700000000000+headNum*60000 {
		t.Fatalf("EpochOfBlock mismatch: %v", ep)
	}

	engine := protocol.NewRPCEngine()
	engine.Register(protocol.RPCMethodBlockViewerCurrentBlock, func(_ context.Context, _ []json.RawMessage) (any, error) {
		return headBlock, nil
	})
	engine.Register(protocol.RPCMethodFinalizationViewerHead, func(_ context.Context, _ []json.RawMessage) (any, error) {
		return finalizedBlock, nil
	})
	engine.Register(protocol.RPCMethodTimeSyncViewerCurrentTime, func(_ context.Context, params []json.RawMessage) (any, error) {
		var dom string
		_ = json.Unmarshal(params[0], &dom)
		return []any{dom, int64(headNum)}, nil
	})
	engine.Register(protocol.RPCMethodAccountBalanceViewerQualifiedBalances, func(_ context.Context, params []json.RawMessage) (any, error) {
		var addrs []string
		_ = json.Unmarshal(params[0], &addrs)
		balMap := map[string]string{}
		for _, a := range addrs {
			balMap[a] = "0xde0b6b3a7640000" // 1 XL1
		}
		return []any{
			balMap,
			protocol.ChainQualification{Head: headBlock.Hash, Range: []int64{0, headNum}},
		}, nil
	})
	var submittedTxs []protocol.HydratedTransaction
	engine.Register(protocol.RPCMethodMempoolRunnerSubmitTransactions, func(_ context.Context, params []json.RawMessage) (any, error) {
		var txs []protocol.HydratedTransaction
		if err := json.Unmarshal(params[0], &txs); err != nil {
			return nil, &protocol.JSONRPCError{Code: protocol.RPCErrInvalidParams, Message: err.Error()}
		}
		submittedTxs = append(submittedTxs, txs...)
		hashes := make([]string, len(txs))
		for i, tx := range txs {
			hashes[i] = tx.Hash
		}
		return hashes, nil
	})
	engine.Register(protocol.RPCMethodMempoolViewerPendingTransactions, func(_ context.Context, _ []json.RawMessage) (any, error) {
		return submittedTxs, nil
	})
	engine.Register(protocol.RPCMethodDataLakeViewerGet, func(_ context.Context, _ []json.RawMessage) (any, error) {
		return []any{payload.NewIdPayload("42")}, nil
	})
	engine.Register(protocol.RPCMethodRewardsByPositionPrefix+"earned", func(_ context.Context, _ []json.RawMessage) (any, error) {
		return map[string]string{"pos1": "0xde0b6b3a7640000"}, nil
	})

	srv := httptest.NewServer(engine)
	defer srv.Close()

	viewer, err := protocol.NewXyoViewerHTTP(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	gotHead, err := viewer.CurrentBlock(ctx)
	if err != nil || gotHead.BoundWitness.Block != headNum {
		t.Fatalf("CurrentBlock: got %+v err=%v", gotHead, err)
	}
	gotFin, err := viewer.FinalizedHead(ctx)
	if err != nil || gotFin.BoundWitness.Block != headNum-6 {
		t.Fatalf("FinalizedHead: got %+v err=%v", gotFin, err)
	}
	dom, val, err := viewer.TimeSync.CurrentTime(ctx, "xl1")
	if err != nil || dom != "xl1" || val != headNum {
		t.Fatalf("TimeSync.CurrentTime: dom=%s val=%d err=%v", dom, val, err)
	}

	qualBal, err := viewer.AccountBalance.QualifiedAccountBalances(ctx, []string{signer.Address()}, nil)
	if err != nil {
		t.Fatalf("QualifiedAccountBalances: %v", err)
	}
	if qualBal.Data[signer.Address()].String() != "1000000000000000000" {
		t.Fatalf("unexpected balance: %s", qualBal.Data[signer.Address()].String())
	}

	tx, err := protocol.NewTransactionBuilder().
		Chain(chainID).
		Fees(protocol.DefaultTransactionFees()).
		Range(headNum, headNum+10).
		Payload(payload.NewIdPayload("tx-test")).
		Signer(signer).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	txHashes, err := viewer.SubmitTransactions(ctx, []protocol.HydratedTransaction{*tx})
	if err != nil || len(txHashes) != 1 {
		t.Fatalf("SubmitTransactions: hashes=%v err=%v", txHashes, err)
	}
	pending, err := viewer.Mempool.PendingTransactions(ctx)
	if err != nil || len(pending) != 1 {
		t.Fatalf("PendingTransactions: len=%d err=%v", len(pending), err)
	}

	dlPayloads, err := viewer.DataLake.Get(ctx, []string{"770b6ca959389c0da23ac969d1d6288c8e96542ce43570a652a2b1f5e4c9759d"})
	if err != nil || len(dlPayloads) != 1 {
		t.Fatalf("DataLake.Get: len=%d err=%v", len(dlPayloads), err)
	}

	rewards, err := viewer.RewardsByPosition.Earned(ctx)
	if err != nil || rewards["pos1"].String() != "1000000000000000000" {
		t.Fatalf("RewardsByPosition.Earned: %v err=%v", rewards, err)
	}

	// Unknown method returns JSON-RPC -32601 error
	var dummy any
	err = viewer.Call(ctx, "unknown_method", &dummy)
	var rpcErr *protocol.JSONRPCError
	if !errors.As(err, &rpcErr) || rpcErr.Code != protocol.RPCErrMethodNotFound {
		t.Fatalf("expected RPCErrMethodNotFound (-32601), got %v", err)
	}
}

func TestDenominationsAmountWrappersAndModels(t *testing.T) {
	// AttoXL1 JSON marshal/unmarshal round-trip & AccountBalanceHistoryItem
	bigAtto, err := protocol.AttoXL1FromString("1234567890123456789012345")
	if err != nil {
		t.Fatal(err)
	}
	hist := protocol.AccountBalanceHistoryItem{Block: 42, Balance: bigAtto}
	raw, err := json.Marshal(hist)
	if err != nil {
		t.Fatal(err)
	}
	var decodedHist protocol.AccountBalanceHistoryItem
	if err := json.Unmarshal(raw, &decodedHist); err != nil {
		t.Fatal(err)
	}
	if decodedHist.Block != 42 || decodedHist.Balance.String() != "1234567890123456789012345" {
		t.Fatalf("AccountBalanceHistoryItem round-trip mismatch: %+v", decodedHist)
	}

	// Strict hex vs decimal disambiguation
	hex100, err := protocol.AttoXL1FromHex("100")
	if err != nil || hex100.String() != "256" {
		t.Fatalf("AttoXL1FromHex(\"100\") should be 256, got %s err=%v", hex100.String(), err)
	}
	dec100, err := protocol.AttoXL1FromString("100")
	if err != nil || dec100.String() != "100" {
		t.Fatalf("AttoXL1FromString(\"100\") should be 100, got %s err=%v", dec100.String(), err)
	}
	if _, err := protocol.AttoXL1FromHex(""); err == nil {
		t.Fatal("empty hex AttoXL1 must fail")
	}
	if _, err := protocol.AttoXL1FromString("deadbeef"); err == nil {
		t.Fatal("bare hex without 0x must fail AttoXL1FromString")
	}

	// DisableGrouping on ShiftedBigIntConfig
	cfgNoGroup := protocol.DefaultShiftedBigIntConfig()
	cfgNoGroup.DisableGrouping = true
	if got := protocol.AmountFromXL1(big.NewInt(1234567)).Format(cfgNoGroup); got != "1234567.0" {
		t.Fatalf("DisableGrouping failed: got %q", got)
	}

	// XL1Amount string parsing & arithmetic
	a1, err := protocol.AmountFromString("1,000.5", protocol.PlacesXL1)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := protocol.AmountFromString("0.5", protocol.PlacesXL1)
	if err != nil {
		t.Fatal(err)
	}
	sum := a1.Add(a2)
	if !sum.Equal(protocol.AmountFromXL1(big.NewInt(1001))) {
		t.Fatalf("XL1Amount Add mismatch: got %s", sum.ToFullString(protocol.PlacesXL1))
	}
	diff := a1.Sub(a2)
	if !diff.Equal(protocol.AmountFromXL1(big.NewInt(1000))) {
		t.Fatalf("XL1Amount Sub mismatch: got %s", diff.ToFullString(protocol.PlacesXL1))
	}
	// Sub clamps to zero
	if !a2.Sub(a1).Equal(protocol.ZeroAmount()) {
		t.Fatal("XL1Amount Sub underflow should clamp to zero")
	}

	// Block range, StepSize, Position lifecycle
	rng, err := protocol.ParseBlockRange("100|250")
	if err != nil || rng.Start != 100 || rng.End != 250 || rng.Key() != "100|250" {
		t.Fatalf("ParseBlockRange failed: %+v err=%v", rng, err)
	}
	if _, err := protocol.ParseBlockRange("bad"); err == nil {
		t.Fatal("expected ParseBlockRange error")
	}
	if sz, err := protocol.StepSize(0); err != nil || sz != 7 {
		t.Fatalf("StepSize(0): %d err=%v", sz, err)
	}
	if _, err := protocol.StepSize(99); err == nil {
		t.Fatal("expected out-of-range StepSize error")
	}

	pos := protocol.Position{Stake: protocol.Stake{ID: 1, AddBlock: 10}}
	if !pos.IsActive() || pos.IsRemoved() || pos.IsWithdrawn() {
		t.Fatal("expected active position")
	}
	remBlock := int64(50)
	pos.RemoveBlock = &remBlock
	if pos.IsActive() || !pos.IsRemoved() {
		t.Fatal("expected removed position")
	}

	// Wrappers: AddressWrapper, FeesWrapper, HydratedTransactionWrapper
	aw := protocol.WrapAddress("0x5E7A847447E7FEC41011AE7D32D768F86605BA03")
	if !aw.IsValid() || !aw.IsLegacy() || aw.IsQuant() {
		t.Fatal("AddressWrapper legacy check failed")
	}
	if norm, err := aw.Normalized(); err != nil || norm != "5e7a847447e7fec41011ae7d32d768f86605ba03" {
		t.Fatalf("AddressWrapper.Normalized: %q err=%v", norm, err)
	}
	fw, err := protocol.FeesWrapperFromBigInts(big.NewInt(10), big.NewInt(20), big.NewInt(3), big.NewInt(5))
	if err != nil {
		t.Fatal(err)
	}
	if tot, err := fw.Total(); err != nil || tot.String() != "75" {
		t.Fatalf("FeesWrapper.Total: %s err=%v", tot.String(), err)
	}

	signer, _ := account.RandomAccount()
	tx, err := protocol.NewTransactionBuilder().
		Chain("c5fe2e6f6841cbab12d8c0618be2df8c6156cc44").
		Fees(protocol.DefaultTransactionFees()).
		Range(10, 20).
		Payload(payload.NewIdPayload("wrap")).
		Signer(signer).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	tw := protocol.WrapTransaction(tx)
	if tw.IsValidAt(9) || !tw.IsValidAt(10) || !tw.IsValidAt(19) || tw.IsValidAt(20) || !tw.IsExpiredAt(20) {
		t.Fatal("HydratedTransactionWrapper validity window mismatch")
	}
}

func TestValidationNegativeCasesAndExtraFieldsPreservation(t *testing.T) {
	signer, _ := account.RandomAccount()
	other, _ := account.RandomAccount()

	// TransactionBuilder rejects invalid range, invalid from, duplicate signers
	if _, err := protocol.NewTransactionBuilder().
		Chain("c5fe2e6f6841cbab12d8c0618be2df8c6156cc44").
		Fees(protocol.DefaultTransactionFees()).
		Range(100, 100).
		Signer(signer).
		Build(); err == nil {
		t.Fatal("expected error for exp <= nbf")
	}
	if _, err := protocol.NewTransactionBuilder().
		Chain("c5fe2e6f6841cbab12d8c0618be2df8c6156cc44").
		Fees(protocol.DefaultTransactionFees()).
		Range(10, 20).
		From("not-an-address").
		Signer(signer).
		Build(); err == nil {
		t.Fatal("expected error for invalid from address")
	}
	if _, err := protocol.NewTransactionBuilder().
		Chain("c5fe2e6f6841cbab12d8c0618be2df8c6156cc44").
		Fees(protocol.DefaultTransactionFees()).
		Range(10, 20).
		Signers(signer, signer).
		Build(); err == nil {
		t.Fatal("expected error for duplicate signers")
	}

	// ValidateTransaction catches from-not-in-signers, bad fees, bad range
	tx, err := protocol.NewTransactionBuilder().
		Chain("c5fe2e6f6841cbab12d8c0618be2df8c6156cc44").
		Fees(protocol.DefaultTransactionFees()).
		Range(10, 20).
		From(other.Address()).
		Signer(signer).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	if errs := protocol.ValidateTransaction(tx); len(errs) == 0 {
		t.Fatal("expected FROM_NOT_SIGNER validation error")
	}

	// Modular ValidateTransactionWith
	vErrs := protocol.ValidateTransactionWith(tx.BoundWitness,
		protocol.TransactionFromValidator,
		protocol.TransactionDurationValidator,
		protocol.TransactionGasValidator,
		protocol.TransactionTransfersValidator,
	)
	foundFromNotSigner := false
	for _, ve := range vErrs {
		if ve.Code == "FROM_NOT_SIGNER" {
			foundFromNotSigner = true
		}
	}
	if !foundFromNotSigner {
		t.Fatalf("expected FROM_NOT_SIGNER code, got %+v", vErrs)
	}

	// Unknown JSON fields preserved on BlockBoundWitness and TransactionBoundWitness
	validTx, err := protocol.NewTransactionBuilder().
		Chain("c5fe2e6f6841cbab12d8c0618be2df8c6156cc44").
		Fees(protocol.DefaultTransactionFees()).
		Range(10, 20).
		Payload(payload.NewIdPayload("extra-field-test")).
		Signer(signer).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	validTx.BoundWitness.Extra = map[string]any{"custom_protocol_ext": "v2"}
	// Re-sign with Extra present so signature covers custom_protocol_ext
	dhBytes, _ := validTx.BoundWitness.DataHashBytes()
	sigBytes, _ := signer.SignDetached(dhBytes)
	sigHex := string(encodeHex(sigBytes))
	validTx.BoundWitness.Signatures = []*string{&sigHex}

	rawTxJSON, err := json.Marshal(validTx)
	if err != nil {
		t.Fatal(err)
	}
	var roundTripped protocol.HydratedTransaction
	if err := json.Unmarshal(rawTxJSON, &roundTripped); err != nil {
		t.Fatal(err)
	}
	if roundTripped.BoundWitness.Extra["custom_protocol_ext"] != "v2" {
		t.Fatalf("expected Extra field preserved, got %+v", roundTripped.BoundWitness.Extra)
	}
	if errs := protocol.ValidateTransaction(&roundTripped); len(errs) != 0 {
		t.Fatalf("round-tripped tx with Extra field failed validation: %v", errs)
	}

	// Genesis block with non-nil previous fails ValidateBlock
	badPrev := strings.Repeat("a", 64)
	genesisWithPrev := &protocol.HydratedBlock{
		BoundWitness: &protocol.BlockBoundWitness{
			BoundWitness: boundwitness.BoundWitness{Schema: payload.SchemaBoundWitness},
			Block:        0,
			Chain:        "c5fe2e6f6841cbab12d8c0618be2df8c6156cc44",
			Previous:     &badPrev,
		},
	}
	if errs := protocol.ValidateBlock(genesisWithPrev); len(errs) == 0 {
		t.Fatal("genesis block with previous hash must fail validation")
	}
}

func TestAllRPCViewersRunnersEngineSpecAndConnection(t *testing.T) {
	const largeAttoStr = "99999999999999999999999999" // > 2^53 (26 digits)
	signer, _ := account.RandomAccount()

	tx, err := protocol.NewTransactionBuilder().
		Chain("c5fe2e6f6841cbab12d8c0618be2df8c6156cc44").
		Fees(protocol.DefaultTransactionFees()).
		Range(1, 100).
		Payload(payload.NewIdPayload("rpc-all")).
		Signer(signer).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	engine := protocol.NewRPCEngine()
	// Null result tests
	engine.Register(protocol.RPCMethodBlockViewerCurrentBlock, func(_ context.Context, _ []json.RawMessage) (any, error) {
		return nil, nil
	})
	engine.Register(protocol.RPCMethodFinalizationViewerHead, func(_ context.Context, _ []json.RawMessage) (any, error) {
		return nil, nil
	})
	engine.Register(protocol.RPCMethodBlockViewerBlocksByHash, func(_ context.Context, _ []json.RawMessage) (any, error) {
		return []protocol.HydratedBlock{}, nil
	})
	engine.Register(protocol.RPCMethodBlockViewerBlocksByNumber, func(_ context.Context, _ []json.RawMessage) (any, error) {
		return []protocol.HydratedBlock{}, nil
	})
	engine.Register(protocol.RPCMethodBlockViewerPayloadsByHash, func(_ context.Context, _ []json.RawMessage) (any, error) {
		return []any{payload.NewIdPayload("b")}, nil
	})
	// TransactionViewer all 4 methods
	var pollCount int
	engine.Register(protocol.RPCMethodTransactionViewerByHash, func(_ context.Context, _ []json.RawMessage) (any, error) {
		pollCount++
		if pollCount == 1 {
			return nil, nil
		}
		return tx, nil
	})
	engine.Register(protocol.RPCMethodTransactionViewerTransactionByHash, func(_ context.Context, _ []json.RawMessage) (any, error) {
		return tx, nil
	})
	engine.Register(protocol.RPCMethodTransactionViewerTransactionByBlockHashAndIndex, func(_ context.Context, _ []json.RawMessage) (any, error) {
		return tx, nil
	})
	engine.Register(protocol.RPCMethodTransactionViewerTransactionByBlockNumAndIndex, func(_ context.Context, _ []json.RawMessage) (any, error) {
		return tx, nil
	})
	// AccountBalance histories with >2^53 JSON number precision
	engine.Register(protocol.RPCMethodAccountBalanceViewerQualifiedBalanceHistories, func(_ context.Context, _ []json.RawMessage) (any, error) {
		return json.RawMessage(`[{"` + signer.Address() + `":[{"block":10,"balance":` + largeAttoStr + `}]},{"head":"abc","range":[0,10]}]`), nil
	})
	// TimeSyncViewer
	engine.Register(protocol.RPCMethodTimeSyncViewerConvertTime, func(_ context.Context, _ []json.RawMessage) (any, error) {
		return int64(1700000000000), nil
	})
	engine.Register(protocol.RPCMethodTimeSyncViewerCurrentTimeAndHash, func(_ context.Context, _ []json.RawMessage) (any, error) {
		return []any{int64(42), strings.Repeat("a", 64)}, nil
	})
	engine.Register(protocol.RPCMethodTimeSyncViewerCurrentTimePayload, func(_ context.Context, _ []json.RawMessage) (any, error) {
		return protocol.NewTimePayload(1700000000000), nil
	})
	// StakeViewer & StakeTotalsViewer & StakeRunner
	sampleStake := protocol.Stake{ID: 7, Staker: signer.Address(), Staked: signer.Address(), Amount: largeAttoStr, AddBlock: 5}
	engine.Register(protocol.RPCMethodStakeViewerStakeByID, func(_ context.Context, params []json.RawMessage) (any, error) {
		var id int64
		_ = json.Unmarshal(params[0], &id)
		if id == 0 {
			return nil, nil
		}
		return sampleStake, nil
	})
	engine.Register(protocol.RPCMethodStakeViewerStakeByStaker, func(_ context.Context, _ []json.RawMessage) (any, error) {
		return sampleStake, nil
	})
	engine.Register(protocol.RPCMethodStakeViewerStakesByStaked, func(_ context.Context, _ []json.RawMessage) (any, error) {
		return []protocol.Stake{sampleStake}, nil
	})
	engine.Register(protocol.RPCMethodStakeViewerStakesByStaker, func(_ context.Context, _ []json.RawMessage) (any, error) {
		return []protocol.Stake{sampleStake}, nil
	})
	engine.Register(protocol.RPCMethodStakeViewerMinWithdrawalBlocks, func(_ context.Context, _ []json.RawMessage) (any, error) {
		return int64(1440), nil
	})
	engine.Register(protocol.RPCMethodStakeViewerRewardsContract, func(_ context.Context, _ []json.RawMessage) (any, error) {
		return signer.Address(), nil
	})
	engine.Register(protocol.RPCMethodStakeViewerStakingTokenAddress, func(_ context.Context, _ []json.RawMessage) (any, error) {
		return signer.Address(), nil
	})
	for _, m := range []string{
		protocol.RPCMethodStakeTotalsViewerActive,
		protocol.RPCMethodStakeTotalsViewerActiveByStaked,
		protocol.RPCMethodStakeTotalsViewerActiveByStaker,
		protocol.RPCMethodStakeTotalsViewerPending,
		protocol.RPCMethodStakeTotalsViewerPendingByStaker,
		protocol.RPCMethodStakeTotalsViewerWithdrawn,
		protocol.RPCMethodStakeTotalsViewerWithdrawnByStaker,
		protocol.RPCMethodStepViewerStake,
		protocol.RPCMethodStepViewerWeight,
		protocol.RPCMethodTransferBalanceViewerBalance,
		protocol.RPCMethodTransferBalanceViewerPairBalance,
		protocol.RPCMethodBlockRewardViewerAllowedRewardForBlock,
	} {
		engine.Register(m, func(_ context.Context, _ []json.RawMessage) (any, error) {
			// Return raw unquoted JSON number > 2^53 to test UseNumber() precision!
			return json.RawMessage(largeAttoStr), nil
		})
	}
	engine.Register(protocol.RPCMethodStakeRunnerAddStake, func(_ context.Context, _ []json.RawMessage) (any, error) { return true, nil })
	engine.Register(protocol.RPCMethodStakeRunnerRemoveStake, func(_ context.Context, _ []json.RawMessage) (any, error) { return true, nil })
	engine.Register(protocol.RPCMethodStakeRunnerWithdrawStake, func(_ context.Context, _ []json.RawMessage) (any, error) { return true, nil })
	engine.Register(protocol.RPCMethodNetworkStakeViewerActive, func(_ context.Context, _ []json.RawMessage) (any, error) { return []any{largeAttoStr, 1}, nil })
	engine.Register(protocol.RPCMethodStepViewerPositionCount, func(_ context.Context, _ []json.RawMessage) (any, error) { return int64(3), nil })
	engine.Register(protocol.RPCMethodStepViewerPositions, func(_ context.Context, _ []json.RawMessage) (any, error) {
		return []protocol.Position{{Stake: sampleStake}}, nil
	})
	engine.Register(protocol.RPCMethodStepViewerRandomizer, func(_ context.Context, _ []json.RawMessage) (any, error) { return "0xabc", nil })
	engine.Register(protocol.RPCMethodStepViewerStakerCount, func(_ context.Context, _ []json.RawMessage) (any, error) { return int64(2), nil })
	engine.Register(protocol.RPCMethodStepViewerStakers, func(_ context.Context, _ []json.RawMessage) (any, error) { return []string{signer.Address()}, nil })
	engine.Register(protocol.RPCMethodTransferBalanceViewerBalances, func(_ context.Context, _ []json.RawMessage) (any, error) {
		return json.RawMessage(`{"` + signer.Address() + `":` + largeAttoStr + `}`), nil
	})
	engine.Register(protocol.RPCMethodTransferBalanceViewerBalanceHistory, func(_ context.Context, _ []json.RawMessage) (any, error) { return []any{}, nil })
	engine.Register(protocol.RPCMethodTransferBalanceViewerPairBalanceHistory, func(_ context.Context, _ []json.RawMessage) (any, error) { return []any{}, nil })
	engine.Register(protocol.RPCMethodTransferBalanceViewerPairBalances, func(_ context.Context, _ []json.RawMessage) (any, error) { return map[string]any{}, nil })
	engine.Register(protocol.RPCMethodForkViewerForkHistory, func(_ context.Context, _ []json.RawMessage) (any, error) { return []any{}, nil })
	engine.Register(protocol.RPCMethodLegacyNetworkStakeRewardsTotal, func(_ context.Context, _ []json.RawMessage) (any, error) {
		return map[string]string{"total": largeAttoStr}, nil
	})

	// Wrap via RPCConnection proxy to test RPCEngineFromConnection!
	backendSrv := httptest.NewServer(engine)
	defer backendSrv.Close()
	backendViewer, err := protocol.NewXyoViewerHTTP(backendSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyEngine := protocol.RPCEngineFromConnection(protocol.RPCConnection{Viewer: backendViewer})
	proxySrv := httptest.NewServer(proxyEngine)
	defer proxySrv.Close()

	v, err := protocol.NewXyoViewerHTTP(proxySrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Null RPC responses must return (nil, nil) instead of (&ZeroStruct{}, nil)
	if b, err := v.CurrentBlock(ctx); err != nil || b != nil {
		t.Fatalf("expected (nil, nil) on null CurrentBlock, got (%+v, %v)", b, err)
	}
	if f, err := v.FinalizedHead(ctx); err != nil || f != nil {
		t.Fatalf("expected (nil, nil) on null FinalizedHead, got (%+v, %v)", f, err)
	}
	if s, err := v.Stake.StakeByID(ctx, 0); err != nil || s != nil {
		t.Fatalf("expected (nil, nil) on null StakeByID(0), got (%+v, %v)", s, err)
	}

	// ConfirmSubmittedTransaction polls until found (attempt 1=nil, attempt 2=tx)
	confirmed, err := protocol.ConfirmSubmittedTransaction(ctx, v.Transaction, tx.Hash, 5*time.Millisecond, 5)
	if err != nil || confirmed == nil || confirmed.BoundWitness.From != signer.Address() {
		t.Fatalf("ConfirmSubmittedTransaction failed: %+v err=%v", confirmed, err)
	}
	// XyoViewer.TransactionByHash calls transactionViewer_transactionByHash
	if gotTx, err := v.TransactionByHash(ctx, tx.Hash); err != nil || gotTx == nil {
		t.Fatalf("XyoViewer.TransactionByHash: %v", err)
	}
	if gotTx, err := v.Transaction.TransactionByBlockHashAndIndex(ctx, strings.Repeat("b", 64), 0); err != nil || gotTx == nil {
		t.Fatalf("TransactionByBlockHashAndIndex: %v", err)
	}
	if gotTx, err := v.Transaction.TransactionByBlockNumberAndIndex(ctx, 1, 0); err != nil || gotTx == nil {
		t.Fatalf("TransactionByBlockNumberAndIndex: %v", err)
	}

	// AccountBalanceHistories >2^53 precision
	hists, err := v.AccountBalance.QualifiedAccountBalanceHistories(ctx, []string{signer.Address()}, nil)
	if err != nil || len(hists.Data[signer.Address()]) != 1 || hists.Data[signer.Address()][0].Balance.String() != largeAttoStr {
		t.Fatalf("QualifiedAccountBalanceHistories precision mismatch: %+v err=%v", hists, err)
	}

	// TimeSyncViewer
	if conv, err := v.TimeSync.ConvertTime(ctx, protocol.TimeDomainXL1, protocol.TimeDomainEpoch, 1); err != nil || conv != 1700000000000 {
		t.Fatalf("ConvertTime: %d err=%v", conv, err)
	}
	if val, h, err := v.TimeSync.CurrentTimeAndHash(ctx, protocol.TimeDomainXL1); err != nil || val != 42 || len(h) != 64 {
		t.Fatalf("CurrentTimeAndHash: %d %s err=%v", val, h, err)
	}
	if tp, err := v.TimeSync.CurrentTimePayload(ctx); err != nil || tp == nil || *tp.Epoch != 1700000000000 {
		t.Fatalf("CurrentTimePayload: %+v err=%v", tp, err)
	}

	// StakeViewer / StakeTotalsViewer / StakeRunner / StepViewer / TransferBalanceViewer / BlockRewardViewer / ForkViewer
	if st, err := v.Stake.StakeByID(ctx, 7); err != nil || st == nil || st.ID != 7 {
		t.Fatalf("StakeByID: %+v err=%v", st, err)
	}
	if mw, err := v.Stake.MinWithdrawalBlocks(ctx); err != nil || mw != 1440 {
		t.Fatalf("MinWithdrawalBlocks: %d err=%v", mw, err)
	}
	if act, err := v.StakeTotals.Active(ctx); err != nil || act.String() != largeAttoStr {
		t.Fatalf("StakeTotals.Active >2^53 precision mismatch: got %s want %s err=%v", act.String(), largeAttoStr, err)
	}
	if w, err := v.Step.Weight(ctx, 0); err != nil || w.String() != largeAttoStr {
		t.Fatalf("Step.Weight >2^53 precision mismatch: got %s err=%v", w.String(), err)
	}
	if tb, err := v.TransferBalance.TransferBalance(ctx, signer.Address()); err != nil || tb.String() != largeAttoStr {
		t.Fatalf("TransferBalance: got %s err=%v", tb.String(), err)
	}
	if tbs, err := v.TransferBalance.TransferBalances(ctx, []string{signer.Address()}); err != nil || tbs[signer.Address()].String() != largeAttoStr {
		t.Fatalf("TransferBalances: got %v err=%v", tbs, err)
	}
	if rew, err := v.BlockReward.AllowedRewardForBlock(ctx, 10); err != nil || rew.String() != largeAttoStr {
		t.Fatalf("AllowedRewardForBlock: got %s err=%v", rew.String(), err)
	}
	if _, err := v.Fork.ForkHistory(ctx); err != nil {
		t.Fatalf("ForkHistory: %v", err)
	}
	if _, err := v.LegacyStepRewards.Total(ctx); err != nil {
		t.Fatalf("LegacyStepRewards.Total: %v", err)
	}
	if _, err := v.StakeRunner.AddStake(ctx, signer.Address(), protocol.AmountFromXL1(big.NewInt(1)).Atto()); err != nil {
		t.Fatalf("AddStake: %v", err)
	}

	// JSON-RPC 2.0 wire spec checks: id=0 preserved, parse error emits id=null, notification returns 204, batch returns array
	rawID0, ok := engine.HandleRawBytes(ctx, []byte(`{"jsonrpc":"2.0","id":0,"method":"stakeViewer_minWithdrawalBlocks"}`))
	if !ok || !strings.Contains(string(rawID0), `"id":0`) {
		t.Fatalf("expected \"id\":0 preserved in JSON-RPC response, got %s", string(rawID0))
	}
	rawParseErr, ok := engine.HandleRawBytes(ctx, []byte(`{bad json`))
	if !ok || !strings.Contains(string(rawParseErr), `"id":null`) || !strings.Contains(string(rawParseErr), `-32700`) {
		t.Fatalf("expected parse error with \"id\":null, got %s", string(rawParseErr))
	}
	// Notification (no "id") -> HTTP 204 No Content
	notifResp, err := http.Post(backendSrv.URL, "application/json", bytes.NewReader([]byte(`{"jsonrpc":"2.0","method":"stakeViewer_minWithdrawalBlocks"}`)))
	if err != nil {
		t.Fatal(err)
	}
	_ = notifResp.Body.Close()
	if notifResp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 No Content for notification, got %d", notifResp.StatusCode)
	}
	// Batch request (1 normal + 1 notification -> 1 response in array)
	batchOut, ok := engine.HandleRawBytes(ctx, []byte(`[
		{"jsonrpc":"2.0","id":1,"method":"stakeViewer_minWithdrawalBlocks"},
		{"jsonrpc":"2.0","method":"stakeViewer_minWithdrawalBlocks"}
	]`))
	if !ok {
		t.Fatal("expected batch response")
	}
	var batchResps []protocol.JSONRPCResponse
	if err := json.Unmarshal(batchOut, &batchResps); err != nil || len(batchResps) != 1 {
		t.Fatalf("expected 1 response in batch array, got %s (err=%v)", string(batchOut), err)
	}
}

func encodeHex(b []byte) []byte {
	const hexChars = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexChars[v>>4]
		out[i*2+1] = hexChars[v&0x0f]
	}
	return out
}
