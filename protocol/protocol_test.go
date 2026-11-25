package protocol_test

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

func encodeHex(b []byte) []byte {
	const hexChars = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexChars[v>>4]
		out[i*2+1] = hexChars[v&0x0f]
	}
	return out
}
