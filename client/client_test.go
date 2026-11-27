package client_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/XYOracleNetwork/sdk-xyo-client-go/account"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/boundwitness"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/client"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/payload"
)

func TestNodeClientAndArchivistWrapperHTTP(t *testing.T) {
	serverAcct, err := account.RandomAccount()
	if err != nil {
		t.Fatal(err)
	}
	clientAcct, err := account.RandomAccount()
	if err != nil {
		t.Fatal(err)
	}

	var receivedQuerySchema string
	var receivedAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		receivedAuth = r.Header.Get("Authorization")

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Verify wire format is [QueryBoundWitness, payloads]
		var tuple []json.RawMessage
		if err := json.Unmarshal(body, &tuple); err != nil || len(tuple) != 2 {
			t.Errorf("invalid wire tuple: %s", string(body))
			http.Error(w, "bad tuple", http.StatusBadRequest)
			return
		}

		var qbw boundwitness.QueryBoundWitness
		if err := json.Unmarshal(tuple[0], &qbw); err != nil {
			t.Errorf("unmarshal qbw: %v", err)
			http.Error(w, "bad qbw", http.StatusBadRequest)
			return
		}

		// Cryptographically verify client's QueryBoundWitness signature!
		if errs := boundwitness.ValidateQueryBoundWitness(&qbw); len(errs) != 0 {
			t.Errorf("client QBW failed server-side validation: %v", errs)
			http.Error(w, "invalid signature", http.StatusBadRequest)
			return
		}

		var incomingPayloads []payload.AnyPayload
		if err := json.Unmarshal(tuple[1], &incomingPayloads); err != nil {
			t.Errorf("unmarshal payloads: %v", err)
			http.Error(w, "bad payloads", http.StatusBadRequest)
			return
		}
		if len(incomingPayloads) > 0 {
			receivedQuerySchema = incomingPayloads[len(incomingPayloads)-1].GetSchema()
		}

		// Echo back non-query payloads wrapped in a server-signed BoundWitness
		var respPayloads []any
		for _, p := range incomingPayloads[:len(incomingPayloads)-1] {
			respPayloads = append(respPayloads, p)
		}
		if len(respPayloads) == 0 {
			respPayloads = append(respPayloads, payload.NewIdPayload("server-resp"))
		}

		respBW, built, err := boundwitness.NewBuilder().
			Signer(serverAcct).
			Payloads(respPayloads...).
			Build()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		envelope := map[string]any{
			"data": []any{respBW, built, []any{}},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(envelope)
	}))
	defer srv.Close()

	node, err := client.NewNodeClient(srv.URL+"/Archivist", clientAcct, client.WithToken("secret-token"))
	if err != nil {
		t.Fatal(err)
	}
	arch := client.NewArchivistWrapper(node)

	ctx := context.Background()
	inserted, err := arch.Insert(ctx, payload.NewIdPayload("go-test-1"))
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if receivedAuth != "Bearer secret-token" {
		t.Errorf("auth header: got %q", receivedAuth)
	}
	if receivedQuerySchema != client.QuerySchemaArchivistInsert {
		t.Errorf("query schema: got %q", receivedQuerySchema)
	}
	if len(inserted) != 1 || inserted[0].GetSchema() != payload.SchemaId {
		t.Fatalf("unexpected inserted payloads: %+v", inserted)
	}

	got, err := arch.Get(ctx, []string{"ada56ff753c0c9b2ce5e1f823eda9ac53501db2843d8883d6cf6869c18ef7f65"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if receivedQuerySchema != client.QuerySchemaArchivistGet || len(got) != 1 {
		t.Fatalf("unexpected Get result: schema=%s len=%d", receivedQuerySchema, len(got))
	}

	limit := 10
	if _, err := arch.Next(ctx, &client.ArchivistNextOptions{Limit: &limit, Order: "desc"}); err != nil {
		t.Fatalf("Next: %v", err)
	}
	if receivedQuerySchema != client.QuerySchemaArchivistNext {
		t.Errorf("Next schema: got %q", receivedQuerySchema)
	}

	if _, err := arch.All(ctx); err != nil {
		t.Fatalf("All: %v", err)
	}
	if err := arch.Clear(ctx); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if _, err := arch.Snapshot(ctx); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if deleted, err := arch.Delete(ctx, []string{"ada56ff753c0c9b2ce5e1f823eda9ac53501db2843d8883d6cf6869c18ef7f65"}); err != nil || len(deleted) != 1 {
		t.Fatalf("Delete: deleted=%v err=%v", deleted, err)
	}
	if _, err := arch.Commit(ctx); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	insRes, err := arch.InsertQuery(ctx, payload.NewIdPayload("go-test-2"))
	if err != nil || insRes.BoundWitness == nil {
		t.Fatalf("InsertQuery: %v", err)
	}
	if dh, err := insRes.BWDataHash(); err != nil || len(dh) != 64 {
		t.Fatalf("BWDataHash: %q err=%v", dh, err)
	}

	// Verify APIConfig.EndpointURL and NewArchivistClient
	cfg := client.APIConfig{Domain: srv.URL + "/", Module: "/Archivist/"}
	if cfg.EndpointURL() != srv.URL+"/Archivist" {
		t.Fatalf("EndpointURL: got %q", cfg.EndpointURL())
	}
	if _, err := client.NewArchivistClient(cfg, clientAcct); err != nil {
		t.Fatalf("NewArchivistClient: %v", err)
	}
}

func TestMemoryArchivistPaginationDeleteAndClear(t *testing.T) {
	ctx := context.Background()
	mem, err := client.NewMemoryArchivist(nil)
	if err != nil {
		t.Fatal(err)
	}

	p0 := payload.NewIdPayload("0")
	p1 := payload.NewIdPayload("1")
	p2 := payload.NewIdPayload("2")
	p3 := payload.NewIdPayload("3")
	inserted, err := mem.Insert(ctx, p0, p1, p2, p3)
	if err != nil || len(inserted) != 4 {
		t.Fatalf("Insert: len=%d err=%v", len(inserted), err)
	}
	h0, _ := inserted[0].String("_hash")
	h1, _ := inserted[1].String("_hash")
	dh2, _ := inserted[2].String("_dataHash")

	// Open=true (default) starts strictly after cursor
	limit := 2
	pageOpen, err := mem.Next(ctx, &client.ArchivistNextOptions{Cursor: h0, Limit: &limit, Order: "asc"})
	if err != nil || len(pageOpen) != 2 {
		t.Fatalf("Next open=default: len=%d err=%v", len(pageOpen), err)
	}
	if s, _ := pageOpen[0].String("salt"); s != "1" {
		t.Fatalf("expected salt=1 after cursor h0, got %q", s)
	}

	// Open=false includes cursor
	closed := false
	pageClosed, err := mem.Next(ctx, &client.ArchivistNextOptions{Cursor: h1, Open: &closed, Limit: &limit, Order: "asc"})
	if err != nil || len(pageClosed) != 2 {
		t.Fatalf("Next open=false: len=%d err=%v", len(pageClosed), err)
	}
	if s, _ := pageClosed[0].String("salt"); s != "1" {
		t.Fatalf("expected salt=1 inclusive cursor h1, got %q", s)
	}

	// Order=desc with cursor
	pageDesc, err := mem.Next(ctx, &client.ArchivistNextOptions{Cursor: dh2, Order: "desc"})
	if err != nil || len(pageDesc) != 2 {
		t.Fatalf("Next desc: len=%d err=%v", len(pageDesc), err)
	}
	if s, _ := pageDesc[0].String("salt"); s != "1" {
		t.Fatalf("expected salt=1 after cursor p2 in desc order, got %q", s)
	}

	// Delete by dataHash and verify Get no longer finds it
	deleted, err := mem.Delete(ctx, []string{dh2})
	if err != nil || len(deleted) != 1 {
		t.Fatalf("Delete by dataHash: %v err=%v", deleted, err)
	}
	if got, _ := mem.Get(ctx, []string{dh2}); len(got) != 0 {
		t.Fatalf("expected deleted payload gone from byData index, got %d", len(got))
	}

	// Commit & Snapshot
	bws, err := mem.Commit(ctx)
	if err != nil || len(bws) != 1 || len(bws[0].PayloadHashes) != 3 {
		t.Fatalf("Commit: bws=%+v err=%v", bws, err)
	}

	// Clear
	if err := mem.Clear(ctx); err != nil {
		t.Fatal(err)
	}
	if all, _ := mem.All(ctx); len(all) != 0 {
		t.Fatalf("expected 0 items after Clear, got %d", len(all))
	}
}

func TestRemoteModuleResolverAndTypeChecks(t *testing.T) {
	serverAcct, _ := account.RandomAccount()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		desc := payload.NewAnyPayload(payload.SchemaModuleDescription, map[string]any{
			"address": serverAcct.Address(),
			"name":    "PrimaryArchivist",
			"queries": []string{client.QuerySchemaArchivistGet, client.QuerySchemaArchivistInsert},
		})
		bw, built, _ := boundwitness.NewBuilder().Signer(serverAcct).Payload(desc).Build()
		// Include an envelope-level warning/error alongside data to test error preservation
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data":   []any{bw, built, []any{}},
			"errors": []any{payload.NewModuleErrorPayload("Warn", "partial notice", "")},
		})
	}))
	defer srv.Close()

	node, err := client.NewNodeClient(srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	rem := client.NewRemoteModule(node, serverAcct.Address(), "PrimaryArchivist", []string{
		client.QuerySchemaArchivistGet,
		client.QuerySchemaArchivistInsert,
	})

	ctx := context.Background()
	desc, err := rem.Describe(ctx)
	if err != nil || desc.Name != "PrimaryArchivist" || desc.Address != serverAcct.Address() {
		t.Fatalf("Describe failed: desc=%+v err=%v", desc, err)
	}

	// Envelope error preserved alongside data
	res, err := rem.Query(ctx, payload.NewBasePayload(client.QuerySchemaModuleDescribe))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Errors) != 1 || res.Errors[0].Name != "Warn" {
		t.Fatalf("expected preserved envelope error, got %+v", res.Errors)
	}

	// StaticModuleResolver & ModuleTypeChecks
	resolver := client.NewStaticModuleResolver(rem)
	if resolver.ResolveByAddress("0x"+serverAcct.Address()) == nil {
		t.Fatal("ResolveByAddress failed")
	}
	if resolver.ResolveByName("PrimaryArchivist") == nil {
		t.Fatal("ResolveByName failed")
	}
	if len(resolver.ResolveByQuery(client.QuerySchemaArchivistGet)) != 1 {
		t.Fatal("ResolveByQuery failed")
	}
	if len(resolver.ResolveAll()) != 1 {
		t.Fatal("ResolveAll failed")
	}
	if !client.IsArchivist(rem) || client.IsDiviner(rem) || client.IsWitness(rem) || client.IsSentinel(rem) || client.IsBridge(rem) || client.IsNode(rem) {
		t.Fatal("ModuleTypeChecks mismatch")
	}
	if !payload.IsValidSchema(client.QuerySchemaModuleAddressPreviousHash) {
		t.Fatalf("QuerySchemaModuleAddressPreviousHash must be valid schema: %q", client.QuerySchemaModuleAddressPreviousHash)
	}
}

func TestXyoPanelWithWitnessesAndMemoryArchivist(t *testing.T) {
	acct, err := account.RandomAccount()
	if err != nil {
		t.Fatal(err)
	}
	memArch, err := client.NewMemoryArchivist(nil)
	if err != nil {
		t.Fatal(err)
	}

	basic := client.NewBasicWitness(nil, func(_ context.Context, _ ...any) ([]any, error) {
		return []any{payload.NewIdPayload("panel-basic")}, nil
	})
	eventWit := client.NewEventWitness(nil, func(_ context.Context) (string, error) {
		return "app_started", nil
	})
	tsWit := client.NewTimestampWitness(nil)

	panel, err := client.NewPanel(acct, []client.ArchivistInstance{memArch}, basic, eventWit, tsWit)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	res, err := panel.ReportQuery(ctx, payload.NewValuePayload(42))
	if err != nil {
		t.Fatalf("ReportQuery: %v", err)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("unexpected panel errors: %+v", res.Errors)
	}
	if len(res.Payloads) != 4 {
		t.Fatalf("expected 4 witnessed payloads, got %d", len(res.Payloads))
	}
	if errs := boundwitness.ValidateBoundWitness(res.BoundWitness); len(errs) != 0 {
		t.Fatalf("panel BoundWitness invalid: %v", errs)
	}

	stored, err := memArch.All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// 1 BoundWitness + 4 witnessed payloads = 5 stored items
	if len(stored) != 5 {
		t.Fatalf("expected 5 stored payloads in MemoryArchivist, got %d", len(stored))
	}

	// Verify Get by hash works on MemoryArchivist
	bwHash, _ := res.BoundWitness.Hash()
	fetched, err := memArch.Get(ctx, []string{bwHash})
	if err != nil || len(fetched) != 1 {
		t.Fatalf("MemoryArchivist.Get(bwHash) failed: len=%d err=%v", len(fetched), err)
	}

	// Nil witness / nil archivist must be safely ignored without panicking
	safePanel, err := client.NewPanel(nil, []client.ArchivistInstance{nil, memArch}, nil, basic)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := safePanel.Report(ctx)
	if err != nil || len(rep) != 1 {
		t.Fatalf("safePanel.Report failed: len=%d err=%v", len(rep), err)
	}
}
