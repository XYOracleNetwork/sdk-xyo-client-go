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
}
