package client

import (
	"context"
	"fmt"
	"sync"

	"github.com/XYOracleNetwork/sdk-xyo-client-go/account"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/boundwitness"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/payload"
)

// XyoPanel composes an Account, zero or more Witnesses, and one or more Archivists
// to observe payloads, sign a BoundWitness, and report them (matching Swift/Android XyoPanel).
type XyoPanel struct {
	account    account.Account
	archivists []ArchivistInstance
	witnesses  []WitnessInstance
}

// NewPanel creates an XyoPanel. If acct is nil, a fresh random secp256k1 account is created.
func NewPanel(acct account.Account, archivists []ArchivistInstance, witnesses ...WitnessInstance) (*XyoPanel, error) {
	if acct == nil {
		var err error
		acct, err = account.RandomAccount()
		if err != nil {
			return nil, fmt.Errorf("create random panel account: %w", err)
		}
	}
	return &XyoPanel{
		account:    acct,
		archivists: append([]ArchivistInstance(nil), archivists...),
		witnesses:  append([]WitnessInstance(nil), witnesses...),
	}, nil
}

// Account returns the panel's signing Account.
func (p *XyoPanel) Account() account.Account {
	return p.account
}

// Report observes all witnesses, builds and signs a BoundWitness, submits to all configured archivists,
// and returns the witnessed payloads.
func (p *XyoPanel) Report(ctx context.Context, adhocPayloads ...any) ([]payload.AnyPayload, error) {
	res, err := p.ReportQuery(ctx, adhocPayloads...)
	if err != nil {
		return nil, err
	}
	return res.Payloads, nil
}

// ReportQuery observes all witnesses concurrently, constructs and signs a BoundWitness with the panel's
// account, inserts [bw, payloads...] into all configured archivists concurrently, and returns the full
// ModuleQueryResult (including any archivist errors collected as ModuleErrorPayloads).
func (p *XyoPanel) ReportQuery(ctx context.Context, adhocPayloads ...any) (*ModuleQueryResult, error) {
	observedSlices := make([][]any, len(p.witnesses))
	witnessErrs := make([]error, len(p.witnesses))

	var wg sync.WaitGroup
	for i, w := range p.witnesses {
		wg.Add(1)
		go func(idx int, wit WitnessInstance) {
			defer wg.Done()
			observedSlices[idx], witnessErrs[idx] = wit.Observe(ctx)
		}(i, w)
	}
	wg.Wait()

	var allPayloads []any
	var modErrors []payload.ModuleErrorPayload
	for i, err := range witnessErrs {
		if err != nil {
			modErrors = append(modErrors, payload.NewModuleErrorPayload("WitnessError", err.Error(), ""))
			continue
		}
		allPayloads = append(allPayloads, observedSlices[i]...)
	}
	allPayloads = append(allPayloads, adhocPayloads...)

	bw, builtPayloads, err := boundwitness.NewBuilder().
		Signer(p.account).
		Payloads(allPayloads...).
		Build()
	if err != nil {
		return nil, fmt.Errorf("panel build bound witness: %w", err)
	}

	// Insert [bw] + payloads into every configured archivist concurrently
	insertItems := make([]any, 0, len(builtPayloads)+1)
	insertItems = append(insertItems, bw)
	insertItems = append(insertItems, builtPayloads...)

	archErrs := make([]error, len(p.archivists))
	var awg sync.WaitGroup
	for i, arch := range p.archivists {
		awg.Add(1)
		go func(idx int, a ArchivistInstance) {
			defer awg.Done()
			_, archErrs[idx] = a.Insert(ctx, insertItems...)
		}(i, arch)
	}
	awg.Wait()

	for _, err := range archErrs {
		if err != nil {
			modErrors = append(modErrors, payload.NewModuleErrorPayload("ArchivistInsertError", err.Error(), ""))
		}
	}

	anyPayloads := make([]payload.AnyPayload, 0, len(builtPayloads))
	for _, item := range builtPayloads {
		ap, err := payload.ToAnyPayload(item)
		if err != nil {
			return nil, err
		}
		anyPayloads = append(anyPayloads, ap)
	}

	return &ModuleQueryResult{
		BoundWitness: bw,
		Payloads:     anyPayloads,
		Errors:       modErrors,
	}, nil
}
