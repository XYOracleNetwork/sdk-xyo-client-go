[![logo][]](https://xyo.network)

# sdk-xyo-client-go

[![go-ci][]][go-ci-link]

> The XYO Foundation provides this source code available in our efforts to advance the understanding of the XYO Protocol and its possible uses. We continue to maintain this software in the interest of developer education. Usage of this source code is not intended for production.

## Table of Contents

- [sdk-xyo-client-go](#sdk-xyo-client-go)
  - [Description](#description)
  - [Packages](#packages)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
    - [Accounts, HD Wallets & Post-Quantum ML-DSA-65](#accounts-hd-wallets--post-quantum-ml-dsa-65)
    - [Payloads & BoundWitnesses](#payloads--boundwitnesses)
    - [NodeClient, ArchivistWrapper & XyoPanel](#nodeclient-archivistwrapper--xyopanel)
    - [XL1 Chain Protocol (Amounts, Transactions & JSON-RPC)](#xl1-chain-protocol-amounts-transactions--json-rpc)
  - [Cross-SDK Compatibility](#cross-sdk-compatibility)
  - [Maintainers](#maintainers)
  - [License](#license)
  - [Credits](#credits)

## Description

Primary pure-Go (zero-CGO) SDK for using **XYO Protocol 2.0** and the **XL1 Chain Protocol**, built as a sister repository to [`sdk-xyo-client-js`](https://github.com/XYOracleNetwork/sdk-xyo-client-js), [`sdk-xyo-client-android`](https://github.com/XYOracleNetwork/sdk-xyo-client-android), and [`sdk-xyo-client-swift`](https://github.com/XYOracleNetwork/sdk-xyo-client-swift).

## Packages

- `account` — Classical `secp256k1` accounts (RFC 6979 deterministic low-S 64-byte compact signatures, Keccak-256 20-byte addresses), BIP-39/BIP-32/BIP-44 `HDWallet`, Post-Quantum NIST FIPS 204 **ML-DSA-65** `QuantAccount` & BIP-85 `QuantHDWallet` (`qm65` Bech32m addresses), unified address-dispatched signature verification, and `PreviousHashStore` (memory & JSON file with compare-and-swap).
- `payload` — JS-conformant canonical JSON serialization (UTF-16 key order, recursive array sorting, depth-0 `_`/`$` meta exclusion, `null` preservation, no HTML escaping), SHA-256 `Hash` & `DataHash`, schema validation, concrete core payloads, `LocalSequence`/`QualifiedSequence`, and `Huri`.
- `boundwitness` — `BoundWitness`, `QueryBoundWitness`, fluent builders, multi-party `CosignBoundWitness`, structural + cryptographic validator (supporting both `secp256k1` and `ml-dsa-65`), and `BoundWitnessWrapper`.
- `client` — XYO Module interfaces & `StaticModuleResolver`, HTTP `NodeClient` (`[QueryBoundWitness, payloads]`), `ArchivistWrapper` (all 8 queries: `get`, `insert`, `delete`, `all`, `clear`, `next`, `commit`, `snapshot`), `MemoryArchivist`, Witnesses (`BasicWitness`, `EventWitness`, `TimestampWitness`), and `XyoPanel`.
- `protocol` — XL1 Chain Protocol: all 7 `big.Int`-backed denominations (`AttoXL1`..`XL1`), `XL1Amount` & `ShiftedBigInt` formatting, `BlockBoundWitness`, `TransactionBoundWitness`, `TransactionBuilder` (bare-hex normalized fees & auto `elevate|<hash>` scripts), elevatable payloads (`TimePayload`, `TransferPayload`, `ChainStakeIntentPayload`, `HashPayload`, `StepCompletePayload`), `BlockValidator` & `TransactionValidator`, JSON-RPC 2.0 `HTTPRPCTransport`, all XL1 Viewers/Runners, `XyoViewer` facade, and server-side `RPCEngine`.

## Installation

```sh
go get github.com/XYOracleNetwork/sdk-xyo-client-go
```

## Quick Start

### Accounts, HD Wallets & Post-Quantum ML-DSA-65

```go
package main

import (
	"fmt"

	"github.com/XYOracleNetwork/sdk-xyo-client-go/account"
)

func main() {
	// Classical secp256k1 HD wallet (default path: m/44'/60'/0'/0/0)
	wallet, _ := account.WalletFromMnemonic(
		"later puppy sound rebuild rebuild noise ozone amazing hope broccoli crystal grief",
		account.DefaultDerivationPath,
	)
	fmt.Println("Legacy address:", wallet.Address())

	// Post-Quantum ML-DSA-65 (FIPS 204) HD wallet via BIP-85 (qm65 Bech32m)
	qWallet, _ := account.QuantWalletFromMnemonic(
		"later puppy sound rebuild rebuild noise ozone amazing hope broccoli crystal grief",
		"",
	)
	fmt.Println("Quant address: ", qWallet.Address())
}
```

### Payloads & BoundWitnesses

```go
acct, _ := account.RandomAccount()

bw, payloads, err := boundwitness.NewBuilder().
	Signer(acct).
	Payload(payload.NewIdPayload("hello-xyo")).
	Build()
if err != nil {
	panic(err)
}
if errs := boundwitness.ValidateBoundWitness(bw); len(errs) != 0 {
	panic(errs[0])
}
_ = payloads
```

### NodeClient, ArchivistWrapper & XyoPanel

```go
ctx := context.Background()
acct, _ := account.RandomAccount()

archivist, _ := client.NewArchivistClient(client.APIConfig{
	Domain: "https://beta.api.archivist.xyo.network",
	Module: "Archivist",
}, acct)

basicWitness := client.NewBasicWitness(nil, func(ctx context.Context, _ ...any) ([]any, error) {
	return []any{payload.NewIdPayload("sensor-reading-1")}, nil
})

panel, _ := client.NewPanel(acct, []client.ArchivistInstance{archivist}, basicWitness)
result, err := panel.ReportQuery(ctx)
```

### XL1 Chain Protocol (Amounts, Transactions & JSON-RPC)

```go
ctx := context.Background()
viewer, _ := protocol.NewXyoViewerHTTP("https://rpc.xl1.xyo.network")

head, _ := viewer.CurrentBlock(ctx)
fmt.Println("Head block:", head.BoundWitness.Block)

sender, _ := account.RandomAccount()
tx, _ := protocol.NewTransactionBuilder().
	Chain(head.BoundWitness.Chain).
	Fees(protocol.DefaultTransactionFees()).
	Range(head.BoundWitness.BlockNumber(), head.BoundWitness.BlockNumber()+100).
	Payload(protocol.NewTransferPayload(sender.Address(), map[string]string{
		"5e7a847447e7fec41011ae7d32d768f86605ba03": protocol.AmountFromXL1(big.NewInt(1)).Atto().Hex(),
	}, nil)).
	Signer(sender).
	Build()

hashes, _ := viewer.SubmitTransactions(ctx, []protocol.HydratedTransaction{*tx})
fmt.Println("Submitted tx:", hashes)
```

## Cross-SDK Compatibility

Every package is verified bit-for-bit against the frozen cross-SDK JS compatibility contract in [`testdata/jsCompatVectors.json`](testdata/jsCompatVectors.json), XYO Yellow Paper §8 test vectors, and NIST FIPS 204 ACVP ML-DSA-65 vectors:

```sh
go test -race -v ./...
```

## Maintainers

- [Arie Trouw](https://arietrouw.com/)

## License

See the [LICENSE](LICENSE) file for license details (LGPL-3.0-only).

## Credits

[Made with 🔥 and ❄️ by XYO Foundation](https://xyo.network)

[go-ci]: https://github.com/XYOracleNetwork/sdk-xyo-client-go/actions/workflows/go.yml/badge.svg
[go-ci-link]: https://github.com/XYOracleNetwork/sdk-xyo-client-go/actions/workflows/go.yml
[logo]: https://cdn.xy.company/img/brand/XYO_full_colored.png
