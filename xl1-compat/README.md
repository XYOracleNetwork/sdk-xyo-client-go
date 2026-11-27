# xl1-compat

JS-side cross-SDK test vector generator. The authoritative XYO JS SDKs
(`@xyo-network/*`) and the XL1 protocol model are the source of truth for
protocol behavior; this script samples their output and freezes it into
`../testdata/jsCompatVectors.json`, which the Go test suites assert against.

This is a faithful port of `sdk-xyo-client-swift/xl1-compat/generate-vectors.mjs`
and `sdk-xyo-client-android/xl1-compat/generate-vectors.mjs`, keeping the frozen
contract byte-for-byte aligned across JS, Android (Kotlin), Swift, and Go.

## Regenerating the vectors

```bash
cd xl1-compat
npm install
npm run generate
```

This writes `../testdata/jsCompatVectors.json`.

## Verifying Go against the frozen vectors

```bash
go test -race -v ./...
```

## Sections

- `accounts` — 5 fixed private keys → uncompressed public key, 20-byte address,
  and 3 RFC 6979 deterministic signatures each (15 signatures total).
- `hd_wallets` — 14 BIP-44 Ethereum-style derivations across 2 BIP-39 mnemonics.
- `payload_hashes` — 26 raw payload JSON cases → `data_hash` (`$` and `_` meta
  stripped at depth 0) and `hash` (only `_` stripped at depth 0).
- `bound_witnesses` — 3 full BoundWitness round-trip cases: fields, `data_hash`,
  `signatures`, and `root_hash`.
- `xl1_amounts` — 13 XL1 denomination conversion vectors (`atto` through `xl1`).
