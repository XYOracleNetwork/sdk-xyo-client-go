// Package xyoclient is the root module for the XYO Protocol 2.0 and XL1 Chain Protocol Go SDK.
//
// The SDK is organized into five cohesive, pure-Go (zero-CGO) subpackages:
//
//   - github.com/XYOracleNetwork/sdk-xyo-client-go/account
//     Classical secp256k1 Accounts (RFC 6979 low-S compact signatures, Keccak-256 addresses),
//     BIP-39/BIP-32/BIP-44 HDWallets, Post-Quantum ML-DSA-65 (FIPS 204) QuantAccounts &
//     BIP-85 QuantHDWallets with Bech32m qm65 addresses, and PreviousHashStore persistence.
//
//   - github.com/XYOracleNetwork/sdk-xyo-client-go/payload
//     JS-conformant canonical JSON serialization, SHA-256 root hash & dataHash computation,
//     schema validation, concrete core payloads, Local/Qualified Sequences, and HURI parsing.
//
//   - github.com/XYOracleNetwork/sdk-xyo-client-go/boundwitness
//     BoundWitness & QueryBoundWitness models, fluent builders, sequential multi-party
//     CosignBoundWitness, structural & cryptographic validation (secp256k1 + ML-DSA-65),
//     and BoundWitnessWrapper.
//
//   - github.com/XYOracleNetwork/sdk-xyo-client-go/client
//     XYO Module interfaces & resolver, HTTP NodeClient, ArchivistWrapper (all 8 queries) &
//     MemoryArchivist, Witnesses (BasicWitness, EventWitness, TimestampWitness), and XyoPanel.
//
//   - github.com/XYOracleNetwork/sdk-xyo-client-go/protocol
//     XL1 Chain Protocol: all 7 XL1 denominations (AttoXL1..XL1), XL1Amount & ShiftedBigInt
//     formatting, BlockBoundWitness & TransactionBoundWitness, TransactionBuilder, elevatable
//     payloads, validators, JSON-RPC 2.0 HTTPRPCTransport, all XL1 Viewers/Runners, XyoViewer
//     facade, and server-side RPCEngine.
package xyoclient
