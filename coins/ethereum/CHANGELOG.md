
# Change Log

All notable changes to this project will be documented in this file.

# [0.0.9](https://github.com/okx/go-wallet-sdk) (2026-05-21)

### Security

- **ethereum-sdk:** harden EIP-712 typed-data hashing against spec divergence — validate inner length of multi-dim fixed arrays at every nesting level, restrict reference-type detection to ASCII uppercase, normalize bare `int`/`uint` to `int256`/`uint256` during `EncodeType`, and range-check signed integers against `[-(2^(N-1)), 2^(N-1)-1]`. Cross-checked against ethers.js v6 typed-data vectors.

### New features

- **ethereum-sdk:** new `coins/ethereum/apitypes/` subpackage carrying the EIP-712 typed-data model and encoder (derived from upstream `github.com/ethereum/go-ethereum/signer/core/apitypes` with the hardening fixes above; uses upstream `go-ethereum` primitive types).
- **ethereum-sdk:** add ethers.js v6 compatibility test vectors (`eip712_test.go` and new cases in `eth_test.go`).

# [0.0.4](https://github.com/okx/go-wallet-sdk) (2025-02-14)

### New features

- **ethereum-sdk:** update functionalities including eip712 and dynamic fee tx ([80](https://github.com/okx/go-wallet-sdk/pull/80))
- 
# [0.0.3](https://github.com/okx/go-wallet-sdk) (2024-06-11)

### updates

- **ethereum-sdk:** support   signing message and verifying signed message. ([50](https://github.com/okx/go-wallet-sdk/pull/50))

# [0.0.2](https://github.com/okx/go-wallet-sdk) (2023-11-20)

### updates

- **ethereum-sdk:** change some files name and remove some unused libs ([21](https://github.com/okx/go-wallet-sdk/pull/21))

