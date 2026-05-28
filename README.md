# ZK Header Verifier

WASM contract for Magi that verifies SP1 Groth16 proofs of Ethereum consensus and stores ZK-verified block headers. Permissionless proof submission with hash chain verification. Read by the EVM bridge via `contracts.read()` for trustless deposit/withdrawal verification.

## How it works

1. A prover generates an SP1-Helios Groth16 proof that an Ethereum block is finalized
2. The prover submits the proof + RLP-encoded block headers to this contract
3. The contract verifies the proof via the `crypto.sp1_verify_groth16` host function
4. The contract verifies the hash chain: `keccak256(RLP(header))` must match the ZK-proven block hash
5. Verified headers are stored in the same format as the EVM mapping contract's blocklist
6. The EVM bridge reads verified headers via `contracts.read(verifierContractId, key)`

## Actions

| Action | Caller | Description |
|--------|--------|-------------|
| `init` | Owner | Set Groth16 VK, VK root, and SP1 program vkey hash |
| `updateVkey` | Owner | Update verification parameters (for SP1 version upgrades) |
| `submitProof` | Anyone | Submit ZK proof + headers. Proof must be valid. Max 12 headers per tx. |

## State keys

| Key | Value | Compatible with |
|-----|-------|-----------------|
| `h` | Last verified block height | evm-mapping-contract `GetLastHeight()` |
| `b-{N}` | 128-byte binary block header | evm-mapping-contract `GetHeader(N)` |
| `vk` | Groth16 VK hex | — |
| `vr` | VK root hex | — |
| `sp1vk` | SP1 program vkey hash hex | — |

## Security

- Proof verification via BN254 pairing check (gnark-crypto on the Go host)
- Hash chain verification: every header's `keccak256(RLP)` verified against proven block hash
- Parent hash chain: each header's parentHash must equal `keccak256(RLP)` of the previous header
- Sequential block numbers enforced
- Max 12 headers per transaction (16KB tx size limit)
- Old headers pruned automatically (10,000 block retention)

## Prerequisites

Requires the `crypto.sp1_verify_groth16` host function in go-vsc-node. See [go-vsc-node feature/zk-eth-oracle branch](https://github.com/vsc-eco/go-vsc-node). All validator nodes must update before this contract is deployed.

## Build

```bash
make            # builds bin/main.wasm via tinygo in Docker; skips if up to date
make clean      # remove bin/*.wasm
make test       # run Go tests on the host toolchain
```

Output: `bin/main.wasm` (~192 KB).

By default the build runs inside the `tinygo/tinygo:0.39.0` Docker image. To use a host tinygo install instead: `USE_DOCKER=0 make`.

## Init parameters

After deployment, call `init` with:

```json
{
  "groth16_vk": "<hex: 492-byte Groth16 verification key for the SP1 version>",
  "vk_root": "<hex: 32-byte SP1 recursion VK root>",
  "sp1_vkey_hash": "<hex: 32-byte SP1 program verification key hash>",
  "max_retention": 50400,
  "initial_height": 12345678,
  "initial_block_hash": "0x<64-hex: finalized L1 block hash at initial_height>",
  "expected_chain_id": 1,
  "is_testnet": false
}
```

These values come from the SP1-Helios fork's build output and the SP1 verifier artifacts.

Required / important fields (init fails closed if missing):

- `initial_height` + `initial_block_hash` — CRIT #25 anchor. The first
  `submitProof` batch must produce a header whose `ParentHash` equals
  `initial_block_hash`. Pick a recent finalized L1 block and its hash from a
  trusted source. Both REQUIRED (init aborts if absent/zero).
- `expected_chain_id` — CRIT #6 Site 6 chain binding. The L1 chainId this
  verifier is bound to (`1` mainnet, `11155111` Sepolia). REQUIRED, non-zero;
  `submitProof` reverts any proof whose committed chainId differs. Immutable
  after init (no setter).
- `max_retention` — optional; defaults to `DefaultMaxRetention` when `0`.
- `is_testnet` — set `true` ONLY on testnet so `clearTestnetState` is
  permitted; leave `false`/unset on mainnet (the sentinel gates that handler).
