# zevm-stateless

Stateless EVM block verifier in Zig. Verifies MPT proofs and executes blocks against a witness, with no access to the full state database.

## Dependencies

- [Zig](https://ziglang.org/) 0.15.1
- [zevm](https://github.com/Consensys/zevm) v0.3.1 (fetched automatically)
- `curl` and `jq`

## Quick start

## Synthetic example

```bash
zig build gen-example   # generate examples/block.json + witness.json
zig build run           # run against them
zig build test          # run all tests
```

## Test vectors

```bash
zig build run-test-block
```

Runs against `test/vectors/test_block.json` + `test/vectors/test_block_witness.json`
(block #1, 100 transactions, 81 nodes, 106 accounts, 11 storage slots, 5 contracts).

## Live node
```bash
zig build
./run_proof.sh http://127.0.0.1:64393 1 # (endpoint, block number)
```
`run_proof.sh` calls `debug_getRawBlock` and `debug_executionWitness` on the node, then runs the verifier.

## Output:

```
=== zevm-stateless: block #1 ===

Phase 1  MPT proof verification
  [   0] account  0x6177843db3138ae69679a54b95cf345ed759450d
        key_hash  0xaba0e686...
        branch    0x79f54cce...  nibble=a    ← follows keccak256(address) nibble by nibble
        branch    0x18e0f191...  nibble=b
        → (absent)                           ← valid non-inclusion: address has no state

  [  10] account  0xf93ee4cf8c6c40b329b0c0626f28333c132cf241
        key_hash  0x7874d298...
        branch    0x79f54cce...  nibble=7
        ...
        leaf      0x203dfb96...
        → nonce=0  balance=1000000000000000000000000000  type=EOA

  [  40] storage  0x000f3df6d732807ef1319fb7b8bb8522d0beac02  slot=0x0000...1a8c
        storage_root  0xaf941126...
        key_hash      0xabdc3a3c...  ← keccak256(slot)
        branch    0xaf941126...  nibble=a
        ...
        leaf      0x1a45d179...
        → value=0x67e0db6c

  OK     root = 0x79f54cce9fd251fcc39c727b5db2d0fa94f7b76782be5cdf8336bd5cae24e609
         81 node(s) in pool, 117 key(s) verified

Phase 2  Block execution
  block env
    number      = 1
    coinbase    = 0x8943545177806ed17b9f23f0a21ee5948ecaa776
    timestamp   = 1772083527
    gas_limit   = 60000000
    basefee     = 875000000
    prevrandao  = 0x19f9fe9e...
    excess_blob_gas = 0  blob_gasprice = 1
  transactions  = 100
  pre_state_root  = 0x79f54cce9fd251fcc39c727b5db2d0fa94f7b76782be5cdf8336bd5cae24e609
  post_state_root = 0x1a2b3c4d...  ✓
  receipts_root   = 0xe4b52b3a...  ✓

OK
```

## Pipeline

- **Step 1** — MPT proof verification: every accessed account and storage slot is verified against the pre-state root using the flat node pool from `debug_executionWitness`.
- **Step 2** — WitnessDatabase: account and bytecode reads are served from the proven witness.
- **Step 3** — Block execution via zevm: transactions are executed against the witness state, and the resulting `post_state_root` and `receipts_root` are verified against the block header.

```bash
./run_proof.sh <RPC_URL> <BLOCK_NUMBER>

# Examples
./run_proof.sh https://mainnet.infura.io/v3/<key> 21000000
./run_proof.sh http://localhost:8545 latest
./run_proof.sh http://localhost:8545 0x140b490   # hex block number also works
```

The script:
1. Calls `debug_getRawBlock` to get the full RLP-encoded block.
2. Calls `debug_generateWitness` (falls back to `debug_executionWitness`).
3. Writes temporary `block.json` and `witness.json` files.
4. Runs `zig-out/bin/zevm_stateless` on them (builds if not already built).

> **Note:** `debug_getRawBlock`, `debug_generateWitness` / `debug_executionWitness` are non-standard Geth debug methods. Most public RPC endpoints do not expose them.

## Witness format

**`block.json`**
```json
{
  "block": "0x<hex RLP>"
}
```

The `block` field is the full RLP-encoded Ethereum block as returned by `debug_getRawBlock`.
The verifier decodes this RLP to extract the block number (header field 8). The state root
used as the proof anchor is **not** taken from here — it is the *pre-execution* (parent
block) state root found in `witness.json`'s `headers` field.

**`witness.json`**:
```json
{
  "state":   ["0x<hex RLP node>", ...],
  "codes":   ["0x<hex bytecode>", ...],
  "keys":    ["0x<20-byte address or 52-byte address+slot>", ...],
  "headers": ["0x<hex RLP block header>", ...]
}
```

See [`WITNESS.md`](WITNESS.md) for a detailed description of all four fields,
their trust relationships, and the pre-state vs post-state root distinction.

`state` is a flat pool of RLP-encoded trie node preimages. The verifier locates each node by scanning the pool for an entry whose `keccak256` matches the expected hash — no pre-assembled ordered proof paths are needed.

`keys` uses length to distinguish key types:
- 20 bytes → account address
- 52 bytes → account address (20) + storage slot (32)

## How proof verification works

Starting from the pre-state root (the `stateRoot` of the parent block, found in `witness.headers`):

1. **`verifyProof(root, key_hash, pool)`** — traverses the trie by repeatedly calling `findNode(pool, expected_hash)`. At each step it decodes the found node and follows the correct branch/leaf path based on the nibbles of `key_hash`. Inline nodes (< 32 bytes, embedded directly in a parent) bypass the pool lookup. Returns the leaf value bytes on inclusion, `null` on valid non-inclusion.

2. **`verifyAccount`** — hashes the address, calls `verifyProof`, RLP-decodes the result into `AccountState { nonce, balance, storage_root, code_hash }`.

3. **`verifyStorage`** — hashes the slot, calls `verifyProof` against the account's `storage_root`.

4. **`verifyWitness`** — iterates all keys, calls `verifyAccount` and `verifyStorage` as appropriate, returns the proven state root.

All functions are allocation-free; stack buffers are used throughout.

## Architecture notes

- **Flat pool lookup** is O(n) per step over ~200 nodes in a typical block witness — acceptable in a zkVM context with bounded state.
- **`EMPTY_TRIE_HASH` short-circuit**: if the storage root is the well-known empty trie hash, `verifyProof` returns `null` immediately without requiring any pool nodes.
- **`WitnessDatabase`** uses the same flat pool for both account trie and all storage trie traversals — both are included in `witness.nodes`.
- **No allocations in the verifier**: RLP decoder, nibble decoder, and node decoder all operate as zero-copy views into the original proof bytes.

## Conformance

Tested against [ethereum/execution-spec-tests](https://github.com/ethereum/execution-spec-tests) v5.4.0.

### Blockchain tests

```
Results: 59253 / 60168 passed  (100% of non-skipped)
Failed:  0
Skipped: 915  (4 files exceed 64 MB read limit; remainder are unsupported fork variants)
```

### State tests (t8n-based)

```
Results: 59253 / 59253 passed  (100%)
```

> Run with `make spec-tests` (both suites) or `make blockchain-tests` / `make state-tests` individually.

## t8n — State Transition Tool

The `t8n` binary implements the [geth `evm t8n`](https://github.com/ethereum/go-ethereum/tree/master/cmd/evm) interface, used by [ethereum/execution-spec-tests](https://github.com/ethereum/execution-spec-tests) to verify EVM implementations.

### Build

```bash
zig build
# produces zig-out/bin/t8n
```

### Usage

```
t8n --input.alloc <alloc.json>  --input.env <env.json>  --input.txs <txs.json> \
    --state.fork <ForkName>                                                      \
    [--output.alloc <out.json>] [--output.result <out.json>]                    \
    [--output.basedir <dir>]
```

| Flag | Description |
|------|-------------|
| `--input.alloc` | Pre-state accounts (address → {balance, nonce, code, storage}) |
| `--input.env` | Block environment (number, timestamp, gasLimit, baseFee, …) |
| `--input.txs` | Transactions to execute (RLP hex or JSON array) |
| `--state.fork` | Fork name: `Frontier` … `Prague` |
| `--output.alloc` | Write post-state to this path (or `stdout`) |
| `--output.result` | Write result (stateRoot, txRoot, receipts, …) to this path (or `stdout`) |
| `--output.basedir` | Directory prefix for output paths |
| `--state.chainid` | Chain ID (default: `1`) |
| `--state.reward` | Mining reward in wei, `-1` to disable (default: `-1`) |

### Supported forks

`Frontier`, `Homestead`, `EIP150`, `EIP158`, `Byzantium`, `Constantinople`, `Istanbul`, `Berlin`, `London`, `Paris`, `Shanghai`, `Cancun`, `Prague`

### Example: ETH transfer

```bash
zig-out/bin/t8n \
  --input.alloc  test/vectors/t8n/transfer_test/alloc.json \
  --input.env    test/vectors/t8n/transfer_test/env.json \
  --input.txs    test/vectors/t8n/transfer_test/txs.json \
  --state.fork   Cancun \
  --output.alloc stdout \
  --output.result stdout
```

Expected `stateRoot`: `0x392fec13c46687c9795fe81317a91e1d70278b5114c5ca66e0d0245994d4f3de`

### Example: TSTORE/SSTORE contract call

```bash
zig-out/bin/t8n \
  --input.alloc  test/vectors/t8n/tstore_test/alloc.json \
  --input.env    test/vectors/t8n/tstore_test/env.json \
  --input.txs    test/vectors/t8n/tstore_test/txs.json \
  --state.fork   Cancun \
  --output.alloc stdout \
  --output.result stdout
```

Expected `stateRoot`: `0xb9e100253042b00aa966b722f6017f627076e5edf25cb781106a7232ac026ef7`
See [`WITNESS.md`](WITNESS.md) for the witness format.
