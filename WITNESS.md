# Witness format

The execution witness (`witness.json`) contains everything needed to execute a
block and verify state transitions without access to the full Ethereum state
database. It is produced by `debug_generateWitness` / `debug_executionWitness`
on a Geth-compatible node.

```json
{
  "state":   ["0x<rlp node>", ...],
  "codes":   ["0x<bytecode>", ...],
  "keys":    ["0x<address or address+slot>", ...],
  "headers": ["0x<rlp header>", ...]
}
```

---

## The four fields

### `state` — MPT node pool

A flat array of RLP-encoded Merkle Patricia Trie node preimages. Both the
global state trie and every per-account storage trie draw nodes from this single
shared pool.

Nodes are addressed by their hash: to find a node the verifier computes
`keccak256` over every entry until one matches the expected hash. No ordered
proof paths are pre-assembled; the pool is unordered.

The pool covers all trie paths touched during block execution:
- branch nodes, extension nodes, and leaf nodes along every accessed account path
- branch nodes, extension nodes, and leaf nodes along every accessed storage path

In `test/vectors/stateless/test_block_witness.json` the pool contains **207 nodes** for
block #51632.

### `codes` — contract bytecodes

A flat array of raw EVM bytecodes for every contract whose code is read during
execution. Each entry is linked to an account via `code_hash`:

```
keccak256(codes[i])  ==  account.code_hash
```

`WitnessDatabase.codeByHash` finds the matching code by scanning this array and
comparing the hash. EOAs (whose `code_hash` is `KECCAK_EMPTY`) do not require
an entry and are handled without scanning.

In the test block there are **13 contract bytecodes**, ranging from 97 bytes
(the EIP-4788 beacon roots contract) to 24 390 bytes.

### `keys` — accessed state keys

An ordered list of the state entries accessed during block execution. Keys tell
the verifier *what* to verify; the actual proofs are the nodes in `state`.

Key length determines the type:

| Length | Interpretation | Verification |
|--------|----------------|--------------|
| 20 bytes | account address | `verifyAccount(state_root, keccak256(address), state)` |
| 52 bytes | address (20) + storage slot (32) | account first → `storage_root` → `verifyStorage(storage_root, keccak256(slot), state)` |
| 32 bytes | standalone storage slot | belongs to the nearest preceding account address (20-byte key) in the array |

For 32-byte keys the account context is implicit: the verifier tracks the most
recently seen address key and uses it as the account for the slot lookup. This
matches how `debug_generateWitness` groups slots immediately after the contract
address that owns them.

For the 52-byte storage keys the account proof is run first to obtain the
account's `storage_root`, which becomes the root for the subsequent storage
trie traversal.

In the test block there are **51 keys**: 38 account addresses, 13 storage
slot entries.

### `headers` — ancestor block headers

An array of bare RLP-encoded block headers for recent ancestor blocks. This
field serves two distinct roles:

**1. Pre-state root anchor (critical)**

The block being executed contains a `stateRoot` in its own header (field 3) that
represents the *post-execution* state — the trie after all transactions have
run. The witness, however, proves the *pre-execution* state: the trie as it
stood before this block ran.

The pre-state root is the `stateRoot` of the *parent* block (number
`block_number - 1`), which lives in the `headers` array. The verifier scans
`headers` for the entry with `number == block_number - 1` and reads its
`stateRoot` as the proof anchor.

Using the wrong root (the current block's post-state root) causes every single
MPT proof to fail because none of the pool nodes hash to it.

**2. BLOCKHASH opcode support (future)**

The EVM `BLOCKHASH` instruction can query hashes of the 256 most recent blocks.
The `headers` array supplies the ancestor headers needed to serve these requests
during execution, without touching external state.

In the test block there are **2 headers**: blocks #51631 (parent) and #51630.

---

## How the fields relate

```
block.json
 └── block header
      ├── stateRoot  (POST-execution — not used as proof anchor)
      └── number     (used to locate the parent in headers)

witness.json
 ├── headers
 │    └── header[number == block_number - 1]
 │         └── stateRoot  ← PRE-execution root: trust anchor for all proofs
 │
 ├── state  (node pool — authenticated by the pre-state root)
 │    ├── state trie nodes  → account: nonce, balance, storage_root, code_hash
 │    └── storage trie nodes → slot values
 │         (state trie and all storage tries share the same pool)
 │
 ├── codes  (authenticated indirectly via code_hash in the proven account)
 │    └── codes[i] where keccak256(codes[i]) == account.code_hash
 │
 └── keys   (the index of what to verify — entries are proven via state)
      ├── 20-byte key  → verifyAccount(pre_state_root, keccak256(addr), state)
      └── 52-byte key  → verifyAccount(...) → storage_root
                          → verifyStorage(storage_root, keccak256(slot), state)
```

### Trust chain summary

- `headers` is trusted because the parent header hash equals the current block's
  `parentHash` (verifiable once block-hash verification is implemented).
- `state` is trusted because every node is authenticated by `keccak256` against
  a hash already proven to be reachable from the pre-state root.
- `codes` is trusted because `code_hash` in the proven account binds each
  bytecode to a specific hash.
- `keys` is a hint, not a trust boundary: omitting a key means the corresponding
  account or slot is simply not checked; it does not affect the soundness of
  checks that are performed.

---

## Key lookup in practice

For each key the verifier walks the trie from the pre-state root:

```
pre_state_root
    │
    ▼  findNode(pool, pre_state_root)  → branch / extension node
    │
    ▼  follow nibble path of keccak256(address)
    │
    ▼  leaf node → RLP-decode → AccountState { nonce, balance, storage_root, code_hash }
                                                                │
                                             ┌──────────────────┘
                                             ▼
                                    findNode(pool, storage_root)
                                             │
                                             ▼  follow nibble path of keccak256(slot)
                                             │
                                             ▼  leaf → u256 slot value
```

All trie nodes — both state and storage — are resolved from the same flat
`state` pool by hash.
