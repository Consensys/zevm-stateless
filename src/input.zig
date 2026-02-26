//! StatelessInput: everything needed to execute a block without full state.
//!
//! The witness format mirrors debug_executionWitness (EL JSON-RPC):
//!   - nodes:   flat pool of RLP-encoded trie node preimages
//!   - codes:   flat array of contract bytecodes
//!   - keys:    20-byte account addresses or 52-byte address+storage_slot pairs
//!   - headers: RLP-encoded block headers (for BLOCKHASH opcode)
//!
//! Proof verification works by hash lookup in the pool: given the state_root,
//! the verifier walks the trie by finding each node via keccak256(node) == expected_hash.

const primitives = @import("primitives");

/// Ethereum block header (post-Cancun, up to and including Osaka/Prague).
///
/// Fields are listed in their canonical RLP order (indices 0–20).
/// Fields not required for stateless execution (bloom [6], extra_data [12],
/// nonce [14]) are omitted and skipped during decoding.
pub const Header = struct {
    parent_hash:              primitives.Hash,    // [0]
    ommers_hash:              primitives.Hash,    // [1]  always KECCAK_EMPTY_LIST in PoS
    coinbase:                 primitives.Address, // [2]
    state_root:               primitives.Hash,    // [3]  post-execution root
    transactions_root:        primitives.Hash,    // [4]
    receipts_root:            primitives.Hash,    // [5]
    // [6] bloom — 256 bytes; omitted (not needed for execution context)
    difficulty:               u256,               // [7]  always 0 for PoS
    number:                   u64,                // [8]
    gas_limit:                u64,                // [9]
    gas_used:                 u64,                // [10]
    timestamp:                u64,                // [11]
    // [12] extra_data — variable length; omitted
    prev_randao:              primitives.Hash,    // [13] mix_hash field
    // [14] nonce — always 0x0000000000000000 in PoS; omitted
    base_fee_per_gas:         u64,                // [15] EIP-1559 (London+)
    withdrawals_root:         primitives.Hash,    // [16] EIP-4895 (Shanghai+)
    blob_gas_used:            u64,                // [17] EIP-4844 (Cancun+)
    excess_blob_gas:          u64,                // [18] EIP-4844 (Cancun+)
    parent_beacon_block_root: primitives.Hash,    // [19] EIP-4788 (Cancun+)
    requests_hash:            primitives.Hash,    // [20] EIP-7685 (Osaka/Prague+)
};

/// State witness in debug_executionWitness flat-pool format.
pub const StateWitness = struct {
    /// Pre-execution state root (from the parent block header — the trust anchor).
    state_root: primitives.Hash,

    /// Flat pool of RLP-encoded trie node preimages.
    /// Nodes are referenced by keccak256(node_bytes) during proof traversal.
    nodes: []const []const u8,

    /// Contract bytecodes. keccak256(codes[i]) == account.code_hash.
    codes: []const []const u8,

    /// Accessed state keys for this block:
    ///   20 bytes = account address
    ///   52 bytes = account address (20) + storage slot (32)
    ///   32 bytes = standalone storage slot (context = nearest preceding address key)
    keys: []const []const u8,

    /// RLP-encoded ancestor block headers needed for the BLOCKHASH opcode.
    headers: []const []const u8,
};

/// Full input to the guest program.
pub const StatelessInput = struct {
    /// Decoded block header (from block.json).
    header: Header,
    /// RLP-encoded transactions in execution order (from the block body).
    /// Legacy transactions are stored as full RLP list bytes.
    /// Typed transactions (EIP-2930/1559/4844/7702) are stored as
    /// canonical wire format: type_byte || rlp_payload.
    transactions: []const []const u8,
    /// State witness for Phase 1 (MPT verification) and Phase 2 (database).
    witness: StateWitness,
};
