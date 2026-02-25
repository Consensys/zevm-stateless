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

/// State witness in debug_executionWitness flat-pool format.
pub const StateWitness = struct {
    /// Pre-execution state root (from block header — the trust anchor).
    state_root: primitives.Hash,

    /// Flat pool of RLP-encoded trie node preimages.
    /// Nodes are referenced by keccak256(node_bytes) during proof traversal.
    nodes: []const []const u8,

    /// Contract bytecodes. keccak256(codes[i]) == account.code_hash.
    codes: []const []const u8,

    /// Accessed state keys for this block:
    ///   20 bytes = account address
    ///   52 bytes = account address (20) + storage slot (32)
    keys: []const []const u8,

    /// RLP-encoded ancestor block headers needed for the BLOCKHASH opcode.
    headers: []const []const u8,
};

/// Full input to the guest program.
pub const StatelessInput = struct {
    /// Decoded block number (from block header).
    block_number: u64,
    /// RLP-encoded transactions, in execution order.
    transactions: []const []const u8,
    /// State witness for Phase 1 (MPT verification) and Phase 2 (database).
    witness: StateWitness,
};
