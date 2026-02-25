//! StatelessInput: everything needed to execute a block without full state.
//!
//! The prover supplies this to the guest. It contains the block header,
//! transactions, and a state witness (MPT proofs for all accounts and
//! storage slots touched during execution).

const primitives = @import("primitives");

/// A single account witness: the RLP-encoded node path proving the account
/// exists (or doesn't) in the state trie at the given address.
pub const AccountWitness = struct {
    address: primitives.Address,
    /// RLP-encoded MPT proof nodes, from root to leaf.
    proof: []const []const u8,
    /// Raw contract bytecode.  Empty slice for EOAs.
    /// Must satisfy keccak256(code) == account.code_hash when non-empty.
    code: []const u8 = &.{},
};

/// A storage slot witness: proves the value of a single storage slot.
pub const StorageWitness = struct {
    address: primitives.Address,
    slot: primitives.Hash,
    proof: []const []const u8,
};

/// The state witness bundled with a block.
pub const StateWitness = struct {
    /// Pre-state root that the witness proves against.
    state_root: primitives.Hash,
    accounts: []const AccountWitness,
    storage: []const StorageWitness,
};

/// Full input to the guest program.
pub const StatelessInput = struct {
    /// RLP-encoded block header.
    header: []const u8,
    /// RLP-encoded transactions, in order.
    transactions: []const []const u8,
    witness: StateWitness,
};
