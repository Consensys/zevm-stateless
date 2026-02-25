//! Merkle Patricia Trie: proof verification for stateless execution.
//!
//! Verifies that account and storage values are consistent with the
//! pre-state root declared in the witness before execution begins.

const primitives = @import("primitives");
const input = @import("../input.zig");

pub const MptError = error{
    InvalidProof,
    RootMismatch,
    UnexpectedNode,
};

/// Verify an account witness against a known state root.
pub fn verifyAccount(
    root: primitives.Hash,
    witness: input.AccountWitness,
) MptError!void {
    _ = root;
    _ = witness;
    @panic("verifyAccount: not yet implemented");
}

/// Verify a storage witness against a known storage root.
pub fn verifyStorage(
    root: primitives.Hash,
    witness: input.StorageWitness,
) MptError!void {
    _ = root;
    _ = witness;
    @panic("verifyStorage: not yet implemented");
}

/// Verify all proofs in the witness, returning the proven pre-state root.
pub fn verifyWitness(witness: input.StateWitness) MptError!primitives.Hash {
    for (witness.accounts) |acc| try verifyAccount(witness.state_root, acc);
    for (witness.storage) |slot| try verifyStorage(witness.state_root, slot);
    return witness.state_root;
}
