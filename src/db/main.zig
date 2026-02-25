//! WitnessDatabase: a zevm database backend backed by a state witness.
//!
//! Instead of querying a live node, account and storage reads are served
//! from the MPT proofs supplied in the StatelessInput. Any access to a key
//! not covered by the witness is a fatal error (the prover must include it).

const input = @import("../input.zig");

/// Stateless database built from a StateWitness.
pub const WitnessDatabase = struct {
    witness: input.StateWitness,

    pub fn init(witness: input.StateWitness) WitnessDatabase {
        return .{ .witness = witness };
    }

    // TODO: implement zevm Database interface methods:
    //   basicAccount, codeByHash, storageSlot, blockHash
};
