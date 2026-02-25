//! BlockExecutor: stateless EVM block execution using zevm.
//!
//! Steps:
//!   1. Verify the state witness (MPT proofs).
//!   2. Build a WitnessDatabase from the proven state.
//!   3. Execute each transaction in order through zevm.
//!   4. Compute the post-state root and receipts root.
//!   5. Return a ProofOutput for the guest to commit.

const input = @import("input");
const output = @import("output");
const db = @import("db");
const mpt = @import("mpt");

pub fn executeBlock(stateless_input: input.StatelessInput) !output.ProofOutput {
    // 1. Verify witness proofs and obtain the pre-state root
    const pre_state_root = try mpt.verifyWitness(stateless_input.witness);

    // 2. Build the stateless database
    const witness_db = db.WitnessDatabase.init(stateless_input.witness);
    _ = witness_db;

    // TODO: decode block header, set up zevm context, execute txs, compute roots

    return output.ProofOutput{
        .pre_state_root = pre_state_root,
        .post_state_root = pre_state_root, // placeholder
        .receipts_root = pre_state_root,   // placeholder
        .receipts = &.{},
    };
}
