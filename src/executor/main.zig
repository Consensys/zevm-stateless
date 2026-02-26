//! BlockExecutor: stateless EVM block execution using zevm.
//!
//! Steps:
//!   1. Verify the state witness (MPT proofs).
//!   2. Build a WitnessDatabase from the proven state.
//!   3. Build the zevm BlockEnv from the Osaka block header.
//!   4. Execute each transaction in order through zevm.       [TODO Phase 3 step 2]
//!   5. Compute the post-state root and receipts root.        [TODO Phase 3 step 3]
//!   6. Return a ProofOutput for the guest to commit.

const primitives = @import("primitives");
const context    = @import("context");
const input      = @import("input");
const output     = @import("output");
const db         = @import("db");
const mpt        = @import("mpt");

pub fn executeBlock(stateless_input: input.StatelessInput) !output.ProofOutput {
    // 1. Verify witness proofs and obtain the pre-state root.
    const pre_state_root = try mpt.verifyWitness(stateless_input.witness);

    // 2. Build the stateless database.
    const witness_db = db.WitnessDatabase.init(stateless_input.witness);
    _ = witness_db;

    // 3. Build the zevm BlockEnv from the decoded Osaka header.
    const block_env = blockEnvFromHeader(stateless_input.header);
    _ = block_env;

    // TODO Phase 3 step 2: decode and execute each transaction in
    //   stateless_input.transactions through zevm using witness_db.

    // TODO Phase 3 step 3: compute post-state root and receipts root.

    return output.ProofOutput{
        .pre_state_root  = pre_state_root,
        .post_state_root = pre_state_root, // placeholder
        .receipts_root   = pre_state_root, // placeholder
        .receipts        = &.{},
    };
}

/// Convert an Header into the zevm BlockEnv required for EVM execution.
///
/// Field mapping (Osaka spec → zevm BlockEnv):
///   header.number           → block_env.number        (U256)
///   header.coinbase         → block_env.beneficiary   (Address)
///   header.timestamp        → block_env.timestamp     (U256)
///   header.gas_limit        → block_env.gas_limit     (u64)
///   header.base_fee_per_gas → block_env.basefee       (u64)
///   header.prev_randao      → block_env.prevrandao    (?Hash)
///   header.excess_blob_gas  → block_env.blob_excess_gas_and_price (derived)
///   header.difficulty       → block_env.difficulty    (U256, always 0 in PoS)
pub fn blockEnvFromHeader(header: input.Header) context.BlockEnv {
    var block_env = context.BlockEnv.default();

    block_env.number      = @as(primitives.U256, header.number);
    block_env.beneficiary = header.coinbase;
    block_env.timestamp   = @as(primitives.U256, header.timestamp);
    block_env.gas_limit   = header.gas_limit;
    block_env.basefee     = header.base_fee_per_gas;
    block_env.difficulty  = @as(primitives.U256, 0); // always 0 for PoS
    block_env.prevrandao  = header.prev_randao;

    // Derive blob gas price from excess_blob_gas using the Prague/Osaka fraction.
    block_env.setBlobExcessGasAndPrice(
        header.excess_blob_gas,
        primitives.BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE,
    );

    return block_env;
}
