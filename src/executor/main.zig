//! BlockExecutor: stateless EVM block execution using zevm.
//!
//! Caller is responsible for:
//!   - Building the NodeIndex from witness nodes (mpt.buildNodeIndex)
//!   - Verifying proofs and constructing pre_alloc from the witness
//!   - Decoding block_hashes from witness headers
//!
//! This function handles:
//!   1. Fork detection and Env construction.
//!   2. Transaction decoding and execution via transition().
//!   3. Post-state root and receipts root computation.
//!   4. Returning a ProofOutput for the guest to commit.

const std        = @import("std");
const primitives = @import("primitives");
const context    = @import("context");
const input      = @import("input");
const output     = @import("output");
const mpt        = @import("mpt");

const transition_mod = @import("executor_transition");
const output_mod     = @import("executor_output");
const fork_mod       = @import("executor_fork");
const tx_decode      = @import("executor_tx_decode");
const types          = @import("executor_types");

/// Re-export so callers can use these types without importing executor_types directly.
pub const BlockHashEntry = types.BlockHashEntry;
pub const AllocAccount   = types.AllocAccount;

pub fn executeBlock(
    alloc: std.mem.Allocator,
    pre_state_root: [32]u8,
    pre_alloc: std.AutoHashMapUnmanaged(types.Address, types.AllocAccount),
    index: *mpt.NodeIndex,
    header: input.BlockHeader,
    transactions: []const input.Transaction,
    withdrawals: []const input.Withdrawal,
    block_hashes: []types.BlockHashEntry,
    fork_name: ?[]const u8,
) !output.ProofOutput {
    // 1. Detect fork and build Env.
    const spec = if (fork_name) |name|
        fork_mod.specFromName(name) orelse fork_mod.mainnetSpec(header.number, header.timestamp)
    else
        fork_mod.mainnetSpec(header.number, header.timestamp);

    // Map input.Withdrawal → types.Withdrawal.
    const mapped_withdrawals = try alloc.alloc(types.Withdrawal, withdrawals.len);
    for (withdrawals, 0..) |wd, i| {
        mapped_withdrawals[i] = .{
            .index           = wd.index,
            .validator_index = wd.validator_index,
            .address         = wd.address,
            .amount          = wd.amount,
        };
    }

    const env = types.Env{
        .coinbase                 = header.beneficiary,
        .gas_limit                = header.gas_limit,
        .number                   = header.number,
        .timestamp                = header.timestamp,
        .difficulty               = header.difficulty,
        .base_fee                 = header.base_fee_per_gas,
        .random                   = header.mix_hash,
        .excess_blob_gas          = header.excess_blob_gas,
        .parent_beacon_block_root = header.parent_beacon_block_root,
        .parent_hash              = header.parent_hash,
        .block_hashes             = block_hashes,
        .withdrawals              = mapped_withdrawals,
    };

    // 2. Decode transactions and execute the block.
    const txs    = try tx_decode.decodeTxsFromInput(alloc, transactions);
    const result = try transition_mod.transition(
        alloc, pre_alloc, env, txs, spec,
        1, // chain_id = mainnet
        fork_mod.blockReward(spec),
    );

    // 3. Compute post-state and receipts roots.
    const post_state_root = try output_mod.computeStateRootDelta(alloc, pre_state_root, result.alloc, index);
    const receipts_root   = try output_mod.computeReceiptsRoot(alloc, result.receipts);

    // Map transition.Receipt → output.ReceiptData.
    const receipts_data = try alloc.alloc(output.ReceiptData, result.receipts.len);
    for (result.receipts, 0..) |r, i| {
        receipts_data[i] = .{
            .cumulative_gas_used = r.cumulative_gas_used,
            .success             = r.status == 1,
            .logs_bloom          = r.logs_bloom,
        };
    }

    return output.ProofOutput{
        .pre_state_root  = pre_state_root,
        .post_state_root = post_state_root,
        .receipts_root   = receipts_root,
        .receipts        = receipts_data,
        .fork_name       = fork_mod.specName(spec),
    };
}

/// Convert a BlockHeader into the zevm BlockEnv required for EVM execution.
pub fn blockEnvFromHeader(header: input.BlockHeader) context.BlockEnv {
    var block_env = context.BlockEnv.default();

    block_env.number      = @as(primitives.U256, header.number);
    block_env.beneficiary = header.beneficiary;
    block_env.timestamp   = @as(primitives.U256, header.timestamp);
    block_env.gas_limit   = header.gas_limit;
    block_env.basefee     = header.base_fee_per_gas orelse 0;
    block_env.difficulty  = @as(primitives.U256, 0); // always 0 for PoS
    block_env.prevrandao  = header.mix_hash;

    block_env.setBlobExcessGasAndPrice(
        header.excess_blob_gas orelse 0,
        primitives.BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE,
    );

    return block_env;
}

