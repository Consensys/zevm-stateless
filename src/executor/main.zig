//! BlockExecutor: stateless EVM block execution using zevm.
//!
//! Caller is responsible for:
//!   - Building the NodeIndex from witness nodes (mpt.buildNodeIndex)
//!   - Decoding block_hashes from witness headers
//!
//! This module handles:
//!   1. Fork detection and Env construction.
//!   2. Transaction decoding and execution via transition().
//!   3. Post-state root and receipts root computation.
//!   4. Returning a ProofOutput for the guest to commit.

const std = @import("std");
const primitives = @import("primitives");
const input = @import("input");
const output = @import("output");
const mpt = @import("mpt");
const rlp_decode = @import("rlp_decode");

const transition_mod = @import("executor_transition");
const output_mod = @import("executor_output");
const fork_mod = @import("hardfork");
const tx_decode = @import("executor_tx_decode");
const types = @import("executor_types");
const db_mod = @import("db");
const database_mod = @import("database");
const block_validation = @import("executor_block_validation");

/// Re-export so callers can use these types without importing executor_types directly.
pub const BlockHashEntry = types.BlockHashEntry;
pub const AllocAccount = types.AllocAccount;

// ─── Private helpers ──────────────────────────────────────────────────────────

fn mapWithdrawals(alloc: std.mem.Allocator, withdrawals: []const input.Withdrawal) ![]types.Withdrawal {
    const out = try alloc.alloc(types.Withdrawal, withdrawals.len);
    for (withdrawals, 0..) |wd, i| {
        out[i] = .{ .index = wd.index, .validator_index = wd.validator_index, .address = wd.address, .amount = wd.amount };
    }
    return out;
}

fn buildEnv(req: input.NewPayloadRequest, block_hashes: []types.BlockHashEntry, withdrawals: []types.Withdrawal) types.Env {
    const ep = &req.execution_payload;
    return .{
        .coinbase = ep.fee_recipient,
        .gas_limit = ep.gas_limit,
        .number = ep.block_number,
        .timestamp = ep.timestamp,
        .difficulty = 0,
        .base_fee = ep.base_fee_per_gas,
        .random = ep.prev_randao,
        .excess_blob_gas = ep.excess_blob_gas,
        .parent_beacon_block_root = req.parent_beacon_block_root,
        .parent_hash = ep.parent_hash,
        .block_hashes = block_hashes,
        .withdrawals = withdrawals,
        .slot_number = ep.slot_number,
    };
}

fn finalizeOutput(
    alloc: std.mem.Allocator,
    pre_state_root: [32]u8,
    result: transition_mod.TransitionResult,
    node_index: *mpt.NodeIndex,
    spec: primitives.SpecId,
) !output.ProofOutput {
    const post_state_root = try output_mod.computeStateRootDelta(alloc, pre_state_root, result.alloc, node_index);
    const receipts_root = try output_mod.computeReceiptsRoot(alloc, result.receipts);
    const receipts_data = try alloc.alloc(output.ReceiptData, result.receipts.len);
    for (result.receipts, 0..) |r, i| {
        receipts_data[i] = .{ .cumulative_gas_used = r.cumulative_gas_used, .success = r.status == 1, .logs_bloom = r.logs_bloom };
    }
    return .{
        .pre_state_root = pre_state_root,
        .post_state_root = post_state_root,
        .receipts_root = receipts_root,
        .receipts = receipts_data,
        .fork_name = fork_mod.specName(spec),
    };
}

// ─── Public API ───────────────────────────────────────────────────────────────

pub const ExecuteBlockResult = struct {
    post_state_root: [32]u8,
    receipts_root: [32]u8,
    post_alloc: std.AutoHashMapUnmanaged(types.Address, types.AllocAccount),
    receipts: []transition_mod.Receipt,
};

pub fn executeBlockFromAlloc(
    alloc: std.mem.Allocator,
    pre_alloc: std.AutoHashMapUnmanaged(types.Address, types.AllocAccount),
    env: types.Env,
    txs: []types.TxInput,
    spec: primitives.SpecId,
    chain_id: u64,
    reward: i64,
) !ExecuteBlockResult {
    try block_validation.validateBlock(env, spec);
    const result = try transition_mod.transition(alloc, pre_alloc, env, txs, spec, chain_id, reward);
    try block_validation.validatePostExecution(env, spec, result.cumulative_gas, result.blob_gas_used);
    const post_state_root = try output_mod.computeStateRoot(alloc, result.alloc, &.{});
    const receipts_root = try output_mod.computeReceiptsRoot(alloc, result.receipts);
    return .{
        .post_state_root = post_state_root,
        .receipts_root = receipts_root,
        .post_alloc = result.alloc,
        .receipts = result.receipts,
    };
}

pub fn executeBlock(
    alloc: std.mem.Allocator,
    pre_state_root: [32]u8,
    pre_alloc: std.AutoHashMapUnmanaged(types.Address, types.AllocAccount),
    index: *mpt.NodeIndex,
    req: input.NewPayloadRequest,
    block_hashes: []types.BlockHashEntry,
    fork_name: ?[]const u8,
) !output.ProofOutput {
    const ep = &req.execution_payload;
    const spec = if (fork_name) |name|
        fork_mod.specFromFork(name) orelse fork_mod.mainnetSpec(ep.block_number, ep.timestamp)
    else
        fork_mod.mainnetSpec(ep.block_number, ep.timestamp);

    const env = buildEnv(req, block_hashes, try mapWithdrawals(alloc, ep.withdrawals));
    try block_validation.validateBlock(env, spec);
    const txs = try tx_decode.decodeTxsFromInput(alloc, ep.transactions);
    const result = try transition_mod.transition(alloc, pre_alloc, env, txs, spec, 1, fork_mod.blockReward(spec));
    return finalizeOutput(alloc, pre_state_root, result, index, spec);
}

/// Stateless block execution: serves all account/storage reads from the MPT witness
/// via `WitnessDatabase` (no pre-built pre_alloc needed).
pub fn executeBlockStateless(
    alloc: std.mem.Allocator,
    pre_state_root: [32]u8,
    node_index: *mpt.NodeIndex,
    req: input.NewPayloadRequest,
    witness_codes: []const []const u8,
    block_hashes: []types.BlockHashEntry,
    fork_name: ?[]const u8,
    chain_id: u64,
    public_keys: []const []const u8,
) !output.ProofOutput {
    const ep = &req.execution_payload;

    const spec = if (fork_name) |name|
        fork_mod.specFromFork(name) orelse fork_mod.mainnetSpec(ep.block_number, ep.timestamp)
    else if (ep.slot_number != null)
        // slot_number presence signals Amsterdam (or later) block.
        primitives.SpecId.amsterdam
    else
        fork_mod.mainnetSpec(ep.block_number, ep.timestamp);

    const env = buildEnv(req, block_hashes, try mapWithdrawals(alloc, ep.withdrawals));
    try block_validation.validateBlock(env, spec);
    const txs = try tx_decode.decodeTxsFromInput(alloc, ep.transactions);

    // Wire WitnessDatabase as fallback on an empty InMemoryDB.
    // All account/storage reads during EVM execution are served via live MPT proof verification.
    var witness_db = db_mod.WitnessDatabase.init(node_index, pre_state_root, witness_codes, block_hashes);
    var db = database_mod.InMemoryDB.init(alloc);
    db.fallback = witness_db.buildFallback();

    const empty_pre_alloc = std.AutoHashMapUnmanaged(types.Address, types.AllocAccount){};
    const result = try transition_mod.transitionWithDb(
        alloc,
        db,
        empty_pre_alloc,
        env,
        txs,
        spec,
        chain_id,
        fork_mod.blockReward(spec),
        public_keys,
    );
    try block_validation.validatePostExecution(env, spec, result.cumulative_gas, result.blob_gas_used);
    return finalizeOutput(alloc, pre_state_root, result, node_index, spec);
}

/// High-level stateless execution from a fully-decoded StatelessInput.
/// Derives pre_state_root, builds the node index and block-hash table
/// internally — callers only need to supply the input and an optional
/// fork override.
pub fn executeStatelessInput(
    alloc: std.mem.Allocator,
    si: input.StatelessInput,
    fork_name: ?[]const u8,
) !output.ProofOutput {
    const ep = &si.new_payload_request.execution_payload;

    const pre_state_root = rlp_decode.findPreStateRoot(si.witness.headers, ep.block_number) orelse ep.state_root;

    var node_index = try mpt.buildNodeIndex(alloc, si.witness.nodes);
    defer node_index.deinit();

    var block_hashes = std.ArrayListUnmanaged(BlockHashEntry){};
    for (si.witness.headers) |hdr_rlp| {
        const hash = mpt.keccak256(hdr_rlp);
        const outer = mpt.rlp.decodeItem(hdr_rlp) catch continue;
        var rest = switch (outer.item) {
            .list => |p| p,
            .bytes => continue,
        };
        var skip: usize = 0;
        while (skip < 8 and rest.len > 0) : (skip += 1) {
            const fr = mpt.rlp.decodeItem(rest) catch break;
            rest = rest[fr.consumed..];
        }
        if (rest.len == 0) continue;
        const num_r = mpt.rlp.decodeItem(rest) catch continue;
        const num_bytes = switch (num_r.item) {
            .bytes => |b| b,
            .list => continue,
        };
        if (num_bytes.len > 8) continue;
        var number: u64 = 0;
        for (num_bytes) |b| number = (number << 8) | b;
        try block_hashes.append(alloc, .{ .number = number, .hash = hash });
    }

    return executeBlockStateless(
        alloc,
        pre_state_root,
        &node_index,
        si.new_payload_request,
        si.witness.codes,
        block_hashes.items,
        fork_name,
        si.chain_config.chain_id,
        si.public_keys,
    );
}
