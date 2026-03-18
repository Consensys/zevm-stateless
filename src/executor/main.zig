//! BlockExecutor: stateless EVM block execution using zevm.
//!
//! Public interface (mirrors stateless guest spec):
//!   prepareWitness        — build NodeIndex + pre_alloc + block_hashes from a StatelessInput
//!   verifyStatelessNewPayload — full pipeline: prepareWitness → executeBlock → StatelessValidationResult
//!   executeBlock          — low-level: fork detection, tx execution, root computation

const std = @import("std");
const primitives = @import("primitives");
const context = @import("context");
const input = @import("input");
const output = @import("output");
const mpt = @import("mpt");

const transition_mod = @import("executor_transition");
const output_mod = @import("executor_output");
const fork_mod = @import("executor_fork");
const tx_decode = @import("executor_tx_decode");
const types = @import("executor_types");

/// Re-export so callers can use these types without importing executor_types directly.
pub const BlockHashEntry = types.BlockHashEntry;
pub const AllocAccount = types.AllocAccount;

/// Pre-processed witness data, ready for executeBlock.
/// Produced by prepareWitness(); caller owns node_index and must call
/// node_index.deinit() when done (no-op for bump allocators).
pub const PreparedWitness = struct {
    pre_state_root: [32]u8,
    pre_alloc: std.AutoHashMapUnmanaged(types.Address, types.AllocAccount),
    node_index: mpt.NodeIndex,
    block_hashes: []types.BlockHashEntry,
};

/// Build the NodeIndex, verify MPT proofs for each witness key, and populate
/// the pre-execution account map. Also decodes ancestor block headers for BLOCKHASH.
///
/// This is the witness-processing phase that precedes executeBlock, extracted
/// so it can be reused by different guest builds (native, zkVM, etc.).
pub fn prepareWitness(alloc: std.mem.Allocator, si: input.StatelessInput) !PreparedWitness {
    var node_index = try mpt.buildNodeIndex(alloc, si.witness.state);

    var pre_alloc: std.AutoHashMapUnmanaged(types.Address, types.AllocAccount) = .{};
    var current_addr: ?[20]u8 = null;

    for (si.witness.keys) |key| {
        if (key.len == 20) {
            var addr: [20]u8 = undefined;
            @memcpy(&addr, key[0..20]);
            current_addr = addr;

            const account_state = (mpt.verifyAccountIndexed(
                si.witness.state_root,
                addr,
                &node_index,
            ) catch |err| {
                std.debug.print("proof error: account 0x{s}: {}\n", .{ std.fmt.bytesToHex(addr, .lower), err });
                return err;
            }) orelse continue;

            const code: []const u8 = blk: {
                if (std.mem.eql(u8, &account_state.code_hash, &primitives.KECCAK_EMPTY)) break :blk &.{};
                for (si.witness.codes) |code_bytes| {
                    if (std.mem.eql(u8, &mpt.keccak256(code_bytes), &account_state.code_hash)) break :blk code_bytes;
                }
                break :blk &.{};
            };

            const entry = try pre_alloc.getOrPut(alloc, addr);
            if (!entry.found_existing) {
                entry.value_ptr.* = .{
                    .balance = account_state.balance,
                    .nonce = account_state.nonce,
                    .code = code,
                    .pre_storage_root = account_state.storage_root,
                };
            }
        } else if (key.len == 52) {
            var addr: [20]u8 = undefined;
            @memcpy(&addr, key[0..20]);
            current_addr = addr;
            var raw_slot: [32]u8 = undefined;
            @memcpy(&raw_slot, key[20..52]);

            const acct_state = (mpt.verifyAccountIndexed(
                si.witness.state_root,
                addr,
                &node_index,
            ) catch |err| {
                std.debug.print("proof error: account 0x{s} (storage lookup): {}\n", .{ std.fmt.bytesToHex(addr, .lower), err });
                return err;
            }) orelse continue;

            const value = mpt.verifyStorageIndexed(acct_state.storage_root, raw_slot, &node_index) catch |err| {
                std.debug.print("proof error: slot 0x{s} of account 0x{s}: {}\n", .{ std.fmt.bytesToHex(raw_slot, .lower), std.fmt.bytesToHex(addr, .lower), err });
                return err;
            };
            if (value != 0) {
                const entry = try pre_alloc.getOrPut(alloc, addr);
                if (!entry.found_existing) entry.value_ptr.* = .{};
                try entry.value_ptr.*.storage.put(alloc, hashToU256(raw_slot), value);
            }
        } else if (key.len == 32) {
            if (current_addr) |addr| {
                var raw_slot: [32]u8 = undefined;
                @memcpy(&raw_slot, key[0..32]);

                const acct_state = (mpt.verifyAccountIndexed(
                    si.witness.state_root,
                    addr,
                    &node_index,
                ) catch |err| {
                    std.debug.print("proof error: account 0x{s} (32-byte slot context): {}\n", .{ std.fmt.bytesToHex(addr, .lower), err });
                    return err;
                }) orelse continue;

                const value = mpt.verifyStorageIndexed(acct_state.storage_root, raw_slot, &node_index) catch |err| {
                    std.debug.print("proof error: slot 0x{s} of account 0x{s} (32-byte key): {}\n", .{ std.fmt.bytesToHex(raw_slot, .lower), std.fmt.bytesToHex(addr, .lower), err });
                    return err;
                };
                if (value != 0) {
                    const entry = try pre_alloc.getOrPut(alloc, addr);
                    if (!entry.found_existing) entry.value_ptr.* = .{};
                    try entry.value_ptr.*.storage.put(alloc, hashToU256(raw_slot), value);
                }
            }
        }
    }

    var block_hashes = std.ArrayListUnmanaged(types.BlockHashEntry){};
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

    return PreparedWitness{
        .pre_state_root = si.witness.state_root,
        .pre_alloc = pre_alloc,
        .node_index = node_index,
        .block_hashes = try block_hashes.toOwnedSlice(alloc),
    };
}

/// Full stateless validation pipeline: deserialize → prepare witness → execute block.
/// Mirrors verify_stateless_new_payload from the stateless guest spec.
pub fn verifyStatelessNewPayload(
    alloc: std.mem.Allocator,
    si: input.StatelessInput,
) !output.StatelessValidationResult {
    var pw = try prepareWitness(alloc, si);
    defer pw.node_index.deinit();

    const proof = try executeBlock(
        alloc,
        pw.pre_state_root,
        pw.pre_alloc,
        &pw.node_index,
        si.block,
        si.transactions,
        si.withdrawals,
        pw.block_hashes,
        null,
    );

    return output.StatelessValidationResult{
        .new_payload_request_root = si.block_hash,
        .successful_validation = true,
        .pre_state_root = proof.pre_state_root,
        .post_state_root = proof.post_state_root,
        .receipts_root = proof.receipts_root,
        .chain_id = si.chain_config.chain_id,
    };
}

fn hashToU256(hash: [32]u8) u256 {
    var result: u256 = 0;
    for (hash) |b| result = (result << 8) | b;
    return result;
}

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
            .index = wd.index,
            .validator_index = wd.validator_index,
            .address = wd.address,
            .amount = wd.amount,
        };
    }

    const env = types.Env{
        .coinbase = header.beneficiary,
        .gas_limit = header.gas_limit,
        .number = header.number,
        .timestamp = header.timestamp,
        .difficulty = header.difficulty,
        .base_fee = header.base_fee_per_gas,
        .random = header.mix_hash,
        .excess_blob_gas = header.excess_blob_gas,
        .parent_beacon_block_root = header.parent_beacon_block_root,
        .parent_hash = header.parent_hash,
        .block_hashes = block_hashes,
        .withdrawals = mapped_withdrawals,
    };

    // 2. Decode transactions and execute the block.
    const txs = try tx_decode.decodeTxsFromInput(alloc, transactions);
    const result = try transition_mod.transition(
        alloc,
        pre_alloc,
        env,
        txs,
        spec,
        1, // chain_id = mainnet
        fork_mod.blockReward(spec),
    );

    // 3. Compute post-state and receipts roots.
    const post_state_root = try output_mod.computeStateRootDelta(alloc, pre_state_root, result.alloc, index);
    const receipts_root = try output_mod.computeReceiptsRoot(alloc, result.receipts);

    // Map transition.Receipt → output.ReceiptData.
    const receipts_data = try alloc.alloc(output.ReceiptData, result.receipts.len);
    for (result.receipts, 0..) |r, i| {
        receipts_data[i] = .{
            .cumulative_gas_used = r.cumulative_gas_used,
            .success = r.status == 1,
            .logs_bloom = r.logs_bloom,
        };
    }

    return output.ProofOutput{
        .pre_state_root = pre_state_root,
        .post_state_root = post_state_root,
        .receipts_root = receipts_root,
        .receipts = receipts_data,
        .fork_name = fork_mod.specName(spec),
    };
}

/// Convert a BlockHeader into the zevm BlockEnv required for EVM execution.
pub fn blockEnvFromHeader(header: input.BlockHeader) context.BlockEnv {
    var block_env = context.BlockEnv.default();

    block_env.number = @as(primitives.U256, header.number);
    block_env.beneficiary = header.beneficiary;
    block_env.timestamp = @as(primitives.U256, header.timestamp);
    block_env.gas_limit = header.gas_limit;
    block_env.basefee = header.base_fee_per_gas orelse 0;
    block_env.difficulty = @as(primitives.U256, 0); // always 0 for PoS
    block_env.prevrandao = header.mix_hash;

    block_env.setBlobExcessGasAndPrice(
        header.excess_blob_gas orelse 0,
        primitives.BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE,
    );

    return block_env;
}
