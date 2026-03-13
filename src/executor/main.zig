//! BlockExecutor: stateless EVM block execution using zevm.
//!
//! Steps:
//!   1. Verify the state witness (MPT proofs).
//!   2. Build pre_alloc from the proven witness keys.
//!   3. Build block-hash table and Env from the block header.
//!   4. Detect the mainnet fork, decode transactions, execute via transition().
//!   5. Compute the post-state root and receipts root.
//!   6. Return a ProofOutput for the guest to commit.

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

pub fn executeBlock(
    alloc: std.mem.Allocator,
    stateless_input: input.StatelessInput,
    fork_name: ?[]const u8,
) !output.ProofOutput {
    // 1. Verify witness proofs and obtain the pre-state root.
    const pre_state_root = try mpt.verifyWitness(stateless_input.witness);

    // 2. Build pre_alloc from witness keys.
    var pre_alloc: std.AutoHashMapUnmanaged(types.Address, types.AllocAccount) = .{};
    var current_addr: ?types.Address = null;

    for (stateless_input.witness.keys) |key| {
        if (key.len == 20) {
            var addr: types.Address = undefined;
            @memcpy(&addr, key[0..20]);
            current_addr = addr;

            const account_state = mpt.verifyAccount(
                stateless_input.witness.state_root,
                addr,
                stateless_input.witness.nodes,
            ) catch null orelse continue;

            // Locate bytecode in the witness codes pool.
            const code: []const u8 = blk: {
                if (std.mem.eql(u8, &account_state.code_hash, &primitives.KECCAK_EMPTY)) {
                    break :blk &.{};
                }
                for (stateless_input.witness.codes) |code_bytes| {
                    const code_hash = mpt.keccak256(code_bytes);
                    if (std.mem.eql(u8, &code_hash, &account_state.code_hash)) {
                        break :blk code_bytes;
                    }
                }
                break :blk &.{};
            };

            const entry = try pre_alloc.getOrPut(alloc, addr);
            if (!entry.found_existing) {
                entry.value_ptr.* = types.AllocAccount{
                    .balance = account_state.balance,
                    .nonce = account_state.nonce,
                    .code = code,
                    .pre_storage_root = account_state.storage_root,
                };
            }
        } else if (key.len == 52) {
            var addr: types.Address = undefined;
            @memcpy(&addr, key[0..20]);
            current_addr = addr;
            var raw_slot: types.Hash = undefined;
            @memcpy(&raw_slot, key[20..52]);

            const acct_state = mpt.verifyAccount(
                stateless_input.witness.state_root,
                addr,
                stateless_input.witness.nodes,
            ) catch null orelse continue;

            const value = mpt.verifyStorage(
                acct_state.storage_root,
                raw_slot,
                stateless_input.witness.nodes,
            ) catch 0;
            if (value != 0) {
                const entry = try pre_alloc.getOrPut(alloc, addr);
                if (!entry.found_existing) entry.value_ptr.* = .{};
                const slot_key = hashToU256(raw_slot);
                try entry.value_ptr.*.storage.put(alloc, slot_key, value);
            }
        } else if (key.len == 32) {
            if (current_addr) |addr| {
                var raw_slot: types.Hash = undefined;
                @memcpy(&raw_slot, key[0..32]);

                const acct_state = mpt.verifyAccount(
                    stateless_input.witness.state_root,
                    addr,
                    stateless_input.witness.nodes,
                ) catch null orelse continue;

                const value = mpt.verifyStorage(
                    acct_state.storage_root,
                    raw_slot,
                    stateless_input.witness.nodes,
                ) catch 0;
                if (value != 0) {
                    const entry = try pre_alloc.getOrPut(alloc, addr);
                    if (!entry.found_existing) entry.value_ptr.* = .{};
                    const slot_key = hashToU256(raw_slot);
                    try entry.value_ptr.*.storage.put(alloc, slot_key, value);
                }
            }
        }
    }

    // 3. Build block-hash table from witness headers.
    var block_hashes = std.ArrayListUnmanaged(types.BlockHashEntry){};
    for (stateless_input.witness.headers) |hdr_rlp| {
        const hash = mpt.keccak256(hdr_rlp);
        const outer = mpt.rlp.decodeItem(hdr_rlp) catch continue;
        var hdr_rest = switch (outer.item) {
            .list => |p| p,
            .bytes => continue,
        };
        // Skip fields 0–7: parentHash, ommersHash, coinbase, stateRoot,
        // txRoot, receiptsRoot, bloom (256 bytes), difficulty.
        var skip: usize = 0;
        while (skip < 8 and hdr_rest.len > 0) : (skip += 1) {
            const fr = mpt.rlp.decodeItem(hdr_rest) catch break;
            hdr_rest = hdr_rest[fr.consumed..];
        }
        if (hdr_rest.len == 0) continue;
        // Field [8] = block number.
        const num_r = mpt.rlp.decodeItem(hdr_rest) catch continue;
        const num_bytes = switch (num_r.item) {
            .bytes => |b| b,
            .list => continue,
        };
        if (num_bytes.len > 8) continue;
        var number: u64 = 0;
        for (num_bytes) |b| number = (number << 8) | b;
        try block_hashes.append(alloc, .{ .number = number, .hash = hash });
    }

    // 4. Build Env from the block header.
    const header = stateless_input.block;
    const spec = if (fork_name) |name| (fork_mod.specFromName(name) orelse fork_mod.mainnetSpec(header.number, header.timestamp)) else fork_mod.mainnetSpec(header.number, header.timestamp);

    // Map input.Withdrawal → types.Withdrawal.
    const withdrawals = try alloc.alloc(types.Withdrawal, stateless_input.withdrawals.len);
    for (stateless_input.withdrawals, 0..) |wd, i| {
        withdrawals[i] = .{
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
        .block_hashes = block_hashes.items,
        .withdrawals = withdrawals,
    };

    // 5. Map decoded transactions to TxInput and execute the block.
    const txs = try tx_decode.decodeTxsFromInput(alloc, stateless_input.transactions);
    const result = try transition_mod.transition(
        alloc,
        pre_alloc,
        env,
        txs,
        spec,
        1, // chain_id = mainnet
        fork_mod.blockReward(spec),
    );

    // 6. Compute post-state and receipts roots.
    const post_state_root = try output_mod.computeStateRootDelta(alloc, pre_state_root, result.alloc, stateless_input.witness.nodes);
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

// ─── Private helpers ─────────────────────────────────────────────────────────

/// Interpret a 32-byte big-endian hash as a u256 storage key.
fn hashToU256(hash: types.Hash) u256 {
    var result: u256 = 0;
    for (hash) |b| result = (result << 8) | b;
    return result;
}
