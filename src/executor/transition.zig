/// Core state transition for the EVM executor.
///
/// Implements the Ethereum state transition function:
///   post_state, receipts = transition(pre_state, env, txs, fork, chain_id, reward)
///
/// Uses zevm's execution pipeline for actual EVM computation.
const std = @import("std");
const primitives = @import("primitives");
const state_mod = @import("state");
const bytecode_mod = @import("bytecode");
const database_mod = @import("database");
const context_mod = @import("context");
const handler_mod = @import("handler");

const input = @import("executor_types");
const bloom = @import("bloom.zig");
const rlp = @import("executor_rlp_encode");
const precompile_mod = @import("precompile");
const secp_wrapper = @import("secp256k1_wrapper");
const output_mod = @import("executor_output");
const alloc_mod = @import("executor_allocator");

const tx_signing = @import("tx_signing.zig");
const system_calls = @import("system_calls.zig");

// ─── Output types (re-exported from executor_types) ───────────────────────────

/// Re-export so callers can use transition.Log / transition.Receipt as before.
pub const Log = input.Log;
pub const Receipt = input.Receipt;

pub const RejectedTx = struct {
    index: usize,
    err: []const u8,
};

pub const TransitionResult = struct {
    alloc: std.AutoHashMapUnmanaged(input.Address, input.AllocAccount),
    receipts: []Receipt,
    rejected: []RejectedTx,
    cumulative_gas: u64,
    block_bloom: input.Bloom,
    // Derived after execution
    current_base_fee: ?u64,
    excess_blob_gas: ?u64,
    blob_gas_used: u64,
    // Accepted txs only (rejected txs excluded, used for txRoot computation)
    accepted_txs: []input.TxInput,
    chain_id: u64,
};

// ─── Dummy block hash ─────────────────────────────────────────────────────────

const DUMMY_BLOCK_HASH: input.Hash = blk: {
    var h: input.Hash = undefined;
    @memset(&h, 0);
    break :blk h;
};

// ─── Pre-state loader ─────────────────────────────────────────────────────────

fn buildDb(
    pre_alloc: std.AutoHashMapUnmanaged(input.Address, input.AllocAccount),
    block_hashes: []const input.BlockHashEntry,
) !database_mod.InMemoryDB {
    var db = database_mod.InMemoryDB.init(alloc_mod.get());

    var it = pre_alloc.iterator();
    while (it.next()) |entry| {
        const addr = entry.key_ptr.*;
        const acct = entry.value_ptr.*;

        const code_hash: primitives.Hash = if (acct.code.len > 0) blk: {
            // Detect EIP-7702 delegation designators (EF 01 00 <20-byte address>)
            // and load them as Eip7702Bytecode so zevm recognizes them as delegations.
            const bc: bytecode_mod.Bytecode = if (acct.code.len == 23 and
                acct.code[0] == 0xEF and acct.code[1] == 0x01 and acct.code[2] == 0x00)
            blk2: {
                var delegation_addr: primitives.Address = [_]u8{0} ** 20;
                @memcpy(&delegation_addr, acct.code[3..23]);
                break :blk2 bytecode_mod.Bytecode{ .eip7702 = bytecode_mod.Eip7702Bytecode.new(delegation_addr) };
            } else bytecode_mod.Bytecode.newLegacy(acct.code);
            const h = bc.hashSlow();
            try db.insertCode(h, bc);
            break :blk h;
        } else primitives.KECCAK_EMPTY;

        try db.insertAccount(addr, state_mod.AccountInfo{
            .balance = acct.balance,
            .nonce = acct.nonce,
            .code_hash = code_hash,
            .code = null,
        });

        var sit = acct.storage.iterator();
        while (sit.next()) |slot| {
            if (slot.value_ptr.* != 0) {
                try db.insertStorage(addr, slot.key_ptr.*, slot.value_ptr.*);
            }
        }
    }

    for (block_hashes) |bhe| {
        try db.insertBlockHash(bhe.number, bhe.hash);
    }

    return db;
}

// ─── Context setup ────────────────────────────────────────────────────────────

/// Returns the blob base fee update fraction for a given spec.
/// Used as fallback when env.blob_base_fee_update_fraction is not set.
fn blobFractionForSpec(spec: primitives.SpecId) u64 {
    if (primitives.isEnabledIn(spec, .bpo2)) return primitives.BLOB_BASE_FEE_UPDATE_FRACTION_BPO2;
    if (primitives.isEnabledIn(spec, .bpo1)) return primitives.BLOB_BASE_FEE_UPDATE_FRACTION_BPO1;
    if (primitives.isEnabledIn(spec, .prague)) return primitives.BLOB_BASE_FEE_UPDATE_FRACTION_OSAKA;
    return primitives.BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN;
}

fn buildBlockEnv(env: input.Env, spec: primitives.SpecId) context_mod.BlockEnv {
    var block = context_mod.BlockEnv.default();
    block.number = @as(primitives.U256, env.number);
    block.timestamp = @as(primitives.U256, env.timestamp);
    block.gas_limit = env.gas_limit;
    block.beneficiary = env.coinbase;
    block.basefee = env.base_fee orelse 0;
    block.difficulty = env.difficulty;
    block.prevrandao = env.random;
    if (env.excess_blob_gas) |ebg| {
        const fraction = env.blob_base_fee_update_fraction orelse blobFractionForSpec(spec);
        block.setBlobExcessGasAndPrice(ebg, fraction);
    }
    return block;
}

fn effectiveGasPrice(tx: *const input.TxInput, base_fee: u64) u128 {
    return switch (tx.type) {
        2 => blk: {
            const max_fee = tx.max_fee_per_gas orelse 0;
            const priority = tx.max_priority_fee_per_gas orelse 0;
            const bf: u128 = base_fee;
            break :blk @min(max_fee, bf + priority);
        },
        else => tx.gas_price orelse tx.max_fee_per_gas orelse 0,
    };
}

// ─── Main transition function ─────────────────────────────────────────────────

pub fn transition(
    arena: std.mem.Allocator,
    pre_alloc_in: std.AutoHashMapUnmanaged(input.Address, input.AllocAccount),
    env: input.Env,
    txs: []input.TxInput,
    spec: primitives.SpecId,
    chain_id: u64,
    reward: i64, // mining reward in wei; -1 = disabled
) !TransitionResult {
    // ── Build DB and EVM context ──────────────────────────────────────────────
    const db = try buildDb(pre_alloc_in, env.block_hashes);
    var ctx = context_mod.Context.new(db, spec);
    ctx.block = buildBlockEnv(env, spec);
    ctx.cfg.chain_id = chain_id;
    ctx.cfg.disable_base_fee = (env.base_fee == null);

    var instructions = handler_mod.Instructions.new(spec);
    var precompiles = handler_mod.Precompiles.new(spec);

    // ── Pre-block system calls (EIP-4788, EIP-2935) ───────────────────────────
    system_calls.applyPreBlockCalls(&ctx, &instructions, &precompiles, env, spec, chain_id);

    var receipts = std.ArrayListUnmanaged(Receipt){};
    var rejected = std.ArrayListUnmanaged(RejectedTx){};
    var accepted_txs = std.ArrayListUnmanaged(input.TxInput){};
    var cumulative_gas: u64 = 0;
    var block_bloom = bloom.ZERO;
    var total_blob_gas: u64 = 0;
    var log_index_global: u64 = 0;

    // Per-block blob gas limit (EIP-4844 / EIP-7691 / BPO forks).
    const max_blob_gas_per_block: u64 = if (!primitives.isEnabledIn(spec, .cancun))
        0
    else if (primitives.isEnabledIn(spec, .bpo2))
        primitives.MAX_BLOB_NUMBER_PER_BLOCK_BPO2 * primitives.GAS_PER_BLOB
    else if (primitives.isEnabledIn(spec, .bpo1))
        primitives.MAX_BLOB_NUMBER_PER_BLOCK_BPO1 * primitives.GAS_PER_BLOB
    else if (primitives.isEnabledIn(spec, .prague))
        primitives.MAX_BLOB_NUMBER_PER_BLOCK_PRAGUE * primitives.GAS_PER_BLOB
    else
        primitives.MAX_BLOB_NUMBER_PER_BLOCK * primitives.GAS_PER_BLOB;

    // ── Execute each transaction ──────────────────────────────────────────────
    for (txs, 0..) |*tx, tx_idx| {
        // 1. Determine sender
        var sender: input.Address = undefined;
        const maybe_sender: ?input.Address = blk: {
            if (tx.secret_key != null and (tx.r == null or (tx.r.? == 0 and tx.s.? == 0))) {
                break :blk try tx_signing.signTx(arena, tx, chain_id);
            }
            if (tx.r != null and tx.s != null and (tx.r.? != 0 or tx.s.? != 0)) {
                break :blk try tx_signing.recoverSender(arena, tx, chain_id);
            }
            break :blk tx.from;
        };
        if (maybe_sender) |s| {
            sender = s;
        } else {
            try rejected.append(arena, .{
                .index = tx_idx,
                .err = "could not determine sender (missing signature or secretKey)",
            });
            continue;
        }

        // 1b. Validate tx type is supported by the current fork
        {
            const type_supported = switch (tx.type) {
                0 => true,
                1 => primitives.isEnabledIn(spec, .berlin),
                2 => primitives.isEnabledIn(spec, .london),
                3 => primitives.isEnabledIn(spec, .cancun),
                4 => primitives.isEnabledIn(spec, .prague),
                else => false,
            };
            if (!type_supported) {
                try rejected.append(arena, .{
                    .index = tx_idx,
                    .err = "transaction type not supported by this fork",
                });
                continue;
            }
        }

        // 1c. EIP-7825 (Osaka+): max gas limit per transaction = 2^24
        if (primitives.isEnabledIn(spec, .osaka) and tx.gas > 0x01000000) {
            try rejected.append(arena, .{
                .index = tx_idx,
                .err = "gas limit exceeds EIP-7825 maximum (2^24)",
            });
            continue;
        }

        // 2. Compute tx hash
        const tx_hash_val = tx_signing.txHash(arena, tx, chain_id) catch [_]u8{0} ** 32;

        // 3. Set up TxEnv
        ctx.tx.caller = sender;
        ctx.tx.nonce = tx.nonce orelse 0;
        ctx.tx.gas_limit = tx.gas;
        ctx.tx.value = tx.value;
        ctx.tx.tx_type = tx.type;

        switch (tx.type) {
            2, 3, 4 => {
                ctx.tx.gas_price = tx.max_fee_per_gas orelse 0;
                ctx.tx.gas_priority_fee = tx.max_priority_fee_per_gas;
            },
            else => {
                ctx.tx.gas_price = tx.gas_price orelse tx.max_fee_per_gas orelse 0;
                ctx.tx.gas_priority_fee = null;
            },
        }

        // EIP-4844: blob hashes and max fee per blob gas
        if (ctx.tx.blob_hashes) |*old_bh| old_bh.deinit(alloc_mod.get());
        if (tx.type == 3) {
            // Always create a blob_hashes list for type-3 txs (even if empty), so that
            // validateBlobTx sees an empty list and rejects it with EmptyBlobList.
            var blob_list = std.ArrayList(primitives.Hash){};
            blob_list.appendSlice(alloc_mod.get(), tx.blob_versioned_hashes) catch {};
            ctx.tx.blob_hashes = blob_list;
            ctx.tx.max_fee_per_blob_gas = tx.max_fee_per_blob_gas orelse 0;
        } else {
            ctx.tx.blob_hashes = null;
            ctx.tx.max_fee_per_blob_gas = 0;
        }

        // EIP-7702: authorization list for type 4 transactions
        if (ctx.tx.authorization_list) |*old_al| old_al.deinit(alloc_mod.get());
        if (tx.type == 4 and tx.authorization_list.len > 0) {
            var auth_list = std.ArrayList(context_mod.Either){};
            for (tx.authorization_list) |ai| {
                const authority: context_mod.RecoveredAuthority = blk: {
                    if (ai.signer) |s| break :blk context_mod.RecoveredAuthority{ .Valid = s };
                    if (ai.y_parity > 1) break :blk context_mod.RecoveredAuthority.Invalid;
                    const SECP256K1N_OVER_2: u256 = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
                    if (ai.s > SECP256K1N_OVER_2) break :blk context_mod.RecoveredAuthority.Invalid;
                    const auth_hash = tx_signing.authorizationSigningHash(arena, &ai) catch break :blk context_mod.RecoveredAuthority.Invalid;
                    const recid: u8 = if (ai.y_parity == 0) 0 else 1;
                    var auth_sig: [64]u8 = undefined;
                    std.mem.writeInt(u256, auth_sig[0..32], ai.r, .big);
                    std.mem.writeInt(u256, auth_sig[32..64], ai.s, .big);
                    const auth_ctx = secp_wrapper.getContext() orelse break :blk context_mod.RecoveredAuthority.Invalid;
                    const signer = auth_ctx.ecrecover(auth_hash, auth_sig, recid) orelse break :blk context_mod.RecoveredAuthority.Invalid;
                    break :blk context_mod.RecoveredAuthority{ .Valid = signer };
                };
                const recovered = context_mod.RecoveredAuthorization.newUnchecked(
                    context_mod.Authorization{
                        .chain_id = ai.chain_id,
                        .address = ai.address,
                        .nonce = ai.nonce,
                    },
                    authority,
                );
                auth_list.append(alloc_mod.get(), context_mod.Either{ .Right = recovered }) catch {};
            }
            ctx.tx.authorization_list = auth_list;
        } else {
            ctx.tx.authorization_list = null;
        }

        // Chain ID
        if (tx.chain_id) |cid| {
            ctx.tx.chain_id = cid;
            ctx.cfg.chain_id = cid;
        } else if (tx.type == 0 and !tx.protected) {
            ctx.tx.chain_id = null;
            ctx.cfg.tx_chain_id_check = false;
        } else {
            ctx.tx.chain_id = chain_id;
            ctx.cfg.chain_id = chain_id;
            ctx.cfg.tx_chain_id_check = true;
        }

        // Destination
        ctx.tx.kind = if (tx.to) |to|
            context_mod.TxKind{ .Call = to }
        else
            context_mod.TxKind.Create;

        // Calldata
        ctx.tx.data = null;
        if (tx.data.len > 0) {
            var data_list = std.ArrayList(u8){};
            data_list.appendSlice(alloc_mod.get(), tx.data) catch {
                try rejected.append(arena, .{ .index = tx_idx, .err = "alloc error for tx data" });
                continue;
            };
            ctx.tx.data = data_list;
        }

        // Access list
        if (tx.access_list.len > 0) {
            var al_items = std.ArrayList(context_mod.AccessListItem){};
            for (tx.access_list) |al_entry| {
                var item = context_mod.AccessListItem{
                    .address = al_entry.address,
                    .storage_keys = std.ArrayList(primitives.StorageKey){},
                };
                for (al_entry.storage_keys) |key| {
                    const sk = std.mem.readInt(u256, &key, .big);
                    item.storage_keys.append(alloc_mod.get(), sk) catch {};
                }
                al_items.append(alloc_mod.get(), item) catch {};
            }
            ctx.tx.access_list = context_mod.AccessList{ .items = al_items };
        } else {
            ctx.tx.access_list = context_mod.AccessList{ .items = null };
        }

        // EIP-7702: type 4 with empty authorization list is invalid.
        if (tx.type == 4 and tx.authorization_list.len == 0) {
            ctx.journaled_state.discardTx();
            try rejected.append(arena, .{ .index = tx_idx, .err = "type 4 transaction with empty authorization list" });
            if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
            ctx.tx.data = null;
            ctx.tx.access_list.deinit();
            if (ctx.tx.blob_hashes) |*bh| bh.deinit(alloc_mod.get());
            ctx.tx.blob_hashes = null;
            ctx.tx.authorization_list = null;
            continue;
        }

        // 3b. Pre-validate sender state — zevm's ExecuteEvm.execute() swallows
        // validation errors and returns Fail(0 gas). To correctly classify
        // invalid txs as "rejected" (vs failed-execution with a receipt), we
        // pre-check nonce and balance here against the current journal state.
        {
            const sender_load = ctx.journaled_state.loadAccount(sender) catch |err| {
                ctx.journaled_state.discardTx();
                const err_msg = std.fmt.allocPrint(arena, "load sender: {}", .{err}) catch "load error";
                try rejected.append(arena, .{ .index = tx_idx, .err = err_msg });
                if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
                ctx.tx.data = null;
                ctx.tx.access_list.deinit();
                if (ctx.tx.blob_hashes) |*bh| bh.deinit(alloc_mod.get());
                ctx.tx.blob_hashes = null;
                if (ctx.tx.authorization_list) |*al| al.deinit(alloc_mod.get());
                ctx.tx.authorization_list = null;
                continue;
            };
            const sender_info = sender_load.data.info;
            const tx_nonce = tx.nonce orelse 0;
            if (sender_info.nonce != tx_nonce) {
                ctx.journaled_state.discardTx();
                const err_msg = std.fmt.allocPrint(arena, "nonce mismatch: have {}, want {}", .{ sender_info.nonce, tx_nonce }) catch "nonce error";
                try rejected.append(arena, .{ .index = tx_idx, .err = err_msg });
                if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
                ctx.tx.data = null;
                ctx.tx.access_list.deinit();
                if (ctx.tx.blob_hashes) |*bh| bh.deinit(alloc_mod.get());
                ctx.tx.blob_hashes = null;
                if (ctx.tx.authorization_list) |*al| al.deinit(alloc_mod.get());
                ctx.tx.authorization_list = null;
                continue;
            }
            const egp_check = effectiveGasPrice(tx, env.base_fee orelse 0);
            const max_gas_fee: u256 = @as(u256, tx.gas) * @as(u256, egp_check);
            const blob_cost: u256 = if (tx.type == 3) blk: {
                const n: u256 = tx.blob_versioned_hashes.len;
                const max_blob_fee: u256 = tx.max_fee_per_blob_gas orelse 0;
                break :blk n * 131_072 * max_blob_fee;
            } else 0;
            const max_cost = max_gas_fee + tx.value + blob_cost;
            if (sender_info.balance < max_cost) {
                ctx.journaled_state.discardTx();
                const err_msg = std.fmt.allocPrint(arena, "insufficient funds: have {}, need {}", .{ sender_info.balance, max_cost }) catch "balance error";
                try rejected.append(arena, .{ .index = tx_idx, .err = err_msg });
                if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
                ctx.tx.data = null;
                ctx.tx.access_list.deinit();
                if (ctx.tx.blob_hashes) |*bh| bh.deinit(alloc_mod.get());
                ctx.tx.blob_hashes = null;
                if (ctx.tx.authorization_list) |*al| al.deinit(alloc_mod.get());
                ctx.tx.authorization_list = null;
                continue;
            }
        }

        // 4. Execute
        var frame_stack = handler_mod.FrameStack.new();
        var evm = handler_mod.Evm.init(&ctx, null, &instructions, &precompiles, &frame_stack);

        var exec_result = handler_mod.ExecuteEvm.execute(&evm) catch |err| {
            ctx.journaled_state.discardTx();
            if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
            ctx.tx.data = null;
            ctx.tx.access_list.deinit();
            if (ctx.tx.blob_hashes) |*bh| bh.deinit(alloc_mod.get());
            ctx.tx.blob_hashes = null;
            if (ctx.tx.authorization_list) |*al| al.deinit(alloc_mod.get());
            ctx.tx.authorization_list = null;
            const err_msg = std.fmt.allocPrint(arena, "{}", .{err}) catch "execution error";
            try rejected.append(arena, .{ .index = tx_idx, .err = err_msg });
            continue;
        };

        if (ctx.tx.data) |*d| d.deinit(alloc_mod.get());
        ctx.tx.data = null;
        ctx.tx.access_list.deinit();
        if (ctx.tx.blob_hashes) |*bh| bh.deinit(alloc_mod.get());
        ctx.tx.blob_hashes = null;
        if (ctx.tx.authorization_list) |*al| al.deinit(alloc_mod.get());
        ctx.tx.authorization_list = null;

        // 5. Build receipt
        const gas_used = exec_result.gas_used;
        cumulative_gas += gas_used;

        const status: u8 = if (exec_result.status == .Success) 1 else 0;
        const egp = effectiveGasPrice(tx, env.base_fee orelse 0);

        const contract_addr: ?input.Address = if (tx.to == null and status == 1)
            tx_signing.createAddress(arena, sender, tx.nonce orelse 0) catch null
        else
            null;

        const logs_start = log_index_global;
        var receipt_logs = std.ArrayListUnmanaged(Log){};
        var receipt_bloom = bloom.ZERO;

        for (exec_result.logs.items) |log| {
            var topics = try arena.alloc(input.Hash, log.topics.len);
            for (log.topics, 0..) |t, ti| topics[ti] = t;

            bloom.addLog(&receipt_bloom, log.address, log.topics);
            bloom.merge(&block_bloom, receipt_bloom);

            try receipt_logs.append(arena, Log{
                .address = log.address,
                .topics = topics,
                .data = try arena.dupe(u8, log.data),
                .block_number = env.number,
                .tx_hash = tx_hash_val,
                .tx_index = tx_idx,
                .block_hash = DUMMY_BLOCK_HASH,
                .log_index = log_index_global,
                .removed = false,
            });
            log_index_global += 1;
        }
        _ = logs_start;

        // Blob gas tracking + per-block limit enforcement.
        if (tx.type == 3) {
            const blobs: u64 = @intCast(tx.blob_versioned_hashes.len);
            const tx_blob_gas = blobs * primitives.GAS_PER_BLOB;
            if (max_blob_gas_per_block > 0 and
                tx_blob_gas <= max_blob_gas_per_block and
                total_blob_gas + tx_blob_gas > max_blob_gas_per_block)
            {
                return error.BlobGasLimitExceeded;
            }
            total_blob_gas += tx_blob_gas;
        }

        try receipts.append(arena, Receipt{
            .type = tx.type,
            .tx_hash = tx_hash_val,
            .tx_index = tx_idx,
            .block_hash = DUMMY_BLOCK_HASH,
            .block_number = env.number,
            .from = sender,
            .to = tx.to,
            .cumulative_gas_used = cumulative_gas,
            .gas_used = gas_used,
            .contract_address = contract_addr,
            .logs = try receipt_logs.toOwnedSlice(arena),
            .logs_bloom = receipt_bloom,
            .status = status,
            .effective_gas_price = egp,
            .blob_gas_used = if (tx.type == 3) tx.blob_versioned_hashes.len * 131_072 else null,
            .blob_gas_price = if (tx.type == 3)
                if (ctx.block.blob_excess_gas_and_price) |bep| bep.blob_gasprice else null
            else
                null,
        });

        exec_result.deinit();

        // Pre-Byzantium (EIP-658 not yet active): compute per-tx intermediate state root.
        if (!primitives.isEnabledIn(spec, .byzantium)) {
            const per_tx_alloc = extractPostState(arena, pre_alloc_in, &ctx) catch null;
            if (per_tx_alloc) |pa| {
                const sr = output_mod.computeStateRoot(arena, pa, &.{}) catch null;
                receipts.items[receipts.items.len - 1].state_root = sr;
            }
        }

        try accepted_txs.append(arena, tx.*);
    }

    // ── Apply mining reward ───────────────────────────────────────────────────
    if (reward >= 0) {
        const reward_wei: primitives.U256 = @intCast(reward);
        ctx.journaled_state.inner.balanceIncr(
            &ctx.journaled_state.database,
            env.coinbase,
            reward_wei,
        ) catch {};
        ctx.journaled_state.commitTx();
    }

    // ── Apply withdrawals (Shanghai+) ─────────────────────────────────────────
    for (env.withdrawals) |wd| {
        const amount_wei: primitives.U256 = @as(u256, wd.amount) * 1_000_000_000;
        ctx.journaled_state.inner.balanceIncr(
            &ctx.journaled_state.database,
            wd.address,
            amount_wei,
        ) catch {};
    }
    if (env.withdrawals.len > 0) {
        ctx.journaled_state.commitTx();
    }

    // ── Post-block system calls (EIP-7002, EIP-7251) ──────────────────────────
    system_calls.applyPostBlockCalls(&ctx, &instructions, &precompiles, spec, chain_id);

    // ── Extract post-state ────────────────────────────────────────────────────
    const post_alloc = try extractPostState(arena, pre_alloc_in, &ctx);

    return TransitionResult{
        .alloc = post_alloc,
        .receipts = try receipts.toOwnedSlice(arena),
        .rejected = try rejected.toOwnedSlice(arena),
        .cumulative_gas = cumulative_gas,
        .block_bloom = block_bloom,
        .current_base_fee = env.base_fee,
        .excess_blob_gas = env.excess_blob_gas,
        .blob_gas_used = total_blob_gas,
        .accepted_txs = try accepted_txs.toOwnedSlice(arena),
        .chain_id = chain_id,
    };
}

// ─── Post-state extraction ────────────────────────────────────────────────────

fn extractPostState(
    arena: std.mem.Allocator,
    pre_alloc: std.AutoHashMapUnmanaged(input.Address, input.AllocAccount),
    ctx: *context_mod.Context,
) !std.AutoHashMapUnmanaged(input.Address, input.AllocAccount) {
    // Start with a mutable copy of pre_alloc (use arena allocation for storage maps)
    var post = std.AutoHashMapUnmanaged(input.Address, input.AllocAccount){};

    // Clone all pre-state accounts
    var pre_it = pre_alloc.iterator();
    while (pre_it.next()) |pre_entry| {
        var acct = input.AllocAccount{
            .balance = pre_entry.value_ptr.*.balance,
            .nonce = pre_entry.value_ptr.*.nonce,
            .code = pre_entry.value_ptr.*.code,
            .pre_storage_root = pre_entry.value_ptr.*.pre_storage_root,
        };
        // Clone storage (included for both normal and delta modes:
        //   - Normal mode (pre_storage_root==null): full pre-state for scratch-build.
        //   - Delta mode (pre_storage_root set): witness-proven slots, applied as
        //     updates/insertions to pre_storage_root; unchanged ones are idempotent.
        //     Zero values written later signal deletions.)
        var sit = pre_entry.value_ptr.*.storage.iterator();
        while (sit.next()) |slot| {
            try acct.storage.put(arena, slot.key_ptr.*, slot.value_ptr.*);
        }
        try post.put(arena, pre_entry.key_ptr.*, acct);
    }

    // Override with evm_state (all accounts touched during execution)
    var state_it = ctx.journaled_state.inner.evm_state.iterator();
    while (state_it.next()) |state_entry| {
        const addr = state_entry.key_ptr.*;
        const account = state_entry.value_ptr.*;

        // Skip accounts that were loaded as non-existent and never touched
        if (account.status.loaded_as_not_existing and !account.status.touched) continue;

        // Remove self-destructed accounts
        if (account.status.self_destructed) {
            _ = post.remove(addr);
            continue;
        }

        // Get or create post-alloc entry (base from pre-state if exists).
        // Newly created accounts (created=true) and accounts whose storage was wiped by a
        // prior SELFDESTRUCT (storage_wiped=true) must NOT inherit pre-state storage.
        const fresh_storage = account.status.created or account.status.storage_wiped;
        var acct = post.get(addr) orelse input.AllocAccount{};
        if (fresh_storage) {
            acct.storage = .{};
            acct.pre_storage_root = null;
        }

        acct.balance = account.info.balance;
        acct.nonce = account.info.nonce;

        // Update code: use code_hash as the source of truth.
        // KECCAK_EMPTY means empty code; otherwise look up actual bytes.
        // Note: Bytecode.new() (default/empty in zevm) has originalBytes() = &[0x00]
        // even though the account has no code — so we must check code_hash first.
        // IMPORTANT: Eip7702Bytecode.raw() returns &self.raw_bytes where self is a value
        // parameter, so it returns a dangling pointer when called on a copy. For EIP-7702
        // bytecode we construct the bytes directly from the address field instead.
        if (!std.mem.eql(u8, &account.info.code_hash, &primitives.KECCAK_EMPTY)) {
            if (account.info.code) |bc| {
                if (bc == .eip7702) {
                    const buf = try arena.alloc(u8, 23);
                    buf[0] = 0xEF;
                    buf[1] = 0x01;
                    buf[2] = 0x00;
                    @memcpy(buf[3..], &bc.eip7702.address);
                    acct.code = buf;
                } else {
                    const raw = bc.originalBytes();
                    acct.code = if (raw.len > 0) raw else &.{};
                }
            } else {
                if (ctx.journaled_state.database.codeByHash(account.info.code_hash)) |db_bc| {
                    if (db_bc == .eip7702) {
                        const buf = try arena.alloc(u8, 23);
                        buf[0] = 0xEF;
                        buf[1] = 0x01;
                        buf[2] = 0x00;
                        @memcpy(buf[3..], &db_bc.eip7702.address);
                        acct.code = buf;
                    } else {
                        const raw = db_bc.originalBytes();
                        acct.code = if (raw.len > 0) raw else &.{};
                    }
                } else |_| {}
            }
        } else {
            acct.code = &.{};
        }

        // Update storage: merge pre-state slots with journal modifications.
        // In delta mode (pre_storage_root != null) keep zero values as deletion markers
        // so computeStorageRoot() can apply the MPT delete operation.
        var stor_it = account.storage.iterator();
        while (stor_it.next()) |slot| {
            const key = slot.key_ptr.*;
            const present = slot.value_ptr.*.present_value;
            if (present == 0) {
                if (acct.pre_storage_root != null) {
                    try acct.storage.put(arena, key, 0);
                } else {
                    _ = acct.storage.remove(key);
                }
            } else {
                try acct.storage.put(arena, key, present);
            }
        }

        // EIP-161 (Spurious Dragon+): remove empty accounts from state.
        if (primitives.isEnabledIn(ctx.cfg.spec, .spurious_dragon)) {
            if (acct.nonce == 0 and acct.balance == 0 and acct.code.len == 0 and acct.storage.count() == 0) {
                _ = post.remove(addr);
                continue;
            }
        }

        try post.put(arena, addr, acct);
    }

    return post;
}
