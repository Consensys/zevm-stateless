/// Core state transition for the t8n tool.
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

const input = @import("input.zig");
const bloom = @import("bloom.zig");
const rlp = @import("rlp_encode.zig");
const precompile_mod = @import("precompile");
const secp_wrapper = precompile_mod.secp256k1_wrapper;

// ─── Output types ─────────────────────────────────────────────────────────────

pub const Log = struct {
    address: input.Address,
    topics: []input.Hash,
    data: []const u8,
    block_number: u64,
    tx_hash: input.Hash,
    tx_index: u64,
    block_hash: input.Hash,
    log_index: u64,
    removed: bool = false,
};

pub const Receipt = struct {
    type: u8,
    tx_hash: input.Hash,
    tx_index: u64,
    block_hash: input.Hash,
    block_number: u64,
    from: input.Address,
    to: ?input.Address,
    cumulative_gas_used: u64,
    gas_used: u64,
    contract_address: ?input.Address,
    logs: []Log,
    logs_bloom: bloom.Bloom,
    status: u8,
    effective_gas_price: u128,
    blob_gas_used: ?u64 = null,
    blob_gas_price: ?u128 = null,
};

pub const RejectedTx = struct {
    index: usize,
    err: []const u8,
};

pub const TransitionResult = struct {
    alloc: std.AutoHashMapUnmanaged(input.Address, input.AllocAccount),
    receipts: []Receipt,
    rejected: []RejectedTx,
    cumulative_gas: u64,
    block_bloom: bloom.Bloom,
    // Derived after execution
    current_base_fee: ?u64,
    excess_blob_gas: ?u64,
    blob_gas_used: u64,
    // Original txs (used for txRoot computation)
    txs: []input.TxInput,
    chain_id: u64,
};

// ─── Dummy block hash ─────────────────────────────────────────────────────────

/// Receipt block hash: the t8n tool convention is 0x1337...0000.
const DUMMY_BLOCK_HASH: input.Hash = blk: {
    var h = [_]u8{0} ** 32;
    h[30] = 0x13;
    h[31] = 0x37;
    break :blk h;
};

// ─── Fork mapping ─────────────────────────────────────────────────────────────

pub fn specFromFork(name: []const u8) ?primitives.SpecId {
    const Entry = struct { k: []const u8, v: primitives.SpecId };
    const table = [_]Entry{
        .{ .k = "Frontier", .v = .frontier },
        .{ .k = "Homestead", .v = .homestead },
        .{ .k = "EIP150", .v = .tangerine },
        .{ .k = "TangerineWhistle", .v = .tangerine },
        .{ .k = "EIP158", .v = .spurious_dragon },
        .{ .k = "SpuriousDragon", .v = .spurious_dragon },
        .{ .k = "Byzantium", .v = .byzantium },
        .{ .k = "Constantinople", .v = .constantinople },
        .{ .k = "ConstantinopleFix", .v = .petersburg },
        .{ .k = "Petersburg", .v = .petersburg },
        .{ .k = "Istanbul", .v = .istanbul },
        .{ .k = "MuirGlacier", .v = .muir_glacier },
        .{ .k = "Berlin", .v = .berlin },
        .{ .k = "London", .v = .london },
        .{ .k = "ArrowGlacier", .v = .arrow_glacier },
        .{ .k = "GrayGlacier", .v = .gray_glacier },
        .{ .k = "Merge", .v = .merge },
        .{ .k = "Paris", .v = .merge },
        .{ .k = "Shanghai", .v = .shanghai },
        .{ .k = "Cancun", .v = .cancun },
        .{ .k = "Prague", .v = .prague },
        .{ .k = "Osaka", .v = .osaka },
        .{ .k = "Amsterdam", .v = .amsterdam },
    };
    for (table) |e| {
        if (std.mem.eql(u8, name, e.k)) return e.v;
    }
    return null;
}

// ─── Transaction hashing and sender recovery ──────────────────────────────────

/// Encode an access list to RLP (for typed tx hashing).
fn rlpAccessList(alloc: std.mem.Allocator, al: []const input.AccessListEntry) ![]u8 {
    var outer_items = std.ArrayListUnmanaged([]const u8){};
    defer outer_items.deinit(alloc);

    for (al) |entry| {
        var inner_items = std.ArrayListUnmanaged([]const u8){};
        defer inner_items.deinit(alloc);

        // Address
        try inner_items.append(alloc, try rlp.encodeBytes(alloc, &entry.address));

        // Storage keys list
        var key_items = std.ArrayListUnmanaged([]const u8){};
        defer key_items.deinit(alloc);
        for (entry.storage_keys) |key| {
            try key_items.append(alloc, try rlp.encodeBytes(alloc, &key));
        }
        try inner_items.append(alloc, try rlp.encodeList(alloc, key_items.items));
        try outer_items.append(alloc, try rlp.encodeList(alloc, inner_items.items));
    }

    return rlp.encodeList(alloc, outer_items.items);
}

/// Encode tx.to as RLP (empty bytes for CREATE, 20-byte address for CALL).
fn rlpTo(alloc: std.mem.Allocator, to: ?input.Address) ![]u8 {
    if (to) |addr| return rlp.encodeBytes(alloc, &addr);
    return rlp.encodeBytes(alloc, &.{});
}

/// Compute the signing hash for an unsigned transaction (pre-signature payload).
fn signingHash(alloc: std.mem.Allocator, tx: *const input.TxInput, chain_id: u64) ![32]u8 {
    const to_enc = try rlpTo(alloc, tx.to);
    const al_enc = try rlpAccessList(alloc, tx.access_list);

    const payload = switch (tx.type) {
        0 => blk: {
            if (tx.protected and chain_id > 0) {
                // EIP-155: include chainId, 0, 0
                const items = [_][]const u8{
                    try rlp.encodeU64(alloc, tx.nonce orelse 0),
                    try rlp.encodeU128(alloc, tx.gas_price orelse 0),
                    try rlp.encodeU64(alloc, tx.gas),
                    to_enc,
                    try rlp.encodeU256(alloc, tx.value),
                    try rlp.encodeBytes(alloc, tx.data),
                    try rlp.encodeU64(alloc, chain_id),
                    try rlp.encodeBytes(alloc, &.{}), // 0
                    try rlp.encodeBytes(alloc, &.{}), // 0
                };
                break :blk try rlp.encodeList(alloc, &items);
            } else {
                const items = [_][]const u8{
                    try rlp.encodeU64(alloc, tx.nonce orelse 0),
                    try rlp.encodeU128(alloc, tx.gas_price orelse 0),
                    try rlp.encodeU64(alloc, tx.gas),
                    to_enc,
                    try rlp.encodeU256(alloc, tx.value),
                    try rlp.encodeBytes(alloc, tx.data),
                };
                break :blk try rlp.encodeList(alloc, &items);
            }
        },
        1 => blk: {
            const items = [_][]const u8{
                try rlp.encodeU64(alloc, tx.chain_id orelse chain_id),
                try rlp.encodeU64(alloc, tx.nonce orelse 0),
                try rlp.encodeU128(alloc, tx.gas_price orelse 0),
                try rlp.encodeU64(alloc, tx.gas),
                to_enc,
                try rlp.encodeU256(alloc, tx.value),
                try rlp.encodeBytes(alloc, tx.data),
                al_enc,
            };
            break :blk try rlp.concat(alloc, &.{ &.{0x01}, try rlp.encodeList(alloc, &items) });
        },
        2 => blk: {
            const items = [_][]const u8{
                try rlp.encodeU64(alloc, tx.chain_id orelse chain_id),
                try rlp.encodeU64(alloc, tx.nonce orelse 0),
                try rlp.encodeU128(alloc, tx.max_priority_fee_per_gas orelse 0),
                try rlp.encodeU128(alloc, tx.max_fee_per_gas orelse 0),
                try rlp.encodeU64(alloc, tx.gas),
                to_enc,
                try rlp.encodeU256(alloc, tx.value),
                try rlp.encodeBytes(alloc, tx.data),
                al_enc,
            };
            break :blk try rlp.concat(alloc, &.{ &.{0x02}, try rlp.encodeList(alloc, &items) });
        },
        else => return error.UnsupportedTxType,
    };

    return rlp.keccak256(payload);
}

/// Compute the hash of a signed transaction (used as receipt txHash).
fn txHash(alloc: std.mem.Allocator, tx: *const input.TxInput, chain_id: u64) ![32]u8 {
    const r = tx.r orelse 0;
    const s = tx.s orelse 0;
    const v = tx.v orelse 0;

    const to_enc = try rlpTo(alloc, tx.to);
    const al_enc = try rlpAccessList(alloc, tx.access_list);

    const payload = switch (tx.type) {
        0 => blk: {
            const items = [_][]const u8{
                try rlp.encodeU64(alloc, tx.nonce orelse 0),
                try rlp.encodeU128(alloc, tx.gas_price orelse 0),
                try rlp.encodeU64(alloc, tx.gas),
                to_enc,
                try rlp.encodeU256(alloc, tx.value),
                try rlp.encodeBytes(alloc, tx.data),
                try rlp.encodeU256(alloc, v),
                try rlp.encodeU256(alloc, r),
                try rlp.encodeU256(alloc, s),
            };
            break :blk try rlp.encodeList(alloc, &items);
        },
        1 => blk: {
            // yParity is v (0 or 1)
            const items = [_][]const u8{
                try rlp.encodeU64(alloc, tx.chain_id orelse chain_id),
                try rlp.encodeU64(alloc, tx.nonce orelse 0),
                try rlp.encodeU128(alloc, tx.gas_price orelse 0),
                try rlp.encodeU64(alloc, tx.gas),
                to_enc,
                try rlp.encodeU256(alloc, tx.value),
                try rlp.encodeBytes(alloc, tx.data),
                al_enc,
                try rlp.encodeU256(alloc, v), // yParity
                try rlp.encodeU256(alloc, r),
                try rlp.encodeU256(alloc, s),
            };
            break :blk try rlp.concat(alloc, &.{ &.{0x01}, try rlp.encodeList(alloc, &items) });
        },
        2 => blk: {
            const items = [_][]const u8{
                try rlp.encodeU64(alloc, tx.chain_id orelse chain_id),
                try rlp.encodeU64(alloc, tx.nonce orelse 0),
                try rlp.encodeU128(alloc, tx.max_priority_fee_per_gas orelse 0),
                try rlp.encodeU128(alloc, tx.max_fee_per_gas orelse 0),
                try rlp.encodeU64(alloc, tx.gas),
                to_enc,
                try rlp.encodeU256(alloc, tx.value),
                try rlp.encodeBytes(alloc, tx.data),
                al_enc,
                try rlp.encodeU256(alloc, v), // yParity
                try rlp.encodeU256(alloc, r),
                try rlp.encodeU256(alloc, s),
            };
            break :blk try rlp.concat(alloc, &.{ &.{0x02}, try rlp.encodeList(alloc, &items) });
        },
        else => return error.UnsupportedTxType,
    };

    return rlp.keccak256(payload);
}

/// Recover the sender address from a signed transaction.
/// Returns null if signature is invalid or missing.
fn recoverSender(alloc: std.mem.Allocator, tx: *const input.TxInput, chain_id: u64) !?input.Address {
    const r = tx.r orelse return null;
    const s = tx.s orelse return null;
    const v_val = tx.v orelse return null;

    // Both r and s zero ⇒ unsigned
    if (r == 0 and s == 0) return null;

    const hash = try signingHash(alloc, tx, chain_id);

    // Recovery ID from v
    const recid: u8 = switch (tx.type) {
        0 => blk: {
            // EIP-155: v = 2*chainId + 35 + recid  → recid = v - 2*chainId - 35
            // Legacy: v = 27/28 → recid = v - 27
            const chain_v: u256 = 2 * @as(u256, chain_id) + 35;
            if (v_val >= chain_v and v_val <= chain_v + 1) {
                break :blk @intCast(v_val - chain_v);
            } else if (v_val == 27 or v_val == 28) {
                break :blk @intCast(v_val - 27);
            } else {
                return null;
            }
        },
        // Type 1/2: yParity is directly 0 or 1
        else => blk: {
            if (v_val > 1) return null;
            break :blk @intCast(v_val);
        },
    };

    // Build compact signature: r[32] ++ s[32]
    var sig: [64]u8 = undefined;
    var r_buf: [32]u8 = undefined;
    var s_buf: [32]u8 = undefined;
    std.mem.writeInt(u256, &r_buf, r, .big);
    std.mem.writeInt(u256, &s_buf, s, .big);
    @memcpy(sig[0..32], &r_buf);
    @memcpy(sig[32..64], &s_buf);

    const ctx = secp_wrapper.getContext() orelse return null;
    return ctx.ecrecover(hash, sig, recid);
}

/// Sign a transaction with a secret key and fill in tx.v, tx.r, tx.s.
/// Returns the sender address.
fn signTx(alloc: std.mem.Allocator, tx: *input.TxInput, chain_id: u64) !?input.Address {
    const seckey = tx.secret_key orelse return null;

    const hash = try signingHash(alloc, tx, chain_id);
    const ctx = secp_wrapper.getContext() orelse return null;
    const result = ctx.sign(hash, seckey) orelse return null;

    // Decode r, s from compact sig
    const r = std.mem.readInt(u256, result.sig[0..32], .big);
    const s = std.mem.readInt(u256, result.sig[32..64], .big);
    tx.r = r;
    tx.s = s;

    // Compute v
    tx.v = switch (tx.type) {
        0 => if (tx.protected and chain_id > 0)
            2 * @as(u256, chain_id) + 35 + result.recid
        else
            @as(u256, 27 + result.recid),
        else => result.recid, // yParity
    };

    // Now recover sender from the signature we just computed
    return recoverSender(alloc, tx, chain_id);
}

/// Compute CREATE address: keccak256(RLP([sender, nonce]))[12:]
fn createAddress(alloc: std.mem.Allocator, sender: input.Address, nonce: u64) !input.Address {
    const items = [_][]const u8{
        try rlp.encodeBytes(alloc, &sender),
        try rlp.encodeU64(alloc, nonce),
    };
    const encoded = try rlp.encodeList(alloc, &items);
    const hash = rlp.keccak256(encoded);
    var addr: input.Address = undefined;
    @memcpy(&addr, hash[12..32]);
    return addr;
}

// ─── Pre-state loader ─────────────────────────────────────────────────────────

fn buildDb(
    alloc: std.mem.Allocator,
    pre_alloc: std.AutoHashMapUnmanaged(input.Address, input.AllocAccount),
    block_hashes: []const input.BlockHashEntry,
) !database_mod.InMemoryDB {
    var db = database_mod.InMemoryDB.init(std.heap.c_allocator);

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

    // Register block hashes for BLOCKHASH opcode
    for (block_hashes) |bhe| {
        try db.insertBlockHash(bhe.number, bhe.hash);
    }

    _ = alloc;
    return db;
}

// ─── Context setup ────────────────────────────────────────────────────────────

fn buildBlockEnv(env: input.Env) context_mod.BlockEnv {
    var block = context_mod.BlockEnv.default();
    block.number = @as(primitives.U256, env.number);
    block.timestamp = @as(primitives.U256, env.timestamp);
    block.gas_limit = env.gas_limit;
    block.beneficiary = env.coinbase;
    block.basefee = env.base_fee orelse 0;
    block.difficulty = env.difficulty;
    block.prevrandao = env.random;
    // Blob gas — compute blob_gasprice via fake_exponential, not hardcode 1
    if (env.excess_blob_gas) |ebg| {
        block.setBlobExcessGasAndPrice(ebg, primitives.BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE);
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
    pre_alloc: std.AutoHashMapUnmanaged(input.Address, input.AllocAccount),
    env: input.Env,
    txs: []input.TxInput,
    spec: primitives.SpecId,
    chain_id: u64,
    reward: i64, // mining reward in wei; -1 = disabled
) !TransitionResult {
    // ── Build DB and EVM context ──────────────────────────────────────────────
    const db = try buildDb(arena, pre_alloc, env.block_hashes);
    // Context takes DB by value (moves into journal)
    var ctx = context_mod.Context.new(db, spec);
    ctx.block = buildBlockEnv(env);
    ctx.cfg.chain_id = chain_id;
    ctx.cfg.disable_base_fee = (env.base_fee == null);

    // Shared instruction/precompile tables (fork-constant within a block)
    var instructions = handler_mod.Instructions.new(spec);
    var precompiles = handler_mod.Precompiles.new(spec);

    var receipts = std.ArrayListUnmanaged(Receipt){};
    var rejected = std.ArrayListUnmanaged(RejectedTx){};
    var cumulative_gas: u64 = 0;
    var block_bloom = bloom.ZERO;
    var total_blob_gas: u64 = 0;
    var log_index_global: u64 = 0;

    // ── Execute each transaction ──────────────────────────────────────────────
    for (txs, 0..) |*tx, tx_idx| {
        // 1. Determine sender
        var sender: input.Address = undefined;
        const maybe_sender: ?input.Address = blk: {
            if (tx.secret_key != null and (tx.r == null or (tx.r.? == 0 and tx.s.? == 0))) {
                break :blk try signTx(arena, tx, chain_id);
            }
            if (tx.r != null and tx.s != null and (tx.r.? != 0 or tx.s.? != 0)) {
                break :blk try recoverSender(arena, tx, chain_id);
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
        const tx_hash_val = txHash(arena, tx, chain_id) catch [_]u8{0} ** 32;

        // 3. Set up TxEnv
        ctx.tx.caller = sender;
        ctx.tx.nonce = tx.nonce orelse 0;
        ctx.tx.gas_limit = tx.gas;
        ctx.tx.value = tx.value;
        ctx.tx.tx_type = tx.type;

        // Gas pricing
        switch (tx.type) {
            2, 3, 4 => {
                // EIP-1559 (type 2), EIP-4844 (type 3), EIP-7702 (type 4): max_fee_per_gas + priority fee
                ctx.tx.gas_price = tx.max_fee_per_gas orelse 0;
                ctx.tx.gas_priority_fee = tx.max_priority_fee_per_gas;
            },
            else => {
                ctx.tx.gas_price = tx.gas_price orelse tx.max_fee_per_gas orelse 0;
                ctx.tx.gas_priority_fee = null;
            },
        }

        // EIP-4844: pass blob hashes and max fee per blob gas to the EVM context
        if (ctx.tx.blob_hashes) |*old_bh| old_bh.deinit(std.heap.c_allocator);
        if (tx.type == 3 and tx.blob_versioned_hashes.len > 0) {
            var blob_list = std.ArrayList(primitives.Hash){};
            blob_list.appendSlice(std.heap.c_allocator, tx.blob_versioned_hashes) catch {};
            ctx.tx.blob_hashes = blob_list;
            ctx.tx.max_fee_per_blob_gas = tx.max_fee_per_blob_gas orelse 0;
        } else {
            ctx.tx.blob_hashes = null;
            ctx.tx.max_fee_per_blob_gas = 0;
        }

        // EIP-7702: populate authorization list for type 4 transactions
        if (ctx.tx.authorization_list) |*old_al| old_al.deinit(std.heap.c_allocator);
        if (tx.type == 4 and tx.authorization_list.len > 0) {
            var auth_list = std.ArrayList(context_mod.Either){};
            for (tx.authorization_list) |ai| {
                const recovered = context_mod.RecoveredAuthorization.newUnchecked(
                    context_mod.Authorization{
                        .chain_id = ai.chain_id,
                        .address = ai.address,
                        .nonce = ai.nonce,
                    },
                    if (ai.signer) |s|
                        context_mod.RecoveredAuthority{ .Valid = s }
                    else
                        context_mod.RecoveredAuthority.Invalid,
                );
                auth_list.append(std.heap.c_allocator, context_mod.Either{ .Right = recovered }) catch {};
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

        // Calldata — use c_allocator to match TxEnv.deinit expectations
        ctx.tx.data = null;
        if (tx.data.len > 0) {
            var data_list = std.ArrayList(u8){};
            data_list.appendSlice(std.heap.c_allocator, tx.data) catch {
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
                    item.storage_keys.append(std.heap.c_allocator, sk) catch {};
                }
                al_items.append(std.heap.c_allocator, item) catch {};
            }
            ctx.tx.access_list = context_mod.AccessList{ .items = al_items };
        } else {
            ctx.tx.access_list = context_mod.AccessList{ .items = null };
        }

        // EIP-7702: type 4 transaction with empty authorization list is invalid.
        if (tx.type == 4 and tx.authorization_list.len == 0) {
            ctx.journaled_state.discardTx();
            try rejected.append(arena, .{ .index = tx_idx, .err = "type 4 transaction with empty authorization list" });
            if (ctx.tx.data) |*d| d.deinit(std.heap.c_allocator);
            ctx.tx.data = null;
            ctx.tx.access_list.deinit();
            if (ctx.tx.blob_hashes) |*bh| bh.deinit(std.heap.c_allocator);
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
                if (ctx.tx.data) |*d| d.deinit(std.heap.c_allocator);
                ctx.tx.data = null;
                ctx.tx.access_list.deinit();
                if (ctx.tx.blob_hashes) |*bh| bh.deinit(std.heap.c_allocator);
                ctx.tx.blob_hashes = null;
                if (ctx.tx.authorization_list) |*al| al.deinit(std.heap.c_allocator);
                ctx.tx.authorization_list = null;
                continue;
            };
            const sender_info = sender_load.data.info;
            const tx_nonce = tx.nonce orelse 0;
            if (sender_info.nonce != tx_nonce) {
                ctx.journaled_state.discardTx();
                const err_msg = std.fmt.allocPrint(arena, "nonce mismatch: have {}, want {}", .{ sender_info.nonce, tx_nonce }) catch "nonce error";
                try rejected.append(arena, .{ .index = tx_idx, .err = err_msg });
                if (ctx.tx.data) |*d| d.deinit(std.heap.c_allocator);
                ctx.tx.data = null;
                ctx.tx.access_list.deinit();
                if (ctx.tx.blob_hashes) |*bh| bh.deinit(std.heap.c_allocator);
                ctx.tx.blob_hashes = null;
                if (ctx.tx.authorization_list) |*al| al.deinit(std.heap.c_allocator);
                ctx.tx.authorization_list = null;
                continue;
            }
            const egp_check = effectiveGasPrice(tx, env.base_fee orelse 0);
            const max_gas_fee: u256 = @as(u256, tx.gas) * @as(u256, egp_check);
            // EIP-4844: blob cost = blob_count * GAS_PER_BLOB * max_fee_per_blob_gas
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
                if (ctx.tx.data) |*d| d.deinit(std.heap.c_allocator);
                ctx.tx.data = null;
                ctx.tx.access_list.deinit();
                if (ctx.tx.blob_hashes) |*bh| bh.deinit(std.heap.c_allocator);
                ctx.tx.blob_hashes = null;
                if (ctx.tx.authorization_list) |*al| al.deinit(std.heap.c_allocator);
                ctx.tx.authorization_list = null;
                continue;
            }
        }

        // 4. Execute
        var frame_stack = handler_mod.FrameStack.new();
        var evm = handler_mod.Evm.init(&ctx, null, &instructions, &precompiles, &frame_stack);

        var exec_result = handler_mod.ExecuteEvm.execute(&evm) catch |err| {
            // Validation or system error: discard any partial state
            ctx.journaled_state.discardTx();
            // Clean up tx data
            if (ctx.tx.data) |*d| d.deinit(std.heap.c_allocator);
            ctx.tx.data = null;
            ctx.tx.access_list.deinit();
            if (ctx.tx.blob_hashes) |*bh| bh.deinit(std.heap.c_allocator);
            ctx.tx.blob_hashes = null;
            if (ctx.tx.authorization_list) |*al| al.deinit(std.heap.c_allocator);
            ctx.tx.authorization_list = null;

            const err_msg = std.fmt.allocPrint(arena, "{}", .{err}) catch "execution error";
            try rejected.append(arena, .{ .index = tx_idx, .err = err_msg });
            continue;
        };

        // Clean up tx data (commitTx already happened inside execute)
        if (ctx.tx.data) |*d| d.deinit(std.heap.c_allocator);
        ctx.tx.data = null;
        ctx.tx.access_list.deinit();
        if (ctx.tx.blob_hashes) |*bh| bh.deinit(std.heap.c_allocator);
        ctx.tx.blob_hashes = null;
        if (ctx.tx.authorization_list) |*al| al.deinit(std.heap.c_allocator);
        ctx.tx.authorization_list = null;

        // 5. Build receipt
        const gas_used = exec_result.gas_used;
        cumulative_gas += gas_used;

        const status: u8 = if (exec_result.status == .Success) 1 else 0;
        const egp = effectiveGasPrice(tx, env.base_fee orelse 0);

        // Contract address for CREATE
        const contract_addr: ?input.Address = if (tx.to == null and status == 1)
            createAddress(arena, sender, tx.nonce orelse 0) catch null
        else
            null;

        // Build logs for this receipt
        const logs_start = log_index_global;
        var receipt_logs = std.ArrayListUnmanaged(Log){};
        var receipt_bloom = bloom.ZERO;

        for (exec_result.logs.items) |log| {
            // Convert topics from ArrayList to []Hash
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

        // Blob gas tracking
        if (tx.type == 3) {
            const blobs: u64 = @intCast(tx.blob_versioned_hashes.len);
            total_blob_gas += blobs * 131_072; // GAS_PER_BLOB
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
                if (ctx.block.blob_excess_gas_and_price) |bep| @as(u128, bep.blob_gasprice) else null
            else null,
        });

        // Free execution result logs (exec_result.logs is an ArrayList we own)
        exec_result.logs.deinit(std.heap.c_allocator);
    }

    // ── Apply mining reward ───────────────────────────────────────────────────
    if (reward >= 0) {
        const reward_wei: primitives.U256 = @intCast(reward);
        ctx.journaled_state.inner.balanceIncr(
            &ctx.journaled_state.database,
            env.coinbase,
            reward_wei,
        ) catch {};
        // Commit the reward as a synthetic "transaction"
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

    // ── Extract post-state ────────────────────────────────────────────────────
    const post_alloc = try extractPostState(arena, pre_alloc, &ctx);

    return TransitionResult{
        .alloc = post_alloc,
        .receipts = try receipts.toOwnedSlice(arena),
        .rejected = try rejected.toOwnedSlice(arena),
        .cumulative_gas = cumulative_gas,
        .block_bloom = block_bloom,
        .current_base_fee = env.base_fee,
        .excess_blob_gas = env.excess_blob_gas,
        .blob_gas_used = total_blob_gas,
        .txs = txs,
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
        };
        // Clone storage
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

        // Get or create post-alloc entry (base from pre-state if exists)
        var acct = post.get(addr) orelse input.AllocAccount{};

        // Update basic fields
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
            // Account has real code — get bytes from embedded code or DB
            if (account.info.code) |bc| {
                if (bc == .eip7702) {
                    // EIP-7702 delegation: 0xEF 0x01 0x00 <20-byte address>
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
            // Empty code: always output empty bytes
            acct.code = &.{};
        }

        // Update storage: merge pre-state slots with journal modifications
        var stor_it = account.storage.iterator();
        while (stor_it.next()) |slot| {
            const key = slot.key_ptr.*;
            const present = slot.value_ptr.*.present_value;
            if (present == 0) {
                _ = acct.storage.remove(key);
            } else {
                try acct.storage.put(arena, key, present);
            }
        }

        // EIP-161: remove empty accounts (nonce=0, balance=0, no code, no storage)
        if (acct.nonce == 0 and acct.balance == 0 and acct.code.len == 0 and acct.storage.count() == 0) {
            _ = post.remove(addr);
            continue;
        }

        try post.put(arena, addr, acct);
    }

    return post;
}
