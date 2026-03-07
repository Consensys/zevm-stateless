/// Decode raw RLP-encoded transaction bytes → []TxInput.
///
/// Dispatch:
///   raw[0] >= 0xc0  → legacy type-0 transaction (full RLP list)
///   raw[0] < 0x80   → typed transaction (type byte = raw[0], payload = raw[1..])
///
/// ECDSA sender recovery is NOT done here — transition() handles it internally.
const std = @import("std");
const types = @import("executor_types");
const mpt   = @import("mpt");
const rlp   = mpt.rlp;

pub const TxDecodeError = error{
    InvalidTx,
    OutOfMemory,
};

/// Decode a slice of raw wire-format transactions into TxInput structs.
pub fn decodeTxs(
    alloc: std.mem.Allocator,
    raw_txs: []const []const u8,
) ![]types.TxInput {
    const result = try alloc.alloc(types.TxInput, raw_txs.len);
    for (raw_txs, 0..) |raw, i| {
        result[i] = try decodeTx(alloc, raw);
    }
    return result;
}

// ─── Top-level dispatch ──────────────────────────────────────────────────────

fn decodeTx(alloc: std.mem.Allocator, raw: []const u8) !types.TxInput {
    if (raw.len == 0) return error.InvalidTx;
    if (raw[0] >= 0xc0) return decodeLegacyTx(alloc, raw);
    if (raw[0] < 0x80)  return decodeTypedTx(alloc, raw[0], raw[1..]);
    return error.InvalidTx;
}

// ─── Type 0 (legacy) ─────────────────────────────────────────────────────────
//   nonce, gasPrice, gas, to, value, data, v, r, s

fn decodeLegacyTx(alloc: std.mem.Allocator, raw: []const u8) !types.TxInput {
    const outer = try rlp.decodeItem(raw);
    var rest = switch (outer.item) {
        .list  => |p| p,
        .bytes => return error.InvalidTx,
    };

    const nonce     = try nextU64(&rest);
    const gas_price = try nextU128(&rest);
    const gas       = try nextU64(&rest);
    const to        = try nextAddr(&rest);
    const value     = try nextU256(&rest);
    const data      = try nextBytesCopy(alloc, &rest);
    const v         = try nextU256(&rest);
    const r         = try nextU256(&rest);
    const s         = try nextU256(&rest);

    const protected = v >= 35;
    const chain_id: ?u64 = if (v >= 35) @intCast((v - 35) / 2) else null;

    return types.TxInput{
        .type      = 0,
        .nonce     = nonce,
        .gas_price = gas_price,
        .gas       = gas,
        .to        = to,
        .value     = value,
        .data      = data,
        .v         = v,
        .r         = r,
        .s         = s,
        .protected = protected,
        .chain_id  = chain_id,
    };
}

// ─── Typed transactions (type 1–4) ───────────────────────────────────────────

fn decodeTypedTx(
    alloc: std.mem.Allocator,
    tx_type: u8,
    inner: []const u8,
) !types.TxInput {
    const outer = try rlp.decodeItem(inner);
    var rest = switch (outer.item) {
        .list  => |p| p,
        .bytes => return error.InvalidTx,
    };

    // All typed txs start with: chainId, nonce
    const chain_id = try nextU64(&rest);
    const nonce    = try nextU64(&rest);

    switch (tx_type) {
        // ── EIP-2930: chainId, nonce, gasPrice, gas, to, value, data,
        //             accessList, yParity, r, s
        1 => {
            const gas_price   = try nextU128(&rest);
            const gas         = try nextU64(&rest);
            const to          = try nextAddr(&rest);
            const value       = try nextU256(&rest);
            const data        = try nextBytesCopy(alloc, &rest);
            const access_list = try nextAccessList(alloc, &rest);
            const y_parity    = try nextU256(&rest);
            const r           = try nextU256(&rest);
            const s           = try nextU256(&rest);
            return types.TxInput{
                .type         = 1,
                .chain_id     = chain_id,
                .nonce        = nonce,
                .gas_price    = gas_price,
                .gas          = gas,
                .to           = to,
                .value        = value,
                .data         = data,
                .access_list  = access_list,
                .v            = y_parity,
                .r            = r,
                .s            = s,
                .protected    = true,
            };
        },

        // ── EIP-1559: chainId, nonce, maxPriorityFee, maxFee, gas, to, value,
        //             data, accessList, yParity, r, s
        2 => {
            const max_priority = try nextU128(&rest);
            const max_fee      = try nextU128(&rest);
            const gas          = try nextU64(&rest);
            const to           = try nextAddr(&rest);
            const value        = try nextU256(&rest);
            const data         = try nextBytesCopy(alloc, &rest);
            const access_list  = try nextAccessList(alloc, &rest);
            const y_parity     = try nextU256(&rest);
            const r            = try nextU256(&rest);
            const s            = try nextU256(&rest);
            return types.TxInput{
                .type                    = 2,
                .chain_id                = chain_id,
                .nonce                   = nonce,
                .max_priority_fee_per_gas = max_priority,
                .max_fee_per_gas         = max_fee,
                .gas                     = gas,
                .to                      = to,
                .value                   = value,
                .data                    = data,
                .access_list             = access_list,
                .v                       = y_parity,
                .r                       = r,
                .s                       = s,
                .protected               = true,
            };
        },

        // ── EIP-4844: chainId, nonce, maxPriorityFee, maxFee, gas, to, value,
        //             data, accessList, maxFeePerBlobGas, blobVersionedHashes,
        //             yParity, r, s
        3 => {
            const max_priority      = try nextU128(&rest);
            const max_fee           = try nextU128(&rest);
            const gas               = try nextU64(&rest);
            const to                = try nextAddr(&rest);
            const value             = try nextU256(&rest);
            const data              = try nextBytesCopy(alloc, &rest);
            const access_list       = try nextAccessList(alloc, &rest);
            const max_fee_blob_gas  = try nextU128(&rest);
            const blob_hashes       = try nextHashList(alloc, &rest);
            const y_parity          = try nextU256(&rest);
            const r                 = try nextU256(&rest);
            const s                 = try nextU256(&rest);
            return types.TxInput{
                .type                    = 3,
                .chain_id                = chain_id,
                .nonce                   = nonce,
                .max_priority_fee_per_gas = max_priority,
                .max_fee_per_gas         = max_fee,
                .gas                     = gas,
                .to                      = to,
                .value                   = value,
                .data                    = data,
                .access_list             = access_list,
                .max_fee_per_blob_gas    = max_fee_blob_gas,
                .blob_versioned_hashes   = blob_hashes,
                .v                       = y_parity,
                .r                       = r,
                .s                       = s,
                .protected               = true,
            };
        },

        // ── EIP-7702: chainId, nonce, maxPriorityFee, maxFee, gas, to, value,
        //             data, accessList, authorizationList, yParity, r, s
        4 => {
            const max_priority  = try nextU128(&rest);
            const max_fee       = try nextU128(&rest);
            const gas           = try nextU64(&rest);
            const to            = try nextAddr(&rest);
            const value         = try nextU256(&rest);
            const data          = try nextBytesCopy(alloc, &rest);
            const access_list   = try nextAccessList(alloc, &rest);
            const auth_list     = try nextAuthList(alloc, &rest);
            const y_parity      = try nextU256(&rest);
            const r             = try nextU256(&rest);
            const s             = try nextU256(&rest);
            return types.TxInput{
                .type                    = 4,
                .chain_id                = chain_id,
                .nonce                   = nonce,
                .max_priority_fee_per_gas = max_priority,
                .max_fee_per_gas         = max_fee,
                .gas                     = gas,
                .to                      = to,
                .value                   = value,
                .data                    = data,
                .access_list             = access_list,
                .authorization_list      = auth_list,
                .v                       = y_parity,
                .r                       = r,
                .s                       = s,
                .protected               = true,
            };
        },

        else => return error.InvalidTx,
    }
}

// ─── Field decoders (advance `rest` in place) ────────────────────────────────

/// Decode the next RLP item as a byte string; return a view (no copy).
fn nextBytesView(rest: *[]const u8) ![]const u8 {
    const r = try rlp.decodeItem(rest.*);
    const bytes = switch (r.item) {
        .bytes => |b| b,
        .list  => return error.InvalidTx,
    };
    rest.* = rest.*[r.consumed..];
    return bytes;
}

/// Decode the next RLP item as a byte string; return a heap copy.
fn nextBytesCopy(alloc: std.mem.Allocator, rest: *[]const u8) ![]const u8 {
    const bytes = try nextBytesView(rest);
    return alloc.dupe(u8, bytes);
}

fn nextU64(rest: *[]const u8) !u64 {
    return decodeUint64(try nextBytesView(rest));
}

fn nextU128(rest: *[]const u8) !u128 {
    return decodeUint128(try nextBytesView(rest));
}

fn nextU256(rest: *[]const u8) !u256 {
    return decodeUint256(try nextBytesView(rest));
}

/// Decode the next RLP item as a 20-byte address or empty bytes (CREATE).
fn nextAddr(rest: *[]const u8) !?types.Address {
    const r = try rlp.decodeItem(rest.*);
    rest.* = rest.*[r.consumed..];
    const bytes = switch (r.item) {
        .bytes => |b| b,
        .list  => return error.InvalidTx,
    };
    if (bytes.len == 0) return null;
    if (bytes.len != 20) return error.InvalidTx;
    var addr: types.Address = undefined;
    @memcpy(&addr, bytes);
    return addr;
}

/// Decode the next RLP item as an access list: [[addr, [key, ...]], ...]
fn nextAccessList(
    alloc: std.mem.Allocator,
    rest: *[]const u8,
) ![]types.AccessListEntry {
    const r = try rlp.decodeItem(rest.*);
    const al_payload = switch (r.item) {
        .list  => |p| p,
        .bytes => return error.InvalidTx,
    };
    rest.* = rest.*[r.consumed..];

    var entries = std.ArrayListUnmanaged(types.AccessListEntry){};
    var al = al_payload;
    while (al.len > 0) {
        const er = try rlp.decodeItem(al);
        const ep = switch (er.item) {
            .list  => |p| p,
            .bytes => return error.InvalidTx,
        };
        al = al[er.consumed..];

        var inner = ep;

        // address
        const addr_r = try rlp.decodeItem(inner);
        const addr_bytes = switch (addr_r.item) {
            .bytes => |b| b,
            .list  => return error.InvalidTx,
        };
        if (addr_bytes.len != 20) return error.InvalidTx;
        var addr: types.Address = undefined;
        @memcpy(&addr, addr_bytes);
        inner = inner[addr_r.consumed..];

        // storage keys
        const keys_r = try rlp.decodeItem(inner);
        const keys_payload = switch (keys_r.item) {
            .list  => |p| p,
            .bytes => return error.InvalidTx,
        };

        var keys = std.ArrayListUnmanaged(types.Hash){};
        var kp = keys_payload;
        while (kp.len > 0) {
            const kr = try rlp.decodeItem(kp);
            const key_bytes = switch (kr.item) {
                .bytes => |b| b,
                .list  => return error.InvalidTx,
            };
            if (key_bytes.len != 32) return error.InvalidTx;
            var key: types.Hash = undefined;
            @memcpy(&key, key_bytes);
            try keys.append(alloc, key);
            kp = kp[kr.consumed..];
        }

        try entries.append(alloc, .{
            .address      = addr,
            .storage_keys = try keys.toOwnedSlice(alloc),
        });
    }
    return entries.toOwnedSlice(alloc);
}

/// Decode the next RLP item as a list of 32-byte hashes (blob versioned hashes).
fn nextHashList(
    alloc: std.mem.Allocator,
    rest: *[]const u8,
) ![]types.Hash {
    const r = try rlp.decodeItem(rest.*);
    const payload = switch (r.item) {
        .list  => |p| p,
        .bytes => return error.InvalidTx,
    };
    rest.* = rest.*[r.consumed..];

    var hashes = std.ArrayListUnmanaged(types.Hash){};
    var p = payload;
    while (p.len > 0) {
        const hr = try rlp.decodeItem(p);
        const bytes = switch (hr.item) {
            .bytes => |b| b,
            .list  => return error.InvalidTx,
        };
        if (bytes.len != 32) return error.InvalidTx;
        var hash: types.Hash = undefined;
        @memcpy(&hash, bytes);
        try hashes.append(alloc, hash);
        p = p[hr.consumed..];
    }
    return hashes.toOwnedSlice(alloc);
}

/// Decode the next RLP item as an EIP-7702 authorization list.
/// Each entry: [chainId, address, nonce, yParity, r, s]
/// Signer recovery is deferred to transition(); signer is set to null here.
fn nextAuthList(
    alloc: std.mem.Allocator,
    rest: *[]const u8,
) ![]types.AuthorizationItem {
    const r = try rlp.decodeItem(rest.*);
    const payload = switch (r.item) {
        .list  => |p| p,
        .bytes => return error.InvalidTx,
    };
    rest.* = rest.*[r.consumed..];

    var items = std.ArrayListUnmanaged(types.AuthorizationItem){};
    var p = payload;
    while (p.len > 0) {
        const ir = try rlp.decodeItem(p);
        var ep = switch (ir.item) {
            .list  => |lp| lp,
            .bytes => return error.InvalidTx,
        };
        p = p[ir.consumed..];

        const auth_chain_id = try decodeUint256(try nextBytesView(&ep));
        const addr_bytes    = try nextBytesView(&ep);
        if (addr_bytes.len != 20) return error.InvalidTx;
        var auth_addr: types.Address = undefined;
        @memcpy(&auth_addr, addr_bytes);
        const auth_nonce    = try decodeUint64(try nextBytesView(&ep));
        const auth_y_parity = try decodeUint256(try nextBytesView(&ep));
        const auth_r        = try decodeUint256(try nextBytesView(&ep));
        const auth_s        = try decodeUint256(try nextBytesView(&ep));

        try items.append(alloc, .{
            .chain_id = auth_chain_id,
            .address  = auth_addr,
            .nonce    = auth_nonce,
            .signer   = null, // recovered later in transition()
            .y_parity = auth_y_parity,
            .r        = auth_r,
            .s        = auth_s,
        });
    }
    return items.toOwnedSlice(alloc);
}

// ─── Integer decoders ────────────────────────────────────────────────────────

fn decodeUint64(bytes: []const u8) error{InvalidTx}!u64 {
    if (bytes.len == 0) return 0;
    if (bytes.len > 8)  return error.InvalidTx;
    var result: u64 = 0;
    for (bytes) |b| result = (result << 8) | b;
    return result;
}

fn decodeUint128(bytes: []const u8) error{InvalidTx}!u128 {
    if (bytes.len == 0)  return 0;
    if (bytes.len > 16)  return error.InvalidTx;
    var result: u128 = 0;
    for (bytes) |b| result = (result << 8) | b;
    return result;
}

fn decodeUint256(bytes: []const u8) error{InvalidTx}!u256 {
    if (bytes.len == 0)  return 0;
    if (bytes.len > 32)  return error.InvalidTx;
    var result: u256 = 0;
    for (bytes) |b| result = (result << 8) | b;
    return result;
}
