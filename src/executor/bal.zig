/// Block Access List (BAL) RLP decoder — EIP-7928.
///
/// The BAL is committed in the execution payload as raw RLP bytes.
/// Actual on-wire format (confirmed from fixtures):
///   outer_list [
///     entry [
///       address (20 bytes),
///       storageChanges [ [slot:bytes, [[blockAccessIndex:u64, postValue:u256], ...]], ... ],
///       storageReads   [ slot:bytes, ... ],   // compact u256 (variable len, 0–32 bytes)
///       balanceChanges [ [blockAccessIndex:u64, postBalance:u256], ... ],
///       nonceChanges   [ [blockAccessIndex:u64, postNonce:u64], ... ],
///       codeChanges    [ [blockAccessIndex:u64, postCode:bytes], ... ],
///     ],
///     ...
///   ]
///
/// Public output is simplified:
///   nonce_changes:   last postNonce per entry ([]u64)
///   balance_changes: last postBalance per entry ([]u256)
///   code_changes:    last postCode per entry ([][]const u8)
///   storage_changes: last postValue per unique slot ([]StorageChange), sorted by slot
///   storage_reads:   slot bytes padded to [32]u8 ([]Hash), sorted
const std = @import("std");
const primitives = @import("primitives");
const mpt = @import("mpt");

pub const StorageChange = struct {
    slot: primitives.Hash,
    post_value: u256,
};

pub const BalEntry = struct {
    address: primitives.Address,
    nonce_changes: []u64,
    balance_changes: []u256,
    code_changes: [][]const u8,
    storage_changes: []StorageChange,
    storage_reads: []primitives.Hash,
};

/// Decode RLP-encoded block access list bytes into a slice of BalEntry.
/// Returns an empty slice for empty input.
pub fn decode(alloc: std.mem.Allocator, data: []const u8) ![]BalEntry {
    if (data.len == 0) return &.{};

    // Outer list
    const outer = mpt.rlp.decodeItem(data) catch return error.InvalidBAL;
    var rest = switch (outer.item) {
        .list => |p| p,
        .bytes => return error.InvalidBAL,
    };

    var entries = std.ArrayListUnmanaged(BalEntry){};

    while (rest.len > 0) {
        const entry_r = mpt.rlp.decodeItem(rest) catch return error.InvalidBAL;
        rest = rest[entry_r.consumed..];

        var ep = switch (entry_r.item) {
            .list => |p| p,
            .bytes => return error.InvalidBAL,
        };

        // address: 20-byte bytes item
        const addr_r = mpt.rlp.decodeItem(ep) catch return error.InvalidBAL;
        const addr_b = switch (addr_r.item) {
            .bytes => |b| b,
            .list => return error.InvalidBAL,
        };
        if (addr_b.len != 20) return error.InvalidBAL;
        var addr: primitives.Address = undefined;
        @memcpy(&addr, addr_b);
        ep = ep[addr_r.consumed..];

        // storageChanges: [ [slot_bytes, [[blockAccessIndex, postValue], ...]], ... ]
        const storage_changes = decodeStorageChangeList(alloc, &ep) catch |err| {
            std.debug.print("DBG BAL decodeStorageChangeList failed: {} ep_rem={}\n", .{ err, ep.len });
            return error.InvalidBAL;
        };

        // storageReads: [ slot_bytes, ... ]  (compact u256, variable len)
        const storage_reads = decodeCompactSlotList(alloc, &ep) catch |err| {
            std.debug.print("DBG BAL decodeCompactSlotList failed: {}\n", .{err});
            return error.InvalidBAL;
        };

        // balanceChanges: [ [blockAccessIndex, postBalance], ... ]
        const balance_changes = decodePairListU256(alloc, &ep) catch |err| {
            std.debug.print("DBG BAL decodePairListU256 failed: {}\n", .{err});
            return error.InvalidBAL;
        };

        // nonceChanges: [ [blockAccessIndex, postNonce], ... ]
        const nonce_changes = decodePairListU64(alloc, &ep) catch |err| {
            std.debug.print("DBG BAL decodePairListU64 failed: {}\n", .{err});
            return error.InvalidBAL;
        };

        // codeChanges: [ [blockAccessIndex, postCode], ... ]
        const code_changes = decodePairListBytes(alloc, &ep) catch |err| {
            std.debug.print("DBG BAL decodePairListBytes failed: {}\n", .{err});
            return error.InvalidBAL;
        };

        try entries.append(alloc, BalEntry{
            .address = addr,
            .nonce_changes = nonce_changes,
            .balance_changes = balance_changes,
            .code_changes = code_changes,
            .storage_changes = storage_changes,
            .storage_reads = storage_reads,
        });
    }

    return entries.toOwnedSlice(alloc);
}

// ─── Private decode helpers ───────────────────────────────────────────────────

/// Convert compact bytes (0–32 bytes, big-endian stripped) to a [32]u8 hash (left-zero-padded).
fn bytesTo32Padded(b: []const u8) !primitives.Hash {
    if (b.len > 32) return error.InvalidBAL;
    var out: primitives.Hash = @splat(0);
    if (b.len > 0) @memcpy(out[32 - b.len ..], b);
    return out;
}

/// Decode a list of [blockAccessIndex, u64_value] pairs; return last u64_value per entry.
fn decodePairListU64(alloc: std.mem.Allocator, ep: *[]const u8) ![]u64 {
    const list_r = mpt.rlp.decodeItem(ep.*) catch return error.InvalidBAL;
    ep.* = ep.*[list_r.consumed..];
    var payload = switch (list_r.item) {
        .list => |p| p,
        .bytes => return error.InvalidBAL,
    };
    var out = std.ArrayListUnmanaged(u64){};
    while (payload.len > 0) {
        const pair_r = mpt.rlp.decodeItem(payload) catch return error.InvalidBAL;
        payload = payload[pair_r.consumed..];
        var pair = switch (pair_r.item) {
            .list => |p| p,
            .bytes => return error.InvalidBAL,
        };
        // skip blockAccessIndex
        const idx_r = mpt.rlp.decodeItem(pair) catch return error.InvalidBAL;
        pair = pair[idx_r.consumed..];
        // decode postNonce
        const val_r = mpt.rlp.decodeItem(pair) catch return error.InvalidBAL;
        const val_b = switch (val_r.item) {
            .bytes => |b| b,
            .list => return error.InvalidBAL,
        };
        out.append(alloc, try bytesToU64(val_b)) catch return error.InvalidBAL;
    }
    return out.toOwnedSlice(alloc);
}

/// Decode a list of [blockAccessIndex, u256_value] pairs; return last u256_value per entry.
fn decodePairListU256(alloc: std.mem.Allocator, ep: *[]const u8) ![]u256 {
    if (ep.len > 0) {
        var tmp: [8]u8 = @splat(0);
        const n = @min(ep.len, 8);
        @memcpy(tmp[0..n], ep.*[0..n]);
        std.debug.print("DBG decodePairListU256 ep_len={} first8=0x{s}\n", .{ ep.len, std.fmt.bytesToHex(tmp, .lower) });
    }
    const list_r = mpt.rlp.decodeItem(ep.*) catch return error.InvalidBAL;
    ep.* = ep.*[list_r.consumed..];
    var payload = switch (list_r.item) {
        .list => |p| p,
        .bytes => return error.InvalidBAL,
    };
    var out = std.ArrayListUnmanaged(u256){};
    while (payload.len > 0) {
        const pair_r = mpt.rlp.decodeItem(payload) catch return error.InvalidBAL;
        payload = payload[pair_r.consumed..];
        var pair = switch (pair_r.item) {
            .list => |p| p,
            .bytes => return error.InvalidBAL,
        };
        const idx_r = mpt.rlp.decodeItem(pair) catch return error.InvalidBAL;
        pair = pair[idx_r.consumed..];
        const val_r = mpt.rlp.decodeItem(pair) catch return error.InvalidBAL;
        const val_b = switch (val_r.item) {
            .bytes => |b| b,
            .list => return error.InvalidBAL,
        };
        out.append(alloc, try bytesToU256(val_b)) catch return error.InvalidBAL;
    }
    return out.toOwnedSlice(alloc);
}

/// Decode a list of [blockAccessIndex, code_bytes] pairs; return last code per entry.
fn decodePairListBytes(alloc: std.mem.Allocator, ep: *[]const u8) ![][]const u8 {
    const list_r = mpt.rlp.decodeItem(ep.*) catch return error.InvalidBAL;
    ep.* = ep.*[list_r.consumed..];
    var payload = switch (list_r.item) {
        .list => |p| p,
        .bytes => return error.InvalidBAL,
    };
    var out = std.ArrayListUnmanaged([]const u8){};
    while (payload.len > 0) {
        const pair_r = mpt.rlp.decodeItem(payload) catch return error.InvalidBAL;
        payload = payload[pair_r.consumed..];
        var pair = switch (pair_r.item) {
            .list => |p| p,
            .bytes => return error.InvalidBAL,
        };
        const idx_r = mpt.rlp.decodeItem(pair) catch return error.InvalidBAL;
        pair = pair[idx_r.consumed..];
        const val_r = mpt.rlp.decodeItem(pair) catch return error.InvalidBAL;
        const val_b = switch (val_r.item) {
            .bytes => |b| b,
            .list => return error.InvalidBAL,
        };
        const copy = alloc.dupe(u8, val_b) catch return error.InvalidBAL;
        out.append(alloc, copy) catch return error.InvalidBAL;
    }
    return out.toOwnedSlice(alloc);
}

/// Decode storageChanges: [ [slot_bytes, [[idx, postValue], ...]], ... ]
/// Returns one StorageChange per unique slot (last postValue), sorted by slot.
fn decodeStorageChangeList(alloc: std.mem.Allocator, ep: *[]const u8) ![]StorageChange {
    const list_r = mpt.rlp.decodeItem(ep.*) catch return error.InvalidBAL;
    ep.* = ep.*[list_r.consumed..];
    var payload = switch (list_r.item) {
        .list => |p| p,
        .bytes => return error.InvalidBAL,
    };
    var out = std.ArrayListUnmanaged(StorageChange){};
    while (payload.len > 0) {
        const sc_r = mpt.rlp.decodeItem(payload) catch return error.InvalidBAL;
        payload = payload[sc_r.consumed..];
        var sc = switch (sc_r.item) {
            .list => |p| p,
            .bytes => return error.InvalidBAL,
        };

        // slot: compact bytes
        const slot_r = mpt.rlp.decodeItem(sc) catch return error.InvalidBAL;
        const slot_b = switch (slot_r.item) {
            .bytes => |b| b,
            .list => return error.InvalidBAL,
        };
        const slot = try bytesTo32Padded(slot_b);
        sc = sc[slot_r.consumed..];

        // slotChanges: [ [blockAccessIndex, postValue], ... ]
        const changes_r = mpt.rlp.decodeItem(sc) catch return error.InvalidBAL;
        var changes = switch (changes_r.item) {
            .list => |p| p,
            .bytes => return error.InvalidBAL,
        };

        var last_value: u256 = 0;
        while (changes.len > 0) {
            const change_r = mpt.rlp.decodeItem(changes) catch return error.InvalidBAL;
            changes = changes[change_r.consumed..];
            var change = switch (change_r.item) {
                .list => |p| p,
                .bytes => return error.InvalidBAL,
            };
            const idx_r = mpt.rlp.decodeItem(change) catch return error.InvalidBAL;
            change = change[idx_r.consumed..];
            const val_r = mpt.rlp.decodeItem(change) catch return error.InvalidBAL;
            const val_b = switch (val_r.item) {
                .bytes => |b| b,
                .list => return error.InvalidBAL,
            };
            last_value = try bytesToU256(val_b);
        }

        out.append(alloc, StorageChange{ .slot = slot, .post_value = last_value }) catch return error.InvalidBAL;
    }

    // Sort by slot (ascending, big-endian compare)
    std.mem.sort(StorageChange, out.items, {}, struct {
        pub fn lessThan(_: void, a: StorageChange, b: StorageChange) bool {
            return std.mem.lessThan(u8, &a.slot, &b.slot);
        }
    }.lessThan);

    return out.toOwnedSlice(alloc);
}

/// Decode storageReads: [ slot_bytes, ... ] — compact u256 slots (variable len 0–32 bytes).
/// Returns sorted []primitives.Hash (each slot padded to [32]u8).
fn decodeCompactSlotList(alloc: std.mem.Allocator, ep: *[]const u8) ![]primitives.Hash {
    const list_r = mpt.rlp.decodeItem(ep.*) catch return error.InvalidBAL;
    ep.* = ep.*[list_r.consumed..];
    var payload = switch (list_r.item) {
        .list => |p| p,
        .bytes => return error.InvalidBAL,
    };
    var out = std.ArrayListUnmanaged(primitives.Hash){};
    while (payload.len > 0) {
        const r = mpt.rlp.decodeItem(payload) catch return error.InvalidBAL;
        const b = switch (r.item) {
            .bytes => |bs| bs,
            .list => return error.InvalidBAL,
        };
        const h = try bytesTo32Padded(b);
        out.append(alloc, h) catch return error.InvalidBAL;
        payload = payload[r.consumed..];
    }

    // Sort by slot value (ascending)
    std.mem.sort(primitives.Hash, out.items, {}, struct {
        pub fn lessThan(_: void, a: primitives.Hash, b: primitives.Hash) bool {
            return std.mem.lessThan(u8, &a, &b);
        }
    }.lessThan);

    return out.toOwnedSlice(alloc);
}

fn bytesToU64(b: []const u8) !u64 {
    if (b.len > 8) return error.InvalidBAL;
    var v: u64 = 0;
    for (b) |byte| v = (v << 8) | byte;
    return v;
}

fn bytesToU256(b: []const u8) !u256 {
    if (b.len > 32) return error.InvalidBAL;
    var v: u256 = 0;
    for (b) |byte| v = (v << 8) | byte;
    return v;
}
