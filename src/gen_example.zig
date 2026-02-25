//! Generate examples/block.json and examples/witness.json.
//!
//! Builds a minimal synthetic state trie containing one account:
//!   address: 0x0000000000000000000000000000000000000001
//!   nonce:   5
//!   balance: 1_000_000_000 wei
//!
//! The account trie is a single leaf node (no branches).  The witness pool
//! contains that one leaf node.  Running the main binary against these files
//! exercises the complete Phase 1 + Phase 2 pipeline.

const std        = @import("std");
const primitives = @import("primitives");
const mpt        = @import("mpt");

// ─── Known constants ───────────────────────────────────────────────────────────

const KECCAK_EMPTY: primitives.Hash = .{
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
    0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
    0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
};

const EMPTY_TRIE_HASH: primitives.Hash = .{
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
};

// ─── Minimal RLP encoder (same logic as mpt/test.zig) ─────────────────────────

fn encBytes(buf: []u8, off: usize, data: []const u8) usize {
    var o = off;
    if (data.len == 0) {
        buf[o] = 0x80; return o + 1;
    } else if (data.len == 1 and data[0] <= 0x7f) {
        buf[o] = data[0]; return o + 1;
    } else if (data.len <= 55) {
        buf[o] = @intCast(0x80 + data.len); o += 1;
        @memcpy(buf[o..][0..data.len], data); return o + data.len;
    } else {
        std.debug.assert(data.len <= 255);
        buf[o] = 0xb8; buf[o + 1] = @intCast(data.len); o += 2;
        @memcpy(buf[o..][0..data.len], data); return o + data.len;
    }
}

fn encList(buf: []u8, off: usize, payload: []const u8) usize {
    var o = off;
    if (payload.len <= 55) {
        buf[o] = @intCast(0xc0 + payload.len); o += 1;
    } else {
        std.debug.assert(payload.len <= 255);
        buf[o] = 0xf8; buf[o + 1] = @intCast(payload.len); o += 2;
    }
    @memcpy(buf[o..][0..payload.len], payload);
    return o + payload.len;
}

fn buildAccountRlp(
    buf: []u8,
    nonce: u64, balance: u256,
    storage_root: primitives.Hash, code_hash: primitives.Hash,
) usize {
    var payload: [200]u8 = undefined;
    var pl: usize = 0;
    if (nonce == 0) { payload[pl] = 0x80; pl += 1; } else {
        var tmp: [8]u8 = undefined; var n = nonce; var nb: usize = 0;
        while (n > 0) : (nb += 1) { tmp[7 - nb] = @intCast(n & 0xff); n >>= 8; }
        pl = encBytes(&payload, pl, tmp[8 - nb ..]);
    }
    if (balance == 0) { payload[pl] = 0x80; pl += 1; } else {
        var tmp: [32]u8 = undefined; var b = balance; var nb: usize = 0;
        while (b > 0) : (nb += 1) { tmp[31 - nb] = @intCast(b & 0xff); b >>= 8; }
        pl = encBytes(&payload, pl, tmp[32 - nb ..]);
    }
    payload[pl] = 0xa0; pl += 1; @memcpy(payload[pl..][0..32], &storage_root); pl += 32;
    payload[pl] = 0xa0; pl += 1; @memcpy(payload[pl..][0..32], &code_hash);    pl += 32;
    return encList(buf, 0, payload[0..pl]);
}

fn buildLeafNode(buf: []u8, key_hash: primitives.Hash, value: []const u8) usize {
    var hp_key: [33]u8 = undefined;
    hp_key[0] = 0x20;
    @memcpy(hp_key[1..33], &key_hash);
    var payload: [512]u8 = undefined;
    var pl: usize = 0;
    pl = encBytes(&payload, pl, &hp_key);
    pl = encBytes(&payload, pl, value);
    return encList(buf, 0, payload[0..pl]);
}

// ─── main ──────────────────────────────────────────────────────────────────────

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Build a one-account state trie.
    var address: primitives.Address = @splat(0x00);
    address[19] = 0x01;

    const key_hash = mpt.keccak256(&address);

    var account_rlp: [200]u8 = undefined;
    const account_len = buildAccountRlp(
        &account_rlp, 5, 1_000_000_000, EMPTY_TRIE_HASH, KECCAK_EMPTY,
    );

    var leaf_node: [512]u8 = undefined;
    const leaf_len = buildLeafNode(&leaf_node, key_hash, account_rlp[0..account_len]);
    const leaf_bytes = leaf_node[0..leaf_len];
    const state_root = mpt.keccak256(leaf_bytes);

    const cwd = std.fs.cwd();
    try cwd.makePath("examples");

    // ── block.json ──────────────────────────────────────────────────────────
    const block_content = try std.fmt.allocPrint(allocator,
        \\{{
        \\  "number": 1,
        \\  "stateRoot": "0x{x}"
        \\}}
        \\
    , .{state_root});
    defer allocator.free(block_content);
    try cwd.writeFile(.{ .sub_path = "examples/block.json", .data = block_content });

    // ── witness.json ────────────────────────────────────────────────────────
    const witness_content = try std.fmt.allocPrint(allocator,
        \\{{
        \\  "state":   ["0x{x}"],
        \\  "codes":   [],
        \\  "keys":    ["0x{x}"],
        \\  "headers": []
        \\}}
        \\
    , .{
        leaf_bytes,
        address,
    });
    defer allocator.free(witness_content);
    try cwd.writeFile(.{ .sub_path = "examples/witness.json", .data = witness_content });

    std.debug.print("Generated examples/block.json and examples/witness.json\n", .{});
    std.debug.print("  address:    0x{x}\n", .{address});
    std.debug.print("  nonce:      5\n",     .{});
    std.debug.print("  balance:    1000000000\n", .{});
    std.debug.print("  state root: 0x{x}\n", .{state_root});
    std.debug.print("\nRun:  zig build run\n", .{});
}
