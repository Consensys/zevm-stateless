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
//!
//! block.json format: {"block":"0x<rlp_hex>"} — a post-Shanghai block whose
//! header stateRoot is set to the computed trie root.

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

/// keccak256(rlp([])) — used as the sha3Uncles field for an empty uncle list.
const SHA3_EMPTY_LIST: primitives.Hash = .{
    0x1d, 0xcc, 0x4d, 0xe8, 0xde, 0xc7, 0x5d, 0x7a,
    0xab, 0x85, 0xb5, 0x67, 0xb6, 0xcc, 0xd4, 0x1a,
    0xd3, 0x12, 0x45, 0x1b, 0x94, 0x8a, 0x74, 0x13,
    0xf0, 0xa1, 0x42, 0xfd, 0x40, 0xd4, 0x93, 0x47,
};

// ─── RLP encoder ───────────────────────────────────────────────────────────────

/// Encode `data` as an RLP byte string, writing into `buf[off..]`.
/// Handles all lengths up to ~64 KiB (2-byte length prefix).
fn encBytes(buf: []u8, off: usize, data: []const u8) usize {
    var o = off;
    if (data.len == 0) {
        buf[o] = 0x80; return o + 1;
    } else if (data.len == 1 and data[0] <= 0x7f) {
        buf[o] = data[0]; return o + 1;
    } else if (data.len <= 55) {
        buf[o] = @intCast(0x80 + data.len); o += 1;
        @memcpy(buf[o..][0..data.len], data); return o + data.len;
    } else if (data.len <= 0xff) {
        // 1-byte length
        buf[o] = 0xb8; buf[o + 1] = @intCast(data.len); o += 2;
        @memcpy(buf[o..][0..data.len], data); return o + data.len;
    } else {
        // 2-byte length (covers 256–65535 bytes; logsBloom = 256 bytes lands here)
        buf[o] = 0xb9;
        buf[o + 1] = @intCast((data.len >> 8) & 0xff);
        buf[o + 2] = @intCast(data.len & 0xff);
        o += 3;
        @memcpy(buf[o..][0..data.len], data); return o + data.len;
    }
}

/// Encode `payload` as an RLP list, writing into `buf[off..]`.
/// Handles payload lengths up to ~64 KiB (2-byte length prefix).
fn encList(buf: []u8, off: usize, payload: []const u8) usize {
    var o = off;
    if (payload.len <= 55) {
        buf[o] = @intCast(0xc0 + payload.len); o += 1;
    } else if (payload.len <= 0xff) {
        buf[o] = 0xf8; buf[o + 1] = @intCast(payload.len); o += 2;
    } else {
        buf[o] = 0xf9;
        buf[o + 1] = @intCast((payload.len >> 8) & 0xff);
        buf[o + 2] = @intCast(payload.len & 0xff);
        o += 3;
    }
    @memcpy(buf[o..][0..payload.len], payload);
    return o + payload.len;
}

/// Encode a uint64 as a minimal big-endian RLP integer (no leading zeros).
fn encUint(buf: []u8, off: usize, val: u64) usize {
    if (val == 0) { buf[off] = 0x80; return off + 1; }
    var tmp: [8]u8 = undefined;
    var v = val;
    var nb: usize = 0;
    while (v > 0) : (nb += 1) { tmp[7 - nb] = @intCast(v & 0xff); v >>= 8; }
    return encBytes(buf, off, tmp[8 - nb ..]);
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

/// Build a minimal but structurally valid post-Shanghai Ethereum block whose
/// header stateRoot is set to `state_root`.  All other fields use zero or
/// well-known empty values.  Returns the number of bytes written to `buf`.
///
/// Block = RLP([header, transactions, uncles, withdrawals])
///
/// Header fields used:
///   0  parentHash:       [0; 32]
///   1  sha3Uncles:       SHA3_EMPTY_LIST
///   2  coinbase:         [0; 20]
///   3  stateRoot:        state_root          ← proof anchor
///   4  transactionsRoot: EMPTY_TRIE_HASH
///   5  receiptsRoot:     EMPTY_TRIE_HASH
///   6  logsBloom:        [0; 256]
///   7  difficulty:       0 (PoS)
///   8  number:           1
///   9  gasLimit:         30_000_000
///  10  gasUsed:          0
///  11  timestamp:        1
///  12  extraData:        []
///  13  mixHash:          [0; 32]  (prevRandao)
///  14  nonce:            [0; 8]   (PoS fixed)
///  15  baseFeePerGas:    7
///  16  withdrawalsRoot:  EMPTY_TRIE_HASH
fn buildBlockRlp(buf: []u8, state_root: primitives.Hash) usize {
    const zero32:  [32]u8  = @splat(0x00);
    const zero20:  [20]u8  = @splat(0x00);
    const zero8:   [8]u8   = @splat(0x00);
    const zero256: [256]u8 = @splat(0x00);

    // ── Build header payload ─────────────────────────────────────────────────
    var hdr_payload: [700]u8 = undefined;
    var hp: usize = 0;

    hp = encBytes(&hdr_payload, hp, &zero32);          // 0: parentHash
    hp = encBytes(&hdr_payload, hp, &SHA3_EMPTY_LIST); // 1: sha3Uncles
    hp = encBytes(&hdr_payload, hp, &zero20);          // 2: coinbase
    hp = encBytes(&hdr_payload, hp, &state_root);      // 3: stateRoot
    hp = encBytes(&hdr_payload, hp, &EMPTY_TRIE_HASH); // 4: transactionsRoot
    hp = encBytes(&hdr_payload, hp, &EMPTY_TRIE_HASH); // 5: receiptsRoot
    hp = encBytes(&hdr_payload, hp, &zero256);         // 6: logsBloom (256 bytes)
    hdr_payload[hp] = 0x80; hp += 1;                  // 7: difficulty = 0
    hp = encUint(&hdr_payload, hp, 1);                 // 8: number = 1
    hp = encUint(&hdr_payload, hp, 30_000_000);        // 9: gasLimit
    hdr_payload[hp] = 0x80; hp += 1;                  // 10: gasUsed = 0
    hp = encUint(&hdr_payload, hp, 1);                 // 11: timestamp = 1
    hdr_payload[hp] = 0x80; hp += 1;                  // 12: extraData = []
    hp = encBytes(&hdr_payload, hp, &zero32);          // 13: mixHash (prevRandao)
    hp = encBytes(&hdr_payload, hp, &zero8);           // 14: nonce = 0
    hp = encUint(&hdr_payload, hp, 7);                 // 15: baseFeePerGas = 7
    hp = encBytes(&hdr_payload, hp, &EMPTY_TRIE_HASH); // 16: withdrawalsRoot

    var hdr_buf: [750]u8 = undefined;
    const hdr_len = encList(&hdr_buf, 0, hdr_payload[0..hp]);

    // ── Build block payload (header + 3 empty body lists) ───────────────────
    var block_payload: [800]u8 = undefined;
    var bp: usize = 0;

    @memcpy(block_payload[bp..][0..hdr_len], hdr_buf[0..hdr_len]);
    bp += hdr_len;
    block_payload[bp] = 0xc0; bp += 1; // transactions: empty list
    block_payload[bp] = 0xc0; bp += 1; // uncles: empty list
    block_payload[bp] = 0xc0; bp += 1; // withdrawals: empty list

    return encList(buf, 0, block_payload[0..bp]);
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

    // ── block.json — full RLP block ──────────────────────────────────────────
    var block_rlp_buf: [900]u8 = undefined;
    const block_rlp_len = buildBlockRlp(&block_rlp_buf, state_root);
    const block_rlp_bytes = block_rlp_buf[0..block_rlp_len];

    const block_content = try std.fmt.allocPrint(allocator,
        \\{{"block":"0x{x}"}}
        \\
    , .{block_rlp_bytes});
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
    std.debug.print("  block RLP:  {} bytes\n", .{block_rlp_len});
    std.debug.print("\nRun:  zig build run\n", .{});
}
