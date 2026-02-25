//! Integration tests for MPT proof verification.
//!
//! Test vectors are built synthetically at runtime using the same RLP rules
//! that the verifier decodes. Each test constructs a minimal trie structure,
//! computes the expected root hash via keccak256, then calls the public API.
//!
//! Run with: zig build test

const std = @import("std");
const primitives = @import("primitives");
const mpt        = @import("mpt");
const input      = @import("input");

// ─── Known constants ───────────────────────────────────────────────────────────

/// keccak256("") — used as codeHash for plain EOA accounts.
const KECCAK_EMPTY: primitives.Hash = .{
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
    0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
    0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
};

/// keccak256(RLP("")) — the root of an empty trie.
const EMPTY_TRIE_HASH: primitives.Hash = .{
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
};

// ─── Minimal RLP encoder (test-local, no allocation) ──────────────────────────

/// RLP-encode a byte string into `buf[off..]`.  Returns new offset.
/// Handles lengths 0–255 bytes; sufficient for our test data.
fn encBytes(buf: []u8, off: usize, data: []const u8) usize {
    var o = off;
    if (data.len == 0) {
        buf[o] = 0x80;
        return o + 1;
    } else if (data.len == 1 and data[0] <= 0x7f) {
        buf[o] = data[0];
        return o + 1;
    } else if (data.len <= 55) {
        buf[o] = @intCast(0x80 + data.len);
        o += 1;
        @memcpy(buf[o..][0..data.len], data);
        return o + data.len;
    } else {
        std.debug.assert(data.len <= 255);
        buf[o]     = 0xb8; // 0xb7 + 1 (one length byte follows)
        buf[o + 1] = @intCast(data.len);
        o += 2;
        @memcpy(buf[o..][0..data.len], data);
        return o + data.len;
    }
}

/// Wrap `payload` in an RLP list header, writing to `buf[off..]`.
/// Handles payload lengths 0–255 bytes.
fn encList(buf: []u8, off: usize, payload: []const u8) usize {
    var o = off;
    if (payload.len <= 55) {
        buf[o] = @intCast(0xc0 + payload.len);
        o += 1;
    } else {
        std.debug.assert(payload.len <= 255);
        buf[o]     = 0xf8; // 0xf7 + 1
        buf[o + 1] = @intCast(payload.len);
        o += 2;
    }
    @memcpy(buf[o..][0..payload.len], payload);
    return o + payload.len;
}

/// Build an RLP-encoded account: [nonce, balance, storageRoot, codeHash].
/// Writes into `buf`; returns the number of bytes written.
fn buildAccountRlp(
    buf:          []u8,
    nonce:        u64,
    balance:      u256,
    storage_root: primitives.Hash,
    code_hash:    primitives.Hash,
) usize {
    var payload: [200]u8 = undefined;
    var pl: usize = 0;

    // nonce: encode as minimal big-endian integer.
    if (nonce == 0) {
        payload[pl] = 0x80; // RLP zero = empty string
        pl += 1;
    } else {
        var tmp: [8]u8 = undefined;
        var n = nonce;
        var nb: usize = 0;
        while (n > 0) : (nb += 1) {
            tmp[7 - nb] = @intCast(n & 0xff);
            n >>= 8;
        }
        pl = encBytes(&payload, pl, tmp[8 - nb ..]);
    }

    // balance: minimal big-endian integer.
    if (balance == 0) {
        payload[pl] = 0x80;
        pl += 1;
    } else {
        var tmp: [32]u8 = undefined;
        var b = balance;
        var nb: usize = 0;
        while (b > 0) : (nb += 1) {
            tmp[31 - nb] = @intCast(b & 0xff);
            b >>= 8;
        }
        pl = encBytes(&payload, pl, tmp[32 - nb ..]);
    }

    // storageRoot (32 bytes).
    payload[pl] = 0xa0; // 0x80 + 32
    pl += 1;
    @memcpy(payload[pl..][0..32], &storage_root);
    pl += 32;

    // codeHash (32 bytes).
    payload[pl] = 0xa0;
    pl += 1;
    @memcpy(payload[pl..][0..32], &code_hash);
    pl += 32;

    return encList(buf, 0, payload[0..pl]);
}

/// Build an HP-encoded (compact) key for a full 64-nibble path (leaf, even).
///   hp_key[0] = 0x20, hp_key[1..33] = key_hash bytes
fn buildHpKey(hp_key: []u8, key_hash: primitives.Hash) void {
    hp_key[0] = 0x20; // leaf flag, even parity
    @memcpy(hp_key[1..33], &key_hash);
}

/// Build an RLP-encoded leaf node: list([hp_key, value]).
///   hp_key: 33 bytes  (flag byte + 32-byte key)
///   value:  raw bytes of the leaf value (already RLP-encoded for account/storage)
/// Returns the number of bytes written to `buf`.
fn buildLeafNode(buf: []u8, hp_key: []const u8, value: []const u8) usize {
    var payload: [512]u8 = undefined;
    var pl: usize = 0;
    pl = encBytes(&payload, pl, hp_key);
    pl = encBytes(&payload, pl, value);
    return encList(buf, 0, payload[0..pl]);
}

/// Build an all-empty branch node: list(0x80 × 17).
fn buildEmptyBranchNode(buf: []u8) usize {
    // 17 × 0x80 = 17 bytes payload; 17 < 56 → short list 0xd1.
    buf[0] = 0xd1; // 0xc0 + 17
    @memset(buf[1..18], 0x80);
    return 18;
}

// ─── Test 1: Account inclusion proof ──────────────────────────────────────────

test "verifyAccount inclusion — single-leaf trie" {
    // Address: 0x0000...0002
    var address: primitives.Address = @splat(0x00);
    address[19] = 0x02;

    const key_hash = mpt.keccak256(&address);

    // Build account RLP: nonce=5, balance=1000, storageRoot=EMPTY, codeHash=KECCAK_EMPTY
    var account_rlp: [200]u8 = undefined;
    const account_len = buildAccountRlp(
        &account_rlp,
        5,
        1000,
        EMPTY_TRIE_HASH,
        KECCAK_EMPTY,
    );
    const account_bytes = account_rlp[0..account_len];

    // Build HP key (leaf, even, full 64-nibble path).
    var hp_key: [33]u8 = undefined;
    buildHpKey(&hp_key, key_hash);

    // Build leaf node RLP.
    var leaf_node: [512]u8 = undefined;
    const leaf_len = buildLeafNode(&leaf_node, &hp_key, account_bytes);
    const leaf_bytes = leaf_node[0..leaf_len];

    // Root = keccak256 of leaf node.
    const root = mpt.keccak256(leaf_bytes);

    // Verify.
    const proof = &[_][]const u8{leaf_bytes};
    const w = input.AccountWitness{ .address = address, .proof = proof };
    const state = try mpt.verifyAccount(root, w);

    try std.testing.expect(state != null);
    try std.testing.expectEqual(@as(u64, 5), state.?.nonce);
    try std.testing.expectEqual(@as(u256, 1000), state.?.balance);
    try std.testing.expectEqualSlices(u8, &EMPTY_TRIE_HASH, &state.?.storage_root);
    try std.testing.expectEqualSlices(u8, &KECCAK_EMPTY, &state.?.code_hash);
}

// ─── Test 2: Storage inclusion proof ──────────────────────────────────────────

test "verifyStorage inclusion — single-leaf trie" {
    // Storage slot 1.
    var slot: primitives.Hash = @splat(0x00);
    slot[31] = 0x01;

    const key_hash = mpt.keccak256(&slot);

    // Storage value = 0xdeadbeef encoded as RLP integer: 0x84 0xde 0xad 0xbe 0xef
    const rlp_value = &[_]u8{ 0x84, 0xde, 0xad, 0xbe, 0xef };

    // Build HP key and leaf node.
    var hp_key: [33]u8 = undefined;
    buildHpKey(&hp_key, key_hash);

    var leaf_node: [256]u8 = undefined;
    const leaf_len = buildLeafNode(&leaf_node, &hp_key, rlp_value);
    const leaf_bytes = leaf_node[0..leaf_len];

    const storage_root = mpt.keccak256(leaf_bytes);

    // Dummy address (unused by verifyStorage, but required by StorageWitness).
    const dummy_address: primitives.Address = @splat(0x00);
    const proof = &[_][]const u8{leaf_bytes};
    const w = input.StorageWitness{
        .address = dummy_address,
        .slot    = slot,
        .proof   = proof,
    };
    const value = try mpt.verifyStorage(storage_root, w);
    try std.testing.expectEqual(@as(u256, 0xdeadbeef), value);
}

// ─── Test 3: Account non-inclusion ────────────────────────────────────────────

test "verifyAccount non-inclusion — empty branch root" {
    // A trie whose root is an all-empty branch node.
    // Any key's first nibble points to an empty child → non-inclusion.
    var branch: [18]u8 = undefined;
    const branch_len = buildEmptyBranchNode(&branch);
    const branch_bytes = branch[0..branch_len];

    const state_root = mpt.keccak256(branch_bytes);

    var address: primitives.Address = @splat(0x00);
    address[0] = 0xab;

    const proof = &[_][]const u8{branch_bytes};
    const w = input.AccountWitness{ .address = address, .proof = proof };
    const state = try mpt.verifyAccount(state_root, w);
    try std.testing.expect(state == null);
}

// ─── Test 4: Storage non-inclusion ────────────────────────────────────────────

test "verifyStorage non-inclusion — empty branch root" {
    var branch: [18]u8 = undefined;
    const branch_len = buildEmptyBranchNode(&branch);
    const branch_bytes = branch[0..branch_len];

    const storage_root = mpt.keccak256(branch_bytes);

    const dummy_address: primitives.Address = @splat(0x00);
    var slot: primitives.Hash = @splat(0x00);
    slot[31] = 0x99;

    const proof = &[_][]const u8{branch_bytes};
    const w = input.StorageWitness{
        .address = dummy_address,
        .slot    = slot,
        .proof   = proof,
    };
    const value = try mpt.verifyStorage(storage_root, w);
    try std.testing.expectEqual(@as(u256, 0), value);
}

// ─── Test 5: Tampered proof ────────────────────────────────────────────────────

test "verifyProof tampered node — returns InvalidProof" {
    // Build a valid single-leaf proof (reuse the storage test setup).
    var slot: primitives.Hash = @splat(0x00);
    slot[31] = 0x07;
    const key_hash = mpt.keccak256(&slot);

    const rlp_value = &[_]u8{ 0x01 }; // storage value = 1

    var hp_key: [33]u8 = undefined;
    buildHpKey(&hp_key, key_hash);

    var leaf_node: [256]u8 = undefined;
    const leaf_len = buildLeafNode(&leaf_node, &hp_key, rlp_value);

    const root = mpt.keccak256(leaf_node[0..leaf_len]);

    // Corrupt one byte in the middle of the leaf node.
    var tampered: [256]u8 = undefined;
    @memcpy(tampered[0..leaf_len], leaf_node[0..leaf_len]);
    tampered[leaf_len / 2] ^= 0xff; // flip all bits in the middle byte

    const bad_proof = &[_][]const u8{tampered[0..leaf_len]};
    const result = mpt.verifyProof(root, key_hash, bad_proof);
    try std.testing.expectError(error.InvalidProof, result);
}

// ─── Test 6: verifyWitness with one account ────────────────────────────────────

test "verifyWitness single account" {
    var address: primitives.Address = @splat(0x00);
    address[19] = 0x03;
    const key_hash = mpt.keccak256(&address);

    var account_rlp: [200]u8 = undefined;
    const account_len = buildAccountRlp(&account_rlp, 0, 0, EMPTY_TRIE_HASH, KECCAK_EMPTY);

    var hp_key: [33]u8 = undefined;
    buildHpKey(&hp_key, key_hash);

    var leaf_node: [512]u8 = undefined;
    const leaf_len = buildLeafNode(&leaf_node, &hp_key, account_rlp[0..account_len]);
    const leaf_bytes = leaf_node[0..leaf_len];

    const state_root = mpt.keccak256(leaf_bytes);

    const proof = &[_][]const u8{leaf_bytes};
    const w = input.StateWitness{
        .state_root = state_root,
        .accounts   = &[_]input.AccountWitness{
            .{ .address = address, .proof = proof },
        },
        .storage = &.{},
    };
    const proven_root = try mpt.verifyWitness(w);
    try std.testing.expectEqualSlices(u8, &state_root, &proven_root);
}
