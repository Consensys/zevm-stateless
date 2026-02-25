//! Merkle Patricia Trie: proof verification for stateless execution.
//!
//! Verifies that account and storage values are consistent with the
//! pre-state root declared in the witness before execution begins.
//!
//! All functions are allocation-free; 64-byte stack buffers are used for
//! nibble conversions and HP-decoded path fragments.

const std = @import("std");
const primitives = @import("primitives");
const input = @import("input");

const rlp     = @import("rlp.zig");
const nibbles = @import("nibbles.zig");
const node    = @import("node.zig");

// ─── Public types ──────────────────────────────────────────────────────────────

pub const MptError = error{
    /// Hash mismatch between proof nodes or proof is truncated.
    InvalidProof,
    /// Malformed node RLP structure (wrong item count, bad types).
    InvalidNode,
    /// Malformed RLP encoding.
    InvalidRlp,
    /// Leaf suffix does not match the remaining key nibbles.
    KeyMismatch,
    /// Malformed hex-prefix (compact) encoding.
    InvalidHp,
};

/// Decoded Ethereum account fields.
pub const AccountState = struct {
    nonce:        u64,
    balance:      u256,
    storage_root: primitives.Hash,
    code_hash:    primitives.Hash,
};

// ─── keccak256 ─────────────────────────────────────────────────────────────────

pub fn keccak256(data: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(data, &out, .{});
    return out;
}

// ─── verifyProof ───────────────────────────────────────────────────────────────

/// Traverse a Merkle proof for `key_hash` against `root_hash`.
///
/// `key_hash` is the keccak256 of the raw key (32 bytes → 64 nibbles).
/// Returns the leaf value bytes on inclusion, or null on a valid
/// non-inclusion proof (empty branch child or mismatched leaf suffix).
pub fn verifyProof(
    root_hash: primitives.Hash,
    key_hash:  primitives.Hash,
    proof:     []const []const u8,
) MptError!?[]const u8 {
    // 1. Convert key to nibbles on the stack.
    var key_nibbles: [64]u8 = undefined;
    nibbles.bytesToNibbles(&key_hash, &key_nibbles);

    // 2. Expected linkage for the next proof node.
    const ExpectedRef = union(enum) {
        hash:        [32]u8,
        inline_node: []const u8,
    };
    var expected: ExpectedRef = .{ .hash = root_hash };
    var pos: usize = 0;

    // 3. Walk the proof.
    for (proof) |node_rlp| {
        // Verify hash / byte linkage to the previous node's child reference.
        switch (expected) {
            .hash => |h| {
                const computed = keccak256(node_rlp);
                if (!std.mem.eql(u8, &computed, &h)) return error.InvalidProof;
            },
            .inline_node => |inl| {
                if (!std.mem.eql(u8, node_rlp, inl)) return error.InvalidProof;
            },
        }

        const decoded = node.decodeNode(node_rlp) catch |err| switch (err) {
            error.InvalidRlp  => return error.InvalidRlp,
            error.InvalidNode => return error.InvalidNode,
        };

        switch (decoded) {
            .branch => |b| {
                if (pos >= 64) return error.InvalidProof;
                const nibble = key_nibbles[pos];
                pos += 1;
                switch (b.children[nibble]) {
                    .empty => return null, // valid non-inclusion
                    .hash  => |h|   expected = .{ .hash = h },
                    .inline_node => |inl| expected = .{ .inline_node = inl },
                }
            },

            .extension => |e| {
                // HP-decode the shared prefix into a stack buffer.
                var path_buf: [128]u8 = undefined;
                const hp = nibbles.hpDecode(e.prefix, &path_buf) catch return error.InvalidHp;
                const prefix_nibs = path_buf[0..hp.len];
                if (pos + prefix_nibs.len > 64) return error.InvalidProof;
                if (!std.mem.eql(u8, prefix_nibs, key_nibbles[pos .. pos + prefix_nibs.len])) {
                    return error.InvalidProof;
                }
                pos += prefix_nibs.len;
                switch (e.child) {
                    .empty => return null,
                    .hash  => |h|   expected = .{ .hash = h },
                    .inline_node => |inl| expected = .{ .inline_node = inl },
                }
            },

            .leaf => |lf| {
                // HP-decode the remaining key suffix stored in this leaf.
                var path_buf: [128]u8 = undefined;
                const hp = nibbles.hpDecode(lf.key_end, &path_buf) catch return error.InvalidHp;
                const suffix_nibs = path_buf[0..hp.len];
                // If the suffix matches our remaining key → inclusion.
                // If it doesn't match → non-inclusion (a different key lives here).
                if (suffix_nibs.len != 64 - pos) return null;
                if (!std.mem.eql(u8, suffix_nibs, key_nibbles[pos..])) return null;
                return lf.value;
            },
        }
    }

    // Proof exhausted without reaching a leaf or empty branch → invalid.
    return error.InvalidProof;
}

// ─── verifyAccount ─────────────────────────────────────────────────────────────

/// Verify an account witness against `state_root`.
///
/// Returns the decoded AccountState on success, or null if the account is
/// absent from the trie (valid non-inclusion proof).
pub fn verifyAccount(
    state_root: primitives.Hash,
    witness:    input.AccountWitness,
) MptError!?AccountState {
    const key_hash = keccak256(&witness.address);
    const value_opt = try verifyProof(state_root, key_hash, witness.proof);
    const value = value_opt orelse return null;

    // The account value is RLP-encoded as a 4-item list:
    //   [nonce, balance, storageRoot, codeHash]
    const outer = rlp.decodeItem(value) catch return error.InvalidRlp;
    const payload = switch (outer.item) {
        .list  => |p| p,
        .bytes => return error.InvalidRlp,
    };
    var rest = payload;

    // nonce (u64, big-endian, stripped leading zeros)
    const nonce_r = rlp.decodeItem(rest) catch return error.InvalidRlp;
    const nonce = decodeUint64(itemBytes(nonce_r.item) orelse return error.InvalidRlp) catch return error.InvalidRlp;
    rest = rest[nonce_r.consumed..];

    // balance (u256, big-endian, stripped leading zeros)
    const balance_r = rlp.decodeItem(rest) catch return error.InvalidRlp;
    const balance = decodeUint256(itemBytes(balance_r.item) orelse return error.InvalidRlp) catch return error.InvalidRlp;
    rest = rest[balance_r.consumed..];

    // storageRoot (32 bytes)
    const storage_r = rlp.decodeItem(rest) catch return error.InvalidRlp;
    const storage_bytes = itemBytes(storage_r.item) orelse return error.InvalidRlp;
    if (storage_bytes.len != 32) return error.InvalidRlp;
    var storage_root: primitives.Hash = undefined;
    @memcpy(&storage_root, storage_bytes);
    rest = rest[storage_r.consumed..];

    // codeHash (32 bytes)
    const code_r = rlp.decodeItem(rest) catch return error.InvalidRlp;
    const code_bytes = itemBytes(code_r.item) orelse return error.InvalidRlp;
    if (code_bytes.len != 32) return error.InvalidRlp;
    var code_hash: primitives.Hash = undefined;
    @memcpy(&code_hash, code_bytes);

    return AccountState{
        .nonce        = nonce,
        .balance      = balance,
        .storage_root = storage_root,
        .code_hash    = code_hash,
    };
}

// ─── verifyStorage ─────────────────────────────────────────────────────────────

/// Verify a storage slot witness against `storage_root`.
///
/// Returns the decoded slot value as u256, or 0 for a valid non-inclusion
/// proof (empty storage slot).
pub fn verifyStorage(
    storage_root: primitives.Hash,
    witness:      input.StorageWitness,
) MptError!u256 {
    const key_hash = keccak256(&witness.slot);
    const value_opt = try verifyProof(storage_root, key_hash, witness.proof);
    const value = value_opt orelse return 0;

    // Storage values are RLP-encoded big-endian integers (0–32 bytes).
    const r = rlp.decodeItem(value) catch return error.InvalidRlp;
    const bytes = itemBytes(r.item) orelse return error.InvalidRlp;
    if (bytes.len > 32) return error.InvalidRlp;
    return decodeUint256(bytes) catch return error.InvalidRlp;
}

// ─── verifyWitness ─────────────────────────────────────────────────────────────

/// Verify all proofs in the witness, returning the proven pre-state root.
///
/// For each StorageWitness, the matching account's storage_root is obtained
/// by verifying the account proof first.
pub fn verifyWitness(witness: input.StateWitness) MptError!primitives.Hash {
    for (witness.accounts) |acc| {
        _ = try verifyAccount(witness.state_root, acc);
    }
    for (witness.storage) |slot| {
        // Find the matching account to obtain its storage root.
        var found_storage_root: ?primitives.Hash = null;
        for (witness.accounts) |acc| {
            if (std.mem.eql(u8, &acc.address, &slot.address)) {
                const maybe_state = try verifyAccount(witness.state_root, acc);
                if (maybe_state) |state| {
                    found_storage_root = state.storage_root;
                } else {
                    // Account absent → storage must also be absent (empty trie).
                    found_storage_root = EMPTY_TRIE_HASH;
                }
                break;
            }
        }
        const storage_root = found_storage_root orelse return error.InvalidProof;
        _ = try verifyStorage(storage_root, slot);
    }
    return witness.state_root;
}

// ─── Private helpers ───────────────────────────────────────────────────────────

/// keccak256 of RLP-encoded empty string — the Ethereum empty trie root.
const EMPTY_TRIE_HASH: primitives.Hash = .{
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
};

/// Extract the bytes slice from a bytes-variant RlpItem, or null for list.
fn itemBytes(item: rlp.RlpItem) ?[]const u8 {
    return switch (item) {
        .bytes => |b| b,
        .list  => null,
    };
}

/// Decode a big-endian unsigned integer from 0–8 bytes (strips leading zeros).
fn decodeUint64(bytes: []const u8) error{InvalidRlp}!u64 {
    if (bytes.len == 0) return 0;
    if (bytes.len > 8)  return error.InvalidRlp;
    var result: u64 = 0;
    for (bytes) |b| result = (result << 8) | b;
    return result;
}

/// Decode a big-endian unsigned integer from 0–32 bytes (strips leading zeros).
fn decodeUint256(bytes: []const u8) error{InvalidRlp}!u256 {
    if (bytes.len == 0)  return 0;
    if (bytes.len > 32) return error.InvalidRlp;
    var result: u256 = 0;
    for (bytes) |b| result = (result << 8) | b;
    return result;
}
