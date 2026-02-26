//! Merkle Patricia Trie: proof verification for stateless execution.
//!
//! Verification works against a flat node pool (from debug_executionWitness).
//! For each step, the next node is located by scanning the pool for an entry
//! whose keccak256 hash matches the expected reference — no pre-assembled
//! ordered proof paths are needed.
//!
//! All functions are allocation-free; stack buffers are used for nibble paths.

const std = @import("std");
const primitives = @import("primitives");
const input     = @import("input");

/// RLP decoder — also re-exported so callers (e.g. io.zig) can reuse it.
pub const rlp = @import("rlp.zig");
const nibbles = @import("nibbles.zig");
const node    = @import("node.zig");

// ─── Public types ──────────────────────────────────────────────────────────────

pub const MptError = error{
    /// No node in the pool hashes to the expected value, or pool exhausted.
    InvalidProof,
    /// Malformed node RLP structure (wrong item count, bad types).
    InvalidNode,
    /// Malformed RLP encoding.
    InvalidRlp,
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

// ─── findNode ──────────────────────────────────────────────────────────────────

/// Linear scan of the node pool for an entry whose keccak256 equals `hash`.
/// Returns the raw node bytes, or null if no match is found.
fn findNode(pool: []const []const u8, hash: primitives.Hash) ?[]const u8 {
    for (pool) |node_bytes| {
        if (std.mem.eql(u8, &keccak256(node_bytes), &hash)) return node_bytes;
    }
    return null;
}

// ─── verifyProof ───────────────────────────────────────────────────────────────

/// Traverse the trie for `key_hash` starting from `root_hash`, using the
/// flat `pool` of node preimages to resolve each hash reference.
///
/// Returns the leaf value bytes on inclusion, or null for a valid
/// non-inclusion proof (empty branch child or mismatched leaf suffix).
pub fn verifyProof(
    root_hash: primitives.Hash,
    key_hash:  primitives.Hash,
    pool:      []const []const u8,
) MptError!?[]const u8 {
    // Empty trie root: non-inclusion is provable without any pool nodes.
    if (std.mem.eql(u8, &root_hash, &EMPTY_TRIE_HASH)) return null;

    var key_nibbles: [64]u8 = undefined;
    nibbles.bytesToNibbles(&key_hash, &key_nibbles);

    // Tracks the next expected node: either a 32-byte hash (pool lookup)
    // or an inline RLP encoding (embedded directly in the parent node).
    const ExpectedRef = union(enum) {
        hash:        [32]u8,
        inline_node: []const u8,
    };
    var expected: ExpectedRef = .{ .hash = root_hash };
    var pos: usize = 0;

    while (true) {
        // Resolve the current node.
        const node_rlp: []const u8 = switch (expected) {
            .hash        => |h|   findNode(pool, h) orelse return error.InvalidProof,
            .inline_node => |inl| inl,
        };

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
                    .empty       => return null, // valid non-inclusion
                    .hash        => |h|   expected = .{ .hash = h },
                    .inline_node => |inl| expected = .{ .inline_node = inl },
                }
            },

            .extension => |e| {
                var path_buf: [128]u8 = undefined;
                const hp = nibbles.hpDecode(e.prefix, &path_buf) catch return error.InvalidHp;
                if (hp.is_leaf) return error.InvalidNode;
                const prefix_nibs = path_buf[0..hp.len];
                if (pos + prefix_nibs.len > 64) return error.InvalidProof;
                if (!std.mem.eql(u8, prefix_nibs, key_nibbles[pos .. pos + prefix_nibs.len]))
                    return null; // prefix diverges → valid non-inclusion
                pos += prefix_nibs.len;
                switch (e.child) {
                    .empty       => return error.InvalidNode,
                    .hash        => |h|   expected = .{ .hash = h },
                    .inline_node => |inl| expected = .{ .inline_node = inl },
                }
            },

            .leaf => |lf| {
                var path_buf: [128]u8 = undefined;
                const hp = nibbles.hpDecode(lf.key_end, &path_buf) catch return error.InvalidHp;
                if (!hp.is_leaf) return error.InvalidNode;
                const suffix_nibs = path_buf[0..hp.len];
                // Suffix must exactly match the remaining key nibbles.
                if (suffix_nibs.len != 64 - pos) return null;
                if (!std.mem.eql(u8, suffix_nibs, key_nibbles[pos..])) return null;
                return lf.value;
            },
        }
    }
}

// ─── verifyProofVerbose ────────────────────────────────────────────────────────

/// Like verifyProof but writes a one-line trace per trie node to `writer`.
///
/// Each line shows: node type, the hash used to locate it (or "(inline)" for
/// embedded nodes), and what was consumed — nibble index for branches,
/// number of skipped nibbles for extensions.
pub fn verifyProofVerbose(
    root_hash: primitives.Hash,
    key_hash:  primitives.Hash,
    pool:      []const []const u8,
    writer:    anytype,
) MptError!?[]const u8 {
    if (std.mem.eql(u8, &root_hash, &EMPTY_TRIE_HASH)) return null;

    var key_nibbles: [64]u8 = undefined;
    nibbles.bytesToNibbles(&key_hash, &key_nibbles);

    const ExpectedRef = union(enum) {
        hash:        [32]u8,
        inline_node: []const u8,
    };
    var expected: ExpectedRef = .{ .hash = root_hash };
    var pos: usize = 0;

    while (true) {
        const node_rlp: []const u8 = switch (expected) {
            .hash        => |h|   findNode(pool, h) orelse return error.InvalidProof,
            .inline_node => |inl| inl,
        };

        const decoded = node.decodeNode(node_rlp) catch |err| switch (err) {
            error.InvalidRlp  => return error.InvalidRlp,
            error.InvalidNode => return error.InvalidNode,
        };

        switch (decoded) {
            .branch => |b| {
                if (pos >= 64) return error.InvalidProof;
                const nibble = key_nibbles[pos];
                pos += 1;
                switch (expected) {
                    .hash        => |h| writer.print("        branch    0x{x}  nibble={x}\n", .{ h, nibble }) catch {},
                    .inline_node =>     writer.print("        branch    (inline)  nibble={x}\n", .{nibble}) catch {},
                }
                switch (b.children[nibble]) {
                    .empty       => return null,
                    .hash        => |h|   expected = .{ .hash = h },
                    .inline_node => |inl| expected = .{ .inline_node = inl },
                }
            },

            .extension => |e| {
                var path_buf: [128]u8 = undefined;
                const hp = nibbles.hpDecode(e.prefix, &path_buf) catch return error.InvalidHp;
                if (hp.is_leaf) return error.InvalidNode;
                const prefix_nibs = path_buf[0..hp.len];
                if (pos + prefix_nibs.len > 64) return error.InvalidProof;
                switch (expected) {
                    .hash        => |h| writer.print("        extension 0x{x}  skip={d}\n", .{ h, hp.len }) catch {},
                    .inline_node =>     writer.print("        extension (inline)  skip={d}\n", .{hp.len}) catch {},
                }
                if (!std.mem.eql(u8, prefix_nibs, key_nibbles[pos .. pos + prefix_nibs.len]))
                    return null;
                pos += prefix_nibs.len;
                switch (e.child) {
                    .empty       => return error.InvalidNode,
                    .hash        => |h|   expected = .{ .hash = h },
                    .inline_node => |inl| expected = .{ .inline_node = inl },
                }
            },

            .leaf => |lf| {
                var path_buf: [128]u8 = undefined;
                const hp = nibbles.hpDecode(lf.key_end, &path_buf) catch return error.InvalidHp;
                if (!hp.is_leaf) return error.InvalidNode;
                const suffix_nibs = path_buf[0..hp.len];
                if (suffix_nibs.len != 64 - pos) return null;
                if (!std.mem.eql(u8, suffix_nibs, key_nibbles[pos..])) return null;
                switch (expected) {
                    .hash        => |h| writer.print("        leaf      0x{x}\n", .{h}) catch {},
                    .inline_node =>     writer.print("        leaf      (inline)\n", .{}) catch {},
                }
                return lf.value;
            },
        }
    }
}

// ─── verifyAccount ─────────────────────────────────────────────────────────────

/// Verify that `address` is (or isn't) in the state trie at `state_root`,
/// using the flat `pool` of node preimages from the witness.
///
/// Returns the decoded AccountState on inclusion, or null on valid
/// non-inclusion (address provably absent from the trie).
pub fn verifyAccount(
    state_root: primitives.Hash,
    address:    primitives.Address,
    pool:       []const []const u8,
) MptError!?AccountState {
    const key_hash = keccak256(&address);
    const value = try verifyProof(state_root, key_hash, pool) orelse return null;

    // Account value is RLP list: [nonce, balance, storageRoot, codeHash]
    const outer = rlp.decodeItem(value) catch return error.InvalidRlp;
    const payload = switch (outer.item) {
        .list  => |p| p,
        .bytes => return error.InvalidRlp,
    };
    var rest = payload;

    const nonce_r   = rlp.decodeItem(rest) catch return error.InvalidRlp;
    const nonce     = decodeUint64(itemBytes(nonce_r.item) orelse return error.InvalidRlp)
        catch return error.InvalidRlp;
    rest = rest[nonce_r.consumed..];

    const balance_r = rlp.decodeItem(rest) catch return error.InvalidRlp;
    const balance   = decodeUint256(itemBytes(balance_r.item) orelse return error.InvalidRlp)
        catch return error.InvalidRlp;
    rest = rest[balance_r.consumed..];

    const storage_r = rlp.decodeItem(rest) catch return error.InvalidRlp;
    const sbytes    = itemBytes(storage_r.item) orelse return error.InvalidRlp;
    if (sbytes.len != 32) return error.InvalidRlp;
    var storage_root: primitives.Hash = undefined;
    @memcpy(&storage_root, sbytes);
    rest = rest[storage_r.consumed..];

    const code_r  = rlp.decodeItem(rest) catch return error.InvalidRlp;
    const cbytes  = itemBytes(code_r.item) orelse return error.InvalidRlp;
    if (cbytes.len != 32) return error.InvalidRlp;
    var code_hash: primitives.Hash = undefined;
    @memcpy(&code_hash, cbytes);

    return AccountState{
        .nonce        = nonce,
        .balance      = balance,
        .storage_root = storage_root,
        .code_hash    = code_hash,
    };
}

// ─── verifyStorage ─────────────────────────────────────────────────────────────

/// Verify that `slot` is (or isn't) in the storage trie at `storage_root`,
/// using the flat `pool` of node preimages.
///
/// Returns the decoded u256 value, or 0 for a valid non-inclusion proof.
pub fn verifyStorage(
    storage_root: primitives.Hash,
    slot:         primitives.Hash,
    pool:         []const []const u8,
) MptError!u256 {
    const key_hash = keccak256(&slot);
    const value = try verifyProof(storage_root, key_hash, pool) orelse return 0;

    const r     = rlp.decodeItem(value) catch return error.InvalidRlp;
    const bytes = itemBytes(r.item) orelse return error.InvalidRlp;
    if (bytes.len > 32) return error.InvalidRlp;
    return decodeUint256(bytes) catch return error.InvalidRlp;
}

// ─── verifyWitness ─────────────────────────────────────────────────────────────

/// Verify all account and storage proofs in the witness.
/// Returns the proven pre-state root (== witness.state_root).
///
/// Keys with length 20 are account addresses.
/// Keys with length 52 are address (20) + storage slot (32).
/// Keys with length 32 are standalone storage slots that belong to the
/// nearest preceding account address (20-byte key) in the array.
pub fn verifyWitness(witness: input.StateWitness) MptError!primitives.Hash {
    var current_addr: ?primitives.Address = null;

    for (witness.keys) |key| {
        if (key.len == 20) {
            var addr: primitives.Address = undefined;
            @memcpy(&addr, key[0..20]);
            current_addr = addr;
            _ = try verifyAccount(witness.state_root, addr, witness.nodes);

        } else if (key.len == 52) {
            var addr: primitives.Address = undefined;
            @memcpy(&addr, key[0..20]);
            current_addr = addr;
            var raw_slot: primitives.Hash = undefined;
            @memcpy(&raw_slot, key[20..52]);

            // Must verify the account first to get its storage_root.
            const account_state = try verifyAccount(witness.state_root, addr, witness.nodes);
            const storage_root = if (account_state) |as| as.storage_root else EMPTY_TRIE_HASH;
            _ = try verifyStorage(storage_root, raw_slot, witness.nodes);

        } else if (key.len == 32) {
            // Standalone slot: context account is the nearest preceding address key.
            if (current_addr) |addr| {
                var raw_slot: primitives.Hash = undefined;
                @memcpy(&raw_slot, key[0..32]);

                const account_state = try verifyAccount(witness.state_root, addr, witness.nodes);
                const storage_root = if (account_state) |as| as.storage_root else EMPTY_TRIE_HASH;
                _ = try verifyStorage(storage_root, raw_slot, witness.nodes);
            }
        }
    }
    return witness.state_root;
}

// ─── Private helpers ───────────────────────────────────────────────────────────

const EMPTY_TRIE_HASH: primitives.Hash = .{
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
};

fn itemBytes(item: rlp.RlpItem) ?[]const u8 {
    return switch (item) { .bytes => |b| b, .list => null };
}

fn decodeUint64(bytes: []const u8) error{InvalidRlp}!u64 {
    if (bytes.len == 0) return 0;
    if (bytes.len > 8)  return error.InvalidRlp;
    var result: u64 = 0;
    for (bytes) |b| result = (result << 8) | b;
    return result;
}

fn decodeUint256(bytes: []const u8) error{InvalidRlp}!u256 {
    if (bytes.len == 0)  return 0;
    if (bytes.len > 32) return error.InvalidRlp;
    var result: u256 = 0;
    for (bytes) |b| result = (result << 8) | b;
    return result;
}
