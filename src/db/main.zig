//! WitnessDatabase: stateless EVM database backed by a pre-built MPT NodeIndex.
//!
//! Serves account/storage reads via live MPT proof verification (O(log n) per read
//! via NodeIndex O(1) node lookups). Contract bytecodes are served via linear scan
//! over the (bounded) codes pool.
//!
//! Wired into execution via InMemoryDB.fallback (see database.FallbackFns).
//! zevm's EVM execution stack is hardcoded to InMemoryDB throughout; making it
//! fully generic would require refactoring the interpreter opcode system.  The
//! fallback vtable is the minimal workaround: InMemoryDB starts empty so every
//! read misses and falls through to WitnessDatabase.

const std = @import("std");
const primitives = @import("primitives");
const state = @import("state");
const bytecode = @import("bytecode");
const mpt = @import("mpt");
const types = @import("executor_types");
const database = @import("database");

pub const DbError = error{
    /// MPT proof verification failed — witness is inconsistent with state root.
    InvalidWitness,
};

const EMPTY_TRIE_HASH: primitives.Hash = .{
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
};

/// Stateless database built from a pre-built NodeIndex + pre-state root.
///
/// Used as a fallback on InMemoryDB for stateless block execution:
///   db.fallback = witness_db.buildFallback();
///
/// Implements duck-typed Database interface (same methods as InMemoryDB):
///   basic(address)              → ?AccountInfo
///   codeByHash(code_hash)       → Bytecode
///   storage(address, key)       → StorageValue
///   blockHash(number)           → Hash
pub const WitnessDatabase = struct {
    node_index: *const mpt.NodeIndex,
    pre_state_root: primitives.Hash,
    codes: []const []const u8,
    block_hashes: []const types.BlockHashEntry,

    const Self = @This();

    pub fn init(
        node_index: *const mpt.NodeIndex,
        pre_state_root: primitives.Hash,
        codes: []const []const u8,
        block_hashes: []const types.BlockHashEntry,
    ) Self {
        return .{
            .node_index = node_index,
            .pre_state_root = pre_state_root,
            .codes = codes,
            .block_hashes = block_hashes,
        };
    }

    // ── basic ───────────────────────────────────────────────────────────────

    pub fn basic(self: *Self, address: primitives.Address) !?state.AccountInfo {
        const account_state = mpt.verifyAccountIndexed(
            self.pre_state_root,
            address,
            self.node_index,
        ) catch return DbError.InvalidWitness;

        const as = account_state orelse return null;
        std.debug.print("DBG basic 0x{s} code_hash=0x{s}\n", .{ std.fmt.bytesToHex(address, .lower), std.fmt.bytesToHex(as.code_hash, .lower) });
        return state.AccountInfo{
            .balance = as.balance,
            .nonce = as.nonce,
            .code_hash = as.code_hash,
            .code = null, // served on demand via codeByHash
        };
    }

    // ── codeByHash ──────────────────────────────────────────────────────────

    pub fn codeByHash(self: *Self, code_hash: primitives.Hash) !bytecode.Bytecode {
        if (std.mem.eql(u8, &code_hash, &primitives.KECCAK_EMPTY)) {
            return bytecode.Bytecode.newLegacy(&.{});
        }
        for (self.codes) |code_bytes| {
            const h = mpt.keccak256(code_bytes);
            if (std.mem.eql(u8, &h, &code_hash)) {
                return bytecode.Bytecode.newLegacy(code_bytes);
            }
        }
        std.debug.print("DBG codeByHash MISS 0x{s} (codes_len={})\n", .{ std.fmt.bytesToHex(code_hash, .lower), self.codes.len });
        return bytecode.Bytecode.new();
    }

    // ── storage ─────────────────────────────────────────────────────────────

    pub fn storage(
        self: *Self,
        address: primitives.Address,
        index: primitives.StorageKey,
    ) !primitives.StorageValue {
        const account_state = mpt.verifyAccountIndexed(
            self.pre_state_root,
            address,
            self.node_index,
        ) catch return DbError.InvalidWitness;

        const storage_root = if (account_state) |as| as.storage_root else EMPTY_TRIE_HASH;
        const slot = u256ToHash(index);
        return mpt.verifyStorageIndexed(storage_root, slot, self.node_index) catch return DbError.InvalidWitness;
    }

    // ── blockHash ───────────────────────────────────────────────────────────

    pub fn blockHash(self: *Self, number: u64) !primitives.Hash {
        for (self.block_hashes) |bhe| {
            if (bhe.number == number) return bhe.hash;
        }
        return [_]u8{0} ** 32;
    }

    // ── FallbackFns builder ─────────────────────────────────────────────────

    /// Build a FallbackFns vtable that routes InMemoryDB fallback calls to this WitnessDatabase.
    pub fn buildFallback(self: *Self) database.FallbackFns {
        return .{
            .ctx = @ptrCast(self),
            .basic = basicFallback,
            .code_by_hash = codeByHashFallback,
            .storage = storageFallback,
            .block_hash = blockHashFallback,
        };
    }

    fn basicFallback(ctx: *anyopaque, address: primitives.Address) anyerror!?state.AccountInfo {
        const self: *Self = @ptrCast(@alignCast(ctx));
        return self.basic(address);
    }

    fn codeByHashFallback(ctx: *anyopaque, code_hash: primitives.Hash) anyerror!bytecode.Bytecode {
        const self: *Self = @ptrCast(@alignCast(ctx));
        return self.codeByHash(code_hash);
    }

    fn storageFallback(ctx: *anyopaque, address: primitives.Address, index: primitives.StorageKey) anyerror!primitives.StorageValue {
        const self: *Self = @ptrCast(@alignCast(ctx));
        return self.storage(address, index);
    }

    fn blockHashFallback(ctx: *anyopaque, number: u64) anyerror!primitives.Hash {
        const self: *Self = @ptrCast(@alignCast(ctx));
        return self.blockHash(number);
    }
};

// ─── Private helpers ───────────────────────────────────────────────────────────

fn u256ToHash(value: u256) primitives.Hash {
    var out: primitives.Hash = @splat(0);
    var n = value;
    var i: usize = 32;
    while (i > 0) {
        i -= 1;
        out[i] = @intCast(n & 0xff);
        n >>= 8;
    }
    return out;
}
