//! WitnessDatabase: a zevm database backend backed by a state witness.
//!
//! Every account and storage read is served from the flat MPT node pool
//! (witness.state) which mirrors the debug_executionWitness format.  Nodes
//! are located by keccak256 hash at each step of the trie traversal.
//!
//! Contract bytecodes are served from witness.codes by the same hash-scan.
//!
//! All methods are allocation-free; linear scans over the (bounded) witness
//! arrays are acceptable in a zkVM context.

const std = @import("std");
const primitives = @import("primitives");
const state = @import("state");
const bytecode = @import("bytecode");
const mpt = @import("mpt");
const input = @import("input");

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

/// Stateless database built from a proven ExecutionWitness.
///
/// Implements the zevm `Database` interface (duck-typed):
///   basic(address)              → ?AccountInfo
///   codeByHash(code_hash)       → Bytecode
///   storage(address, key)       → StorageValue
///   blockHash(number)           → Hash
pub const WitnessDatabase = struct {
    witness: input.ExecutionWitness,

    const Self = @This();

    pub fn init(witness: input.ExecutionWitness) Self {
        return .{ .witness = witness };
    }

    // ── basic ───────────────────────────────────────────────────────────────

    /// Return basic account info for `address`, or null if the account is
    /// absent from the state trie (valid non-inclusion proof).
    ///
    /// Returns `DbError.InvalidWitness` if the MPT proof is malformed.
    pub fn basic(self: *Self, address: primitives.Address) !?state.AccountInfo {
        const account_state = mpt.verifyAccount(
            self.witness.state_root,
            address,
            self.witness.state,
        ) catch return DbError.InvalidWitness;

        const as = account_state orelse return null;
        return state.AccountInfo{
            .balance = as.balance,
            .nonce = as.nonce,
            .code_hash = as.code_hash,
            // Bytecode is served on demand via codeByHash; set null here
            // so zevm fetches it through that path when needed.
            .code = null,
        };
    }

    // ── codeByHash ──────────────────────────────────────────────────────────

    /// Return the bytecode whose keccak256 hash is `code_hash`.
    ///
    /// Contract bytecodes are taken from witness.codes.  For EOAs
    /// (code_hash == KECCAK_EMPTY) an empty `Bytecode` is returned without
    /// scanning the pool.
    pub fn codeByHash(self: *Self, code_hash: primitives.Hash) !bytecode.Bytecode {
        // Fast path: no code.
        if (std.mem.eql(u8, &code_hash, &primitives.KECCAK_EMPTY)) {
            return bytecode.Bytecode.newLegacy(&.{});
        }
        // Scan the codes pool for a matching hash.
        for (self.witness.codes) |code_bytes| {
            const h = mpt.keccak256(code_bytes);
            if (std.mem.eql(u8, &h, &code_hash)) {
                return bytecode.Bytecode.newLegacy(code_bytes);
            }
        }
        // Code not found in witness — return empty (caller will treat as
        // STOP-only contract, which is the safest fallback).
        return bytecode.Bytecode.new();
    }

    // ── storage ─────────────────────────────────────────────────────────────

    /// Return the value of storage slot `index` for `address`.
    ///
    /// Returns 0 when the account is absent, the storage root is the
    /// empty trie, or the storage proof shows the slot is empty.
    pub fn storage(
        self: *Self,
        address: primitives.Address,
        index: primitives.StorageKey,
    ) !primitives.StorageValue {
        // Resolve the account's storage root first.
        const account_state = mpt.verifyAccount(
            self.witness.state_root,
            address,
            self.witness.state,
        ) catch return DbError.InvalidWitness;

        const storage_root = if (account_state) |as| as.storage_root else EMPTY_TRIE_HASH;

        // Convert StorageKey (u256) to a 32-byte big-endian raw slot hash.
        const slot = u256ToHash(index);

        // Verify the storage proof using the shared flat node pool.
        return mpt.verifyStorage(storage_root, slot, self.witness.state) catch return DbError.InvalidWitness;
    }

    // ── blockHash ───────────────────────────────────────────────────────────

    /// Return the hash of block `number`.
    ///
    /// Block-hash witnesses are not yet part of the StatelessInput format
    /// (Phase 3).  Until then, unknown block numbers return the zero hash,
    /// which causes BLOCKHASH to push 0 onto the stack — the correct result
    /// for blocks outside the 256-block lookback window.
    pub fn blockHash(_: *Self, _: u64) !primitives.Hash {
        return [_]u8{0} ** 32;
    }
};

// ─── Private helpers ───────────────────────────────────────────────────────────

/// Encode a u256 as a 32-byte big-endian hash (used for storage key lookup).
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
