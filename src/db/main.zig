//! WitnessDatabase: a zevm database backend backed by a state witness.
//!
//! Every account and storage read is served from the MPT proofs supplied in
//! the StatelessInput.  Any access to a key not covered by the witness is
//! treated as non-existent (returns null / zero), which is the correct
//! stateless-execution semantics: the prover must include all touched state.
//!
//! All methods are allocation-free; linear scans over the (bounded) witness
//! arrays are acceptable in a zkVM context.

const std = @import("std");
const primitives = @import("primitives");
const state     = @import("state");
const bytecode  = @import("bytecode");
const mpt       = @import("mpt");
const input     = @import("input");

pub const DbError = error{
    /// MPT proof verification failed — witness is inconsistent with state root.
    InvalidWitness,
};

/// Stateless database built from a proven StateWitness.
///
/// Implements the zevm `Database` interface (duck-typed):
///   basic(address)              → ?AccountInfo
///   codeByHash(code_hash)       → Bytecode
///   storage(address, key)       → StorageValue
///   blockHash(number)           → Hash
pub const WitnessDatabase = struct {
    witness: input.StateWitness,

    const Self = @This();

    pub fn init(witness: input.StateWitness) Self {
        return .{ .witness = witness };
    }

    // ── basic ───────────────────────────────────────────────────────────────

    /// Return basic account info for `address`, or null if the account is
    /// absent from the trie (valid non-inclusion proof).
    ///
    /// Returns `DbError.InvalidWitness` if the MPT proof is malformed.
    pub fn basic(self: *Self, address: primitives.Address) !?state.AccountInfo {
        for (self.witness.accounts) |acc| {
            if (!std.mem.eql(u8, &acc.address, &address)) continue;

            const account_state = mpt.verifyAccount(self.witness.state_root, acc) catch
                return DbError.InvalidWitness;

            const as = account_state orelse return null;
            return state.AccountInfo{
                .balance   = as.balance,
                .nonce     = as.nonce,
                .code_hash = as.code_hash,
                // Bytecode is served on demand via codeByHash; set null here
                // so zevm fetches it through that path when needed.
                .code = null,
            };
        }
        // Address not in witness → account does not exist in the state trie.
        return null;
    }

    // ── codeByHash ──────────────────────────────────────────────────────────

    /// Return the bytecode whose keccak256 hash is `code_hash`.
    ///
    /// The code bytes are taken from the matching AccountWitness.  For EOAs
    /// (code_hash == KECCAK_EMPTY) an empty `Bytecode` is returned without
    /// scanning the witness.
    pub fn codeByHash(self: *Self, code_hash: primitives.Hash) !bytecode.Bytecode {
        // Fast path: no code.
        if (std.mem.eql(u8, &code_hash, &primitives.KECCAK_EMPTY)) {
            return bytecode.Bytecode.newLegacy(&.{});
        }
        // Find the account whose code matches.
        for (self.witness.accounts) |acc| {
            if (acc.code.len == 0) continue;
            const h = mpt.keccak256(acc.code);
            if (std.mem.eql(u8, &h, &code_hash)) {
                return bytecode.Bytecode.newLegacy(acc.code);
            }
        }
        // Code not found in witness — return empty (caller will treat as
        // STOP-only contract, which is the safest fallback).
        return bytecode.Bytecode.new();
    }

    // ── storage ─────────────────────────────────────────────────────────────

    /// Return the value of storage slot `index` for `address`.
    ///
    /// Returns 0 when the account is absent, the slot is not in the witness,
    /// or the storage proof shows the slot is empty.
    pub fn storage(
        self: *Self,
        address: primitives.Address,
        index:   primitives.StorageKey,
    ) !primitives.StorageValue {
        // Resolve the account's storage root first.
        const storage_root = blk: {
            for (self.witness.accounts) |acc| {
                if (!std.mem.eql(u8, &acc.address, &address)) continue;
                const as = mpt.verifyAccount(self.witness.state_root, acc) catch
                    return DbError.InvalidWitness;
                break :blk (as orelse return 0).storage_root;
            }
            return 0; // address not in witness
        };

        // Convert StorageKey (u256) to a 32-byte big-endian slot hash.
        const slot = u256ToHash(index);

        // Find the matching StorageWitness and verify it.
        for (self.witness.storage) |sw| {
            if (!std.mem.eql(u8, &sw.address, &address)) continue;
            if (!std.mem.eql(u8, &sw.slot, &slot)) continue;
            return mpt.verifyStorage(storage_root, sw) catch DbError.InvalidWitness;
        }
        // Slot not in witness → value is 0 (not touched during this block).
        return 0;
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
