//! Binary deserializer for the zevm-zisk StatelessInput format.
//!
//! Reads from stdin the raw binary stream produced by zevm-zisk's serialize.zig:
//!
//!   Block:
//!     Header (all fields in order, big-endian ints, optional fields prefixed with a flag byte)
//!     Transactions: u64 count + [per-tx binary]
//!     Ommers:       u64 count + [header binary]  — parsed through but discarded
//!     Withdrawals:  u8 flag + u64 count + [u64,u64,[20]u8,u64] — parsed through, discarded
//!   ExecutionWitness:
//!     state / codes / keys / headers: u64 count + [u64-len-prefixed byte slices]
//!
//! Returned slices point directly into the arena-owned stdin buffer (zero-copy).

const std        = @import("std");
const input_mod  = @import("input");
const primitives = @import("primitives");
const rlp_decode = @import("rlp_decode");
const json_mod   = @import("json.zig");

/// Read all of stdin into a freshly allocated slice owned by `allocator`.
fn readStdin(allocator: std.mem.Allocator) ![]u8 {
    const stdin = std.fs.File{ .handle = std.posix.STDIN_FILENO };
    var list = std.ArrayListUnmanaged(u8){};
    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = try stdin.read(&chunk);
        if (n == 0) break;
        try list.appendSlice(allocator, chunk[0..n]);
    }
    return list.toOwnedSlice(allocator);
}

const Deserializer = struct {
    buf:   []const u8,
    pos:   usize,
    alloc: std.mem.Allocator,

    fn init(alloc: std.mem.Allocator, buf: []const u8) Deserializer {
        return .{ .buf = buf, .pos = 0, .alloc = alloc };
    }

    // ── Primitive readers ────────────────────────────────────────────────────

    fn readU8(self: *Deserializer) !u8 {
        if (self.pos >= self.buf.len) return error.UnexpectedEndOfInput;
        defer self.pos += 1;
        return self.buf[self.pos];
    }

    fn readU64(self: *Deserializer) !u64 {
        if (self.pos + 8 > self.buf.len) return error.UnexpectedEndOfInput;
        const v = std.mem.readInt(u64, self.buf[self.pos..][0..8], .big);
        self.pos += 8;
        return v;
    }

    fn readU128(self: *Deserializer) !u128 {
        if (self.pos + 16 > self.buf.len) return error.UnexpectedEndOfInput;
        const v = std.mem.readInt(u128, self.buf[self.pos..][0..16], .big);
        self.pos += 16;
        return v;
    }

    fn readU256(self: *Deserializer) !u256 {
        if (self.pos + 32 > self.buf.len) return error.UnexpectedEndOfInput;
        const v = std.mem.readInt(u256, self.buf[self.pos..][0..32], .big);
        self.pos += 32;
        return v;
    }

    fn readFixedBytes(self: *Deserializer, comptime N: usize) ![N]u8 {
        if (self.pos + N > self.buf.len) return error.UnexpectedEndOfInput;
        var out: [N]u8 = undefined;
        @memcpy(&out, self.buf[self.pos..][0..N]);
        self.pos += N;
        return out;
    }

    /// Return a zero-copy slice into the arena-owned buf.
    fn readByteSlice(self: *Deserializer) ![]const u8 {
        const len = try self.readU64();
        if (self.pos + len > self.buf.len) return error.UnexpectedEndOfInput;
        const slice = self.buf[self.pos..][0..len];
        self.pos += len;
        return slice;
    }

    fn skipByteSlice(self: *Deserializer) !void {
        const len = try self.readU64();
        if (self.pos + len > self.buf.len) return error.UnexpectedEndOfInput;
        self.pos += len;
    }

    fn skipOptionalU64(self: *Deserializer) !void {
        const present = try self.readU8();
        if (present != 0) _ = try self.readU64();
    }

    fn skipOptionalHash(self: *Deserializer) !void {
        const present = try self.readU8();
        if (present != 0) _ = try self.readFixedBytes(32);
    }

    // ── Skip a full binary block header ──────────────────────────────────────

    fn skipHeader(self: *Deserializer) !void {
        _ = try self.readFixedBytes(32);  // parent_hash
        _ = try self.readFixedBytes(32);  // ommers_hash
        _ = try self.readFixedBytes(20);  // beneficiary
        _ = try self.readFixedBytes(32);  // state_root
        _ = try self.readFixedBytes(32);  // transactions_root
        _ = try self.readFixedBytes(32);  // receipts_root
        _ = try self.readFixedBytes(256); // logs_bloom
        _ = try self.readU256();          // difficulty
        _ = try self.readU64();           // number
        _ = try self.readU64();           // gas_limit
        _ = try self.readU64();           // gas_used
        _ = try self.readU64();           // timestamp
        try self.skipByteSlice();         // extra_data
        _ = try self.readFixedBytes(32);  // mix_hash
        _ = try self.readU64();           // nonce
        try self.skipOptionalU64();       // base_fee_per_gas
        try self.skipOptionalHash();      // withdrawals_root
        try self.skipOptionalU64();       // blob_gas_used
        try self.skipOptionalU64();       // excess_blob_gas
        try self.skipOptionalHash();      // parent_beacon_block_root
        try self.skipOptionalHash();      // requests_hash
    }

    // ── Read access list + auth list ─────────────────────────────────────────

    fn readAccessListEntry(self: *Deserializer) !input_mod.AccessListEntry {
        const address  = try self.readFixedBytes(20);
        const num_keys = try self.readU64();
        const keys     = try self.alloc.alloc(primitives.Hash, num_keys);
        for (0..num_keys) |i| keys[i] = try self.readFixedBytes(32);
        return .{ .address = address, .storage_keys = keys };
    }

    // ── Read one transaction ─────────────────────────────────────────────────

    fn readTransaction(self: *Deserializer) !input_mod.Transaction {
        var tx = input_mod.Transaction{
            .tx_type              = try self.readU8(),
            .chain_id             = null,
            .nonce                = 0,
            .gas_price            = 0,
            .gas_priority_fee     = null,
            .gas_limit            = 0,
            .to                   = null,
            .value                = 0,
            .data                 = &.{},
            .access_list          = &.{},
            .blob_hashes          = &.{},
            .max_fee_per_blob_gas = 0,
            .authorization_list   = &.{},
            .v                    = 0,
            .r                    = 0,
            .s                    = 0,
        };

        if (try self.readU8() != 0) tx.chain_id = try self.readU64();
        tx.nonce     = try self.readU64();
        tx.gas_price = try self.readU128();
        if (try self.readU8() != 0) tx.gas_priority_fee = try self.readU128();
        tx.gas_limit = try self.readU64();
        if (try self.readU8() != 0) tx.to = try self.readFixedBytes(20);
        tx.value     = try self.readU256();
        tx.data      = try self.readByteSlice();

        const al_len = try self.readU64();
        if (al_len > 0) {
            const al = try self.alloc.alloc(input_mod.AccessListEntry, al_len);
            for (0..al_len) |i| al[i] = try self.readAccessListEntry();
            tx.access_list = al;
        }

        const bh_len = try self.readU64();
        if (bh_len > 0) {
            const bh = try self.alloc.alloc(primitives.Hash, bh_len);
            for (0..bh_len) |i| bh[i] = try self.readFixedBytes(32);
            tx.blob_hashes = bh;
        }

        tx.max_fee_per_blob_gas = try self.readU128();

        tx.v = try self.readU64(); // y_parity, encoded as u64
        tx.r = try self.readU256();
        tx.s = try self.readU256();

        return tx;
    }

    fn skipWithdrawal(self: *Deserializer) !void {
        _ = try self.readU64(); // index
        _ = try self.readU64(); // validator_index
        _ = try self.readFixedBytes(20); // address
        _ = try self.readU64(); // amount (gwei)
    }

    // ── Read block header ─────────────────────────────────────────────────────

    fn readBlockHeader(self: *Deserializer) !input_mod.BlockHeader {
        var hdr: input_mod.BlockHeader = std.mem.zeroes(input_mod.BlockHeader);
        hdr.parent_hash       = try self.readFixedBytes(32);
        hdr.ommers_hash       = try self.readFixedBytes(32);
        hdr.beneficiary       = try self.readFixedBytes(20);
        hdr.state_root        = try self.readFixedBytes(32);
        hdr.transactions_root = try self.readFixedBytes(32);
        hdr.receipts_root     = try self.readFixedBytes(32);
        hdr.logs_bloom        = try self.readFixedBytes(256);
        hdr.difficulty        = try self.readU256();
        hdr.number            = try self.readU64();
        hdr.gas_limit         = try self.readU64();
        hdr.gas_used          = try self.readU64();
        hdr.timestamp         = try self.readU64();
        hdr.extra_data        = try self.readByteSlice();
        hdr.mix_hash          = try self.readFixedBytes(32);
        hdr.nonce             = try self.readU64();

        if (try self.readU8() != 0) hdr.base_fee_per_gas         = try self.readU64();
        if (try self.readU8() != 0) hdr.withdrawals_root         = try self.readFixedBytes(32);
        if (try self.readU8() != 0) hdr.blob_gas_used            = try self.readU64();
        if (try self.readU8() != 0) hdr.excess_blob_gas          = try self.readU64();
        if (try self.readU8() != 0) hdr.parent_beacon_block_root = try self.readFixedBytes(32);
        if (try self.readU8() != 0) hdr.requests_hash            = try self.readFixedBytes(32);

        return hdr;
    }

    // ── Read ExecutionWitness ─────────────────────────────────────────────────

    fn readExecutionWitness(self: *Deserializer) !input_mod.StateWitness {
        const state_count = try self.readU64();
        const nodes = try self.alloc.alloc([]const u8, state_count);
        for (0..state_count) |i| nodes[i] = try self.readByteSlice();

        const code_count = try self.readU64();
        const codes = try self.alloc.alloc([]const u8, code_count);
        for (0..code_count) |i| codes[i] = try self.readByteSlice();

        const key_count = try self.readU64();
        const keys = try self.alloc.alloc([]const u8, key_count);
        for (0..key_count) |i| keys[i] = try self.readByteSlice();

        const hdr_count = try self.readU64();
        const headers = try self.alloc.alloc([]const u8, hdr_count);
        for (0..hdr_count) |i| headers[i] = try self.readByteSlice();

        return input_mod.StateWitness{
            .state_root = @splat(0), // resolved by caller via findPreStateRoot
            .nodes      = nodes,
            .codes      = codes,
            .keys       = keys,
            .headers    = headers,
        };
    }

    // ── Top-level read ────────────────────────────────────────────────────────

    fn readStatelessInput(self: *Deserializer) !input_mod.StatelessInput {
        const hdr = try self.readBlockHeader();

        const tx_count = try self.readU64();
        const transactions = try self.alloc.alloc(input_mod.Transaction, tx_count);
        for (0..tx_count) |i| transactions[i] = try self.readTransaction();

        // Ommers — skip
        const ommer_count = try self.readU64();
        for (0..ommer_count) |_| try self.skipHeader();

        // Withdrawals — optional
        if (try self.readU8() != 0) {
            const w_count = try self.readU64();
            for (0..w_count) |_| try self.skipWithdrawal();
        }

        var witness = try self.readExecutionWitness();
        witness.state_root = rlp_decode.findPreStateRoot(witness.headers, hdr.number) orelse hdr.state_root;

        return input_mod.StatelessInput{
            .block        = hdr,
            .transactions = transactions,
            .witness      = witness,
        };
    }
};

/// Deserialize a zevm-zisk binary StatelessInput from stdin.
pub fn fromStdin(allocator: std.mem.Allocator) !input_mod.StatelessInput {
    const data = try readStdin(allocator);
    var d = Deserializer.init(allocator, data);
    return d.readStatelessInput();
}

/// Deserialize a Besu-plugin framed binary input from stdin.
///
/// Frame layout (all integers big-endian):
///   [u32: block RLP length] [block RLP bytes]
///   [u32: witness JSON length] [witness JSON bytes]
///
/// The block RLP is the raw wire bytes from debug_getRawBlock.
/// The witness JSON is the full JSON-RPC response from debug_executionWitness.
pub fn fromStdinFramed(allocator: std.mem.Allocator) !input_mod.StatelessInput {
    const data = try readStdin(allocator);
    if (data.len < 8) return error.UnexpectedEndOfInput;

    const rlp_len: usize = std.mem.readInt(u32, data[0..4], .big);
    if (4 + rlp_len + 4 > data.len) return error.UnexpectedEndOfInput;
    const rlp_bytes = data[4..][0..rlp_len];

    const after_rlp = 4 + rlp_len;
    const json_len: usize = std.mem.readInt(u32, data[after_rlp..][0..4], .big);
    if (after_rlp + 4 + json_len > data.len) return error.UnexpectedEndOfInput;
    const json_bytes = data[after_rlp + 4..][0..json_len];

    const blk = try json_mod.parseBlockFromRlp(allocator, rlp_bytes);
    var wit   = try json_mod.parseWitnessJson(allocator, json_bytes);
    wit.state_root = rlp_decode.findPreStateRoot(wit.headers, blk.header.number)
                     orelse blk.header.state_root;

    return input_mod.StatelessInput{
        .block        = blk.header,
        .transactions = blk.transactions,
        .witness      = wit,
        .withdrawals  = blk.withdrawals,
    };
}
