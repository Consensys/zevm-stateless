//! Stateless guest I/O: serialize/deserialize the spec-defined wire types.
//!
//! Public interface mirrors stateless_guest.py from ethereum/execution-specs:
//!   deserializeStatelessInput  — raw bytes → StatelessInput
//!   serializeStatelessOutput   — StatelessValidationResult → raw bytes
//!
//! Binary input layout (all integers big-endian):
//!   [u64: block_rlp_len] [block_rlp_bytes]   — raw Ethereum block RLP
//!   ExecutionWitness:
//!     state / codes / keys / headers: u64 count + [u64-len-prefixed byte slices]
//!   [u64: chain_id]                           — ChainConfig.chain_id
//!   [u64: public_keys_count] [u64 len + key bytes] ...  — public keys (may be 0)
//!
//! Binary output layout:
//!   pre_state_root  [32 bytes]
//!   post_state_root [32 bytes]
//!   receipts_root   [32 bytes]
//!   block_hash      [32 bytes]   — keccak256 of block header RLP
//!   chain_id        [8 bytes BE]
//!   success         [1 byte]     — 0x01 = valid, 0x00 = invalid
//!
//! Input slices point directly into the caller-owned data buffer (zero-copy).

const std = @import("std");
const input_mod = @import("input");
const output_mod = @import("output");
const rlp_decode = @import("rlp_decode");
const json_mod = @import("json.zig");
const zkvm_io = @import("zkvm_io");

// ── deserializeStatelessInput ─────────────────────────────────────────────────

/// Deserialize a StatelessInput from the binary wire format.
/// Mirrors deserialize_stateless_input from the stateless guest spec.
///
/// `data` must remain valid for the lifetime of the returned StatelessInput;
/// all witness slices are zero-copy views into `data`.
pub fn deserializeStatelessInput(
    allocator: std.mem.Allocator,
    data: []const u8,
) !input_mod.StatelessInput {
    var pos: usize = 0;

    // ── Block RLP ─────────────────────────────────────────────────────────────
    if (pos + 8 > data.len) return error.UnexpectedEndOfInput;
    const rlp_len: usize = @intCast(std.mem.readInt(u64, data[pos..][0..8], .big));
    pos += 8;
    if (pos + rlp_len > data.len) return error.UnexpectedEndOfInput;
    const block_rlp = data[pos..][0..rlp_len];
    pos += rlp_len;

    const blk = try json_mod.parseBlockFromRlp(allocator, block_rlp);
    const block_hash = rlp_decode.keccak256Header(block_rlp);

    // ── ExecutionWitness ──────────────────────────────────────────────────────
    const state = try readSliceArray(allocator, data, &pos);
    const codes = try readSliceArray(allocator, data, &pos);
    const keys = try readSliceArray(allocator, data, &pos);
    const headers = try readSliceArray(allocator, data, &pos);

    var witness = input_mod.ExecutionWitness{
        .state_root = @splat(0),
        .state = state,
        .codes = codes,
        .keys = keys,
        .headers = headers,
    };
    witness.state_root = rlp_decode.findPreStateRoot(witness.headers, blk.header.number) orelse blk.header.state_root;

    // ── ChainConfig + public_keys (optional; default to mainnet / empty) ──────
    var chain_id: u64 = 1;
    var public_keys: []const []const u8 = &.{};
    if (pos + 8 <= data.len) {
        chain_id = std.mem.readInt(u64, data[pos..][0..8], .big);
        pos += 8;
        public_keys = try readSliceArray(allocator, data, &pos);
    }

    return input_mod.StatelessInput{
        .block = blk.header,
        .transactions = blk.transactions,
        .witness = witness,
        .withdrawals = blk.withdrawals,
        .block_hash = block_hash,
        .chain_config = .{ .chain_id = chain_id },
        .public_keys = public_keys,
    };
}

// ── serializeStatelessOutput ──────────────────────────────────────────────────

/// Serialize a StatelessValidationResult to the binary wire format.
/// Mirrors serialize_stateless_output from the stateless guest spec.
pub fn serializeStatelessOutput(
    allocator: std.mem.Allocator,
    result: output_mod.StatelessValidationResult,
) ![]const u8 {
    var chain_id_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &chain_id_buf, result.chain_id, .big);

    const parts: []const []const u8 = &.{
        &result.pre_state_root,
        &result.post_state_root,
        &result.receipts_root,
        &result.new_payload_request_root,
        &chain_id_buf,
        &.{if (result.successful_validation) @as(u8, 0x01) else @as(u8, 0x00)},
    };

    var total: usize = 0;
    for (parts) |p| total += p.len;
    const out = try allocator.alloc(u8, total);
    var cursor: usize = 0;
    for (parts) |p| {
        @memcpy(out[cursor..][0..p.len], p);
        cursor += p.len;
    }
    return out;
}

// ── fromStdin ─────────────────────────────────────────────────────────────────

/// Read and deserialize a StatelessInput from stdin (native builds).
/// Delegates to deserializeStatelessInput after reading all bytes.
pub fn fromStdin(allocator: std.mem.Allocator) !input_mod.StatelessInput {
    const data = try zkvm_io.read_input(allocator);
    return deserializeStatelessInput(allocator, data);
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Read a u64-count array of u64-length-prefixed byte slices (zero-copy into `data`).
fn readSliceArray(allocator: std.mem.Allocator, data: []const u8, pos: *usize) ![]const []const u8 {
    if (pos.* + 8 > data.len) return error.UnexpectedEndOfInput;
    const count: usize = @intCast(std.mem.readInt(u64, data[pos.*..][0..8], .big));
    pos.* += 8;
    const result = try allocator.alloc([]const u8, count);
    for (0..count) |i| {
        if (pos.* + 8 > data.len) return error.UnexpectedEndOfInput;
        const len: usize = @intCast(std.mem.readInt(u64, data[pos.*..][0..8], .big));
        pos.* += 8;
        if (pos.* + len > data.len) return error.UnexpectedEndOfInput;
        result[i] = data[pos.*..][0..len];
        pos.* += len;
    }
    return result;
}
