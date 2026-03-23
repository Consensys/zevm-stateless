//! Binary deserializer for the zevm-zisk StatelessInput format.
//!
//! Binary layout (all integers big-endian):
//!
//!   [u64: block_rlp_len] [block_rlp_bytes]   — raw Ethereum block RLP
//!   ExecutionWitness:
//!     state / codes / keys / headers: u64 count + [u64-len-prefixed byte slices]
//!
//! Returned slices point directly into the arena-owned stdin buffer (zero-copy).

const std = @import("std");
const input_mod = @import("input");
const rlp_decode = @import("rlp_decode");
const json_mod = @import("json.zig");
const ssz = @import("ssz.zig");
const zkvm_io = @import("zkvm_io");

/// Deserialize a zevm-zisk binary StatelessInput from stdin.
///
/// The sender writes:
///   [u64 big-endian: block_rlp_len] [raw block RLP bytes]
///   [u64: state_count]   [u64 len + node bytes] ...
///   [u64: codes_count]   [u64 len + code bytes] ...
///   [u64: keys_count]    [u64 len + key bytes]  ...
///   [u64: headers_count] [u64 len + header RLP bytes] ...
pub fn fromStdin(allocator: std.mem.Allocator) !input_mod.StatelessInput {
    const data = try zkvm_io.read_input(allocator);

    var pos: usize = 0;

    // ── Block RLP ─────────────────────────────────────────────────────────────
    if (pos + 8 > data.len) return error.UnexpectedEndOfInput;
    const rlp_len: usize = @intCast(std.mem.readInt(u64, data[pos..][0..8], .big));
    pos += 8;
    if (pos + rlp_len > data.len) return error.UnexpectedEndOfInput;
    const block_rlp = data[pos..][0..rlp_len];
    pos += rlp_len;

    const blk = try json_mod.parseBlockFromRlp(allocator, block_rlp);

    // ── ExecutionWitness ──────────────────────────────────────────────────────
    const nodes = try readSliceArray(allocator, data, &pos);
    const codes = try readSliceArray(allocator, data, &pos);
    const keys = try readSliceArray(allocator, data, &pos);
    const headers = try readSliceArray(allocator, data, &pos);

    var witness = input_mod.StateWitness{
        .state_root = @splat(0),
        .nodes = nodes,
        .codes = codes,
        .keys = keys,
        .headers = headers,
    };
    witness.state_root = rlp_decode.findPreStateRoot(witness.headers, blk.header.number) orelse blk.header.state_root;

    return input_mod.StatelessInput{
        .block = blk.header,
        .transactions = blk.transactions,
        .witness = witness,
        .withdrawals = blk.withdrawals,
    };
}

/// Decode an SSZ-encoded SszStatelessInput from a byte slice.
pub fn fromSszData(allocator: std.mem.Allocator, data: []const u8) !input_mod.StatelessInput {
    return ssz.decode(allocator, data);
}

/// Decode an SSZ-encoded SszStatelessInput from a file on disk.
pub fn fromSszFile(allocator: std.mem.Allocator, path: []const u8) !input_mod.StatelessInput {
    const data = try std.fs.cwd().readFileAlloc(allocator, path, 1 << 30);
    return ssz.decode(allocator, data);
}

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
