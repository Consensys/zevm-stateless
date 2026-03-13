//! SSZ deserialization for StatelessInput.
//!
//! Public interface mirrors io.zig — drop-in replacement for SSZ-encoded input:
//!   deserializeStatelessInput  — SSZ bytes → StatelessInput
//!   serializeStatelessOutput   — StatelessValidationResult → raw bytes (identical to io.zig)
//!   fromStdin                  — reads SSZ-encoded StatelessInput from stdin
//!
//! SSZ container layout for StatelessInput:
//!
//!   Fixed part (32 bytes total):
//!     block_rlp    : offset (4 bytes LE)  — Bytes (raw block RLP)
//!     state        : offset (4 bytes LE)  — List[Bytes]
//!     codes        : offset (4 bytes LE)  — List[Bytes]
//!     keys         : offset (4 bytes LE)  — List[Bytes]
//!     headers      : offset (4 bytes LE)  — List[Bytes]
//!     chain_id     : uint64 (8 bytes LE)  — inline fixed field
//!     public_keys  : offset (4 bytes LE)  — List[Bytes]
//!
//!   Variable section (immediately after fixed part, offsets are absolute):
//!     block_rlp data  [block_rlp_offset .. state_offset]
//!     state data      [state_offset .. codes_offset]       — List[Bytes] encoding
//!     codes data      [codes_offset .. keys_offset]
//!     keys data       [keys_offset .. headers_offset]
//!     headers data    [headers_offset .. public_keys_offset]
//!     public_keys data[public_keys_offset .. data.len]
//!
//! List[Bytes] encoding (variable-length elements):
//!   [offset0, offset1, ..., offsetN-1] (each 4 bytes LE, relative to list slice start)
//!   [bytes0, bytes1, ..., bytesN-1]
//!   Empty list = zero bytes.
//!
//! Binary output layout (identical to io.zig):
//!   pre_state_root  [32 bytes]
//!   post_state_root [32 bytes]
//!   receipts_root   [32 bytes]
//!   block_hash      [32 bytes]
//!   chain_id        [8 bytes BE]
//!   success         [1 byte]

const std = @import("std");
const input_mod = @import("input");
const output_mod = @import("output");
const rlp_decode = @import("rlp_decode");
const json_mod = @import("json");
const zkvm_io = @import("zkvm_io");

// Fixed part: 5 variable offsets × 4 bytes + chain_id 8 bytes + 1 variable offset × 4 bytes = 32
const FIXED_PART_SIZE: usize = 32;

// ── deserializeStatelessInput ─────────────────────────────────────────────────

/// Deserialize a StatelessInput from SSZ wire format.
/// `data` must remain valid for the lifetime of the returned StatelessInput;
/// witness slices are zero-copy views into `data`.
pub fn deserializeStatelessInput(
    allocator: std.mem.Allocator,
    data: []const u8,
) !input_mod.StatelessInput {
    if (data.len < FIXED_PART_SIZE) return error.UnexpectedEndOfInput;

    var pos: usize = 0;
    const block_rlp_offset = readU32Le(data, &pos);
    const state_offset = readU32Le(data, &pos);
    const codes_offset = readU32Le(data, &pos);
    const keys_offset = readU32Le(data, &pos);
    const headers_offset = readU32Le(data, &pos);
    const chain_id = readU64Le(data, &pos);
    const public_keys_offset = readU32Le(data, &pos);

    // Validate offsets are within bounds and monotonically ordered.
    if (block_rlp_offset < FIXED_PART_SIZE or
        state_offset < block_rlp_offset or
        codes_offset < state_offset or
        keys_offset < codes_offset or
        headers_offset < keys_offset or
        public_keys_offset < headers_offset or
        public_keys_offset > data.len)
    {
        return error.InvalidSszOffset;
    }

    // ── Block RLP ─────────────────────────────────────────────────────────────
    const block_rlp = data[block_rlp_offset..state_offset];
    const blk = try json_mod.parseBlockFromRlp(allocator, block_rlp);
    const block_hash = rlp_decode.keccak256Header(block_rlp);

    // ── ExecutionWitness ──────────────────────────────────────────────────────
    const state = try readBytesList(allocator, data[state_offset..codes_offset]);
    const codes = try readBytesList(allocator, data[codes_offset..keys_offset]);
    const keys = try readBytesList(allocator, data[keys_offset..headers_offset]);
    const headers = try readBytesList(allocator, data[headers_offset..public_keys_offset]);
    const public_keys = try readBytesList(allocator, data[public_keys_offset..]);

    var witness = input_mod.ExecutionWitness{
        .state_root = @splat(0),
        .state = state,
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
        .block_hash = block_hash,
        .chain_config = .{ .chain_id = chain_id },
        .public_keys = public_keys,
    };
}

// ── serializeStatelessOutput ──────────────────────────────────────────────────

/// Serialize a StatelessValidationResult to the binary wire format.
/// Identical to io.zig — output encoding is independent of input format.
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

/// Read and deserialize a StatelessInput from stdin (SSZ-encoded).
pub fn fromStdin(allocator: std.mem.Allocator) !input_mod.StatelessInput {
    const data = try zkvm_io.read_input(allocator);
    return deserializeStatelessInput(allocator, data);
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn readU32Le(data: []const u8, pos: *usize) u32 {
    const val = std.mem.readInt(u32, data[pos.*..][0..4], .little);
    pos.* += 4;
    return val;
}

fn readU64Le(data: []const u8, pos: *usize) u64 {
    const val = std.mem.readInt(u64, data[pos.*..][0..8], .little);
    pos.* += 8;
    return val;
}

/// Decode a List[Bytes] SSZ field from `slice`.
/// SSZ encodes List[Bytes] as offsets followed by variable data, with all
/// offsets 4-byte LE and relative to the start of `slice`.
/// Returns slices that are zero-copy views into `slice`.
fn readBytesList(allocator: std.mem.Allocator, slice: []const u8) ![]const []const u8 {
    if (slice.len == 0) return &.{};
    if (slice.len < 4) return error.UnexpectedEndOfInput;

    // The first 4-byte value is the offset to the first element's data.
    // Since each offset is 4 bytes, first_offset / 4 = number of elements.
    const first_offset = std.mem.readInt(u32, slice[0..4], .little);
    if (first_offset == 0 or first_offset % 4 != 0 or first_offset > slice.len)
        return error.InvalidSszOffset;

    const n = first_offset / 4;
    const offsets_end = n * 4;
    if (offsets_end > slice.len) return error.InvalidSszOffset;

    const result = try allocator.alloc([]const u8, n);
    for (0..n) |i| {
        const elem_start = std.mem.readInt(u32, slice[i * 4 ..][0..4], .little);
        const elem_end: u32 = if (i + 1 < n)
            std.mem.readInt(u32, slice[(i + 1) * 4 ..][0..4], .little)
        else
            @intCast(slice.len);
        if (elem_start > slice.len or elem_end > slice.len or elem_start > elem_end)
            return error.InvalidSszOffset;
        result[i] = slice[elem_start..elem_end];
    }
    return result;
}
