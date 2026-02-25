//! JSON I/O: parse block.json + witness.json into StatelessInput.
//!
//! The JSON formats mirror debug_executionWitness (EL JSON-RPC):
//!
//!   block.json:
//!     { "number": <u64>, "stateRoot": "0x<64 hex chars>", ... }
//!
//!   witness.json:
//!     { "state":   ["0x<hex>", ...],   — flat pool of RLP trie node preimages
//!       "codes":   ["0x<hex>", ...],   — contract bytecodes
//!       "keys":    ["0x<hex>", ...],   — 20-byte addrs or 52-byte addr+slot
//!       "headers": ["0x<hex>", ...] }  — RLP block headers for BLOCKHASH
//!
//! All hex-decoded byte slices are allocated from the provided allocator.

const std    = @import("std");
const primitives = @import("primitives");
const input  = @import("input");

// ─── JSON schema structs ───────────────────────────────────────────────────────

const BlockJson = struct {
    number:    u64,
    stateRoot: []const u8,
};

/// Matches the debug_executionWitness flat-pool witness format.
const WitnessJson = struct {
    state:   []const []const u8,
    codes:   []const []const u8,
    keys:    []const []const u8,
    headers: []const []const u8,
};

// ─── Public API ────────────────────────────────────────────────────────────────

/// Parse a block.json + witness.json pair into a StatelessInput.
///
/// The returned value borrows heap memory from `allocator`; the caller is
/// responsible for freeing all slices in nodes/codes/keys/headers.
/// Using an arena allocator is the simplest ownership strategy.
pub fn parseBlockAndWitness(
    allocator:        std.mem.Allocator,
    block_json_str:   []const u8,
    witness_json_str: []const u8,
) !input.StatelessInput {
    // ── block.json ──────────────────────────────────────────────────────────
    const block_parsed = try std.json.parseFromSlice(
        BlockJson, allocator, block_json_str,
        .{ .ignore_unknown_fields = true },
    );
    defer block_parsed.deinit();

    const state_root   = try hexToHash(block_parsed.value.stateRoot);
    const block_number = block_parsed.value.number;

    // ── witness.json ────────────────────────────────────────────────────────
    const witness_parsed = try std.json.parseFromSlice(
        WitnessJson, allocator, witness_json_str,
        .{ .ignore_unknown_fields = true },
    );
    defer witness_parsed.deinit();

    // Decode each hex string array into owned byte-slice arrays.
    // hexSliceArray allocates from `allocator`, independent of witness_parsed.
    const nodes   = try hexSliceArray(allocator, witness_parsed.value.state);
    const codes   = try hexSliceArray(allocator, witness_parsed.value.codes);
    const keys    = try hexSliceArray(allocator, witness_parsed.value.keys);
    const headers = try hexSliceArray(allocator, witness_parsed.value.headers);

    return input.StatelessInput{
        .block_number = block_number,
        .transactions = &.{},
        .witness = input.StateWitness{
            .state_root = state_root,
            .nodes      = nodes,
            .codes      = codes,
            .keys       = keys,
            .headers    = headers,
        },
    };
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

/// Decode a "0x…" hex string into a [32]u8 hash.
fn hexToHash(hex: []const u8) ![32]u8 {
    const s = stripHexPrefix(hex);
    if (s.len != 64) return error.InvalidHexLength;
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, s);
    return out;
}

/// Allocate a new []u8 slice decoded from a "0x…" hex string.
fn hexToSlice(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const s = stripHexPrefix(hex);
    if (s.len % 2 != 0) return error.OddHexLength;
    const out = try allocator.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

/// Decode an array of "0x…" hex strings into an array of owned byte slices.
fn hexSliceArray(
    allocator: std.mem.Allocator,
    hexes:     []const []const u8,
) ![]const []const u8 {
    const result = try allocator.alloc([]const u8, hexes.len);
    for (hexes, 0..) |h, i| {
        result[i] = try hexToSlice(allocator, h);
    }
    return result;
}

fn stripHexPrefix(hex: []const u8) []const u8 {
    if (hex.len >= 2 and hex[0] == '0' and (hex[1] == 'x' or hex[1] == 'X'))
        return hex[2..];
    return hex;
}
