//! Input loaders for zevm_stateless.
//!
//! Each function reads bytes from a source (zkvm_io stream or file) and
//! delegates format decoding to the appropriate format module (rlp.zig, ssz.zig, …).

const std = @import("std");
const input_mod = @import("input");
const rlp = @import("rlp.zig");
const zkvm_io = @import("zkvm_io");

/// RLP from zkvm_io.read_input() — default / zkVM production path.
pub fn fromRlpStream(allocator: std.mem.Allocator) !input_mod.StatelessInput {
    const data = try zkvm_io.read_input(allocator);
    return rlp.decode(allocator, data);
}

/// RLP from a binary file — testing convenience.
pub fn fromRlpFile(allocator: std.mem.Allocator, path: []const u8) !input_mod.StatelessInput {
    const data = try std.fs.cwd().readFileAlloc(allocator, path, 256 << 20);
    return rlp.decode(allocator, data);
}

/// SSZ from zkvm_io.read_input() — not yet implemented.
pub fn fromSszStream(_: std.mem.Allocator) !input_mod.StatelessInput {
    return error.SszNotImplemented;
}

/// SSZ from a binary file — not yet implemented.
pub fn fromSszFile(_: std.mem.Allocator, _: []const u8) !input_mod.StatelessInput {
    return error.SszNotImplemented;
}
