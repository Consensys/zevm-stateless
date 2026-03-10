/// Default Keccak-256 implementation using std.crypto.
/// Overridden in Zisk builds via the keccak_impl module injection point
/// in build.zig (mpt_mod.addImport("keccak_impl", your_hw_module)).
const std = @import("std");

pub fn keccak256(data: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(data, &out, .{});
    return out;
}
