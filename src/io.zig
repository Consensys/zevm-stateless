//! zkVM I/O: read structured input and write structured output.
//!
//! The concrete implementation depends on the target zkVM (SP1, RISC Zero,
//! Zisk, …). For now this is a placeholder that reads/writes raw bytes via
//! stdin/stdout so the program can be tested natively.

const std = @import("std");

/// Read and deserialize a value of type T from the zkVM input channel.
pub fn readInput(comptime T: type) !T {
    @panic("readInput(" ++ @typeName(T) ++ "): not yet implemented");
}

/// Serialize and write a value to the zkVM output channel.
pub fn writeOutput(value: anytype) !void {
    _ = value;
    @panic("writeOutput: not yet implemented");
}
