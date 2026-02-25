const std = @import("std");
const io = @import("io.zig");
const input = @import("input");
const executor = @import("executor");
const output = @import("output");

pub fn main() !void {
    // 1. Read the StatelessInput from the zkVM input channel
    const stateless_input = try io.readInput(input.StatelessInput);

    // 2. Execute the block against the witness
    const result = try executor.executeBlock(stateless_input);

    // 3. Write the ProofOutput to the zkVM output channel
    try io.writeOutput(result);
}
