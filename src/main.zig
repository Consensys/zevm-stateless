const std = @import("std");

const io = @import("io.zig");
const json = @import("json.zig");
const rlp_decode = @import("rlp_decode");
const input = @import("input");
const executor = @import("executor");
const alloc_mod = @import("main_allocator");
const zkvm_io = @import("zkvm_io");

pub fn main() void {
    run() catch |err| {
        std.debug.print("fatal: {}\n", .{err});
        std.process.exit(1);
    };
}

fn run() !void {
    const allocator = alloc_mod.get();

    const args = try std.process.argsAlloc(allocator);

    // Parse flags and collect positional (file path) arguments.
    // --fork <name> may appear anywhere; all other args are treated as file paths.
    // Note: fork override is not exposed in the spec interface; it is applied
    // internally for dev/testing via executor.verifyStatelessNewPayload's fork_name
    // parameter. For now native builds ignore --fork here and rely on auto-detection.
    var file_paths = std.ArrayListUnmanaged([]const u8){};
    {
        var arg_i: usize = 1;
        while (arg_i < args.len) : (arg_i += 1) {
            if (std.mem.eql(u8, args[arg_i], "--fork") and arg_i + 1 < args.len) {
                arg_i += 1; // consume --fork <name> but ignore for now
            } else {
                try file_paths.append(allocator, args[arg_i]);
            }
        }
    }

    // ── deserialize_stateless_input ───────────────────────────────────────────
    const si: input.StatelessInput = if (file_paths.items.len == 0) blk: {
        // No file paths — read binary StatelessInput from stdin.
        break :blk io.fromStdin(allocator) catch |err| {
            std.debug.print("error: failed to parse stateless input from stdin: {}\n", .{err});
            std.debug.print("hint:  pipe a zevm-zisk binary StatelessInput, or pass block/witness paths as args\n", .{});
            std.process.exit(1);
        };
    } else blk: {
        const block_path = file_paths.items[0];
        const witness_path = if (file_paths.items.len > 1) file_paths.items[1] else "examples/witness.json";

        const block_json = std.fs.cwd().readFileAlloc(allocator, block_path, 1 << 20) catch |err| {
            std.debug.print("error: cannot read {s}: {}\n", .{ block_path, err });
            std.debug.print("hint:  run `zig build gen-example` to create the example files.\n", .{});
            std.process.exit(1);
        };

        const witness_json = std.fs.cwd().readFileAlloc(allocator, witness_path, 64 << 20) catch |err| {
            std.debug.print("error: cannot read {s}: {}\n", .{ witness_path, err });
            std.process.exit(1);
        };

        const parsed_block = json.parseBlockJson(allocator, block_json) catch |err| {
            std.debug.print("error: failed to parse {s}: {}\n", .{ block_path, err });
            std.process.exit(1);
        };

        var wit = json.parseWitnessJson(allocator, witness_json) catch |err| {
            std.debug.print("error: failed to parse {s}: {}\n", .{ witness_path, err });
            std.process.exit(1);
        };
        wit.state_root = rlp_decode.findPreStateRoot(wit.headers, parsed_block.header.number) orelse parsed_block.header.state_root;

        break :blk input.StatelessInput{
            .block = parsed_block.header,
            .transactions = parsed_block.transactions,
            .witness = wit,
        };
    };

    std.debug.print("=== zevm-stateless: block #{d} ===\n\n", .{si.block.number});
    std.debug.print(
        "witness  root = 0x{x}\n" ++
            "         {d} node(s), {d} code(s), {d} key(s), {d} header(s)\n\n",
        .{ si.witness.state_root, si.witness.state.len, si.witness.codes.len, si.witness.keys.len, si.witness.headers.len },
    );

    // ── verify_stateless_new_payload ──────────────────────────────────────────
    const result = executor.verifyStatelessNewPayload(allocator, si) catch |err| {
        std.debug.print("  FAIL → {}\n", .{err});
        std.process.exit(1);
    };

    const state_ok = std.mem.eql(u8, &result.post_state_root, &si.block.state_root);
    const receipts_ok = std.mem.eql(u8, &result.receipts_root, &si.block.receipts_root);

    std.debug.print("  pre_state_root  = 0x{x}\n", .{result.pre_state_root});
    if (state_ok) {
        std.debug.print("  post_state_root = 0x{x}  ✓\n", .{result.post_state_root});
    } else {
        std.debug.print("  post_state_root = 0x{x}  ✗  MISMATCH\n", .{result.post_state_root});
        std.debug.print("  expected        = 0x{x}\n", .{si.block.state_root});
    }
    if (receipts_ok) {
        std.debug.print("  receipts_root   = 0x{x}  ✓\n", .{result.receipts_root});
    } else {
        std.debug.print("  receipts_root   = 0x{x}  ✗  MISMATCH\n", .{result.receipts_root});
        std.debug.print("  expected        = 0x{x}\n", .{si.block.receipts_root});
    }

    if (!state_ok or !receipts_ok) {
        std.debug.print("\nFAIL\n", .{});
        std.process.exit(1);
    }

    // ── serialize_stateless_output ────────────────────────────────────────────
    const output_bytes = try io.serializeStatelessOutput(allocator, result);
    zkvm_io.write_output(output_bytes);

    std.debug.print("\nOK\n", .{});
}
