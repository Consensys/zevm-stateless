const std = @import("std");

const io_ssz = @import("io_ssz");
const io_rlp = @import("io_rlp");
const json = @import("json");
const rlp_decode = @import("rlp_decode");
const input = @import("input");
const output_mod = @import("output");
const executor = @import("executor");
const alloc_mod = @import("main_allocator");
const zkvm_io = @import("zkvm_io");

const InFormat = enum { ssz, rlp, json };
const OutFormat = enum { ssz, rlp, json };

fn parseInFormat(s: []const u8) ?InFormat {
    if (std.mem.eql(u8, s, "ssz")) return .ssz;
    if (std.mem.eql(u8, s, "rlp")) return .rlp;
    if (std.mem.eql(u8, s, "json")) return .json;
    return null;
}

/// run_stateless_guest — spec entry point: deserialize → validate → serialize.
/// Mirrors run_stateless_guest from stateless_guest.py in ethereum/execution-specs.
/// Uses SSZ encoding for both input and output per the spec default.
pub fn runStatelessGuest(allocator: std.mem.Allocator, input_bytes: []const u8) ![]const u8 {
    const si = try io_ssz.deserializeStatelessInput(allocator, input_bytes);
    const result = try executor.verifyStatelessNewPayload(allocator, si);
    return io_ssz.serializeStatelessOutput(allocator, result);
}

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
    var file_paths = std.ArrayListUnmanaged([]const u8){};
    var in_format: InFormat = .ssz;
    var out_format: OutFormat = .ssz;
    {
        var arg_i: usize = 1;
        while (arg_i < args.len) : (arg_i += 1) {
            const arg = args[arg_i];
            if (std.mem.eql(u8, arg, "--fork") and arg_i + 1 < args.len) {
                arg_i += 1; // consume --fork <name> but ignore for now
            } else if (std.mem.startsWith(u8, arg, "--input=")) {
                const val = arg["--input=".len..];
                in_format = parseInFormat(val) orelse {
                    std.debug.print("error: unknown input format '{s}' (valid: ssz, rlp, json)\n", .{val});
                    std.process.exit(1);
                };
            } else if (std.mem.startsWith(u8, arg, "-i=")) {
                const val = arg["-i=".len..];
                in_format = parseInFormat(val) orelse {
                    std.debug.print("error: unknown input format '{s}' (valid: ssz, rlp, json)\n", .{val});
                    std.process.exit(1);
                };
            } else if (std.mem.startsWith(u8, arg, "--out=")) {
                const val = arg["--out=".len..];
                out_format = parseOutFormat(val) orelse {
                    std.debug.print("error: unknown output format '{s}' (valid: ssz, rlp, json)\n", .{val});
                    std.process.exit(1);
                };
            } else if (std.mem.startsWith(u8, arg, "-o=")) {
                const val = arg["-o=".len..];
                out_format = parseOutFormat(val) orelse {
                    std.debug.print("error: unknown output format '{s}' (valid: ssz, rlp, json)\n", .{val});
                    std.process.exit(1);
                };
            } else {
                try file_paths.append(allocator, arg);
            }
        }
    }

    // ── stdin mode: binary input (SSZ or RLP) ────────────────────────────────
    // JSON input requires file path arguments; json+no-files is an error.
    if (file_paths.items.len == 0) {
        if (in_format == .json) {
            std.debug.print("error: --input=json requires file path arguments (block.json [witness.json])\n", .{});
            std.process.exit(1);
        }
        const input_bytes = zkvm_io.read_input(allocator) catch |err| {
            std.debug.print("error: failed to read stdin: {}\n", .{err});
            std.process.exit(1);
        };
        const si = deserializeInput(allocator, input_bytes, in_format) catch |err| {
            std.debug.print("error: failed to parse stateless input: {}\n", .{err});
            std.process.exit(1);
        };
        const result = executor.verifyStatelessNewPayload(allocator, si) catch |err| {
            std.debug.print("error: stateless validation failed: {}\n", .{err});
            std.process.exit(1);
        };
        try writeOutput(allocator, result, out_format);
        return;
    }

    // ── file mode: debug-friendly execution ───────────────────────────────────
    const si: input.StatelessInput = blk: {
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
    try writeOutput(allocator, result, out_format);

    std.debug.print("\nOK\n", .{});
}

fn parseOutFormat(s: []const u8) ?OutFormat {
    if (std.mem.eql(u8, s, "ssz")) return .ssz;
    if (std.mem.eql(u8, s, "rlp")) return .rlp;
    if (std.mem.eql(u8, s, "json")) return .json;
    return null;
}

fn deserializeInput(
    allocator: std.mem.Allocator,
    data: []const u8,
    format: InFormat,
) !input.StatelessInput {
    return switch (format) {
        .ssz => io_ssz.deserializeStatelessInput(allocator, data),
        .rlp => io_rlp.deserializeStatelessInput(allocator, data),
        .json => error.JsonInputRequiresFilePaths,
    };
}

fn writeOutput(
    allocator: std.mem.Allocator,
    result: output_mod.StatelessValidationResult,
    format: OutFormat,
) !void {
    switch (format) {
        .ssz => {
            const output_bytes = try io_ssz.serializeStatelessOutput(allocator, result);
            zkvm_io.write_output(output_bytes);
        },
        .rlp => {
            const output_bytes = try io_rlp.serializeStatelessOutput(allocator, result);
            zkvm_io.write_output(output_bytes);
        },
        .json => {
            var list = std.ArrayListUnmanaged(u8){};
            defer list.deinit(allocator);
            try writeResultJson(list.writer(allocator), result);
            _ = try std.posix.write(std.posix.STDOUT_FILENO, list.items);
        },
    }
}

fn writeResultJson(
    writer: anytype,
    result: output_mod.StatelessValidationResult,
) !void {
    try writer.print(
        \\{{
        \\  "new_payload_request_root": "0x{s}",
        \\  "successful_validation": {s},
        \\  "pre_state_root": "0x{s}",
        \\  "post_state_root": "0x{s}",
        \\  "receipts_root": "0x{s}",
        \\  "chain_id": {d}
        \\}}
        \\
    , .{
        std.fmt.bytesToHex(result.new_payload_request_root, .lower),
        if (result.successful_validation) "true" else "false",
        std.fmt.bytesToHex(result.pre_state_root, .lower),
        std.fmt.bytesToHex(result.post_state_root, .lower),
        std.fmt.bytesToHex(result.receipts_root, .lower),
        result.chain_id,
    });
}
