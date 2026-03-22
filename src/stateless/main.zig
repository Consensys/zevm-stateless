const std = @import("std");

const io = @import("io.zig");
const json = @import("json.zig");
const rlp_decode = @import("rlp_decode");
const input = @import("input");
const primitives = @import("primitives");
const mpt = @import("mpt");
const executor = @import("executor");
const alloc_mod = @import("main_allocator");
const zkvm_io = @import("zkvm_io");

const InputSource = union(enum) {
    rlp_stream, // default: zkvm_io.read_input()
    ssz_stream, // --ssz (no file)
    rlp_file: []const u8, // --rlp <file>
    ssz_file: []const u8, // --ssz <file>
    json: struct { block: []const u8, witness: []const u8 }, // --json <b> <w>
};

pub fn main() !void {
    const allocator = alloc_mod.get();

    const args = try std.process.argsAlloc(allocator);

    // ── Arg parsing ───────────────────────────────────────────────────────────
    var fork_name: ?[]const u8 = null;
    var source: InputSource = .rlp_stream;

    var arg_i: usize = 1;
    while (arg_i < args.len) : (arg_i += 1) {
        const arg = args[arg_i];

        if (std.mem.eql(u8, arg, "--fork")) {
            arg_i += 1;
            if (arg_i >= args.len) {
                std.debug.print("error: --fork requires a fork name\n", .{});
                printUsage();
                std.process.exit(1);
            }
            fork_name = args[arg_i];
        } else if (std.mem.eql(u8, arg, "--rlp")) {
            arg_i += 1;
            if (arg_i >= args.len or std.mem.startsWith(u8, args[arg_i], "--")) {
                std.debug.print("error: --rlp requires a file path\n", .{});
                printUsage();
                std.process.exit(1);
            }
            source = .{ .rlp_file = args[arg_i] };
        } else if (std.mem.eql(u8, arg, "--ssz")) {
            // --ssz may optionally be followed by a file path
            if (arg_i + 1 < args.len and !std.mem.startsWith(u8, args[arg_i + 1], "--")) {
                arg_i += 1;
                source = .{ .ssz_file = args[arg_i] };
            } else {
                source = .ssz_stream;
            }
        } else if (std.mem.eql(u8, arg, "--json")) {
            arg_i += 1;
            if (arg_i >= args.len) {
                std.debug.print("error: --json requires block and witness paths\n", .{});
                printUsage();
                std.process.exit(1);
            }
            const block_path = args[arg_i];
            arg_i += 1;
            if (arg_i >= args.len) {
                std.debug.print("error: --json requires block and witness paths\n", .{});
                printUsage();
                std.process.exit(1);
            }
            const witness_path = args[arg_i];
            source = .{ .json = .{ .block = block_path, .witness = witness_path } };
        } else {
            std.debug.print("error: unexpected argument '{s}'\n", .{arg});
            std.debug.print("hint:  use --json <block> <witness>, --rlp <file>, or --ssz [file]\n", .{});
            printUsage();
            std.process.exit(1);
        }
    }

    // ── Load input ────────────────────────────────────────────────────────────
    const si: input.StatelessInput = switch (source) {
        .rlp_stream => io.fromRlpStream(allocator) catch |err| {
            std.debug.print("error: failed to parse RLP from zkvm_io.read_input(): {}\n", .{err});
            std.debug.print("hint:  pipe a zevm-zisk binary StatelessInput, or use --rlp/--json flags\n", .{});
            std.process.exit(1);
        },
        .ssz_stream => io.fromSszStream(allocator) catch |err| {
            std.debug.print("error: SSZ input not yet implemented: {}\n", .{err});
            std.process.exit(1);
        },
        .rlp_file => |path| io.fromRlpFile(allocator, path) catch |err| {
            std.debug.print("error: failed to parse RLP from '{s}': {}\n", .{ path, err });
            std.process.exit(1);
        },
        .ssz_file => |path| io.fromSszFile(allocator, path) catch |err| {
            std.debug.print("error: SSZ input not yet implemented (file: '{s}'): {}\n", .{ path, err });
            std.process.exit(1);
        },
        .json => |p| loadFromJson(allocator, p.block, p.witness) catch |err| {
            std.debug.print("error: failed to load JSON input: {}\n", .{err});
            std.process.exit(1);
        },
    };

    std.debug.print("=== zevm-stateless: block #{d} ===\n\n", .{si.block.number});

    std.debug.print(
        "witness  root = 0x{x}\n" ++
            "         {d} node(s), {d} code(s), {d} key(s), {d} header(s)\n\n",
        .{ si.witness.state_root, si.witness.nodes.len, si.witness.codes.len, si.witness.keys.len, si.witness.headers.len },
    );

    // ── Witness processing ────────────────────────────────────────────────────
    var node_index = try mpt.buildNodeIndex(allocator, si.witness.nodes);
    defer node_index.deinit();

    const pre_state_root = si.witness.state_root;
    var pre_alloc: std.AutoHashMapUnmanaged([20]u8, executor.AllocAccount) = .{};
    var current_addr: ?[20]u8 = null;

    for (si.witness.keys) |key| {
        if (key.len == 20) {
            var addr: [20]u8 = undefined;
            @memcpy(&addr, key[0..20]);
            current_addr = addr;

            const account_state = (try mpt.verifyAccountIndexed(
                si.witness.state_root,
                addr,
                &node_index,
            )) orelse continue;

            const code: []const u8 = blk: {
                if (std.mem.eql(u8, &account_state.code_hash, &primitives.KECCAK_EMPTY)) break :blk &.{};
                for (si.witness.codes) |code_bytes| {
                    if (std.mem.eql(u8, &mpt.keccak256(code_bytes), &account_state.code_hash)) break :blk code_bytes;
                }
                break :blk &.{};
            };

            const entry = try pre_alloc.getOrPut(allocator, addr);
            if (!entry.found_existing) {
                entry.value_ptr.* = .{
                    .balance = account_state.balance,
                    .nonce = account_state.nonce,
                    .code = code,
                    .pre_storage_root = account_state.storage_root,
                };
            }
        } else if (key.len == 52) {
            var addr: [20]u8 = undefined;
            @memcpy(&addr, key[0..20]);
            current_addr = addr;
            var raw_slot: [32]u8 = undefined;
            @memcpy(&raw_slot, key[20..52]);
            try putStorageSlot(allocator, &pre_alloc, &node_index, si.witness.state_root, addr, raw_slot);
        } else if (key.len == 32) {
            if (current_addr) |addr| {
                var raw_slot: [32]u8 = undefined;
                @memcpy(&raw_slot, key[0..32]);
                try putStorageSlot(allocator, &pre_alloc, &node_index, si.witness.state_root, addr, raw_slot);
            }
        }
    }

    // Decode block-hash table from witness headers.
    var block_hashes = std.ArrayListUnmanaged(executor.BlockHashEntry){};
    for (si.witness.headers) |hdr_rlp| {
        const hash = mpt.keccak256(hdr_rlp);
        const outer = mpt.rlp.decodeItem(hdr_rlp) catch continue;
        var rest = switch (outer.item) {
            .list => |p| p,
            .bytes => continue,
        };
        var skip: usize = 0;
        while (skip < 8 and rest.len > 0) : (skip += 1) {
            const fr = mpt.rlp.decodeItem(rest) catch break;
            rest = rest[fr.consumed..];
        }
        if (rest.len == 0) continue;
        const num_r = mpt.rlp.decodeItem(rest) catch continue;
        const num_bytes = switch (num_r.item) {
            .bytes => |b| b,
            .list => continue,
        };
        if (num_bytes.len > 8) continue;
        var number: u64 = 0;
        for (num_bytes) |b| number = (number << 8) | b;
        try block_hashes.append(allocator, .{ .number = number, .hash = hash });
    }

    // ── Block execution ───────────────────────────────────────────────────────
    std.debug.print("Block execution\n", .{});
    std.debug.print("  block env\n", .{});
    std.debug.print("    number      = {d}\n", .{si.block.number});
    std.debug.print("    coinbase    = 0x{x}\n", .{si.block.beneficiary});
    std.debug.print("    timestamp   = {d}\n", .{si.block.timestamp});
    std.debug.print("    gas_limit   = {d}\n", .{si.block.gas_limit});
    std.debug.print("    basefee     = {d}\n", .{si.block.base_fee_per_gas orelse 0});
    std.debug.print("    prevrandao  = 0x{x}\n", .{si.block.mix_hash});
    if (si.block.excess_blob_gas) |excess| {
        std.debug.print("    excess_blob_gas = {d}\n", .{excess});
    }

    std.debug.print("  transactions  = {d}\n", .{si.transactions.len});
    if (fork_name) |f| std.debug.print("  fork override = {s}\n", .{f});

    const proof_out = executor.executeBlock(
        allocator,
        pre_state_root,
        pre_alloc,
        &node_index,
        si.block,
        si.transactions,
        si.withdrawals,
        block_hashes.items,
        fork_name,
    ) catch |err| {
        std.debug.print("  FAIL → {}\n", .{err});
        std.process.exit(1);
    };

    std.debug.print("  fork            = {s}\n", .{proof_out.fork_name});
    std.debug.print("  receipts        = {d}\n", .{proof_out.receipts.len});
    std.debug.print("  pre_state_root  = 0x{x}\n", .{proof_out.pre_state_root});

    const state_ok = std.mem.eql(u8, &proof_out.post_state_root, &si.block.state_root);
    const receipts_ok = std.mem.eql(u8, &proof_out.receipts_root, &si.block.receipts_root);

    if (state_ok) {
        std.debug.print("  post_state_root = 0x{x}  ✓\n", .{proof_out.post_state_root});
    } else {
        std.debug.print("  post_state_root = 0x{x}  ✗  MISMATCH\n", .{proof_out.post_state_root});
        std.debug.print("  expected        = 0x{x}\n", .{si.block.state_root});
    }

    if (receipts_ok) {
        std.debug.print("  receipts_root   = 0x{x}  ✓\n", .{proof_out.receipts_root});
    } else {
        std.debug.print("  receipts_root   = 0x{x}  ✗  MISMATCH\n", .{proof_out.receipts_root});
        std.debug.print("  expected        = 0x{x}\n", .{si.block.receipts_root});
    }

    if (!state_ok or !receipts_ok) {
        std.debug.print("\nFAIL\n", .{});
        std.process.exit(1);
    }

    // Emit a machine-readable JSON result line to stdout.
    var out_buf: [512]u8 = undefined;
    const out = try std.fmt.bufPrint(
        &out_buf,
        "{{\"block\":{d},\"valid\":true," ++
            "\"pre_state_root\":\"0x{x}\"," ++
            "\"post_state_root\":\"0x{x}\"," ++
            "\"receipts_root\":\"0x{x}\"}}\n",
        .{
            si.block.number,
            proof_out.pre_state_root,
            proof_out.post_state_root,
            proof_out.receipts_root,
        },
    );
    zkvm_io.write_output(out);

    std.debug.print("\nOK\n", .{});
}

fn loadFromJson(allocator: std.mem.Allocator, block_path: []const u8, witness_path: []const u8) !input.StatelessInput {
    const block_json = std.fs.cwd().readFileAlloc(allocator, block_path, 1 << 20) catch |err| {
        std.debug.print("error: cannot read {s}: {}\n", .{ block_path, err });
        return err;
    };

    const witness_json = std.fs.cwd().readFileAlloc(allocator, witness_path, 64 << 20) catch |err| {
        std.debug.print("error: cannot read {s}: {}\n", .{ witness_path, err });
        return err;
    };

    const parsed_block = json.parseBlockJson(allocator, block_json) catch |err| {
        std.debug.print("error: failed to parse {s}: {}\n", .{ block_path, err });
        std.debug.print("  accepted formats:\n", .{});
        std.debug.print("    {{\"result\":\"0x<rlp>\"}}  raw JSON-RPC response from debug_getRawBlock\n", .{});
        std.debug.print("    {{\"block\": \"0x<rlp>\"}}  generated by `zig build gen-example`\n", .{});
        return err;
    };

    var wit = json.parseWitnessJson(allocator, witness_json) catch |err| {
        std.debug.print("error: failed to parse {s}: {}\n", .{ witness_path, err });
        std.debug.print("  accepted formats:\n", .{});
        std.debug.print("    {{\"state\":[...],\"codes\":[...],\"keys\":[...],\"headers\":[...]}}  direct\n", .{});
        std.debug.print("    {{\"jsonrpc\":\"2.0\",\"result\":{{...}}}}  JSON-RPC envelope\n", .{});
        return err;
    };
    wit.state_root = rlp_decode.findPreStateRoot(wit.headers, parsed_block.header.number) orelse parsed_block.header.state_root;

    return input.StatelessInput{
        .block = parsed_block.header,
        .transactions = parsed_block.transactions,
        .witness = wit,
        .withdrawals = parsed_block.withdrawals,
    };
}

fn printUsage() void {
    std.debug.print(
        \\usage:
        \\  zevm_stateless [--fork F]                              # RLP from zkvm_io (default / zkVM)
        \\  zevm_stateless --ssz [--fork F]                        # SSZ from zkvm_io (stub)
        \\  zevm_stateless --rlp <file> [--fork F]                 # RLP binary file
        \\  zevm_stateless --ssz <file> [--fork F]                 # SSZ binary file (stub)
        \\  zevm_stateless --json <block.json> <witness.json> [--fork F]
        \\
    , .{});
}

fn putStorageSlot(
    allocator: std.mem.Allocator,
    pre_alloc: *std.AutoHashMapUnmanaged([20]u8, executor.AllocAccount),
    node_index: *mpt.NodeIndex,
    state_root: [32]u8,
    addr: [20]u8,
    raw_slot: [32]u8,
) !void {
    const acct_state = (try mpt.verifyAccountIndexed(state_root, addr, node_index)) orelse return;
    const value = try mpt.verifyStorageIndexed(acct_state.storage_root, raw_slot, node_index);
    if (value != 0) {
        const entry = try pre_alloc.getOrPut(allocator, addr);
        if (!entry.found_existing) entry.value_ptr.* = .{};
        try entry.value_ptr.*.storage.put(allocator, hashToU256(raw_slot), value);
    }
}

fn hashToU256(hash: [32]u8) u256 {
    var result: u256 = 0;
    for (hash) |b| result = (result << 8) | b;
    return result;
}
