const std = @import("std");

const io         = @import("io.zig");
const primitives = @import("primitives");
const mpt        = @import("mpt");
const db         = @import("db");

pub fn main() void {
    run() catch |err| {
        std.debug.print("fatal: {}\n", .{err});
        std.process.exit(1);
    };
}

fn run() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const args = try std.process.argsAlloc(allocator);

    const block_path   = if (args.len > 1) args[1] else "examples/block.json";
    const witness_path = if (args.len > 2) args[2] else "examples/witness.json";

    const block_json = std.fs.cwd().readFileAlloc(allocator, block_path, 1 << 20) catch |err| {
        std.debug.print("error: cannot read {s}: {}\n", .{ block_path, err });
        std.debug.print("hint:  run `zig build gen-example` to create the example files.\n", .{});
        std.process.exit(1);
    };

    const witness_json = std.fs.cwd().readFileAlloc(allocator, witness_path, 64 << 20) catch |err| {
        std.debug.print("error: cannot read {s}: {}\n", .{ witness_path, err });
        std.process.exit(1);
    };

    const si = io.parseBlockAndWitness(allocator, block_json, witness_json) catch |err| {
        std.debug.print("error: failed to parse input: {}\n", .{err});
        std.process.exit(1);
    };

    std.debug.print("=== zevm-stateless: block #{d} ===\n\n", .{si.block_number});

    // ── Phase 1: MPT proof verification ───────────────────────────────────────
    std.debug.print("Phase 1  MPT proof verification\n", .{});
    const proven_root = mpt.verifyWitness(si.witness) catch |err| {
        std.debug.print("  FAILED: {}\n", .{err});
        std.process.exit(1);
    };
    std.debug.print(
        "  OK     root = 0x{x}\n",
        .{proven_root},
    );
    std.debug.print(
        "         {d} node(s) in pool, {d} key(s) verified\n\n",
        .{ si.witness.nodes.len, si.witness.keys.len },
    );

    // ── Phase 2: WitnessDatabase queries ──────────────────────────────────────
    std.debug.print("Phase 2  WitnessDatabase queries\n", .{});
    var witness_db = db.WitnessDatabase.init(si.witness);

    var account_count: usize = 0;
    for (si.witness.keys) |key| {
        if (key.len != 20) continue;
        account_count += 1;

        var addr: primitives.Address = undefined;
        @memcpy(&addr, key[0..20]);

        const info = witness_db.basic(addr) catch |err| {
            std.debug.print(
                "  0x{x}  error: {}\n",
                .{ addr, err },
            );
            continue;
        };

        if (info) |a| {
            const code_desc = if (std.mem.eql(u8, &a.code_hash, &primitives.KECCAK_EMPTY))
                "EOA" else "contract";
            std.debug.print(
                "  0x{x}  nonce={d}  balance={d}  type={s}\n",
                .{ addr, a.nonce, a.balance, code_desc },
            );
        } else {
            std.debug.print(
                "  0x{x}  (absent from trie)\n",
                .{addr},
            );
        }
    }

    if (account_count == 0) {
        std.debug.print("  (no account keys in witness)\n", .{});
    }

    std.debug.print("\nDone.\n", .{});
}
