/// all-spec-tests-runner — combined execution-spec-tests runner.
///
/// Runs both the state-test suite (state_tests) and the blockchain-test suite
/// (blockchain_tests) in sequence, then prints a unified summary.
///
/// Each suite delegates to its dedicated runner binary (spec-test-runner and
/// blockchain-test-runner) which live alongside this binary in zig-out/bin/.
/// Per-file subprocess isolation is handled inside each runner.
///
/// Usage:
///   all-spec-tests-runner [OPTIONS]
///
/// Options:
///   --fork FORK    Only run tests for a specific fork (e.g. Cancun, Prague)
///   --state-fixtures DIR        Override state_tests fixtures dir
///   --blockchain-fixtures DIR   Override blockchain_tests fixtures dir
///   -x             Stop after the first failure (passed to both runners)
///   -q             Quiet — only print FAIL lines and the final summary
///
/// Build:
///   zig build spec-tests [-- --fork Cancun -q]
const std = @import("std");

const RunStats = struct {
    passed:  u64 = 0,
    failed:  u64 = 0,
    skipped: u64 = 0,

    fn total(self: RunStats) u64 {
        return self.passed + self.failed + self.skipped;
    }

    fn add(self: *RunStats, other: RunStats) void {
        self.passed  += other.passed;
        self.failed  += other.failed;
        self.skipped += other.skipped;
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // ── Parse flags ───────────────────────────────────────────────────────────

    var fork_filter:          ?[]const u8 = null;
    var state_fixtures:       ?[]const u8 = null;
    var blockchain_fixtures:  ?[]const u8 = null;
    var stop_on_fail:         bool = false;
    var quiet:                bool = false;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--fork") and i + 1 < args.len) {
            i += 1; fork_filter = args[i];
        } else if (std.mem.eql(u8, arg, "--state-fixtures") and i + 1 < args.len) {
            i += 1; state_fixtures = args[i];
        } else if (std.mem.eql(u8, arg, "--blockchain-fixtures") and i + 1 < args.len) {
            i += 1; blockchain_fixtures = args[i];
        } else if (std.mem.eql(u8, arg, "-x")) {
            stop_on_fail = true;
        } else if (std.mem.eql(u8, arg, "-q")) {
            quiet = true;
        } else if (std.mem.startsWith(u8, arg, "--fork=")) {
            fork_filter = arg["--fork=".len..];
        } else if (std.mem.startsWith(u8, arg, "--state-fixtures=")) {
            state_fixtures = arg["--state-fixtures=".len..];
        } else if (std.mem.startsWith(u8, arg, "--blockchain-fixtures=")) {
            blockchain_fixtures = arg["--blockchain-fixtures=".len..];
        }
    }

    // ── Locate sibling binaries ───────────────────────────────────────────────

    var exe_dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const exe_path = std.fs.selfExePath(&exe_dir_buf) catch args[0];
    const exe_dir  = std.fs.path.dirname(exe_path) orelse ".";

    const state_runner_path = try std.fs.path.join(allocator, &.{ exe_dir, "spec-test-runner" });
    defer allocator.free(state_runner_path);
    const bc_runner_path = try std.fs.path.join(allocator, &.{ exe_dir, "blockchain-test-runner" });
    defer allocator.free(bc_runner_path);

    // ── Run state tests ───────────────────────────────────────────────────────

    if (!quiet) std.debug.print("── State tests ─────────────────────────────────────────────────────────\n", .{});

    var state_argv = std.ArrayList([]const u8){};
    defer state_argv.deinit(allocator);
    try state_argv.append(allocator, state_runner_path);
    if (state_fixtures) |d| try state_argv.appendSlice(allocator, &.{ "--fixtures", d });
    if (fork_filter)    |f| try state_argv.appendSlice(allocator, &.{ "--fork",     f });
    if (quiet)              try state_argv.append(allocator, "-q");
    if (stop_on_fail)       try state_argv.append(allocator, "-x");

    const state_stats = runSuite(allocator, state_argv.items, quiet) catch RunStats{};

    if (stop_on_fail and state_stats.failed > 0) {
        printSummary("State tests", state_stats);
        std.process.exit(1);
    }

    // ── Run blockchain tests ──────────────────────────────────────────────────

    if (!quiet) std.debug.print("\n── Blockchain tests ────────────────────────────────────────────────────\n", .{});

    var bc_argv = std.ArrayList([]const u8){};
    defer bc_argv.deinit(allocator);
    try bc_argv.append(allocator, bc_runner_path);
    if (blockchain_fixtures) |d| try bc_argv.appendSlice(allocator, &.{ "--fixtures", d });
    if (fork_filter)         |f| try bc_argv.appendSlice(allocator, &.{ "--fork",     f });
    if (quiet)                   try bc_argv.append(allocator, "-q");
    if (stop_on_fail)            try bc_argv.append(allocator, "-x");

    const bc_stats = runSuite(allocator, bc_argv.items, quiet) catch RunStats{};

    // ── Combined summary ──────────────────────────────────────────────────────

    var combined = RunStats{};
    combined.add(state_stats);
    combined.add(bc_stats);

    std.debug.print("\n════════════════════════════════════════════════════════════\n", .{});
    std.debug.print("  COMBINED RESULTS\n", .{});
    std.debug.print("────────────────────────────────────────────────────────────\n", .{});
    printSuiteLine("State tests      ", state_stats);
    printSuiteLine("Blockchain tests ", bc_stats);
    std.debug.print("────────────────────────────────────────────────────────────\n", .{});
    const pct: u64 = if (combined.total() > 0) 100 * combined.passed / combined.total() else 0;
    std.debug.print("  Total:  {}/{} passed  ({}%)\n", .{ combined.passed, combined.total(), pct });
    if (combined.failed  > 0) std.debug.print("  Failed:   {}\n", .{combined.failed});
    if (combined.skipped > 0) std.debug.print("  Skipped:  {}\n", .{combined.skipped});
    std.debug.print("════════════════════════════════════════════════════════════\n", .{});
    std.debug.print("STATS: passed={} failed={} skipped={}\n",
        .{ combined.passed, combined.failed, combined.skipped });

    if (combined.failed > 0) std.process.exit(1);
}

/// Spawn a runner subprocess, stream its stderr, and return the aggregated stats.
fn runSuite(allocator: std.mem.Allocator, argv: []const []const u8, quiet: bool) !RunStats {
    var child = std.process.Child.init(argv, allocator);
    child.stderr_behavior = .Pipe;
    try child.spawn();

    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);
    var tmp: [4096]u8 = undefined;
    while (true) {
        const n = child.stderr.?.read(&tmp) catch break;
        if (n == 0) break;
        try buf.appendSlice(allocator, tmp[0..n]);
    }

    var stats = RunStats{};
    var lines = std.mem.splitScalar(u8, buf.items, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "STATS:")) {
            var tok = std.mem.tokenizeScalar(u8, line["STATS:".len..], ' ');
            while (tok.next()) |kv| {
                if (std.mem.startsWith(u8, kv, "passed="))
                    stats.passed  += std.fmt.parseInt(u64, kv["passed=".len..],  10) catch 0
                else if (std.mem.startsWith(u8, kv, "failed="))
                    stats.failed  += std.fmt.parseInt(u64, kv["failed=".len..],  10) catch 0
                else if (std.mem.startsWith(u8, kv, "skipped="))
                    stats.skipped += std.fmt.parseInt(u64, kv["skipped=".len..], 10) catch 0;
            }
        } else if (!std.mem.startsWith(u8, line, "===") and
                   !std.mem.startsWith(u8, line, "════") and
                   !std.mem.startsWith(u8, line, "  Results:") and
                   !std.mem.startsWith(u8, line, "  Failed:") and
                   !std.mem.startsWith(u8, line, "  Skipped:") and
                   line.len > 0)
        {
            if (!quiet or std.mem.startsWith(u8, line, "FAIL") or std.mem.startsWith(u8, line, "CRASH"))
                std.debug.print("{s}\n", .{line});
        }
    }

    _ = child.wait() catch {};
    return stats;
}

fn printSummary(label: []const u8, stats: RunStats) void {
    const pct: u64 = if (stats.total() > 0) 100 * stats.passed / stats.total() else 0;
    std.debug.print("\n{s}: {}/{} passed ({}%)\n", .{ label, stats.passed, stats.total(), pct });
}

fn printSuiteLine(label: []const u8, stats: RunStats) void {
    const pct: u64 = if (stats.total() > 0) 100 * stats.passed / stats.total() else 0;
    std.debug.print("  {s}  {}/{} ({}%)", .{ label, stats.passed, stats.total(), pct });
    if (stats.failed  > 0) std.debug.print("  ✗ {} failed",  .{stats.failed});
    if (stats.skipped > 0) std.debug.print("  ~ {} skipped", .{stats.skipped});
    std.debug.print("\n", .{});
}
