const types = @import("executor_types");
const primitives = @import("primitives");
const bal = @import("executor_bal");

// EIP-1559 / gas limit constants
const MIN_GAS_LIMIT: u64 = 5_000;
const MAX_GAS_LIMIT: u64 = 0x7fff_ffff_ffff_ffff;
const GAS_LIMIT_ADJUSTMENT_FACTOR: u64 = 1_024;
const BASE_FEE_MAX_CHANGE_DENOMINATOR: u64 = 8;
const ELASTICITY_MULTIPLIER: u64 = 2;

// EIP-4844 blob gas constants
const GAS_PER_BLOB: u64 = 131_072;
// EIP-7918 blob reserve price constant (2^13)
const BLOB_BASE_COST: u64 = 8_192;

/// Validates block-level invariants before execution.
/// Returns an error if the block header is invalid.
pub fn validateBlock(env: types.Env, spec: primitives.SpecId) !void {
    // GASLIMIT_TOO_BIG: gas limit must fit in a signed 64-bit integer
    if (env.gas_limit > MAX_GAS_LIMIT) return error.GasLimitTooBig;

    // INVALID_BLOCK_TIMESTAMP_OLDER_THAN_PARENT
    if (env.parent_timestamp) |pt| {
        if (env.timestamp <= pt) return error.InvalidBlockTimestampOlderThanParent;
    }

    // INVALID_GASLIMIT: |gas_limit - parent_gas_limit| < parent_gas_limit / 1024
    // and gas_limit >= MIN_GAS_LIMIT
    if (env.parent_gas_limit) |pgl| {
        if (env.gas_limit < MIN_GAS_LIMIT) return error.InvalidGasLimit;
        const max_delta = pgl / GAS_LIMIT_ADJUSTMENT_FACTOR;
        const diff = if (env.gas_limit > pgl) env.gas_limit - pgl else pgl - env.gas_limit;
        if (diff >= max_delta) return error.InvalidGasLimit;
    }

    // INVALID_BASEFEE_PER_GAS (EIP-1559, London+)
    if (primitives.isEnabledIn(spec, .london)) {
        if (env.parent_base_fee) |pbf| if (env.parent_gas_limit) |pgl| if (env.parent_gas_used) |pgu| {
            if (env.base_fee) |actual_base_fee| {
                const gas_target = pgl / ELASTICITY_MULTIPLIER;
                const expected_base_fee: u64 = blk: {
                    if (pgu == gas_target) {
                        break :blk pbf;
                    } else if (pgu > gas_target) {
                        const delta: u128 = pgu - gas_target;
                        const fee_delta: u64 = @intCast(@max(1, @as(u128, pbf) * delta / gas_target / BASE_FEE_MAX_CHANGE_DENOMINATOR));
                        break :blk pbf + fee_delta;
                    } else {
                        const delta: u128 = gas_target - pgu;
                        const fee_delta: u64 = @intCast(@as(u128, pbf) * delta / gas_target / BASE_FEE_MAX_CHANGE_DENOMINATOR);
                        break :blk pbf - fee_delta;
                    }
                };
                if (actual_base_fee != expected_base_fee) return error.InvalidBaseFeePerGas;
            }
        };
    }

    // INCORRECT_EXCESS_BLOB_GAS (EIP-4844, Cancun+)
    if (primitives.isEnabledIn(spec, .cancun)) {
        if (env.parent_excess_blob_gas) |pebg| if (env.parent_blob_gas_used) |pbgu| {
            const expected: u64 = calcExcessBlobGas(pebg, pbgu, env.parent_base_fee, spec, env.blob_base_fee_update_fraction);
            if (env.excess_blob_gas) |actual| {
                if (actual != expected) return error.IncorrectExcessBlobGas;
            }
        };
    }
}

/// Returns the blob gas TARGET per block for the given spec.
/// - BPO2/Amsterdam+: 14 blobs
/// - BPO1:            10 blobs
/// - Prague/Osaka:     6 blobs
/// - Cancun:           3 blobs
pub fn blobGasTarget(spec: primitives.SpecId) u64 {
    return if (primitives.isEnabledIn(spec, .bpo2))
        14 * GAS_PER_BLOB
    else if (primitives.isEnabledIn(spec, .bpo1))
        10 * GAS_PER_BLOB
    else if (primitives.isEnabledIn(spec, .prague))
        6 * GAS_PER_BLOB
    else
        3 * GAS_PER_BLOB;
}

/// Returns the blob gas MAX per block for the given spec.
/// - BPO2/Amsterdam+: 21 blobs
/// - BPO1:            15 blobs
/// - Prague/Osaka:     9 blobs
/// - Cancun:           6 blobs
pub fn blobGasMax(spec: primitives.SpecId) u64 {
    return if (primitives.isEnabledIn(spec, .bpo2))
        21 * GAS_PER_BLOB
    else if (primitives.isEnabledIn(spec, .bpo1))
        15 * GAS_PER_BLOB
    else if (primitives.isEnabledIn(spec, .prague))
        9 * GAS_PER_BLOB
    else
        6 * GAS_PER_BLOB;
}

/// Post-execution block validation.
/// Called after transition() with the actual gas totals.
///   total_gas_used — cumulative gas from all transactions (result.cumulative_gas)
///   blob_gas_used  — total blob gas from type-3 transactions (result.blob_gas_used)
pub fn validatePostExecution(
    env: types.Env,
    spec: primitives.SpecId,
    total_gas_used: u64,
    blob_gas_used: u64,
) !void {
    // INVALID_GAS_USED_ABOVE_LIMIT: header gasUsed > gasLimit
    if (env.gas_used_header) |declared| {
        if (declared > env.gas_limit) return error.InvalidGasUsedAboveLimit;
    }

    // GAS_USED_OVERFLOW: actual execution gas > gasLimit (sanity guard)
    if (total_gas_used > env.gas_limit) return error.GasUsedOverflow;

    // INVALID_GAS_USED: computed total ≠ header's declared gasUsed.
    // Gated to pre-Amsterdam: EIP-7778 (Amsterdam+) splits block-header gasUsed
    // (no-refund accounting) from receipt cumulative_gas_used (post-refund).
    // result.cumulative_gas tracks receipt-level gas; once EIP-7778 is
    // implemented in transition(), remove this gate.
    if (!primitives.isEnabledIn(spec, .amsterdam)) {
        if (env.gas_used_header) |declared| {
            if (total_gas_used != declared) return error.InvalidGasUsed;
        }
    }

    if (primitives.isEnabledIn(spec, .cancun)) {
        // BLOB_GAS_USED_ABOVE_LIMIT
        if (blob_gas_used > blobGasMax(spec)) return error.BlobGasUsedAboveLimit;

        // INCORRECT_BLOB_GAS_USED: computed blob gas ≠ header's declared blobGasUsed
        if (env.blob_gas_used_header) |declared| {
            if (blob_gas_used != declared) return error.IncorrectBlobGasUsed;
        }
    }
}

/// Validates blob gas used against the per-block maximum (post-execution check).
/// Deprecated: prefer validatePostExecution. Kept for callers that only need this one check.
pub fn validateBlobGasUsed(blob_gas_used: u64, spec: primitives.SpecId) !void {
    if (!primitives.isEnabledIn(spec, .cancun)) return;
    if (blob_gas_used > blobGasMax(spec)) return error.BlobGasUsedAboveLimit;
}

/// Calculates the expected excess_blob_gas for the next block.
/// For Osaka+ (EIP-7918), applies the reserve price adjustment when active.
/// For Cancun/Prague, uses the standard EIP-4844 formula.
pub fn calcExcessBlobGas(
    parent_excess: u64,
    parent_used: u64,
    parent_base_fee: ?u64,
    spec: primitives.SpecId,
    update_fraction_override: ?u64,
) u64 {
    const target = blobGasTarget(spec);
    const sum = parent_excess + parent_used;

    // Standard EIP-4844 formula applies when sum < target (no excess regardless of EIP-7918)
    if (sum < target) return 0;

    // EIP-7918 reserve price adjustment (Osaka+)
    if (primitives.isEnabledIn(spec, .osaka)) {
        if (parent_base_fee) |pbf| {
            const fraction = update_fraction_override orelse defaultBlobUpdateFraction(spec);
            const current_blob_fee = fakeBlobGasPrice(parent_excess, fraction);
            // Reserve price active when: BLOB_BASE_COST * base_fee > GAS_PER_BLOB * blob_fee
            const lhs: u128 = @as(u128, BLOB_BASE_COST) * @as(u128, pbf);
            const rhs: u128 = @as(u128, GAS_PER_BLOB) * current_blob_fee;
            if (lhs > rhs) {
                // Reserve price active: partial adjustment only
                const max_gas = blobGasMax(spec);
                const adjustment = @as(u128, parent_used) * (max_gas - target) / max_gas;
                return parent_excess + @as(u64, @intCast(adjustment));
            }
        }
    }

    // Standard EIP-4844 formula
    return sum - target;
}

/// Returns the default blob base fee update fraction for the given spec.
fn defaultBlobUpdateFraction(spec: primitives.SpecId) u64 {
    if (primitives.isEnabledIn(spec, .bpo2)) return primitives.BLOB_BASE_FEE_UPDATE_FRACTION_BPO2;
    if (primitives.isEnabledIn(spec, .bpo1)) return primitives.BLOB_BASE_FEE_UPDATE_FRACTION_BPO1;
    if (primitives.isEnabledIn(spec, .prague)) return primitives.BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE;
    return primitives.BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN;
}

/// fake_exponential(factor=1, numerator=excess_blob_gas, denominator=update_fraction)
/// Mirrors the EIP-4844 blob gas price formula in zevm/src/context/block.zig.
fn fakeBlobGasPrice(excess_blob_gas: u64, update_fraction: u64) u128 {
    if (update_fraction == 0) return std.math.maxInt(u128);
    const numerator: u128 = excess_blob_gas;
    const denominator: u128 = update_fraction;
    var i: u128 = 1;
    var output: u128 = 0;
    var accum: u128 = denominator; // factor=1 * denominator
    while (accum > 0) {
        output +|= accum;
        accum = (accum *| numerator) / (denominator * i);
        i += 1;
        if (i > 512) break;
    }
    return output / denominator;
}

const std = @import("std");

/// Post-execution BAL validation (EIP-7928, Amsterdam+).
/// `accessed` must be sorted ascending by address (as returned by buildAccessedEntries).
pub fn validateBlockAccessList(
    alloc: std.mem.Allocator,
    declared_bytes: []const u8,
    accessed: []const types.AccessedEntry,
    spec: primitives.SpecId,
) !void {
    if (!primitives.isEnabledIn(spec, .amsterdam)) return;

    if (declared_bytes.len == 0) {
        if (accessed.len == 0) return;
        return error.InvalidBlockAccessList;
    }

    {
        var tmp: [16]u8 = @splat(0);
        const n = @min(declared_bytes.len, 16);
        @memcpy(tmp[0..n], declared_bytes[0..n]);
        std.debug.print("DBG BAL declared_bytes len={} first16=0x{s}\n", .{ declared_bytes.len, std.fmt.bytesToHex(tmp, .lower) });
    }
    const declared = bal.decode(alloc, declared_bytes) catch |err| {
        std.debug.print("DBG BAL decode failed: {}\n", .{err});
        return error.InvalidBlockAccessList;
    };

    // Verify declared is strictly ascending by address (canonical BAL order)
    for (1..@max(1, declared.len)) |i| {
        if (std.mem.order(u8, &declared[i - 1].address, &declared[i].address) != .lt) {
            return error.InvalidBlockAccessList;
        }
    }

    if (declared.len != accessed.len) {
        std.debug.print("DBG BAL count mismatch: declared={} computed={}\n", .{ declared.len, accessed.len });
        for (declared) |d| std.debug.print("  declared: 0x{s}\n", .{std.fmt.bytesToHex(d.address, .lower)});
        for (accessed) |a| std.debug.print("  computed: 0x{s}\n", .{std.fmt.bytesToHex(a.address, .lower)});
        return error.InvalidBlockAccessList;
    }

    for (declared, accessed) |decl, comp| {
        if (!std.mem.eql(u8, &decl.address, &comp.address)) {
            std.debug.print("DBG BAL addr mismatch: declared=0x{s} computed=0x{s}\n", .{ std.fmt.bytesToHex(decl.address, .lower), std.fmt.bytesToHex(comp.address, .lower) });
            return error.InvalidBlockAccessList;
        }

        // Nonce: non-empty iff changed; last entry == post_nonce
        if (comp.pre_nonce != comp.post_nonce) {
            if (decl.nonce_changes.len == 0) {
                std.debug.print("DBG BAL 0x{s}: nonce changed ({}->{}) but decl nonce_changes empty\n", .{ std.fmt.bytesToHex(comp.address, .lower), comp.pre_nonce, comp.post_nonce });
                return error.InvalidBlockAccessList;
            }
            if (decl.nonce_changes[decl.nonce_changes.len - 1] != comp.post_nonce) {
                std.debug.print("DBG BAL 0x{s}: nonce last={} expected={}\n", .{ std.fmt.bytesToHex(comp.address, .lower), decl.nonce_changes[decl.nonce_changes.len - 1], comp.post_nonce });
                return error.InvalidBlockAccessList;
            }
        } else {
            if (decl.nonce_changes.len != 0) {
                std.debug.print("DBG BAL 0x{s}: nonce unchanged ({}) but decl nonce_changes len={}\n", .{ std.fmt.bytesToHex(comp.address, .lower), comp.pre_nonce, decl.nonce_changes.len });
                return error.InvalidBlockAccessList;
            }
        }

        // Balance: last entry must equal post_balance; empty iff no net change AND no intermediate changes.
        // Note: EIP-7928 records ALL per-tx balance changes, including those that net to zero
        // (e.g., funded in tx0 and fully spent in tx1).  We can't detect intermediate-only changes
        // without per-tx tracking, so we accept decl.balance_changes.len != 0 even when pre==post,
        // as long as the last entry equals the final balance.
        if (decl.balance_changes.len != 0) {
            if (decl.balance_changes[decl.balance_changes.len - 1] != comp.post_balance) {
                std.debug.print("DBG BAL 0x{s}: balance last={} expected={}\n", .{ std.fmt.bytesToHex(comp.address, .lower), decl.balance_changes[decl.balance_changes.len - 1], comp.post_balance });
                return error.InvalidBlockAccessList;
            }
        } else if (comp.pre_balance != comp.post_balance) {
            std.debug.print("DBG BAL 0x{s}: balance changed ({}->{}) but decl balance_changes empty\n", .{ std.fmt.bytesToHex(comp.address, .lower), comp.pre_balance, comp.post_balance });
            return error.InvalidBlockAccessList;
        }

        // Code: last code_change (if any) must match post_code_hash.
        // EIP-7928 records ALL per-tx code changes, including intermediate ones that net
        // to zero (e.g., delegation set in tx0 then cleared in tx1 = 2 code_changes with
        // pre_code_hash == post_code_hash).  Mirror the balance_changes logic: accept
        // non-empty code_changes as long as the last entry hashes to post_code_hash.
        if (decl.code_changes.len != 0) {
            const last_code = decl.code_changes[decl.code_changes.len - 1];
            var last_code_hash: primitives.Hash = primitives.KECCAK_EMPTY;
            if (last_code.len > 0) {
                var h = std.crypto.hash.sha3.Keccak256.init(.{});
                h.update(last_code);
                h.final(&last_code_hash);
            }
            if (!std.mem.eql(u8, &last_code_hash, &comp.post_code_hash)) {
                std.debug.print("DBG BAL 0x{s}: code_change last hash mismatch\n", .{std.fmt.bytesToHex(comp.address, .lower)});
                return error.InvalidBlockAccessList;
            }
        } else {
            // No code changes: code must be unchanged net.
            if (!std.mem.eql(u8, &comp.pre_code_hash, &comp.post_code_hash)) {
                std.debug.print("DBG BAL 0x{s}: code changed but decl code_changes empty\n", .{std.fmt.bytesToHex(comp.address, .lower)});
                return error.InvalidBlockAccessList;
            }
        }

        // Storage changes: exact sorted match on {slot, post_value}
        if (decl.storage_changes.len != comp.storage_changes.len) {
            std.debug.print("DBG BAL 0x{s}: storage_changes count decl={} computed={}\n", .{ std.fmt.bytesToHex(comp.address, .lower), decl.storage_changes.len, comp.storage_changes.len });
            for (decl.storage_changes) |ds| std.debug.print("  decl  slot=0x{s} val={}\n", .{ std.fmt.bytesToHex(ds.slot, .lower), ds.post_value });
            for (comp.storage_changes) |cs| std.debug.print("  comp  slot=0x{s} val={}\n", .{ std.fmt.bytesToHex(cs.slot, .lower), cs.post_value });
            return error.InvalidBlockAccessList;
        }
        for (decl.storage_changes, comp.storage_changes) |ds, cs| {
            if (!std.mem.eql(u8, &ds.slot, &cs.slot)) {
                std.debug.print("DBG BAL 0x{s}: storage_change slot mismatch decl=0x{s} comp=0x{s}\n", .{ std.fmt.bytesToHex(comp.address, .lower), std.fmt.bytesToHex(ds.slot, .lower), std.fmt.bytesToHex(cs.slot, .lower) });
                return error.InvalidBlockAccessList;
            }
            if (ds.post_value != cs.post_value) {
                std.debug.print("DBG BAL 0x{s}: storage_change value mismatch slot=0x{s} decl={} comp={}\n", .{ std.fmt.bytesToHex(comp.address, .lower), std.fmt.bytesToHex(ds.slot, .lower), ds.post_value, cs.post_value });
                return error.InvalidBlockAccessList;
            }
        }

        // Storage reads: exact sorted match
        if (decl.storage_reads.len != comp.storage_reads.len) {
            std.debug.print("DBG BAL 0x{s}: storage_reads count decl={} computed={}\n", .{ std.fmt.bytesToHex(comp.address, .lower), decl.storage_reads.len, comp.storage_reads.len });
            return error.InvalidBlockAccessList;
        }
        for (decl.storage_reads, comp.storage_reads) |dr, cr| {
            if (!std.mem.eql(u8, &dr, &cr)) {
                std.debug.print("DBG BAL 0x{s}: storage_read mismatch decl=0x{s} comp=0x{s}\n", .{ std.fmt.bytesToHex(comp.address, .lower), std.fmt.bytesToHex(dr, .lower), std.fmt.bytesToHex(cr, .lower) });
                return error.InvalidBlockAccessList;
            }
        }
    }
}
