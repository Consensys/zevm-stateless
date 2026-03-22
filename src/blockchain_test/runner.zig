/// Blockchain test runner for zevm-stateless.
///
/// Reads blockchain test fixtures (JSON), executes the single block in each
/// test case, and validates:
///   1. post_state_root  == blocks[0].blockHeader.stateRoot
///   2. receipts_root    == blocks[0].blockHeader.receiptTrie
///   3. lastblockhash    == blocks[0].blockHeader.hash   (if 1+2 pass and no exec error)
///                       == genesisBlockHeader.hash      (otherwise)
///
/// Multi-block fixtures (blocks.len != 1) are skipped.
const std = @import("std");
const primitives = @import("primitives");
const hardfork = @import("hardfork");
const executor_types = @import("executor_types");
const executor_transition = @import("executor_transition");
const executor_output = @import("executor_output");
const executor_tx_decode = @import("executor_tx_decode");
const mpt = @import("mpt");

const Address = executor_types.Address;
const Hash = executor_types.Hash;
const AllocAccount = executor_types.AllocAccount;
const AllocMap = std.AutoHashMapUnmanaged(Address, AllocAccount);
const Env = executor_types.Env;
const Withdrawal = executor_types.Withdrawal;

// ─── Public types ─────────────────────────────────────────────────────────────

pub const RunStats = struct {
    passed: u64 = 0,
    failed: u64 = 0,
    skipped: u64 = 0,

    pub fn total(self: RunStats) u64 {
        return self.passed + self.failed + self.skipped;
    }
};

// ─── Main entry point ─────────────────────────────────────────────────────────

pub fn runFixture(
    alloc: std.mem.Allocator,
    json_text: []const u8,
    fork_filter: ?[]const u8,
    stop_on_fail: bool,
    quiet: bool,
    raw_json: bool,
    stats: *RunStats,
    rel_path: []const u8,
) !bool {
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        alloc,
        json_text,
        .{ .duplicate_field_behavior = .use_last },
    );
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |o| o,
        else => return true,
    };

    var it = root.iterator();
    while (it.next()) |entry| {
        const test_name = entry.key_ptr.*;
        const test_obj = switch (entry.value_ptr.*) {
            .object => |o| o,
            else => continue,
        };

        // Extract description from _info for failure diagnostics.
        const test_description: []const u8 = blk: {
            const info = test_obj.get("_info") orelse break :blk "";
            const info_obj = switch (info) {
                .object => |o| o,
                else => break :blk "",
            };
            break :blk getString(info_obj, "description") orelse "";
        };

        // Get network (fork) name.
        const network = if (test_obj.get("network")) |v| switch (v) {
            .string => |s| s,
            else => continue,
        } else continue;

        // Fork filter.
        if (fork_filter) |f| {
            if (!std.mem.eql(u8, f, network)) {
                stats.skipped += 1;
                continue;
            }
        }

        // Parse the blocks array.
        const blocks_arr = blk: {
            const bv = test_obj.get("blocks") orelse {
                stats.skipped += 1;
                continue;
            };
            break :blk switch (bv) {
                .array => |a| a,
                else => {
                    stats.skipped += 1;
                    continue;
                },
            };
        };
        if (blocks_arr.items.len == 0) {
            stats.skipped += 1;
            continue;
        }

        const genesis_bh = switch (test_obj.get("genesisBlockHeader") orelse {
            stats.skipped += 1;
            continue;
        }) {
            .object => |o| o,
            else => {
                stats.skipped += 1;
                continue;
            },
        };
        const genesis_number = if (genesis_bh.get("number")) |v| jsonU64(v) catch 0 else 0;
        const genesis_hash = hexToHash(getString(genesis_bh, "hash") orelse "") catch [_]u8{0} ** 32;

        const expected_lastblockhash = blk: {
            const lv = test_obj.get("lastblockhash") orelse break :blk [_]u8{0} ** 32;
            break :blk hexToHash(switch (lv) {
                .string => |s| s,
                else => "",
            }) catch [_]u8{0} ** 32;
        };

        // Chain id and blobSchedule from config.
        const fixture_chain_id: u64 = blk: {
            const cv = test_obj.get("config") orelse break :blk 1;
            const co = switch (cv) {
                .object => |o| o,
                else => break :blk 1,
            };
            const v = co.get("chainid") orelse break :blk 1;
            break :blk jsonU64(v) catch 1;
        };
        const blob_schedule: ?std.json.ObjectMap = blk: {
            const cv = test_obj.get("config") orelse break :blk null;
            const co = switch (cv) {
                .object => |o| o,
                else => break :blk null,
            };
            const bsv = co.get("blobSchedule") orelse break :blk null;
            break :blk switch (bsv) {
                .object => |o| o,
                else => null,
            };
        };

        // Decode SpecId from network string.
        // For transition forks, use the post-transition spec as the fixture-level default.
        const spec = hardfork.specForBlock(network, std.math.maxInt(u64)) orelse {
            if (!quiet) std.debug.print("SKIP {s}/{s} (unknown network: {s})\n", .{ rel_path, test_name, network });
            stats.skipped += 1;
            continue;
        };

        // Parse pre alloc.
        const pre_val = test_obj.get("pre") orelse {
            stats.skipped += 1;
            continue;
        };
        const pre_alloc = parseAllocFromValue(alloc, pre_val) catch {
            stats.skipped += 1;
            continue;
        };

        // ── Chain state threaded across blocks ───────────────────────────────
        var chain_alloc = pre_alloc;
        var block_hashes_list = std.ArrayListUnmanaged(executor_types.BlockHashEntry){};
        try block_hashes_list.append(alloc, .{ .number = genesis_number, .hash = genesis_hash });
        var last_valid_hash = genesis_hash;
        var test_failed = false;

        for (blocks_arr.items) |block_val| {
            const block = switch (block_val) {
                .object => |o| o,
                else => continue,
            };

            // expectException: this block is expected to be invalid — freeze state, don't update last_valid_hash.
            const expect_exception = blk: {
                const ev = block.get("expectException") orelse break :blk false;
                break :blk switch (ev) {
                    .string => |s| s.len > 0,
                    else => false,
                };
            };
            if (expect_exception) continue;

            // blockHeader must be present for a valid block.
            const bh = switch (block.get("blockHeader") orelse continue) {
                .object => |o| o,
                else => continue,
            };
            const expected_block_state_root = hexToHash(getString(bh, "stateRoot") orelse "") catch [_]u8{0} ** 32;
            const expected_block_receipts_root = hexToHash(getString(bh, "receiptTrie") orelse "") catch [_]u8{0} ** 32;
            const expected_block_hash = hexToHash(getString(bh, "hash") orelse "") catch [_]u8{0} ** 32;

            // Decode block RLP → raw transaction bytes.
            const rlp_hex = switch (block.get("rlp") orelse continue) {
                .string => |s| s,
                else => continue,
            };
            const block_bytes = hexToSlice(alloc, rlp_hex) catch continue;
            const raw_txs = decodeTxsFromBlock(alloc, block_bytes) catch continue;

            // Build execution environment from blockHeader + accumulated block hashes.
            var env = buildEnv(alloc, bh, block, block_hashes_list.items) catch continue;
            env.blob_base_fee_update_fraction = blobFractionForBlock(blob_schedule, network, env.timestamp);

            // Decode transactions.
            const txs = executor_tx_decode.decodeTxs(alloc, raw_txs) catch |err| {
                if (!quiet) {
                    var out = std.ArrayListUnmanaged(u8){};
                    defer out.deinit(alloc);
                    const w = out.writer(alloc);
                    try w.writeAll("{\"test_output\":{\"test\":\"");
                    try writeJsonStr(w, test_name);
                    try w.print("\",\"error\":\"tx-decode block {}: {s}\",\"description\":\"", .{ env.number, @errorName(err) });
                    try writeJsonStr(w, test_description);
                    try w.writeAll("\"}}");
                    printPrettyJson(alloc, out.items, raw_json);
                }
                test_failed = true;
                break;
            };

            // Execute the block. An execution error means the block is invalid — freeze state.
            // For transition forks, select the spec appropriate for this block's timestamp.
            const block_spec = hardfork.specForBlock(network, env.timestamp) orelse spec;
            const reward = hardfork.blockReward(block_spec);
            const result = executor_transition.transition(
                alloc,
                chain_alloc,
                env,
                txs,
                block_spec,
                fixture_chain_id,
                reward,
            ) catch continue;

            // Compute post-state root.
            const post_state_root = executor_output.computeStateRoot(alloc, result.alloc, &.{}) catch [_]u8{0} ** 32;

            // Pre-Byzantium: per-tx state roots are now computed inside transition().
            // Each receipt already has .state_root set correctly.

            const receipts_root = executor_output.computeReceiptsRoot(alloc, result.receipts) catch [_]u8{0} ** 32;

            const state_ok = std.mem.eql(u8, &post_state_root, &expected_block_state_root);
            const receipts_ok = std.mem.eql(u8, &receipts_root, &expected_block_receipts_root);

            if (state_ok and receipts_ok) {
                // Commit: thread state to next block.
                chain_alloc = result.alloc;
                last_valid_hash = expected_block_hash;
                try block_hashes_list.append(alloc, .{ .number = env.number, .hash = expected_block_hash });
            } else {
                test_failed = true;

                if (!quiet) {
                    std.debug.print("FAIL {s} ReceiptsOK={} StateOK={}\n", .{ test_name, receipts_ok, state_ok });

                    var out = std.ArrayListUnmanaged(u8){};
                    defer out.deinit(alloc);
                    const w = out.writer(alloc);

                    try w.writeAll("{\"test_output\":{");
                    try w.writeAll("\"test\":\"");
                    try writeJsonStr(w, test_name);
                    try w.print("\",\"state_ok\":{},\"receipts_ok\":{}", .{ state_ok, receipts_ok });
                    try w.writeAll(",\"description\":\"");
                    try writeJsonStr(w, test_description);
                    try w.print("\",\"expected_state_root\":\"0x{x}\"", .{expected_block_state_root});
                    try w.print(",\"actual_state_root\":\"0x{x}\"", .{post_state_root});
                    try w.print(",\"expected_receipts_root\":\"0x{x}\"", .{expected_block_receipts_root});
                    try w.print(",\"actual_receipts_root\":\"0x{x}\"", .{receipts_root});

                    // Expected receipts from fixture (if present).
                    try w.writeAll(",\"expected_receipts\":[");
                    if (block.get("receipts")) |rv| {
                        if (rv == .array) {
                            for (rv.array.items, 0..) |rec_v, i| {
                                if (i > 0) try w.writeByte(',');
                                if (rec_v != .object) {
                                    try w.writeAll("{}");
                                    continue;
                                }
                                const ro = rec_v.object;
                                const ty_s = if (ro.get("type")) |tv| switch (tv) {
                                    .string => |s| s,
                                    else => "0x0",
                                } else "0x0";
                                const status_s = if (ro.get("status")) |sv| switch (sv) {
                                    .bool => |b| if (b) "true" else "false",
                                    .string => |s| s,
                                    else => "false",
                                } else "false";
                                const gas_s = if (ro.get("cumulativeGasUsed")) |gv| switch (gv) {
                                    .string => |s| s,
                                    else => "0x0",
                                } else "0x0";
                                try w.print("{{\"type\":\"{s}\",\"status\":{s},\"cumulativeGasUsed\":\"{s}\",\"logs\":[", .{ ty_s, status_s, gas_s });
                                if (ro.get("logs")) |lv| {
                                    if (lv == .array) {
                                        for (lv.array.items, 0..) |log_v, j| {
                                            if (j > 0) try w.writeByte(',');
                                            if (log_v != .object) {
                                                try w.writeAll("{}");
                                                continue;
                                            }
                                            const lo = log_v.object;
                                            const addr_s = if (lo.get("address")) |av| switch (av) {
                                                .string => |s| s,
                                                else => "0x",
                                            } else "0x";
                                            try w.print("{{\"address\":\"{s}\",\"topics\":[", .{addr_s});
                                            if (lo.get("topics")) |tv| {
                                                if (tv == .array) {
                                                    for (tv.array.items, 0..) |t_v, k| {
                                                        if (k > 0) try w.writeByte(',');
                                                        const t_s = switch (t_v) {
                                                            .string => |s| s,
                                                            else => "0x",
                                                        };
                                                        try w.print("\"{s}\"", .{t_s});
                                                    }
                                                }
                                            }
                                            const data_s = if (lo.get("data")) |dv| switch (dv) {
                                                .string => |s| s,
                                                else => "0x",
                                            } else "0x";
                                            try w.print("],\"data\":\"{s}\"}}", .{data_s});
                                        }
                                    }
                                }
                                try w.writeAll("]}");
                            }
                        }
                    }
                    try w.writeByte(']');

                    // Actual receipts from execution.
                    try w.writeAll(",\"actual_receipts\":[");
                    for (result.receipts, 0..) |r, i| {
                        if (i > 0) try w.writeByte(',');
                        try w.print("{{\"type\":\"0x{x}\",\"status\":{},\"cumulativeGasUsed\":\"0x{x}\",\"logs\":[", .{ r.type, r.status, r.cumulative_gas_used });
                        for (r.logs, 0..) |log, j| {
                            if (j > 0) try w.writeByte(',');
                            try w.print("{{\"address\":\"0x{x}\",\"topics\":[", .{log.address});
                            for (log.topics, 0..) |topic, k| {
                                if (k > 0) try w.writeByte(',');
                                try w.print("\"0x{x}\"", .{topic});
                            }
                            try w.print("],\"data\":\"0x{x}\"}}", .{log.data});
                        }
                        try w.writeAll("]}");
                    }
                    try w.writeByte(']');

                    // Add state comparison when state root mismatches.
                    if (!state_ok) {
                        // Expected post state from fixture.
                        try w.writeAll(",\"expected_post_state\":{");
                        const post_state_val = test_obj.get("postState");
                        if (post_state_val != null and post_state_val.? == .object) {
                            var ps_it = post_state_val.?.object.iterator();
                            var ps_first = true;
                            while (ps_it.next()) |ps_entry| {
                                if (!ps_first) try w.writeByte(',');
                                ps_first = false;
                                try w.writeByte('"');
                                try writeJsonStr(w, ps_entry.key_ptr.*);
                                try w.writeAll("\":{");
                                const acct_obj2 = switch (ps_entry.value_ptr.*) {
                                    .object => |o| o,
                                    else => {
                                        try w.writeByte('}');
                                        continue;
                                    },
                                };
                                // balance
                                const bal_s2 = if (acct_obj2.get("balance")) |bv| switch (bv) {
                                    .string => |s| s,
                                    else => "0x0",
                                } else "0x0";
                                try w.print("\"balance\":\"{s}\"", .{bal_s2});
                                // nonce
                                const nonce_s2 = if (acct_obj2.get("nonce")) |nv| switch (nv) {
                                    .string => |s| s,
                                    else => "0x0",
                                } else "0x0";
                                try w.print(",\"nonce\":\"{s}\"", .{nonce_s2});
                                // codeHash
                                const code_hex2 = if (acct_obj2.get("code")) |cv| switch (cv) {
                                    .string => |s| s,
                                    else => "0x",
                                } else "0x";
                                const code_bytes2 = hexToSlice(alloc, code_hex2) catch &[_]u8{};
                                var code_hash2: [32]u8 = undefined;
                                std.crypto.hash.sha3.Keccak256.hash(code_bytes2, &code_hash2, .{});
                                try w.print(",\"codeHash\":\"0x{x}\"", .{code_hash2});
                                // storage
                                try w.writeAll(",\"storage\":{");
                                if (acct_obj2.get("storage")) |sv2| {
                                    if (sv2 == .object) {
                                        var slot_it = sv2.object.iterator();
                                        var slot_first = true;
                                        while (slot_it.next()) |slot_entry| {
                                            if (!slot_first) try w.writeByte(',');
                                            slot_first = false;
                                            try w.writeByte('"');
                                            try writeJsonStr(w, slot_entry.key_ptr.*);
                                            try w.writeAll("\":\"");
                                            const sv3 = switch (slot_entry.value_ptr.*) {
                                                .string => |s| s,
                                                else => "0x0",
                                            };
                                            try writeJsonStr(w, sv3);
                                            try w.writeByte('"');
                                        }
                                    }
                                }
                                try w.writeAll("}}");
                            }
                        }
                        try w.writeByte('}');

                        // Actual post state from execution.
                        try w.writeAll(",\"actual_post_state\":{");
                        var alloc_it = result.alloc.iterator();
                        var alloc_first = true;
                        while (alloc_it.next()) |alloc_entry| {
                            if (!alloc_first) try w.writeByte(',');
                            alloc_first = false;
                            try w.print("\"0x{x}\":{{", .{alloc_entry.key_ptr.*});
                            const acct2 = alloc_entry.value_ptr.*;
                            try w.print("\"balance\":\"0x{x}\"", .{acct2.balance});
                            try w.print(",\"nonce\":\"0x{x}\"", .{acct2.nonce});
                            var code_hash3: [32]u8 = undefined;
                            std.crypto.hash.sha3.Keccak256.hash(acct2.code, &code_hash3, .{});
                            try w.print(",\"codeHash\":\"0x{x}\"", .{code_hash3});
                            try w.writeAll(",\"storage\":{");
                            var stor_it = acct2.storage.iterator();
                            var stor_first = true;
                            while (stor_it.next()) |stor_entry| {
                                if (!stor_first) try w.writeByte(',');
                                stor_first = false;
                                try w.print("\"0x{x}\":\"0x{x}\"", .{ stor_entry.key_ptr.*, stor_entry.value_ptr.* });
                            }
                            try w.writeAll("}}");
                        }
                        try w.writeByte('}');
                    }

                    try w.writeAll("}}");

                    printPrettyJson(alloc, out.items, raw_json);
                }
            }
        }

        // Validate lastblockhash = hash of last successfully committed block.
        const lbh_ok = std.mem.eql(u8, &last_valid_hash, &expected_lastblockhash);
        if (!test_failed and lbh_ok) {
            stats.passed += 1;
        } else {
            stats.failed += 1;
            if (!quiet and !test_failed and !lbh_ok) {
                var out = std.ArrayListUnmanaged(u8){};
                defer out.deinit(alloc);
                const w = out.writer(alloc);
                try w.writeAll("{\"test_output\":{\"test\":\"");
                try writeJsonStr(w, test_name);
                try w.print("\",\"error\":\"lastblockhash\",\"expected\":\"0x{x}\",\"actual\":\"0x{x}\",\"description\":\"", .{ expected_lastblockhash, last_valid_hash });
                try writeJsonStr(w, test_description);
                try w.writeAll("\"}}");
                printPrettyJson(alloc, out.items, raw_json);
            }
            if (stop_on_fail) return false;
        }
    }

    return stats.failed == 0 or !stop_on_fail;
}

// ─── Block RLP decoder ────────────────────────────────────────────────────────

/// Extract raw transaction bytes from a full block RLP.
/// Block structure: RLP([header_list, txns_list, ommers_list, withdrawals_list])
///
/// Each returned entry is in canonical wire format:
///   legacy tx (type 0): full RLP list bytes
///   typed tx  (1–4):    type_byte || rlp_payload (content of the RLP byte string)
fn decodeTxsFromBlock(alloc: std.mem.Allocator, block_rlp: []const u8) ![]const []const u8 {
    const outer = try mpt.rlp.decodeItem(block_rlp);
    const block_payload = switch (outer.item) {
        .list => |p| p,
        .bytes => return error.InvalidBlock,
    };

    // Skip header.
    const hdr = try mpt.rlp.decodeItem(block_payload);
    const after_hdr = block_payload[hdr.consumed..];

    // Decode txns list.
    const txns_r = try mpt.rlp.decodeItem(after_hdr);
    const txns_payload = switch (txns_r.item) {
        .list => |p| p,
        .bytes => return error.InvalidBlock,
    };

    // Count items.
    var count: usize = 0;
    var tmp = txns_payload;
    while (tmp.len > 0) {
        const r = try mpt.rlp.decodeItem(tmp);
        count += 1;
        tmp = tmp[r.consumed..];
    }

    const txns = try alloc.alloc([]const u8, count);
    var offset: usize = 0;
    for (0..count) |i| {
        const r = try mpt.rlp.decodeItem(txns_payload[offset..]);
        txns[i] = switch (r.item) {
            .bytes => |b| b, // typed tx: byte string content
            .list => txns_payload[offset .. offset + r.consumed], // legacy
        };
        offset += r.consumed;
    }
    return txns;
}

// ─── Environment builder ──────────────────────────────────────────────────────

/// Build an Env from the blockHeader JSON object and block entry (for withdrawals).
fn buildEnv(
    alloc: std.mem.Allocator,
    bh: std.json.ObjectMap,
    b0: std.json.ObjectMap,
    block_hashes: []executor_types.BlockHashEntry,
) !Env {
    var env = Env{};
    env.block_hashes = block_hashes;

    if (bh.get("coinbase")) |v| env.coinbase = hexToAddr(getString2(v) orelse "") catch env.coinbase;
    if (bh.get("gasLimit")) |v| env.gas_limit = jsonU64(v) catch env.gas_limit;
    if (bh.get("number")) |v| env.number = jsonU64(v) catch env.number;
    if (bh.get("timestamp")) |v| env.timestamp = jsonU64(v) catch env.timestamp;
    if (bh.get("difficulty")) |v| env.difficulty = jsonU256(v) catch env.difficulty;

    if (bh.get("baseFeePerGas")) |v| env.base_fee = jsonU64(v) catch null;

    // prevRandao / mixHash (same field, different names across forks)
    const randao_val = bh.get("mixHash") orelse bh.get("prevRandao");
    if (randao_val) |v| env.random = hexToHash(getString2(v) orelse "") catch null;

    if (bh.get("excessBlobGas")) |v| env.excess_blob_gas = jsonU64(v) catch null;
    if (bh.get("parentBeaconBlockRoot")) |v| env.parent_beacon_block_root =
        hexToHash(getString2(v) orelse "") catch null;
    if (bh.get("parentHash")) |v| env.parent_hash =
        hexToHash(getString2(v) orelse "") catch null;

    // Withdrawals from block entry.
    if (b0.get("withdrawals")) |wv| {
        if (wv == .array) {
            var wds = std.ArrayListUnmanaged(Withdrawal){};
            for (wv.array.items) |wd_v| {
                if (wd_v != .object) continue;
                const wo = wd_v.object;
                try wds.append(alloc, Withdrawal{
                    .index = if (wo.get("index")) |v| jsonU64(v) catch 0 else 0,
                    .validator_index = if (wo.get("validatorIndex")) |v| jsonU64(v) catch 0 else 0,
                    .address = if (wo.get("address")) |v|
                        hexToAddr(getString2(v) orelse "") catch [_]u8{0} ** 20
                    else
                        [_]u8{0} ** 20,
                    .amount = if (wo.get("amount")) |v| jsonU64(v) catch 0 else 0,
                });
            }
            env.withdrawals = try wds.toOwnedSlice(alloc);
        }
    }

    return env;
}

// ─── Pre-alloc parser ─────────────────────────────────────────────────────────

fn parseAllocFromValue(alloc: std.mem.Allocator, val: std.json.Value) !AllocMap {
    var map = AllocMap{};
    const obj = switch (val) {
        .object => |o| o,
        else => return map,
    };

    var it = obj.iterator();
    while (it.next()) |entry| {
        const addr = hexToAddr(entry.key_ptr.*) catch continue;
        const acct_obj = switch (entry.value_ptr.*) {
            .object => |o| o,
            else => continue,
        };

        var acct = AllocAccount{};
        if (acct_obj.get("balance")) |v| acct.balance = jsonU256(v) catch 0;
        if (acct_obj.get("nonce")) |v| acct.nonce = jsonU64(v) catch 0;
        if (acct_obj.get("code")) |v| {
            acct.code = hexToSlice(alloc, getString2(v) orelse "") catch &.{};
        }
        if (acct_obj.get("storage")) |sv| {
            if (sv == .object) {
                var sit = sv.object.iterator();
                while (sit.next()) |skv| {
                    const key = hexToU256(skv.key_ptr.*) catch continue;
                    const val2 = jsonU256(skv.value_ptr.*) catch continue;
                    if (val2 != 0) try acct.storage.put(alloc, key, val2);
                }
            }
        }
        try map.put(alloc, addr, acct);
    }
    return map;
}

// ─── Blob schedule helpers ────────────────────────────────────────────────────

/// Look up baseFeeUpdateFraction from a fixture's blobSchedule for this block.
fn blobFractionForBlock(blob_schedule: ?std.json.ObjectMap, network: []const u8, timestamp: u64) ?u64 {
    const bs = blob_schedule orelse return null;
    const fork_name = hardfork.activeForkName(network, timestamp);
    const fork_entry = bs.get(fork_name) orelse return null;
    const entry_obj = switch (fork_entry) {
        .object => |o| o,
        else => return null,
    };
    const fraction_val = entry_obj.get("baseFeeUpdateFraction") orelse return null;
    return jsonU64(fraction_val) catch null;
}

// ─── Hex / JSON helpers ───────────────────────────────────────────────────────

fn stripHex(s: []const u8) []const u8 {
    if (s.len >= 2 and s[0] == '0' and (s[1] == 'x' or s[1] == 'X')) return s[2..];
    return s;
}

fn hexToSlice(alloc: std.mem.Allocator, hex: []const u8) ![]u8 {
    const s = stripHex(hex);
    if (s.len % 2 != 0) return error.OddHexLength;
    const out = try alloc.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

fn hexToAddr(hex: []const u8) ![20]u8 {
    const s = stripHex(hex);
    var padded: [40]u8 = [_]u8{'0'} ** 40;
    if (s.len > 40) return error.InvalidAddress;
    @memcpy(padded[40 - s.len ..], s);
    var out: [20]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, &padded);
    return out;
}

fn hexToHash(hex: []const u8) ![32]u8 {
    const s = stripHex(hex);
    var padded: [64]u8 = [_]u8{'0'} ** 64;
    if (s.len > 64) return error.InvalidHash;
    @memcpy(padded[64 - s.len ..], s);
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, &padded);
    return out;
}

fn hexToU256(hex: []const u8) !u256 {
    const s = stripHex(hex);
    if (s.len == 0) return 0;
    return std.fmt.parseInt(u256, s, 16);
}

fn jsonU64(v: std.json.Value) !u64 {
    return switch (v) {
        .integer => |n| @intCast(n),
        .string => |s| std.fmt.parseInt(u64, stripHex(s), 16) catch
            std.fmt.parseInt(u64, s, 10),
        else => error.InvalidNumeric,
    };
}

fn jsonU256(v: std.json.Value) !u256 {
    return switch (v) {
        .integer => |n| @intCast(n),
        .string => |s| std.fmt.parseInt(u256, stripHex(s), 16) catch
            std.fmt.parseInt(u256, s, 10),
        else => error.InvalidNumeric,
    };
}

fn getString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

fn getString2(v: std.json.Value) ?[]const u8 {
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

fn printPrettyJson(alloc: std.mem.Allocator, json: []const u8, raw: bool) void {
    if (raw) {
        std.debug.print("{s}\n", .{json});
        return;
    }
    var child = std.process.Child.init(&.{ "jq", "." }, alloc);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Inherit;
    child.spawn() catch {
        std.debug.print("{s}\n", .{json});
        return;
    };
    child.stdin.?.writeAll(json) catch {};
    child.stdin.?.close();
    child.stdin = null;
    const out = child.stdout.?.readToEndAlloc(alloc, 4 * 1024 * 1024) catch {
        _ = child.wait() catch {};
        std.debug.print("{s}\n", .{json});
        return;
    };
    defer alloc.free(out);
    _ = child.wait() catch {};
    std.debug.print("{s}", .{out});
}

fn writeJsonStr(w: anytype, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f => try w.print("\\u{x:0>4}", .{c}),
            else => try w.writeByte(c),
        }
    }
}
