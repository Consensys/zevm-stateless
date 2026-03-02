/// JSON output serialization for the t8n tool.
///
/// Produces geth-compatible result.json and alloc.json files.
/// All numbers are hex-encoded with 0x prefix; hashes are 0x-prefixed 32-byte hex.
const std = @import("std");

const input = @import("input.zig");
const transition = @import("transition.zig");
const rlp = @import("rlp_encode.zig");
const mpt_builder = @import("mpt_builder");

// ─── Formatting helpers ───────────────────────────────────────────────────────

fn writeHex(w: anytype, bytes: []const u8) !void {
    try w.writeAll("\"0x");
    for (bytes) |b| try w.print("{x:0>2}", .{b});
    try w.writeAll("\"");
}

fn writeHash(w: anytype, hash: [32]u8) !void {
    return writeHex(w, &hash);
}

fn writeAddr(w: anytype, addr: [20]u8) !void {
    return writeHex(w, &addr);
}

fn writeU64Hex(w: anytype, n: u64) !void {
    try w.print("\"0x{x}\"", .{n});
}

fn writeU128Hex(w: anytype, n: u128) !void {
    try w.print("\"0x{x}\"", .{n});
}

fn writeU256Hex(w: anytype, n: u256) !void {
    try w.print("\"0x{x}\"", .{n});
}

fn writeBloom(w: anytype, b: [256]u8) !void {
    try w.writeAll("\"0x");
    for (b) |byte| try w.print("{x:0>2}", .{byte});
    try w.writeAll("\"");
}

// ─── Logs hash ────────────────────────────────────────────────────────────────

/// Compute logsHash: keccak256 of the RLP-encoded list of all logs across all transactions.
/// Each log is encoded as RLP([address, [topic1, ...], data]).
pub fn computeLogsHash(alloc: std.mem.Allocator, receipts: []const transition.Receipt) ![32]u8 {
    var log_items = std.ArrayListUnmanaged([]const u8){};
    defer log_items.deinit(alloc);

    for (receipts) |receipt| {
        for (receipt.logs) |log| {
            // topics list
            var topic_items = std.ArrayListUnmanaged([]const u8){};
            defer topic_items.deinit(alloc);
            for (log.topics) |t| try topic_items.append(alloc, try rlp.encodeBytes(alloc, &t));
            const topics_enc = try rlp.encodeList(alloc, topic_items.items);

            // log = [address, topics_list, data]
            const log_parts = [_][]const u8{
                try rlp.encodeBytes(alloc, &log.address),
                topics_enc,
                try rlp.encodeBytes(alloc, log.data),
            };
            try log_items.append(alloc, try rlp.encodeList(alloc, &log_parts));
        }
    }

    const logs_rlp = try rlp.encodeList(alloc, log_items.items);
    return rlp.keccak256(logs_rlp);
}

// ─── Trie root computations ───────────────────────────────────────────────────

/// txRoot: transactions trie, keys = RLP(index), values = typed tx bytes.
pub fn computeTxRoot(
    alloc: std.mem.Allocator,
    txs: []const input.TxInput,
    chain_id: u64,
) ![32]u8 {
    if (txs.len == 0) return mpt_builder.EMPTY_TRIE_HASH;
    var items = try alloc.alloc(mpt_builder.KV, txs.len);
    for (txs, 0..) |*tx, i| {
        items[i].key = try rlpIndex(alloc, i);
        items[i].value = encodeTxBytes(alloc, tx, chain_id, null, null, null) catch
            try alloc.dupe(u8, &.{});
    }
    return mpt_builder.trieRoot(alloc, items);
}

/// receiptsRoot: receipts trie, keys = RLP(index), values = typed receipt RLP.
pub fn computeReceiptsRoot(
    alloc: std.mem.Allocator,
    receipts: []const transition.Receipt,
) ![32]u8 {
    if (receipts.len == 0) return mpt_builder.EMPTY_TRIE_HASH;
    var items = try alloc.alloc(mpt_builder.KV, receipts.len);
    for (receipts, 0..) |receipt, i| {
        items[i].key = try rlpIndex(alloc, i);
        items[i].value = try encodeReceiptRlp(alloc, receipt);
    }
    return mpt_builder.trieRoot(alloc, items);
}

/// stateRoot: state trie, keys = keccak256(address), values = account RLP.
pub fn computeStateRoot(
    alloc: std.mem.Allocator,
    alloc_map: std.AutoHashMapUnmanaged(input.Address, input.AllocAccount),
) ![32]u8 {
    const count = alloc_map.count();
    if (count == 0) return mpt_builder.EMPTY_TRIE_HASH;
    var items = try alloc.alloc(mpt_builder.KV, count);
    var it = alloc_map.iterator();
    var i: usize = 0;
    while (it.next()) |entry| {
        const addr = entry.key_ptr.*;
        const acct = entry.value_ptr.*;
        // key = keccak256(address)
        const key = try alloc.dupe(u8, &mpt_builder.keccak256(&addr));
        // storage trie root
        const storage_root = try computeStorageRoot(alloc, acct.storage);
        // code hash
        const code_hash: [32]u8 = if (acct.code.len > 0)
            mpt_builder.keccak256(acct.code)
        else
            KECCAK_EMPTY;
        // account RLP: [nonce, balance, storageRoot, codeHash]
        const value = try encodeAccountRlp(alloc, acct.nonce, acct.balance, storage_root, code_hash);
        items[i] = .{ .key = key, .value = value };
        i += 1;
    }
    return mpt_builder.trieRoot(alloc, items);
}

fn computeStorageRoot(
    alloc: std.mem.Allocator,
    storage: std.AutoHashMapUnmanaged(u256, u256),
) ![32]u8 {
    const count = storage.count();
    if (count == 0) return mpt_builder.EMPTY_TRIE_HASH;
    var items = try alloc.alloc(mpt_builder.KV, count);
    var it = storage.iterator();
    var i: usize = 0;
    while (it.next()) |entry| {
        if (entry.value_ptr.* == 0) continue; // skip zero slots
        var slot_key: [32]u8 = undefined;
        std.mem.writeInt(u256, &slot_key, entry.key_ptr.*, .big);
        items[i].key = try alloc.dupe(u8, &mpt_builder.keccak256(&slot_key));
        items[i].value = try rlp.encodeU256(alloc, entry.value_ptr.*);
        i += 1;
    }
    return mpt_builder.trieRoot(alloc, items[0..i]);
}

fn encodeAccountRlp(
    alloc: std.mem.Allocator,
    nonce: u64,
    balance: u256,
    storage_root: [32]u8,
    code_hash: [32]u8,
) ![]u8 {
    const parts = [_][]const u8{
        try rlp.encodeU64(alloc, nonce),
        try rlp.encodeU256(alloc, balance),
        try rlp.encodeBytes(alloc, &storage_root),
        try rlp.encodeBytes(alloc, &code_hash),
    };
    return rlp.encodeList(alloc, &parts);
}

fn encodeReceiptRlp(alloc: std.mem.Allocator, receipt: transition.Receipt) ![]u8 {
    // Encode logs
    var log_items = std.ArrayListUnmanaged([]const u8){};
    for (receipt.logs) |log| {
        var topic_items = std.ArrayListUnmanaged([]const u8){};
        for (log.topics) |t| try topic_items.append(alloc, try rlp.encodeBytes(alloc, &t));
        const log_parts = [_][]const u8{
            try rlp.encodeBytes(alloc, &log.address),
            try rlp.encodeList(alloc, topic_items.items),
            try rlp.encodeBytes(alloc, log.data),
        };
        try log_items.append(alloc, try rlp.encodeList(alloc, &log_parts));
    }
    const bloom_bytes: []const u8 = &receipt.logs_bloom;
    const parts = [_][]const u8{
        try rlp.encodeBytes(alloc, if (receipt.status == 1) &.{0x01} else &.{}),
        try rlp.encodeU64(alloc, receipt.cumulative_gas_used),
        try rlp.encodeBytes(alloc, bloom_bytes),
        try rlp.encodeList(alloc, log_items.items),
    };
    const body = try rlp.encodeList(alloc, &parts);
    return if (receipt.type == 0)
        body
    else
        rlp.concat(alloc, &.{ &.{receipt.type}, body });
}

/// RLP-encode a transaction index as the trie key.
fn rlpIndex(alloc: std.mem.Allocator, i: usize) ![]u8 {
    return rlp.encodeU64(alloc, i);
}

/// Encode a signed transaction to its wire bytes (type_byte ++ rlp for typed).
/// Falls back to empty on error.
fn encodeTxBytes(
    alloc: std.mem.Allocator,
    tx: *const input.TxInput,
    chain_id: u64,
    v_override: ?u256,
    r_override: ?u256,
    s_override: ?u256,
) ![]u8 {
    const v = v_override orelse tx.v orelse 0;
    const r = r_override orelse tx.r orelse 0;
    const s = s_override orelse tx.s orelse 0;

    // Encode access list
    var al_items = std.ArrayListUnmanaged([]const u8){};
    for (tx.access_list) |entry| {
        var key_items = std.ArrayListUnmanaged([]const u8){};
        for (entry.storage_keys) |key| try key_items.append(alloc, try rlp.encodeBytes(alloc, &key));
        const al_entry_parts = [_][]const u8{
            try rlp.encodeBytes(alloc, &entry.address),
            try rlp.encodeList(alloc, key_items.items),
        };
        try al_items.append(alloc, try rlp.encodeList(alloc, &al_entry_parts));
    }
    const al_enc = try rlp.encodeList(alloc, al_items.items);
    const to_enc = if (tx.to) |to| try rlp.encodeBytes(alloc, &to) else try rlp.encodeBytes(alloc, &.{});

    return switch (tx.type) {
        0 => blk: {
            const items = [_][]const u8{
                try rlp.encodeU64(alloc, tx.nonce orelse 0),
                try rlp.encodeU128(alloc, tx.gas_price orelse 0),
                try rlp.encodeU64(alloc, tx.gas),
                to_enc,
                try rlp.encodeU256(alloc, tx.value),
                try rlp.encodeBytes(alloc, tx.data),
                try rlp.encodeU256(alloc, v),
                try rlp.encodeU256(alloc, r),
                try rlp.encodeU256(alloc, s),
            };
            break :blk try rlp.encodeList(alloc, &items);
        },
        1 => blk: {
            const items = [_][]const u8{
                try rlp.encodeU64(alloc, tx.chain_id orelse chain_id),
                try rlp.encodeU64(alloc, tx.nonce orelse 0),
                try rlp.encodeU128(alloc, tx.gas_price orelse 0),
                try rlp.encodeU64(alloc, tx.gas),
                to_enc,
                try rlp.encodeU256(alloc, tx.value),
                try rlp.encodeBytes(alloc, tx.data),
                al_enc,
                try rlp.encodeU256(alloc, v),
                try rlp.encodeU256(alloc, r),
                try rlp.encodeU256(alloc, s),
            };
            break :blk try rlp.concat(alloc, &.{ &.{0x01}, try rlp.encodeList(alloc, &items) });
        },
        2 => blk: {
            const items = [_][]const u8{
                try rlp.encodeU64(alloc, tx.chain_id orelse chain_id),
                try rlp.encodeU64(alloc, tx.nonce orelse 0),
                try rlp.encodeU128(alloc, tx.max_priority_fee_per_gas orelse 0),
                try rlp.encodeU128(alloc, tx.max_fee_per_gas orelse 0),
                try rlp.encodeU64(alloc, tx.gas),
                to_enc,
                try rlp.encodeU256(alloc, tx.value),
                try rlp.encodeBytes(alloc, tx.data),
                al_enc,
                try rlp.encodeU256(alloc, v),
                try rlp.encodeU256(alloc, r),
                try rlp.encodeU256(alloc, s),
            };
            break :blk try rlp.concat(alloc, &.{ &.{0x02}, try rlp.encodeList(alloc, &items) });
        },
        else => return error.UnsupportedTxType,
    };
}

const KECCAK_EMPTY: [32]u8 = [_]u8{
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
    0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
    0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
};

// ─── result.json writer ───────────────────────────────────────────────────────

pub fn writeResult(
    alloc: std.mem.Allocator,
    writer: anytype,
    result: transition.TransitionResult,
    block_number: u64,
    difficulty: u256,
) !void {
    const logs_hash = try computeLogsHash(alloc, result.receipts);
    _ = block_number;

    // Stubs for unimplemented fields
    const ZERO_HASH = [_]u8{0} ** 32;

    try writer.writeAll("{\n");

    // State/tx/receipts roots (stubs — MPT construction not yet implemented)
    try writer.writeAll("  \"stateRoot\": ");
    try writeHash(writer, ZERO_HASH);
    try writer.writeAll(",\n");

    try writer.writeAll("  \"txRoot\": ");
    try writeHash(writer, ZERO_HASH);
    try writer.writeAll(",\n");

    try writer.writeAll("  \"receiptsRoot\": ");
    try writeHash(writer, ZERO_HASH);
    try writer.writeAll(",\n");

    // Logs hash (computed from actual logs)
    try writer.writeAll("  \"logsHash\": ");
    try writeHash(writer, logs_hash);
    try writer.writeAll(",\n");

    // Block bloom filter
    try writer.writeAll("  \"logsBloom\": ");
    try writeBloom(writer, result.block_bloom);
    try writer.writeAll(",\n");

    // Receipts array
    try writer.writeAll("  \"receipts\": [\n");
    for (result.receipts, 0..) |receipt, i| {
        try writeReceiptJson(writer, receipt);
        if (i < result.receipts.len - 1) try writer.writeAll(",");
        try writer.writeAll("\n");
    }
    try writer.writeAll("  ],\n");

    // Rejected transactions
    try writer.writeAll("  \"rejected\": [\n");
    for (result.rejected, 0..) |rej, i| {
        try writer.writeAll("    {");
        try writer.print("\"index\": {}, \"error\": ", .{rej.index});
        try writeJsonString(writer, rej.err);
        try writer.writeAll("}");
        if (i < result.rejected.len - 1) try writer.writeAll(",");
        try writer.writeAll("\n");
    }
    try writer.writeAll("  ],\n");

    // Block-level fields
    try writer.writeAll("  \"currentDifficulty\": ");
    try writeU256Hex(writer, difficulty);
    try writer.writeAll(",\n");

    try writer.writeAll("  \"gasUsed\": ");
    try writeU64Hex(writer, result.cumulative_gas);
    try writer.writeAll("\n");

    // Optional fields (only if present)
    if (result.current_base_fee) |bf| {
        // We already closed the last required field without comma; re-open
        // Actually we need to add comma before these. Let me restructure.
        // We'll add a trailing comma to gasUsed if optional fields exist.
        _ = bf; // handled below with proper trailing comma logic
    }

    // NOTE: The JSON above has a trailing comma issue if optional fields follow.
    // For correctness, we write gasUsed last among required fields,
    // and handle optional fields by buffering. See writeResultBuffered below.
    try writer.writeAll("}\n");
}

/// Buffered version that handles optional fields with correct JSON commas.
pub fn writeResultJson(
    alloc: std.mem.Allocator,
    writer: anytype,
    result: transition.TransitionResult,
    difficulty: u256,
) !void {
    const logs_hash = try computeLogsHash(alloc, result.receipts);
    const state_root = try computeStateRoot(alloc, result.alloc);
    const tx_root = try computeTxRoot(alloc, result.txs, result.chain_id);
    const receipts_root = try computeReceiptsRoot(alloc, result.receipts);

    // Collect all fields into a list, then join with commas
    var fields = std.ArrayListUnmanaged([]const u8){};
    defer fields.deinit(alloc);

    var buf = std.ArrayListUnmanaged(u8){};
    defer buf.deinit(alloc);

    const bw = buf.writer(alloc);

    // stateRoot
    buf.clearRetainingCapacity();
    try bw.writeAll("\"stateRoot\": ");
    try writeHash(bw, state_root);
    try fields.append(alloc, try alloc.dupe(u8, buf.items));

    // txRoot
    buf.clearRetainingCapacity();
    try bw.writeAll("\"txRoot\": ");
    try writeHash(bw, tx_root);
    try fields.append(alloc, try alloc.dupe(u8, buf.items));

    // receiptsRoot
    buf.clearRetainingCapacity();
    try bw.writeAll("\"receiptsRoot\": ");
    try writeHash(bw, receipts_root);
    try fields.append(alloc, try alloc.dupe(u8, buf.items));

    // logsHash
    buf.clearRetainingCapacity();
    try bw.writeAll("\"logsHash\": ");
    try writeHash(bw, logs_hash);
    try fields.append(alloc, try alloc.dupe(u8, buf.items));

    // logsBloom
    buf.clearRetainingCapacity();
    try bw.writeAll("\"logsBloom\": ");
    try writeBloom(bw, result.block_bloom);
    try fields.append(alloc, try alloc.dupe(u8, buf.items));

    // receipts
    buf.clearRetainingCapacity();
    try bw.writeAll("\"receipts\": [\n");
    for (result.receipts, 0..) |receipt, i| {
        try writeReceiptJson(bw, receipt);
        if (i < result.receipts.len - 1) try bw.writeAll(",");
        try bw.writeAll("\n");
    }
    try bw.writeAll("  ]");
    try fields.append(alloc, try alloc.dupe(u8, buf.items));

    // rejected
    buf.clearRetainingCapacity();
    try bw.writeAll("\"rejected\": [");
    for (result.rejected, 0..) |rej, i| {
        try bw.print("{{\"index\": {}, \"error\": ", .{rej.index});
        try writeJsonString(bw, rej.err);
        try bw.writeAll("}");
        if (i < result.rejected.len - 1) try bw.writeAll(", ");
    }
    try bw.writeAll("]");
    try fields.append(alloc, try alloc.dupe(u8, buf.items));

    // currentDifficulty
    buf.clearRetainingCapacity();
    try bw.writeAll("\"currentDifficulty\": ");
    try writeU256Hex(bw, difficulty);
    try fields.append(alloc, try alloc.dupe(u8, buf.items));

    // gasUsed
    buf.clearRetainingCapacity();
    try bw.writeAll("\"gasUsed\": ");
    try writeU64Hex(bw, result.cumulative_gas);
    try fields.append(alloc, try alloc.dupe(u8, buf.items));

    // currentBaseFee (optional)
    if (result.current_base_fee) |bf| {
        buf.clearRetainingCapacity();
        try bw.writeAll("\"currentBaseFee\": ");
        try writeU64Hex(bw, bf);
        try fields.append(alloc, try alloc.dupe(u8, buf.items));
    }

    // currentExcessBlobGas (optional)
    if (result.excess_blob_gas) |ebg| {
        buf.clearRetainingCapacity();
        try bw.writeAll("\"currentExcessBlobGas\": ");
        try writeU64Hex(bw, ebg);
        try fields.append(alloc, try alloc.dupe(u8, buf.items));
    }

    // blobGasUsed (optional, if non-zero)
    if (result.blob_gas_used > 0) {
        buf.clearRetainingCapacity();
        try bw.writeAll("\"blobGasUsed\": ");
        try writeU64Hex(bw, result.blob_gas_used);
        try fields.append(alloc, try alloc.dupe(u8, buf.items));
    }

    // Emit JSON
    try writer.writeAll("{\n");
    for (fields.items, 0..) |field, i| {
        try writer.writeAll("  ");
        try writer.writeAll(field);
        if (i < fields.items.len - 1) try writer.writeAll(",");
        try writer.writeAll("\n");
    }
    try writer.writeAll("}\n");
}

fn writeReceiptJson(writer: anytype, receipt: transition.Receipt) !void {
    try writer.writeAll("    {\n");
    try writer.print("      \"type\": \"0x{x}\",\n", .{receipt.type});
    try writer.writeAll("      \"transactionHash\": ");
    try writeHash(writer, receipt.tx_hash);
    try writer.writeAll(",\n");
    try writer.print("      \"transactionIndex\": \"0x{x}\",\n", .{receipt.tx_index});
    try writer.writeAll("      \"blockHash\": ");
    try writeHash(writer, receipt.block_hash);
    try writer.writeAll(",\n");
    try writer.print("      \"blockNumber\": \"0x{x}\",\n", .{receipt.block_number});
    try writer.writeAll("      \"from\": ");
    try writeAddr(writer, receipt.from);
    try writer.writeAll(",\n");

    if (receipt.to) |to| {
        try writer.writeAll("      \"to\": ");
        try writeAddr(writer, to);
        try writer.writeAll(",\n");
    } else {
        try writer.writeAll("      \"to\": null,\n");
    }

    try writer.print("      \"cumulativeGasUsed\": \"0x{x}\",\n", .{receipt.cumulative_gas_used});
    try writer.print("      \"gasUsed\": \"0x{x}\",\n", .{receipt.gas_used});

    if (receipt.contract_address) |ca| {
        try writer.writeAll("      \"contractAddress\": ");
        try writeAddr(writer, ca);
        try writer.writeAll(",\n");
    } else {
        try writer.writeAll("      \"contractAddress\": null,\n");
    }

    // Logs
    try writer.writeAll("      \"logs\": [\n");
    for (receipt.logs, 0..) |log, li| {
        try writeLogJson(writer, log);
        if (li < receipt.logs.len - 1) try writer.writeAll(",");
        try writer.writeAll("\n");
    }
    try writer.writeAll("      ],\n");

    try writer.writeAll("      \"logsBloom\": ");
    try writeBloom(writer, receipt.logs_bloom);
    try writer.writeAll(",\n");

    try writer.print("      \"status\": \"0x{x}\",\n", .{receipt.status});
    try writer.print("      \"effectiveGasPrice\": \"0x{x}\"", .{receipt.effective_gas_price});

    if (receipt.blob_gas_used) |bgu| {
        try writer.writeAll(",\n");
        try writer.print("      \"blobGasUsed\": \"0x{x}\"", .{bgu});
    }
    if (receipt.blob_gas_price) |bgp| {
        try writer.writeAll(",\n");
        try writer.print("      \"blobGasPrice\": \"0x{x}\"", .{bgp});
    }

    try writer.writeAll("\n    }");
}

fn writeLogJson(writer: anytype, log: transition.Log) !void {
    try writer.writeAll("        {\n");
    try writer.writeAll("          \"address\": ");
    try writeAddr(writer, log.address);
    try writer.writeAll(",\n");

    try writer.writeAll("          \"topics\": [");
    for (log.topics, 0..) |t, ti| {
        try writeHash(writer, t);
        if (ti < log.topics.len - 1) try writer.writeAll(", ");
    }
    try writer.writeAll("],\n");

    try writer.writeAll("          \"data\": ");
    try writeHex(writer, log.data);
    try writer.writeAll(",\n");

    try writer.print("          \"blockNumber\": \"0x{x}\",\n", .{log.block_number});
    try writer.writeAll("          \"transactionHash\": ");
    try writeHash(writer, log.tx_hash);
    try writer.writeAll(",\n");
    try writer.print("          \"transactionIndex\": \"0x{x}\",\n", .{log.tx_index});
    try writer.writeAll("          \"blockHash\": ");
    try writeHash(writer, log.block_hash);
    try writer.writeAll(",\n");
    try writer.print("          \"logIndex\": \"0x{x}\",\n", .{log.log_index});
    try writer.writeAll("          \"removed\": false\n");
    try writer.writeAll("        }");
}

// ─── alloc.json writer ────────────────────────────────────────────────────────

pub fn writeAllocJson(
    writer: anytype,
    alloc_map: std.AutoHashMapUnmanaged(input.Address, input.AllocAccount),
) !void {
    try writer.writeAll("{\n");

    var it = alloc_map.iterator();
    var first = true;
    while (it.next()) |entry| {
        if (!first) try writer.writeAll(",\n");
        first = false;

        const addr = entry.key_ptr.*;
        const acct = entry.value_ptr.*;

        try writer.writeAll("  \"0x");
        for (addr) |b| try writer.print("{x:0>2}", .{b});
        try writer.writeAll("\": {\n");

        try writer.writeAll("    \"balance\": ");
        try writeU256Hex(writer, acct.balance);
        try writer.writeAll(",\n");

        try writer.print("    \"nonce\": \"0x{x}\",\n", .{acct.nonce});

        try writer.writeAll("    \"code\": ");
        try writeHex(writer, acct.code);
        try writer.writeAll(",\n");

        try writer.writeAll("    \"storage\": {");
        var sit = acct.storage.iterator();
        var sfirst = true;
        while (sit.next()) |slot| {
            if (!sfirst) try writer.writeAll(", ");
            sfirst = false;
            try writer.writeAll("\n      ");
            try writeU256HexQuoted(writer, slot.key_ptr.*);
            try writer.writeAll(": ");
            try writeU256HexQuoted(writer, slot.value_ptr.*);
        }
        if (!sfirst) try writer.writeAll("\n    ");
        try writer.writeAll("}\n");

        try writer.writeAll("  }");
    }

    if (!first) try writer.writeAll("\n");
    try writer.writeAll("}\n");
}

fn writeU256HexQuoted(writer: anytype, n: u256) !void {
    try writer.print("\"0x{x}\"", .{n});
}

// ─── Utility ──────────────────────────────────────────────────────────────────

fn writeJsonString(writer: anytype, s: []const u8) !void {
    try writer.writeAll("\"");
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => try writer.writeByte(c),
        }
    }
    try writer.writeAll("\"");
}
