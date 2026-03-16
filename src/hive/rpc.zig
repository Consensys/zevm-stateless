/// Minimal HTTP/1.1 JSON-RPC server for Hive consume-rlp.
///
/// Listens on :8545. Handles only:
///   eth_blockNumber          → hex block number (liveness probe)
///   eth_getBlockByNumber     → { "hash": "0x...", "number": "0x..." }
const std = @import("std");
const Chain = @import("chain.zig").Chain;

pub fn serve(chain: *Chain) !void {
    const addr = try std.net.Address.parseIp4("0.0.0.0", 8545);
    var server = try addr.listen(.{ .reuse_address = true });
    defer server.deinit();

    while (true) {
        const conn = server.accept() catch continue;
        defer conn.stream.close();
        handleConn(chain, conn.stream) catch {};
    }
}

fn handleConn(chain: *Chain, stream: std.net.Stream) !void {
    // Arena lives for the entire connection so that the RPC response string
    // (allocated inside processRpc) remains valid until after writeAll.
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var buf: [65536]u8 = undefined;
    var total: usize = 0;

    // Read until we have a complete HTTP request (headers + body)
    while (total < buf.len) {
        const n = try stream.read(buf[total..]);
        if (n == 0) break;
        total += n;

        // Check if we have full headers (\r\n\r\n)
        if (std.mem.indexOf(u8, buf[0..total], "\r\n\r\n") != null) break;
    }
    const raw = buf[0..total];

    // Find headers / body split
    const header_end = std.mem.indexOf(u8, raw, "\r\n\r\n") orelse return;
    const headers_str = raw[0..header_end];
    const body_start = header_end + 4;

    // Parse Content-Length
    var content_length: usize = 0;
    var lines = std.mem.splitScalar(u8, headers_str, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \r");
        if (std.ascii.startsWithIgnoreCase(trimmed, "content-length:")) {
            const val = std.mem.trim(u8, trimmed["content-length:".len..], " ");
            content_length = std.fmt.parseInt(usize, val, 10) catch 0;
        }
    }

    // Read remaining body bytes if needed
    while (total - body_start < content_length and total < buf.len) {
        const n = stream.read(buf[total..]) catch break;
        if (n == 0) break;
        total += n;
    }

    const body = buf[body_start..@min(body_start + content_length, total)];
    const response_body = processRpc(chain, alloc, body);

    // Write HTTP 200 response
    var resp_buf: [4096]u8 = undefined;
    const resp = std.fmt.bufPrint(
        &resp_buf,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{s}",
        .{ response_body.len, response_body },
    ) catch return;
    _ = stream.writeAll(resp) catch {};
}

fn processRpc(chain: *Chain, alloc: std.mem.Allocator, body: []const u8) []const u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, alloc, body, .{}) catch
        return errorResponse("-32700", "Parse error");
    const root = switch (parsed.value) {
        .object => |o| o,
        else => return errorResponse("-32600", "Invalid Request"),
    };

    const id = root.get("id") orelse std.json.Value{ .integer = 0 };
    const method = switch (root.get("method") orelse return errorResponse("-32600", "Missing method")) {
        .string => |s| s,
        else => return errorResponse("-32600", "Invalid method"),
    };

    const id_str = jsonValueToIdStr(alloc, id);

    if (std.mem.eql(u8, method, "eth_blockNumber")) {
        const latest = chain.getLatest() orelse return buildResponse(alloc, id_str, "\"0x0\"");
        const result = std.fmt.allocPrint(alloc, "\"0x{x}\"", .{latest.number}) catch return "{}";
        return buildResponse(alloc, id_str, result);
    }

    if (std.mem.eql(u8, method, "eth_getBlockByNumber")) {
        const params = switch (root.get("params") orelse return nullResponse(alloc, id_str)) {
            .array => |a| a,
            else => return nullResponse(alloc, id_str),
        };
        if (params.items.len == 0) return nullResponse(alloc, id_str);

        const tag = switch (params.items[0]) {
            .string => |s| s,
            else => return nullResponse(alloc, id_str),
        };

        const stored = resolveBlock(chain, tag) orelse return nullResponse(alloc, id_str);
        const result = std.fmt.allocPrint(
            alloc,
            "{{\"hash\":\"0x{x}\",\"number\":\"0x{x}\"}}",
            .{ stored.hash, stored.number },
        ) catch return "{}";
        return buildResponse(alloc, id_str, result);
    }

    return errorResponse("-32601", "Method not found");
}

fn resolveBlock(chain: *Chain, tag: []const u8) ?@import("chain.zig").StoredHeader {
    if (std.mem.eql(u8, tag, "latest") or std.mem.eql(u8, tag, "pending"))
        return chain.getLatest();
    if (std.mem.eql(u8, tag, "earliest"))
        return chain.getByNumber(0);

    // Hex block number
    const s = if (std.mem.startsWith(u8, tag, "0x") or std.mem.startsWith(u8, tag, "0X"))
        tag[2..]
    else
        tag;
    const n = std.fmt.parseInt(u64, s, 16) catch return null;
    return chain.getByNumber(n);
}

fn jsonValueToIdStr(alloc: std.mem.Allocator, id: std.json.Value) []const u8 {
    return switch (id) {
        .integer => |n| std.fmt.allocPrint(alloc, "{}", .{n}) catch "0",
        .string => |s| std.fmt.allocPrint(alloc, "\"{s}\"", .{s}) catch "\"\"",
        .null => "null",
        else => "0",
    };
}

fn buildResponse(alloc: std.mem.Allocator, id: []const u8, result: []const u8) []const u8 {
    return std.fmt.allocPrint(
        alloc,
        "{{\"jsonrpc\":\"2.0\",\"id\":{s},\"result\":{s}}}",
        .{ id, result },
    ) catch "{}";
}

fn nullResponse(alloc: std.mem.Allocator, id: []const u8) []const u8 {
    return buildResponse(alloc, id, "null");
}

fn errorResponse(code: []const u8, message: []const u8) []const u8 {
    // Static buffer for error responses (no alloc needed)
    const S = struct {
        var buf: [256]u8 = undefined;
    };
    return std.fmt.bufPrint(
        &S.buf,
        "{{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{{\"code\":{s},\"message\":\"{s}\"}}}}",
        .{ code, message },
    ) catch "{}";
}
