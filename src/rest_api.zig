//! RESTful API for log collection
//! HTTP server for receiving logs via POST requests using karlseguin/http.zig

const std = @import("std");
const httpz = @import("httpz");
const storage = @import("storage.zig");
const LogEntry = storage.LogEntry;
const LogLevel = storage.LogLevel;
const LogSource = storage.LogSource;

/// Simple JSON log message parser
pub const JsonLogMessage = struct {
    level: ?[]const u8 = null,
    message: ?[]const u8 = null,
    host: ?[]const u8 = null,
    app_name: ?[]const u8 = null,
    timestamp: ?i64 = null,
    raw_body: []const u8 = "", // Original JSON body

    pub fn toLogEntry(self: JsonLogMessage) LogEntry {
        const level: LogLevel = if (self.level) |l| blk: {
            if (std.mem.eql(u8, l, "emergency")) break :blk .emergency;
            if (std.mem.eql(u8, l, "alert")) break :blk .alert;
            if (std.mem.eql(u8, l, "critical")) break :blk .critical;
            if (std.mem.eql(u8, l, "error")) break :blk .err;
            if (std.mem.eql(u8, l, "warning")) break :blk .warning;
            if (std.mem.eql(u8, l, "notice")) break :blk .notice;
            if (std.mem.eql(u8, l, "info")) break :blk .info;
            if (std.mem.eql(u8, l, "debug")) break :blk .debug;
            break :blk .info;
        } else .info;

        return LogEntry{
            .timestamp = self.timestamp orelse std.time.timestamp(),
            .level = level,
            .source = .rest_api,
            .host = self.host orelse "unknown",
            .app_name = self.app_name,
            .message = self.message orelse "",
            .raw_data = self.raw_body,
        };
    }
};

/// Parse JSON log message (simple parser)
pub fn parseJsonLog(allocator: std.mem.Allocator, json: []const u8) !JsonLogMessage {
    _ = allocator;
    var result = JsonLogMessage{
        .raw_body = json, // Store original JSON body
    };

    // Simple JSON parsing for common fields
    if (findJsonString(json, "message")) |msg| {
        result.message = msg;
    }
    if (findJsonString(json, "level")) |lvl| {
        result.level = lvl;
    }
    if (findJsonString(json, "host")) |h| {
        result.host = h;
    }
    if (findJsonString(json, "app_name")) |app| {
        result.app_name = app;
    }
    if (findJsonNumber(json, "timestamp")) |ts| {
        result.timestamp = ts;
    }

    return result;
}

/// Find a string value in JSON
fn findJsonString(json: []const u8, key: []const u8) ?[]const u8 {
    // Look for "key": "value" pattern
    var search_buf: [256]u8 = undefined;
    const pattern = std.fmt.bufPrint(&search_buf, "\"{s}\"", .{key}) catch return null;

    const key_pos = std.mem.indexOf(u8, json, pattern) orelse return null;
    var pos = key_pos + pattern.len;

    // Skip whitespace and colon
    while (pos < json.len and (json[pos] == ' ' or json[pos] == ':' or json[pos] == '\t')) {
        pos += 1;
    }

    if (pos >= json.len or json[pos] != '"') return null;
    pos += 1;

    const value_start = pos;
    while (pos < json.len and json[pos] != '"') {
        if (json[pos] == '\\' and pos + 1 < json.len) {
            pos += 2;
        } else {
            pos += 1;
        }
    }

    if (pos > value_start) {
        return json[value_start..pos];
    }
    return null;
}

/// Find a number value in JSON
fn findJsonNumber(json: []const u8, key: []const u8) ?i64 {
    var search_buf: [256]u8 = undefined;
    const pattern = std.fmt.bufPrint(&search_buf, "\"{s}\"", .{key}) catch return null;

    const key_pos = std.mem.indexOf(u8, json, pattern) orelse return null;
    var pos = key_pos + pattern.len;

    // Skip whitespace and colon
    while (pos < json.len and (json[pos] == ' ' or json[pos] == ':' or json[pos] == '\t')) {
        pos += 1;
    }

    const num_start = pos;
    while (pos < json.len and (json[pos] >= '0' and json[pos] <= '9')) {
        pos += 1;
    }

    if (pos > num_start) {
        return std.fmt.parseInt(i64, json[num_start..pos], 10) catch null;
    }
    return null;
}

/// Handler context for HTTP routes
pub const RestApiHandler = struct {
    storage_ptr: *storage.LogStorage,
    allocator: std.mem.Allocator,

    /// POST /api/logs - Submit a log entry
    pub fn handlePostLog(self: *RestApiHandler, req: *httpz.Request, res: *httpz.Response) !void {
        const body = req.body() orelse {
            res.status = 400;
            try res.json(.{ .@"error" = "Empty body" }, .{});
            return;
        };

        const json_msg = parseJsonLog(self.allocator, body) catch {
            res.status = 400;
            try res.json(.{ .@"error" = "Invalid JSON" }, .{});
            return;
        };

        const entry = json_msg.toLogEntry();
        const id = self.storage_ptr.insert(entry) catch {
            res.status = 500;
            try res.json(.{ .@"error" = "Storage Error" }, .{});
            return;
        };

        res.status = 201;
        try res.json(.{ .id = id, .status = "created" }, .{});
    }

    /// GET /api/logs - Get log count
    pub fn handleGetLogs(self: *RestApiHandler, _: *httpz.Request, res: *httpz.Response) !void {
        const count = self.storage_ptr.getLogCount() catch {
            res.status = 500;
            try res.json(.{ .@"error" = "Storage Error" }, .{});
            return;
        };

        try res.json(.{ .count = count }, .{});
    }

    /// GET /health - Health check
    pub fn handleHealth(_: *RestApiHandler, _: *httpz.Request, res: *httpz.Response) !void {
        try res.json(.{ .status = "ok" }, .{});
    }

    /// Handle not found routes
    pub fn notFound(_: *RestApiHandler, _: *httpz.Request, res: *httpz.Response) !void {
        res.status = 404;
        try res.json(.{ .@"error" = "Not Found" }, .{});
    }

    /// Handle uncaught errors
    pub fn uncaughtError(_: *RestApiHandler, _: *httpz.Request, res: *httpz.Response, err: anyerror) void {
        res.status = 500;
        res.body = "{\"error\":\"Internal Server Error\"}";
        std.log.err("HTTP handler error: {}", .{err});
    }
};

pub const RestApiServer = struct {
    server: ?httpz.Server(*RestApiHandler),
    port: u16,
    running: std.atomic.Value(bool),
    storage_ptr: *storage.LogStorage,
    allocator: std.mem.Allocator,
    handler: RestApiHandler,
    listen_thread: ?std.Thread = null,

    pub fn init(allocator: std.mem.Allocator, port: u16, store: *storage.LogStorage) RestApiServer {
        return RestApiServer{
            .server = null,
            .port = port,
            .running = std.atomic.Value(bool).init(false),
            .storage_ptr = store,
            .allocator = allocator,
            .handler = RestApiHandler{
                .storage_ptr = store,
                .allocator = allocator,
            },
            .listen_thread = null,
        };
    }

    pub fn deinit(self: *RestApiServer) void {
        self.stop();
    }

    pub fn start(self: *RestApiServer) !void {
        self.server = try httpz.Server(*RestApiHandler).init(self.allocator, .{
            .port = self.port,
            .workers = .{
                .count = 2,
            },
            .thread_pool = .{
                .count = 4,
            },
        }, &self.handler);

        const router = try self.server.?.router(.{});
        router.post("/api/logs", RestApiHandler.handlePostLog, .{});
        router.get("/api/logs", RestApiHandler.handleGetLogs, .{});
        router.get("/health", RestApiHandler.handleHealth, .{});

        self.running.store(true, .seq_cst);

        // Start HTTP server in a separate thread
        self.listen_thread = try std.Thread.spawn(.{}, listenThread, .{self});
    }

    fn listenThread(self: *RestApiServer) void {
        if (self.server) |*srv| {
            srv.listen() catch |err| {
                std.log.err("HTTP server listen error: {}", .{err});
            };
        }
    }

    pub fn stop(self: *RestApiServer) void {
        self.running.store(false, .seq_cst);
        if (self.server) |*srv| {
            srv.stop();
            srv.deinit();
            self.server = null;
        }
        if (self.listen_thread) |thread| {
            thread.join();
            self.listen_thread = null;
        }
    }

    /// Polling interface for compatibility with main server loop
    /// http.zig handles connections internally, so this is a no-op
    pub fn acceptAndHandle(self: *RestApiServer) !void {
        _ = self;
        // http.zig manages its own connection handling internally
        // This method is kept for API compatibility but does nothing
    }
};

test "parse JSON log" {
    const allocator = std.testing.allocator;
    const json = "{\"message\":\"Hello World\",\"level\":\"error\",\"host\":\"server1\"}";

    const result = try parseJsonLog(allocator, json);

    try std.testing.expectEqualStrings("Hello World", result.message.?);
    try std.testing.expectEqualStrings("error", result.level.?);
    try std.testing.expectEqualStrings("server1", result.host.?);
}

test "REST API JSON log to entry and storage" {
    const allocator = std.testing.allocator;
    var store = try storage.LogStorage.initInMemory(allocator);
    defer store.deinit();

    // Test the same JSON format used in REST API
    const json = "{\"message\":\"Application started\",\"level\":\"info\",\"host\":\"server1\",\"app_name\":\"myapp\",\"timestamp\":1700000000}";

    const json_msg = try parseJsonLog(allocator, json);
    const entry = json_msg.toLogEntry();

    // Insert into storage
    const id = try store.insert(entry);
    try std.testing.expect(id == 1);

    // Verify it was stored
    const count = try store.getLogCount();
    try std.testing.expect(count == 1);

    // Query and verify content
    const results = try store.queryByTimeRange(allocator, 0, std.math.maxInt(i64), 10);
    defer {
        for (results) |r| {
            allocator.free(r.host);
            allocator.free(r.message);
            allocator.free(r.raw_data);
            if (r.app_name) |a| allocator.free(a);
            if (r.proc_id) |p| allocator.free(p);
            if (r.msg_id) |m| allocator.free(m);
        }
        allocator.free(results);
    }

    try std.testing.expect(results.len == 1);
    try std.testing.expectEqualStrings("server1", results[0].host);
    try std.testing.expectEqualStrings("Application started", results[0].message);
    try std.testing.expectEqualStrings("myapp", results[0].app_name.?);
    try std.testing.expect(results[0].source == .rest_api);
    try std.testing.expect(results[0].level == .info);
    try std.testing.expect(results[0].timestamp == 1700000000);
    // Verify raw_data contains original JSON
    try std.testing.expectEqualStrings(json, results[0].raw_data);
}

test "REST API with all log levels" {
    const allocator = std.testing.allocator;
    var store = try storage.LogStorage.initInMemory(allocator);
    defer store.deinit();

    const levels = [_]struct { name: []const u8, expected: LogLevel }{
        .{ .name = "emergency", .expected = .emergency },
        .{ .name = "alert", .expected = .alert },
        .{ .name = "critical", .expected = .critical },
        .{ .name = "error", .expected = .err },
        .{ .name = "warning", .expected = .warning },
        .{ .name = "notice", .expected = .notice },
        .{ .name = "info", .expected = .info },
        .{ .name = "debug", .expected = .debug },
    };

    var buf: [256]u8 = undefined;
    for (levels, 1..) |lvl, i| {
        const json = std.fmt.bufPrint(&buf, "{{\"message\":\"Test\",\"level\":\"{s}\",\"host\":\"h\"}}", .{lvl.name}) catch unreachable;
        const json_msg = try parseJsonLog(allocator, json);
        const entry = json_msg.toLogEntry();
        const id = try store.insert(entry);
        try std.testing.expect(id == @as(i64, @intCast(i)));
    }

    const count = try store.getLogCount();
    try std.testing.expect(count == 8);
}
