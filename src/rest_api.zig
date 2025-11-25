//! RESTful API for log collection
//! Simple HTTP server for receiving logs via POST requests

const std = @import("std");
const net = std.net;
const storage = @import("storage.zig");
const LogEntry = storage.LogEntry;
const LogLevel = storage.LogLevel;
const LogSource = storage.LogSource;

pub const HttpError = error{
    InvalidRequest,
    InvalidMethod,
    InvalidPath,
    InvalidJson,
    ConnectionClosed,
    BufferOverflow,
};

pub const HttpMethod = enum {
    GET,
    POST,
    PUT,
    DELETE,
    OPTIONS,

    pub fn fromString(s: []const u8) ?HttpMethod {
        if (std.mem.eql(u8, s, "GET")) return .GET;
        if (std.mem.eql(u8, s, "POST")) return .POST;
        if (std.mem.eql(u8, s, "PUT")) return .PUT;
        if (std.mem.eql(u8, s, "DELETE")) return .DELETE;
        if (std.mem.eql(u8, s, "OPTIONS")) return .OPTIONS;
        return null;
    }
};

pub const HttpRequest = struct {
    method: HttpMethod,
    path: []const u8,
    headers: std.StringHashMap([]const u8),
    body: []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *HttpRequest) void {
        self.headers.deinit();
    }
};

pub const HttpResponse = struct {
    status: u16,
    status_text: []const u8,
    headers: std.StringHashMap([]const u8),
    body: []const u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) HttpResponse {
        return HttpResponse{
            .status = 200,
            .status_text = "OK",
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = "",
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *HttpResponse) void {
        self.headers.deinit();
    }

    pub fn setStatus(self: *HttpResponse, code: u16, text: []const u8) void {
        self.status = code;
        self.status_text = text;
    }

    pub fn setBody(self: *HttpResponse, body: []const u8) void {
        self.body = body;
    }

    pub fn format(self: *HttpResponse, allocator: std.mem.Allocator) ![]u8 {
        var buf = std.ArrayList(u8).empty;
        const writer = buf.writer(allocator);

        try writer.print("HTTP/1.1 {} {s}\r\n", .{ self.status, self.status_text });
        try writer.print("Content-Length: {}\r\n", .{self.body.len});
        try writer.print("Content-Type: application/json\r\n", .{});
        try writer.print("Connection: close\r\n", .{});

        var it = self.headers.iterator();
        while (it.next()) |entry| {
            try writer.print("{s}: {s}\r\n", .{ entry.key_ptr.*, entry.value_ptr.* });
        }

        try writer.writeAll("\r\n");
        try writer.writeAll(self.body);

        return buf.toOwnedSlice(allocator);
    }
};

/// Parse HTTP request from raw bytes
pub fn parseHttpRequest(allocator: std.mem.Allocator, data: []const u8) !HttpRequest {
    var headers = std.StringHashMap([]const u8).init(allocator);
    errdefer headers.deinit();

    // Find end of headers
    var header_end: usize = 0;
    for (0..data.len - 3) |i| {
        if (std.mem.eql(u8, data[i..][0..4], "\r\n\r\n")) {
            header_end = i;
            break;
        }
    }

    if (header_end == 0) {
        return HttpError.InvalidRequest;
    }

    const header_section = data[0..header_end];
    const body = if (header_end + 4 < data.len) data[header_end + 4 ..] else "";

    // Parse request line
    var lines = std.mem.splitSequence(u8, header_section, "\r\n");
    const request_line = lines.next() orelse return HttpError.InvalidRequest;

    var parts = std.mem.splitScalar(u8, request_line, ' ');
    const method_str = parts.next() orelse return HttpError.InvalidRequest;
    const path = parts.next() orelse return HttpError.InvalidRequest;

    const method = HttpMethod.fromString(method_str) orelse return HttpError.InvalidMethod;

    // Parse headers
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const sep_pos = std.mem.indexOf(u8, line, ":") orelse continue;
        const key = std.mem.trim(u8, line[0..sep_pos], " ");
        const value = std.mem.trim(u8, line[sep_pos + 1 ..], " ");
        try headers.put(key, value);
    }

    return HttpRequest{
        .method = method,
        .path = path,
        .headers = headers,
        .body = body,
        .allocator = allocator,
    };
}

/// Simple JSON log message parser
pub const JsonLogMessage = struct {
    level: ?[]const u8 = null,
    message: ?[]const u8 = null,
    host: ?[]const u8 = null,
    app_name: ?[]const u8 = null,
    timestamp: ?i64 = null,

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
        };
    }
};

/// Parse JSON log message (simple parser)
pub fn parseJsonLog(allocator: std.mem.Allocator, json: []const u8) !JsonLogMessage {
    _ = allocator;
    var result = JsonLogMessage{};

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

pub const RestApiServer = struct {
    listener: ?net.Server,
    port: u16,
    running: std.atomic.Value(bool),
    storage_ptr: *storage.LogStorage,
    allocator: std.mem.Allocator,

    const BUFFER_SIZE = 65536;

    pub fn init(allocator: std.mem.Allocator, port: u16, store: *storage.LogStorage) RestApiServer {
        return RestApiServer{
            .listener = null,
            .port = port,
            .running = std.atomic.Value(bool).init(false),
            .storage_ptr = store,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *RestApiServer) void {
        self.stop();
    }

    pub fn start(self: *RestApiServer) !void {
        const address = net.Address.initIp4(.{ 0, 0, 0, 0 }, self.port);
        const server = try address.listen(.{
            .reuse_address = true,
        });
        self.listener = server;
        self.running.store(true, .seq_cst);
    }

    pub fn acceptAndHandle(self: *RestApiServer) !void {
        if (self.listener == null) return;

        const conn = self.listener.?.accept() catch |err| {
            if (err == error.WouldBlock) return;
            return err;
        };
        defer conn.stream.close();

        var buffer: [BUFFER_SIZE]u8 = undefined;
        const bytes_read = conn.stream.read(&buffer) catch return;
        if (bytes_read == 0) return;

        var request = parseHttpRequest(self.allocator, buffer[0..bytes_read]) catch {
            self.sendError(conn.stream, 400, "Bad Request");
            return;
        };
        defer request.deinit();

        self.handleRequest(&request, conn.stream);
    }

    fn handleRequest(self: *RestApiServer, request: *HttpRequest, stream: net.Stream) void {
        if (request.method == .POST and std.mem.startsWith(u8, request.path, "/api/logs")) {
            self.handlePostLog(request, stream);
        } else if (request.method == .GET and std.mem.startsWith(u8, request.path, "/api/logs")) {
            self.handleGetLogs(request, stream);
        } else if (request.method == .GET and std.mem.eql(u8, request.path, "/health")) {
            self.sendSuccess(stream, "{\"status\":\"ok\"}");
        } else {
            self.sendError(stream, 404, "Not Found");
        }
    }

    fn handlePostLog(self: *RestApiServer, request: *HttpRequest, stream: net.Stream) void {
        const json_msg = parseJsonLog(self.allocator, request.body) catch {
            self.sendError(stream, 400, "Invalid JSON");
            return;
        };

        const entry = json_msg.toLogEntry();
        const id = self.storage_ptr.insert(entry) catch {
            self.sendError(stream, 500, "Storage Error");
            return;
        };

        var buf: [128]u8 = undefined;
        const response = std.fmt.bufPrint(&buf, "{{\"id\":{},\"status\":\"created\"}}", .{id}) catch {
            self.sendError(stream, 500, "Format Error");
            return;
        };

        self.sendSuccess(stream, response);
    }

    fn handleGetLogs(self: *RestApiServer, request: *HttpRequest, stream: net.Stream) void {
        _ = request;
        const count = self.storage_ptr.getLogCount() catch {
            self.sendError(stream, 500, "Storage Error");
            return;
        };

        var buf: [128]u8 = undefined;
        const response = std.fmt.bufPrint(&buf, "{{\"count\":{}}}", .{count}) catch {
            self.sendError(stream, 500, "Format Error");
            return;
        };

        self.sendSuccess(stream, response);
    }

    fn sendSuccess(self: *RestApiServer, stream: net.Stream, body: []const u8) void {
        var response = HttpResponse.init(self.allocator);
        defer response.deinit();

        response.setStatus(200, "OK");
        response.setBody(body);

        const formatted = response.format(self.allocator) catch return;
        defer self.allocator.free(formatted);

        stream.writeAll(formatted) catch {};
    }

    fn sendError(self: *RestApiServer, stream: net.Stream, code: u16, message: []const u8) void {
        var response = HttpResponse.init(self.allocator);
        defer response.deinit();

        response.setStatus(code, message);

        var buf: [256]u8 = undefined;
        const body = std.fmt.bufPrint(&buf, "{{\"error\":\"{s}\"}}", .{message}) catch return;
        response.setBody(body);

        const formatted = response.format(self.allocator) catch return;
        defer self.allocator.free(formatted);

        stream.writeAll(formatted) catch {};
    }

    pub fn stop(self: *RestApiServer) void {
        self.running.store(false, .seq_cst);
        if (self.listener) |*listener| {
            listener.deinit();
            self.listener = null;
        }
    }
};

test "parse HTTP request" {
    const allocator = std.testing.allocator;
    const raw_request =
        "POST /api/logs HTTP/1.1\r\n" ++
        "Host: localhost:8080\r\n" ++
        "Content-Type: application/json\r\n" ++
        "Content-Length: 44\r\n" ++
        "\r\n" ++
        "{\"message\":\"test\",\"level\":\"info\"}";

    var request = try parseHttpRequest(allocator, raw_request);
    defer request.deinit();

    try std.testing.expect(request.method == .POST);
    try std.testing.expectEqualStrings("/api/logs", request.path);
    try std.testing.expectEqualStrings("{\"message\":\"test\",\"level\":\"info\"}", request.body);
}

test "parse JSON log" {
    const allocator = std.testing.allocator;
    const json = "{\"message\":\"Hello World\",\"level\":\"error\",\"host\":\"server1\"}";

    const result = try parseJsonLog(allocator, json);

    try std.testing.expectEqualStrings("Hello World", result.message.?);
    try std.testing.expectEqualStrings("error", result.level.?);
    try std.testing.expectEqualStrings("server1", result.host.?);
}
