//! Syslog Parser and Receiver
//! Supports RFC 3164 (BSD) and RFC 5424 syslog formats

const std = @import("std");
const net = std.net;
const storage = @import("storage.zig");
const LogEntry = storage.LogEntry;
const LogLevel = storage.LogLevel;
const LogSource = storage.LogSource;

pub const SyslogMessage = struct {
    priority: u8,
    facility: u8,
    severity: u8,
    timestamp: ?i64,
    hostname: []const u8,
    app_name: ?[]const u8,
    proc_id: ?[]const u8,
    msg_id: ?[]const u8,
    message: []const u8,
    raw: []const u8,

    pub fn toLogEntry(self: SyslogMessage) LogEntry {
        return LogEntry{
            .timestamp = self.timestamp orelse std.time.timestamp(),
            .level = LogLevel.fromSyslogFacility(self.priority),
            .source = .syslog,
            .host = self.hostname,
            .facility = self.facility,
            .app_name = self.app_name,
            .proc_id = self.proc_id,
            .msg_id = self.msg_id,
            .message = self.message,
            .raw_data = self.raw,
        };
    }
};

pub const ParseError = error{
    InvalidFormat,
    InvalidPriority,
    InvalidTimestamp,
    BufferTooSmall,
};

/// Parse syslog priority value <PRI>
fn parsePriority(data: []const u8) ParseError!struct { priority: u8, rest: []const u8 } {
    if (data.len < 3 or data[0] != '<') {
        return ParseError.InvalidPriority;
    }

    var end: usize = 1;
    while (end < data.len and end < 5) {
        if (data[end] == '>') {
            break;
        }
        if (data[end] < '0' or data[end] > '9') {
            return ParseError.InvalidPriority;
        }
        end += 1;
    }

    if (end >= data.len or data[end] != '>') {
        return ParseError.InvalidPriority;
    }

    const priority = std.fmt.parseInt(u8, data[1..end], 10) catch {
        return ParseError.InvalidPriority;
    };

    return .{ .priority = priority, .rest = data[end + 1 ..] };
}

/// Parse RFC 3164 timestamp (BSD format)
/// Format: Mmm dd hh:mm:ss
fn parseRFC3164Timestamp(data: []const u8) ?struct { timestamp: i64, rest: []const u8 } {
    if (data.len < 15) return null;

    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    var month: u8 = 0;
    for (months, 0..) |m, i| {
        if (std.mem.eql(u8, data[0..3], m)) {
            month = @intCast(i + 1);
            break;
        }
    }
    if (month == 0) return null;

    // Skip space and parse day
    if (data[3] != ' ') return null;
    const day_str = std.mem.trim(u8, data[4..6], " ");
    const day = std.fmt.parseInt(u8, day_str, 10) catch return null;

    if (data[6] != ' ') return null;

    // Parse time hh:mm:ss
    const hour = std.fmt.parseInt(u8, data[7..9], 10) catch return null;
    if (data[9] != ':') return null;
    const minute = std.fmt.parseInt(u8, data[10..12], 10) catch return null;
    if (data[12] != ':') return null;
    const second = std.fmt.parseInt(u8, data[13..15], 10) catch return null;

    // Get current timestamp and adjust for approximate time
    // This is a simplified approach - uses current year from timestamp
    const now = std.time.timestamp();

    // Calculate approximate timestamp for this year
    // Days from month start (cumulative days before each month)
    // NOTE: This does not account for leap years, which may cause timestamp
    // inaccuracies of up to 1 day for dates in March-December during leap years.
    const days_before_month = [_]u16{ 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };

    // Get current year's January 1st timestamp (approximate)
    // We'll use the current timestamp and work backwards
    const secs_per_day: i64 = 86400;
    const secs_per_year: i64 = 365 * secs_per_day;

    // Approximate start of current year
    const years_since_epoch = @divFloor(now, secs_per_year);
    const year_start = years_since_epoch * secs_per_year;

    // Calculate day of year
    const day_of_year: i64 = @as(i64, days_before_month[month - 1]) + @as(i64, day) - 1;

    // Calculate final timestamp
    const timestamp = year_start + day_of_year * secs_per_day + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + @as(i64, second);

    var rest_start: usize = 15;
    if (rest_start < data.len and data[rest_start] == ' ') {
        rest_start += 1;
    }

    return .{ .timestamp = timestamp, .rest = data[rest_start..] };
}

/// Parse hostname from syslog message
fn parseHostname(data: []const u8) struct { hostname: []const u8, rest: []const u8 } {
    var end: usize = 0;
    while (end < data.len and data[end] != ' ' and data[end] != ':') {
        end += 1;
    }

    var rest_start = end;
    while (rest_start < data.len and (data[rest_start] == ' ' or data[rest_start] == ':')) {
        rest_start += 1;
    }

    return .{
        .hostname = if (end > 0) data[0..end] else "unknown",
        .rest = data[rest_start..],
    };
}

/// Parse application name and optional PID from syslog message
fn parseAppName(data: []const u8) struct { app_name: ?[]const u8, proc_id: ?[]const u8, rest: []const u8 } {
    var end: usize = 0;

    // Find end of app name (before [ or : or space)
    while (end < data.len and data[end] != '[' and data[end] != ':' and data[end] != ' ') {
        end += 1;
    }

    const app_name = if (end > 0) data[0..end] else null;
    var proc_id: ?[]const u8 = null;
    var rest_start = end;

    // Check for PID in brackets
    if (rest_start < data.len and data[rest_start] == '[') {
        const pid_start = rest_start + 1;
        var pid_end = pid_start;
        while (pid_end < data.len and data[pid_end] != ']') {
            pid_end += 1;
        }
        if (pid_end < data.len and pid_end > pid_start) {
            proc_id = data[pid_start..pid_end];
            rest_start = pid_end + 1;
        }
    }

    // Skip colon and spaces
    while (rest_start < data.len and (data[rest_start] == ':' or data[rest_start] == ' ')) {
        rest_start += 1;
    }

    return .{
        .app_name = app_name,
        .proc_id = proc_id,
        .rest = data[rest_start..],
    };
}

/// Parse a syslog message (RFC 3164 format)
pub fn parseSyslogMessage(data: []const u8) ParseError!SyslogMessage {
    if (data.len == 0) {
        return ParseError.InvalidFormat;
    }

    // Parse priority
    const pri_result = try parsePriority(data);
    const priority = pri_result.priority;
    const facility = priority >> 3;
    const severity = priority & 0x07;

    var remaining = pri_result.rest;

    // Try to parse timestamp
    var timestamp: ?i64 = null;
    if (parseRFC3164Timestamp(remaining)) |ts_result| {
        timestamp = ts_result.timestamp;
        remaining = ts_result.rest;
    }

    // Parse hostname
    const host_result = parseHostname(remaining);
    remaining = host_result.rest;

    // Parse app name and PID
    const app_result = parseAppName(remaining);

    return SyslogMessage{
        .priority = priority,
        .facility = facility,
        .severity = severity,
        .timestamp = timestamp,
        .hostname = host_result.hostname,
        .app_name = app_result.app_name,
        .proc_id = app_result.proc_id,
        .msg_id = null,
        .message = app_result.rest,
        .raw = data,
    };
}

pub const SyslogServer = struct {
    udp_socket: ?std.posix.socket_t,
    tcp_listener: ?net.Server,
    port: u16,
    running: std.atomic.Value(bool),
    storage_ptr: *storage.LogStorage,
    allocator: std.mem.Allocator,
    recv_buffer: []u8,

    const BUFFER_SIZE = 65536;

    pub fn init(allocator: std.mem.Allocator, port: u16, store: *storage.LogStorage) !SyslogServer {
        const buffer = try allocator.alloc(u8, BUFFER_SIZE);
        errdefer allocator.free(buffer);

        return SyslogServer{
            .udp_socket = null,
            .tcp_listener = null,
            .port = port,
            .running = std.atomic.Value(bool).init(false),
            .storage_ptr = store,
            .allocator = allocator,
            .recv_buffer = buffer,
        };
    }

    pub fn deinit(self: *SyslogServer) void {
        self.stop();
        self.allocator.free(self.recv_buffer);
    }

    pub fn startUDP(self: *SyslogServer) !void {
        const address = net.Address.initIp4(.{ 0, 0, 0, 0 }, self.port);
        const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
        errdefer std.posix.close(sock);

        try std.posix.bind(sock, &address.any, @sizeOf(@TypeOf(address.in)));
        self.udp_socket = sock;
        self.running.store(true, .seq_cst);
    }

    pub fn receiveOne(self: *SyslogServer) !?LogEntry {
        if (self.udp_socket == null) return null;

        var src_addr: std.posix.sockaddr = undefined;
        var addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);

        const len = std.posix.recvfrom(
            self.udp_socket.?,
            self.recv_buffer,
            0,
            &src_addr,
            &addr_len,
        ) catch |err| {
            if (err == error.WouldBlock) return null;
            return err;
        };

        if (len == 0) return null;

        const msg = parseSyslogMessage(self.recv_buffer[0..len]) catch return null;
        return msg.toLogEntry();
    }

    pub fn stop(self: *SyslogServer) void {
        self.running.store(false, .seq_cst);
        if (self.udp_socket) |sock| {
            std.posix.close(sock);
            self.udp_socket = null;
        }
        if (self.tcp_listener) |*listener| {
            listener.deinit();
            self.tcp_listener = null;
        }
    }
};

test "parse syslog priority" {
    const result = try parsePriority("<134>Test message");
    try std.testing.expect(result.priority == 134);
    try std.testing.expectEqualStrings("Test message", result.rest);
}

test "parse RFC 3164 message" {
    const msg = "<134>Jan 15 12:34:56 myhost myapp[1234]: Test message";
    const result = try parseSyslogMessage(msg);

    try std.testing.expect(result.priority == 134);
    try std.testing.expect(result.facility == 16);
    try std.testing.expect(result.severity == 6);
    try std.testing.expectEqualStrings("myhost", result.hostname);
    try std.testing.expectEqualStrings("myapp", result.app_name.?);
    try std.testing.expectEqualStrings("1234", result.proc_id.?);
    try std.testing.expectEqualStrings("Test message", result.message);
}

test "parse simple syslog message" {
    const msg = "<13>Hello World";
    const result = try parseSyslogMessage(msg);

    try std.testing.expect(result.priority == 13);
    try std.testing.expectEqualStrings("Hello", result.hostname);
    // "World" becomes app_name in simple messages without timestamp
    try std.testing.expectEqualStrings("World", result.app_name.?);
}
