//! Log Storage Module using ZDBC
//! Handles database schema and log insertion using zdbc library

const std = @import("std");
const zdbc = @import("zdbc");

pub const LogLevel = enum(u8) {
    emergency = 0,
    alert = 1,
    critical = 2,
    err = 3,
    warning = 4,
    notice = 5,
    info = 6,
    debug = 7,

    pub fn fromSyslogFacility(priority: u8) LogLevel {
        const severity = priority & 0x07;
        return @enumFromInt(severity);
    }

    pub fn toString(self: LogLevel) []const u8 {
        return switch (self) {
            .emergency => "EMERGENCY",
            .alert => "ALERT",
            .critical => "CRITICAL",
            .err => "ERROR",
            .warning => "WARNING",
            .notice => "NOTICE",
            .info => "INFO",
            .debug => "DEBUG",
        };
    }
};

pub const LogSource = enum(u8) {
    syslog = 0,
    rest_api = 1,
    snmp = 2,

    pub fn toString(self: LogSource) []const u8 {
        return switch (self) {
            .syslog => "SYSLOG",
            .rest_api => "REST_API",
            .snmp => "SNMP",
        };
    }
};

pub const LogEntry = struct {
    id: ?i64 = null,
    timestamp: i64,
    level: LogLevel,
    source: LogSource,
    host: []const u8,
    facility: ?u8 = null,
    app_name: ?[]const u8 = null,
    proc_id: ?[]const u8 = null,
    msg_id: ?[]const u8 = null,
    message: []const u8,
    raw_data: []const u8, // Required field, supports binary data
    hmac: [32]u8 = [_]u8{0} ** 32, // Chain-based HMAC for tamper detection (required)
};

pub const LogStorage = struct {
    conn: zdbc.Connection,
    allocator: std.mem.Allocator,
    prev_hmac: [32]u8 = [_]u8{0} ** 32, // Chain HMAC state
    next_id: i64 = 1, // Cached next expected ID for performance
    mutex: std.Thread.Mutex = .{}, // Protect HMAC chain state

    const SCHEMA =
        \\CREATE TABLE IF NOT EXISTS logs (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    timestamp INTEGER NOT NULL,
        \\    level INTEGER NOT NULL,
        \\    source INTEGER NOT NULL,
        \\    host TEXT NOT NULL,
        \\    facility INTEGER,
        \\    app_name TEXT,
        \\    proc_id TEXT,
        \\    msg_id TEXT,
        \\    message TEXT NOT NULL,
        \\    raw_data BLOB NOT NULL,
        \\    hmac BLOB NOT NULL,
        \\    created_at INTEGER DEFAULT (strftime('%s', 'now'))
        \\);
        \\
        \\CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
        \\CREATE INDEX IF NOT EXISTS idx_logs_level ON logs(level);
        \\CREATE INDEX IF NOT EXISTS idx_logs_source ON logs(source);
        \\CREATE INDEX IF NOT EXISTS idx_logs_host ON logs(host);
        \\CREATE INDEX IF NOT EXISTS idx_logs_app_name ON logs(app_name);
    ;

    const INSERT_SQL =
        \\INSERT INTO logs (timestamp, level, source, host, facility, app_name, proc_id, msg_id, message, raw_data, hmac)
        \\VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ;

    pub fn init(allocator: std.mem.Allocator, db_path: [:0]const u8) !LogStorage {
        // Create URI for SQLite connection
        // For absolute paths like `/path`: results in `sqlite:///path`
        // For relative paths like `logs.db`: results in `sqlite://logs.db`
        const uri = try std.fmt.allocPrint(allocator, "sqlite://{s}", .{db_path});
        defer allocator.free(uri);

        var conn = try zdbc.open(allocator, uri);
        errdefer conn.close();

        // Enable WAL mode for better concurrent performance
        _ = try conn.exec("PRAGMA journal_mode=WAL", &.{});
        _ = try conn.exec("PRAGMA synchronous=NORMAL", &.{});
        _ = try conn.exec("PRAGMA busy_timeout=5000", &.{});

        // Create schema
        _ = try conn.exec(SCHEMA, &.{});

        // Load the last HMAC and next_id from existing records for chain continuation
        var prev_hmac: [32]u8 = [_]u8{0} ** 32;
        var next_id: i64 = 1;

        var result = try conn.query("SELECT id, hmac FROM logs ORDER BY id DESC LIMIT 1", &.{});
        defer result.deinit();

        if (try result.next()) |row| {
            if (try row.getInt(0)) |id| {
                next_id = id + 1;
            }
            if (try row.getBlob(1)) |blob| {
                if (blob.len == 32) {
                    @memcpy(&prev_hmac, blob);
                }
            }
        }

        return LogStorage{
            .conn = conn,
            .allocator = allocator,
            .prev_hmac = prev_hmac,
            .next_id = next_id,
        };
    }

    pub fn initInMemory(allocator: std.mem.Allocator) !LogStorage {
        var conn = try zdbc.open(allocator, "sqlite://:memory:");
        errdefer conn.close();

        // Create schema
        _ = try conn.exec(SCHEMA, &.{});

        return LogStorage{
            .conn = conn,
            .allocator = allocator,
            .prev_hmac = [_]u8{0} ** 32,
            .next_id = 1,
        };
    }

    pub fn deinit(self: *LogStorage) void {
        self.conn.close();
    }

    /// Compute chain HMAC: current_value = hash(raw_data || id) XOR previous_value
    /// Uses SHA-256 for hashing
    fn computeChainHmac(self: *LogStorage, raw_data: []const u8, id: i64) [32]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});

        // Hash raw_data || id
        hasher.update(raw_data);

        // Convert id to bytes (little-endian)
        const id_bytes: [8]u8 = @bitCast(id);
        hasher.update(&id_bytes);

        const hash_result = hasher.finalResult();

        // XOR with previous HMAC
        var result: [32]u8 = undefined;
        for (&result, hash_result, self.prev_hmac) |*r, h, p| {
            r.* = h ^ p;
        }

        return result;
    }

    pub fn insert(self: *LogStorage, entry: LogEntry) !i64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Use cached next_id for performance (no database query needed)
        const expected_id = self.next_id;

        // Compute chain HMAC using the expected ID
        const hmac = self.computeChainHmac(entry.raw_data, expected_id);

        // Use parameterized INSERT with zdbc.Value for safety and performance
        _ = try self.conn.exec(INSERT_SQL, &.{
            zdbc.Value.initInt(entry.timestamp),
            zdbc.Value.initInt(@as(i64, @intFromEnum(entry.level))),
            zdbc.Value.initInt(@as(i64, @intFromEnum(entry.source))),
            zdbc.Value.initText(entry.host),
            if (entry.facility) |f| zdbc.Value.initInt(@as(i64, f)) else zdbc.Value.initNull(),
            if (entry.app_name) |app| zdbc.Value.initText(app) else zdbc.Value.initNull(),
            if (entry.proc_id) |pid| zdbc.Value.initText(pid) else zdbc.Value.initNull(),
            if (entry.msg_id) |mid| zdbc.Value.initText(mid) else zdbc.Value.initNull(),
            zdbc.Value.initText(entry.message),
            zdbc.Value.initBlob(entry.raw_data),
            zdbc.Value.initBlob(&hmac),
        });

        const actual_id = self.conn.lastInsertId() orelse expected_id;

        // Verify ID matches expected (should always match with AUTOINCREMENT)
        if (actual_id != expected_id) {
            // If IDs don't match (rare edge case), update HMAC with correct ID
            const correct_hmac = self.computeChainHmac(entry.raw_data, actual_id);
            _ = try self.conn.exec("UPDATE logs SET hmac = ? WHERE id = ?", &.{
                zdbc.Value.initBlob(&correct_hmac),
                zdbc.Value.initInt(actual_id),
            });
            self.prev_hmac = correct_hmac;
            // Reset next_id to actual_id + 1 to recover from mismatch
            self.next_id = actual_id + 1;
        } else {
            // Update previous HMAC and next_id for chain continuity
            self.prev_hmac = hmac;
            self.next_id = expected_id + 1;
        }

        return actual_id;
    }

    pub fn insertBatch(self: *LogStorage, entries: []const LogEntry) !usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Use transaction for batch insert (as per zdbc example)
        try self.conn.begin();
        errdefer self.conn.rollback() catch {};

        var count: usize = 0;
        for (entries) |entry| {
            // Use cached next_id for performance
            const expected_id = self.next_id;

            // Compute chain HMAC using the expected ID
            const hmac = self.computeChainHmac(entry.raw_data, expected_id);

            // Use parameterized INSERT with zdbc.Value
            _ = try self.conn.exec(INSERT_SQL, &.{
                zdbc.Value.initInt(entry.timestamp),
                zdbc.Value.initInt(@as(i64, @intFromEnum(entry.level))),
                zdbc.Value.initInt(@as(i64, @intFromEnum(entry.source))),
                zdbc.Value.initText(entry.host),
                if (entry.facility) |f| zdbc.Value.initInt(@as(i64, f)) else zdbc.Value.initNull(),
                if (entry.app_name) |app| zdbc.Value.initText(app) else zdbc.Value.initNull(),
                if (entry.proc_id) |pid| zdbc.Value.initText(pid) else zdbc.Value.initNull(),
                if (entry.msg_id) |mid| zdbc.Value.initText(mid) else zdbc.Value.initNull(),
                zdbc.Value.initText(entry.message),
                zdbc.Value.initBlob(entry.raw_data),
                zdbc.Value.initBlob(&hmac),
            });

            const actual_id = self.conn.lastInsertId() orelse expected_id;

            // Verify ID matches expected
            if (actual_id != expected_id) {
                // If IDs don't match, update HMAC with correct ID
                const correct_hmac = self.computeChainHmac(entry.raw_data, actual_id);
                _ = try self.conn.exec("UPDATE logs SET hmac = ? WHERE id = ?", &.{
                    zdbc.Value.initBlob(&correct_hmac),
                    zdbc.Value.initInt(actual_id),
                });
                self.prev_hmac = correct_hmac;
                self.next_id = actual_id + 1;
            } else {
                // Update previous HMAC and next_id for chain continuity
                self.prev_hmac = hmac;
                self.next_id = expected_id + 1;
            }

            count += 1;
        }

        try self.conn.commit();
        return count;
    }

    pub fn getLogCount(self: *LogStorage) !i64 {
        var result = try self.conn.query("SELECT COUNT(*) FROM logs", &.{});
        defer result.deinit();

        if (try result.next()) |row| {
            if (try row.getInt(0)) |count| {
                return count;
            }
        }
        return 0;
    }

    pub fn queryByTimeRange(self: *LogStorage, allocator: std.mem.Allocator, start: i64, end: i64, limit: u32) ![]LogEntry {
        var result = try self.conn.query(
            "SELECT id, timestamp, level, source, host, facility, app_name, proc_id, msg_id, message, raw_data, hmac FROM logs WHERE timestamp >= ? AND timestamp <= ? ORDER BY timestamp DESC LIMIT ?",
            &.{
                zdbc.Value.initInt(start),
                zdbc.Value.initInt(end),
                zdbc.Value.initInt(@as(i64, limit)),
            },
        );
        defer result.deinit();

        var results = std.ArrayList(LogEntry).empty;
        errdefer results.deinit(allocator);

        var count: usize = 0;
        while (try result.next()) |row| {
            count += 1;
            // Get hmac from BLOB - required field
            var hmac: [32]u8 = [_]u8{0} ** 32;
            if (try row.getBlob(11)) |blob| {
                if (blob.len == 32) {
                    @memcpy(&hmac, blob);
                }
            }

            const entry = LogEntry{
                .id = try row.getInt(0),
                .timestamp = (try row.getInt(1)) orelse 0,
                .level = @enumFromInt(@as(u8, @intCast((try row.getInt(2)) orelse 0))),
                .source = @enumFromInt(@as(u8, @intCast((try row.getInt(3)) orelse 0))),
                .host = if (try row.getText(4)) |h| try allocator.dupe(u8, h) else "",
                .facility = if ((try row.getInt(5)) orelse 0 != 0) @as(u8, @intCast((try row.getInt(5)) orelse 0)) else null,
                .app_name = if (try row.getText(6)) |a| try allocator.dupe(u8, a) else null,
                .proc_id = if (try row.getText(7)) |p| try allocator.dupe(u8, p) else null,
                .msg_id = if (try row.getText(8)) |m| try allocator.dupe(u8, m) else null,
                .message = if (try row.getText(9)) |msg| try allocator.dupe(u8, msg) else "",
                .raw_data = if (try row.getBlob(10)) |r| try allocator.dupe(u8, r) else "",
                .hmac = hmac,
            };
            try results.append(allocator, entry);
        }

        return results.toOwnedSlice(allocator);
    }
};

test "log storage basic operations" {
    const allocator = std.testing.allocator;
    var storage_inst = try LogStorage.initInMemory(allocator);
    defer storage_inst.deinit();

    const raw_msg = "<134>Test raw syslog message";
    const entry = LogEntry{
        .timestamp = std.time.timestamp(),
        .level = .info,
        .source = .syslog,
        .host = "localhost",
        .facility = 16,
        .app_name = "test",
        .message = "Test message",
        .raw_data = raw_msg,
    };

    const id = try storage_inst.insert(entry);
    try std.testing.expect(id == 1);

    const count = try storage_inst.getLogCount();
    try std.testing.expect(count == 1);
}

test "log storage batch insert" {
    const allocator = std.testing.allocator;
    var storage_inst = try LogStorage.initInMemory(allocator);
    defer storage_inst.deinit();

    const now = std.time.timestamp();
    var entries: [100]LogEntry = undefined;
    for (&entries, 0..) |*e, i| {
        e.* = LogEntry{
            .timestamp = now + @as(i64, @intCast(i)),
            .level = .info,
            .source = .rest_api,
            .host = "192.168.1.1",
            .message = "Batch test message",
            .raw_data = "raw batch data",
        };
    }

    const inserted = try storage_inst.insertBatch(&entries);
    try std.testing.expect(inserted == 100);

    const count = try storage_inst.getLogCount();
    try std.testing.expect(count == 100);
}

test "chain hmac computation and verification" {
    const allocator = std.testing.allocator;
    var storage_inst = try LogStorage.initInMemory(allocator);
    defer storage_inst.deinit();

    // Insert multiple entries and verify HMAC chain
    const entry1 = LogEntry{
        .timestamp = std.time.timestamp(),
        .level = .info,
        .source = .syslog,
        .host = "localhost",
        .message = "First message",
        .raw_data = "raw data 1",
    };

    const entry2 = LogEntry{
        .timestamp = std.time.timestamp() + 1,
        .level = .warning,
        .source = .rest_api,
        .host = "localhost",
        .message = "Second message",
        .raw_data = "raw data 2",
    };

    const id1 = try storage_inst.insert(entry1);
    try std.testing.expect(id1 == 1);

    const id2 = try storage_inst.insert(entry2);
    try std.testing.expect(id2 == 2);

    // Query entries and verify HMAC is set
    const results = try storage_inst.queryByTimeRange(allocator, 0, std.math.maxInt(i64), 10);
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

    try std.testing.expect(results.len == 2);

    // Both entries should have HMAC set (non-zero)
    const zero_hmac = [_]u8{0} ** 32;
    try std.testing.expect(!std.mem.eql(u8, &results[0].hmac, &zero_hmac));
    try std.testing.expect(!std.mem.eql(u8, &results[1].hmac, &zero_hmac));

    // HMACs should be different (chain property)
    try std.testing.expect(!std.mem.eql(u8, &results[0].hmac, &results[1].hmac));
}

test "binary data support in raw_data" {
    const allocator = std.testing.allocator;
    var storage_inst = try LogStorage.initInMemory(allocator);
    defer storage_inst.deinit();

    // Test with binary data including null bytes
    const binary_data = [_]u8{ 0x00, 0x01, 0x02, 0xFF, 0xFE, 0x00, 0x80, 0x7F };
    const entry = LogEntry{
        .timestamp = std.time.timestamp(),
        .level = .debug,
        .source = .snmp,
        .host = "localhost",
        .message = "Binary test",
        .raw_data = &binary_data,
    };

    const id = try storage_inst.insert(entry);
    try std.testing.expect(id == 1);

    // Query and verify binary data is preserved
    const results = try storage_inst.queryByTimeRange(allocator, 0, std.math.maxInt(i64), 10);
    defer {
        for (results) |r| {
            allocator.free(r.host);
            allocator.free(r.message);
            allocator.free(r.raw_data);
        }
        allocator.free(results);
    }

    try std.testing.expect(results.len == 1);
    try std.testing.expectEqualSlices(u8, &binary_data, results[0].raw_data);
}
