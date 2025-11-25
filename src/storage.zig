//! Log Storage Module
//! Handles database schema and log insertion

const std = @import("std");
const sqlite = @import("sqlite.zig");

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
    hmac: ?[32]u8 = null, // Chain-based HMAC for tamper detection
};

pub const LogStorage = struct {
    db: sqlite.Database,
    insert_stmt: ?sqlite.Statement = null,
    allocator: std.mem.Allocator,
    prev_hmac: [32]u8 = [_]u8{0} ** 32, // Chain HMAC state

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
        \\    hmac BLOB,
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

    pub fn init(allocator: std.mem.Allocator, db_path: [*:0]const u8) !LogStorage {
        var db = try sqlite.Database.open(db_path);
        errdefer db.close();

        // Enable WAL mode for better concurrent performance
        try db.enableWAL();
        try db.setSynchronous(.normal);
        try db.setBusyTimeout(5000);

        // Create schema
        try db.exec(SCHEMA);

        // Load the last HMAC from existing records for chain continuation
        var prev_hmac: [32]u8 = [_]u8{0} ** 32;
        var stmt = try db.prepare("SELECT hmac FROM logs ORDER BY id DESC LIMIT 1");
        defer stmt.finalize();
        if (try stmt.step()) {
            if (stmt.columnBlob(0)) |blob| {
                if (blob.len == 32) {
                    @memcpy(&prev_hmac, blob);
                }
            }
        }

        return LogStorage{
            .db = db,
            .allocator = allocator,
            .prev_hmac = prev_hmac,
        };
    }

    pub fn initInMemory(allocator: std.mem.Allocator) !LogStorage {
        var db = try sqlite.Database.openInMemory();
        errdefer db.close();

        try db.exec(SCHEMA);

        // For in-memory database, prev_hmac is initialized to zeros
        // (new empty database has no previous HMAC)
        return LogStorage{
            .db = db,
            .allocator = allocator,
            .prev_hmac = [_]u8{0} ** 32,
        };
    }

    pub fn deinit(self: *LogStorage) void {
        if (self.insert_stmt) |*stmt| {
            stmt.finalize();
        }
        self.db.close();
    }

    fn getInsertStmt(self: *LogStorage) !*sqlite.Statement {
        if (self.insert_stmt == null) {
            self.insert_stmt = try self.db.prepare(INSERT_SQL);
        }
        return &self.insert_stmt.?;
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
        // Get the next expected ID (MAX(id) + 1 or 1 if table is empty)
        var id_stmt = try self.db.prepare("SELECT COALESCE(MAX(id), 0) + 1 FROM logs");
        defer id_stmt.finalize();
        _ = try id_stmt.step();
        const expected_id = id_stmt.columnInt(0);

        // Compute chain HMAC using the expected ID
        const hmac = self.computeChainHmac(entry.raw_data, expected_id);

        var stmt = try self.getInsertStmt();
        defer {
            stmt.reset() catch {};
            stmt.clearBindings() catch {};
        }

        try stmt.bind(1, entry.timestamp);
        try stmt.bind(2, @as(i64, @intFromEnum(entry.level)));
        try stmt.bind(3, @as(i64, @intFromEnum(entry.source)));
        try stmt.bind(4, entry.host);

        if (entry.facility) |f| {
            try stmt.bind(5, @as(i64, f));
        } else {
            try stmt.bind(5, null);
        }

        if (entry.app_name) |app| {
            try stmt.bind(6, app);
        } else {
            try stmt.bind(6, null);
        }

        if (entry.proc_id) |pid| {
            try stmt.bind(7, pid);
        } else {
            try stmt.bind(7, null);
        }

        if (entry.msg_id) |mid| {
            try stmt.bind(8, mid);
        } else {
            try stmt.bind(8, null);
        }

        try stmt.bind(9, entry.message);

        // Bind raw_data as BLOB (required field)
        try stmt.bindBlob(10, entry.raw_data);

        // Bind computed HMAC
        try stmt.bindBlob(11, &hmac);

        _ = try stmt.step();
        const actual_id = self.db.lastInsertRowId();

        // Verify ID matches expected (should always match with AUTOINCREMENT)
        if (actual_id != expected_id) {
            // If IDs don't match (rare edge case), update HMAC with correct ID
            const correct_hmac = self.computeChainHmac(entry.raw_data, actual_id);
            var update_stmt = try self.db.prepare("UPDATE logs SET hmac = ? WHERE id = ?");
            defer update_stmt.finalize();
            try update_stmt.bindBlob(1, &correct_hmac);
            try update_stmt.bind(2, actual_id);
            _ = try update_stmt.step();
            self.prev_hmac = correct_hmac;
        } else {
            // Update previous HMAC for chain continuity
            self.prev_hmac = hmac;
        }

        return actual_id;
    }

    pub fn insertBatch(self: *LogStorage, entries: []const LogEntry) !usize {
        try self.db.beginTransaction();
        errdefer self.db.rollback() catch {};

        var count: usize = 0;
        for (entries) |entry| {
            _ = try self.insert(entry);
            count += 1;
        }

        try self.db.commit();
        return count;
    }

    pub fn getLogCount(self: *LogStorage) !i64 {
        var stmt = try self.db.prepare("SELECT COUNT(*) FROM logs");
        defer stmt.finalize();

        _ = try stmt.step();
        return stmt.columnInt(0);
    }

    pub fn queryByTimeRange(self: *LogStorage, allocator: std.mem.Allocator, start: i64, end: i64, limit: u32) ![]LogEntry {
        var stmt = try self.db.prepare(
            "SELECT id, timestamp, level, source, host, facility, app_name, proc_id, msg_id, message, raw_data, hmac FROM logs WHERE timestamp >= ? AND timestamp <= ? ORDER BY timestamp DESC LIMIT ?",
        );
        defer stmt.finalize();

        try stmt.bind(1, start);
        try stmt.bind(2, end);
        try stmt.bind(3, @as(i64, limit));

        var results = std.ArrayList(LogEntry).empty;
        errdefer results.deinit(allocator);

        while (try stmt.step()) {
            // Get hmac if present
            var hmac: ?[32]u8 = null;
            if (stmt.columnBlob(11)) |blob| {
                if (blob.len == 32) {
                    var hmac_arr: [32]u8 = undefined;
                    @memcpy(&hmac_arr, blob);
                    hmac = hmac_arr;
                }
            }

            const entry = LogEntry{
                .id = stmt.columnInt(0),
                .timestamp = stmt.columnInt(1),
                .level = @enumFromInt(@as(u8, @intCast(stmt.columnInt(2)))),
                .source = @enumFromInt(@as(u8, @intCast(stmt.columnInt(3)))),
                .host = if (stmt.columnText(4)) |h| try allocator.dupe(u8, h) else "",
                .facility = if (stmt.columnInt(5) != 0) @as(u8, @intCast(stmt.columnInt(5))) else null,
                .app_name = if (stmt.columnText(6)) |a| try allocator.dupe(u8, a) else null,
                .proc_id = if (stmt.columnText(7)) |p| try allocator.dupe(u8, p) else null,
                .msg_id = if (stmt.columnText(8)) |m| try allocator.dupe(u8, m) else null,
                .message = if (stmt.columnText(9)) |msg| try allocator.dupe(u8, msg) else "",
                .raw_data = if (stmt.columnBlob(10)) |r| try allocator.dupe(u8, r) else "",
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

    // Both entries should have HMAC set
    try std.testing.expect(results[0].hmac != null);
    try std.testing.expect(results[1].hmac != null);

    // HMACs should be different (chain property)
    try std.testing.expect(!std.mem.eql(u8, &results[0].hmac.?, &results[1].hmac.?));
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
