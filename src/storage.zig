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
    raw_data: ?[]const u8 = null,
};

pub const LogStorage = struct {
    db: sqlite.Database,
    insert_stmt: ?sqlite.Statement = null,
    allocator: std.mem.Allocator,

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
        \\    raw_data TEXT,
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
        \\INSERT INTO logs (timestamp, level, source, host, facility, app_name, proc_id, msg_id, message, raw_data)
        \\VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

        return LogStorage{
            .db = db,
            .allocator = allocator,
        };
    }

    pub fn initInMemory(allocator: std.mem.Allocator) !LogStorage {
        var db = try sqlite.Database.openInMemory();
        errdefer db.close();

        try db.exec(SCHEMA);

        return LogStorage{
            .db = db,
            .allocator = allocator,
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

    pub fn insert(self: *LogStorage, entry: LogEntry) !i64 {
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

        if (entry.raw_data) |raw| {
            try stmt.bind(10, raw);
        } else {
            try stmt.bind(10, null);
        }

        _ = try stmt.step();
        return self.db.lastInsertRowId();
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
            "SELECT id, timestamp, level, source, host, facility, app_name, proc_id, msg_id, message, raw_data FROM logs WHERE timestamp >= ? AND timestamp <= ? ORDER BY timestamp DESC LIMIT ?",
        );
        defer stmt.finalize();

        try stmt.bind(1, start);
        try stmt.bind(2, end);
        try stmt.bind(3, @as(i64, limit));

        var results = std.ArrayList(LogEntry).empty;
        errdefer results.deinit(allocator);

        while (try stmt.step()) {
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
                .raw_data = if (stmt.columnText(10)) |r| try allocator.dupe(u8, r) else null,
            };
            try results.append(allocator, entry);
        }

        return results.toOwnedSlice(allocator);
    }
};

test "log storage basic operations" {
    const allocator = std.testing.allocator;
    var storage = try LogStorage.initInMemory(allocator);
    defer storage.deinit();

    const entry = LogEntry{
        .timestamp = std.time.timestamp(),
        .level = .info,
        .source = .syslog,
        .host = "localhost",
        .facility = 16,
        .app_name = "test",
        .message = "Test message",
    };

    const id = try storage.insert(entry);
    try std.testing.expect(id == 1);

    const count = try storage.getLogCount();
    try std.testing.expect(count == 1);
}

test "log storage batch insert" {
    const allocator = std.testing.allocator;
    var storage = try LogStorage.initInMemory(allocator);
    defer storage.deinit();

    const now = std.time.timestamp();
    var entries: [100]LogEntry = undefined;
    for (&entries, 0..) |*e, i| {
        e.* = LogEntry{
            .timestamp = now + @as(i64, @intCast(i)),
            .level = .info,
            .source = .rest_api,
            .host = "192.168.1.1",
            .message = "Batch test message",
        };
    }

    const inserted = try storage.insertBatch(&entries);
    try std.testing.expect(inserted == 100);

    const count = try storage.getLogCount();
    try std.testing.expect(count == 100);
}
