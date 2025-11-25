//! SQLite3 wrapper for Zig
//! Provides a safe, ergonomic interface to SQLite3 C API

const std = @import("std");
const c = @cImport({
    @cInclude("sqlite3.h");
});

pub const Error = error{
    SqliteError,
    SqliteBusy,
    SqliteConstraint,
    SqliteMismatch,
    SqliteNoMem,
    InvalidColumn,
    NullValue,
};

pub const OpenFlags = struct {
    pub const READONLY = c.SQLITE_OPEN_READONLY;
    pub const READWRITE = c.SQLITE_OPEN_READWRITE;
    pub const CREATE = c.SQLITE_OPEN_CREATE;
    pub const URI = c.SQLITE_OPEN_URI;
    pub const MEMORY = c.SQLITE_OPEN_MEMORY;
    pub const NOMUTEX = c.SQLITE_OPEN_NOMUTEX;
    pub const FULLMUTEX = c.SQLITE_OPEN_FULLMUTEX;
    pub const SHAREDCACHE = c.SQLITE_OPEN_SHAREDCACHE;
    pub const PRIVATECACHE = c.SQLITE_OPEN_PRIVATECACHE;
};

pub const Statement = struct {
    stmt: *c.sqlite3_stmt,
    db: *Database,

    pub fn bind(self: *Statement, index: u32, value: anytype) Error!void {
        const T = @TypeOf(value);
        const idx = @as(c_int, @intCast(index));

        const rc = switch (@typeInfo(T)) {
            .null => c.sqlite3_bind_null(self.stmt, idx),
            .int, .comptime_int => c.sqlite3_bind_int64(self.stmt, idx, @as(i64, @intCast(value))),
            .float, .comptime_float => c.sqlite3_bind_double(self.stmt, idx, @as(f64, value)),
            .pointer => |ptr_info| blk: {
                switch (ptr_info.size) {
                    .slice => {
                        if (ptr_info.child == u8) {
                            break :blk c.sqlite3_bind_text(self.stmt, idx, value.ptr, @as(c_int, @intCast(value.len)), c.SQLITE_TRANSIENT);
                        }
                    },
                    .one => {
                        // Handle pointer to array (string literals like "test")
                        if (@typeInfo(ptr_info.child) == .array) {
                            const arr_info = @typeInfo(ptr_info.child).array;
                            if (arr_info.child == u8) {
                                break :blk c.sqlite3_bind_text(self.stmt, idx, value, @as(c_int, @intCast(arr_info.len)), c.SQLITE_TRANSIENT);
                            }
                        }
                    },
                    .many, .c => {
                        if (ptr_info.child == u8) {
                            const len = std.mem.len(value);
                            break :blk c.sqlite3_bind_text(self.stmt, idx, value, @as(c_int, @intCast(len)), c.SQLITE_TRANSIENT);
                        }
                    },
                }
                @compileError("Unsupported pointer type for binding");
            },
            .optional => blk: {
                if (value) |v| {
                    return self.bind(index, v);
                } else {
                    break :blk c.sqlite3_bind_null(self.stmt, idx);
                }
            },
            else => @compileError("Unsupported type for binding: " ++ @typeName(T)),
        };

        if (rc != c.SQLITE_OK) {
            return Error.SqliteError;
        }
    }

    pub fn bindAll(self: *Statement, values: anytype) Error!void {
        const fields = std.meta.fields(@TypeOf(values));
        inline for (fields, 0..) |_, i| {
            try self.bind(i + 1, values[i]);
        }
    }

    pub fn step(self: *Statement) Error!bool {
        const rc = c.sqlite3_step(self.stmt);
        return switch (rc) {
            c.SQLITE_ROW => true,
            c.SQLITE_DONE => false,
            c.SQLITE_BUSY => Error.SqliteBusy,
            c.SQLITE_CONSTRAINT => Error.SqliteConstraint,
            else => Error.SqliteError,
        };
    }

    pub fn columnText(self: *Statement, index: u32) ?[]const u8 {
        const idx = @as(c_int, @intCast(index));
        const text = c.sqlite3_column_text(self.stmt, idx);
        if (text == null) return null;
        const len = c.sqlite3_column_bytes(self.stmt, idx);
        return text[0..@as(usize, @intCast(len))];
    }

    pub fn columnInt(self: *Statement, index: u32) i64 {
        return c.sqlite3_column_int64(self.stmt, @as(c_int, @intCast(index)));
    }

    pub fn columnDouble(self: *Statement, index: u32) f64 {
        return c.sqlite3_column_double(self.stmt, @as(c_int, @intCast(index)));
    }

    pub fn columnBlob(self: *Statement, index: u32) ?[]const u8 {
        const idx = @as(c_int, @intCast(index));
        const blob = c.sqlite3_column_blob(self.stmt, idx);
        if (blob == null) return null;
        const len = c.sqlite3_column_bytes(self.stmt, idx);
        return @as([*]const u8, @ptrCast(blob))[0..@as(usize, @intCast(len))];
    }

    pub fn reset(self: *Statement) Error!void {
        if (c.sqlite3_reset(self.stmt) != c.SQLITE_OK) {
            return Error.SqliteError;
        }
    }

    pub fn clearBindings(self: *Statement) Error!void {
        if (c.sqlite3_clear_bindings(self.stmt) != c.SQLITE_OK) {
            return Error.SqliteError;
        }
    }

    pub fn finalize(self: *Statement) void {
        _ = c.sqlite3_finalize(self.stmt);
    }
};

pub const Database = struct {
    db: *c.sqlite3,

    pub fn open(path: [*:0]const u8) Error!Database {
        return openWithFlags(path, OpenFlags.READWRITE | OpenFlags.CREATE);
    }

    pub fn openWithFlags(path: [*:0]const u8, flags: c_int) Error!Database {
        var db: ?*c.sqlite3 = null;
        const rc = c.sqlite3_open_v2(path, &db, flags, null);
        if (rc != c.SQLITE_OK) {
            if (db) |d| {
                _ = c.sqlite3_close(d);
            }
            return Error.SqliteError;
        }
        return Database{ .db = db.? };
    }

    pub fn openInMemory() Error!Database {
        return open(":memory:");
    }

    pub fn close(self: *Database) void {
        _ = c.sqlite3_close(self.db);
    }

    pub fn exec(self: *Database, sql: [*:0]const u8) Error!void {
        var err_msg: [*c]u8 = null;
        const rc = c.sqlite3_exec(self.db, sql, null, null, &err_msg);
        if (rc != c.SQLITE_OK) {
            if (err_msg) |msg| {
                c.sqlite3_free(msg);
            }
            return Error.SqliteError;
        }
    }

    pub fn prepare(self: *Database, sql: []const u8) Error!Statement {
        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(
            self.db,
            sql.ptr,
            @as(c_int, @intCast(sql.len)),
            &stmt,
            null,
        );
        if (rc != c.SQLITE_OK) {
            return Error.SqliteError;
        }
        return Statement{ .stmt = stmt.?, .db = self };
    }

    pub fn lastInsertRowId(self: *Database) i64 {
        return c.sqlite3_last_insert_rowid(self.db);
    }

    pub fn changes(self: *Database) i32 {
        return @as(i32, @intCast(c.sqlite3_changes(self.db)));
    }

    pub fn getErrorMsg(self: *Database) []const u8 {
        const msg = c.sqlite3_errmsg(self.db);
        return std.mem.span(msg);
    }

    pub fn beginTransaction(self: *Database) Error!void {
        return self.exec("BEGIN TRANSACTION");
    }

    pub fn commit(self: *Database) Error!void {
        return self.exec("COMMIT");
    }

    pub fn rollback(self: *Database) Error!void {
        return self.exec("ROLLBACK");
    }

    pub fn setBusyTimeout(self: *Database, ms: c_int) Error!void {
        if (c.sqlite3_busy_timeout(self.db, ms) != c.SQLITE_OK) {
            return Error.SqliteError;
        }
    }

    pub fn enableWAL(self: *Database) Error!void {
        return self.exec("PRAGMA journal_mode=WAL");
    }

    pub fn setSynchronous(self: *Database, mode: enum { off, normal, full, extra }) Error!void {
        const sql: [*:0]const u8 = switch (mode) {
            .off => "PRAGMA synchronous=OFF",
            .normal => "PRAGMA synchronous=NORMAL",
            .full => "PRAGMA synchronous=FULL",
            .extra => "PRAGMA synchronous=EXTRA",
        };
        return self.exec(sql);
    }
};

test "database basic operations" {
    var db = try Database.openInMemory();
    defer db.close();

    try db.exec("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)");
    try db.exec("INSERT INTO test (name) VALUES ('hello')");

    const row_id = db.lastInsertRowId();
    try std.testing.expect(row_id == 1);
}

test "prepared statement" {
    var db = try Database.openInMemory();
    defer db.close();

    try db.exec("CREATE TABLE test (id INTEGER PRIMARY KEY, value INTEGER, name TEXT)");

    var stmt = try db.prepare("INSERT INTO test (value, name) VALUES (?, ?)");
    defer stmt.finalize();

    try stmt.bind(1, @as(i64, 42));
    try stmt.bind(2, "test");
    _ = try stmt.step();

    try stmt.reset();
    try stmt.clearBindings();

    try stmt.bind(1, @as(i64, 100));
    try stmt.bind(2, "another");
    _ = try stmt.step();

    var select = try db.prepare("SELECT value, name FROM test WHERE value = ?");
    defer select.finalize();

    try select.bind(1, @as(i64, 42));
    const has_row = try select.step();
    try std.testing.expect(has_row);

    const value = select.columnInt(0);
    try std.testing.expect(value == 42);

    if (select.columnText(1)) |name| {
        try std.testing.expectEqualStrings("test", name);
    }
}
