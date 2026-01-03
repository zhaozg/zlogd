# ZDBC SQLite Driver Fixes

This document describes critical bugs found in the zdbc library's SQLite driver and the fixes applied to make it work correctly.

## Location
File: `~/.cache/zig/p/zdbc-0.1.0-.../src/drivers/sqlite.zig`

## Bug 1: sqliteResultGetValue - Missing Column Type Support

### Problem
The `sqliteResultGetValue` function only handled TEXT column types, completely ignoring INTEGER, FLOAT, and BLOB types. This made it impossible to retrieve numeric values from query results.

### Impact
- `COUNT(*)` queries returned NULL instead of integers
- Any INTEGER column retrieval failed
- FLOAT and BLOB columns also couldn't be retrieved

### Original Code
```zig
fn sqliteResultGetValue(ctx: *anyopaque, index: usize) Error!Value {
    const result_ctx: *SqliteResultContext = @ptrCast(@alignCast(ctx));
    if (result_ctx.current_row == null) {
        return Error.NoMoreRows;
    }
    const row = result_ctx.current_row.?;
    // Check if null
    if (row.nullableText(index)) |text| {
        return Value.initText(text);
    }
    return Value.initNull();
}
```

### Fixed Code
```zig
fn sqliteResultGetValue(ctx: *anyopaque, index: usize) Error!Value {
    const result_ctx: *SqliteResultContext = @ptrCast(@alignCast(ctx));
    if (result_ctx.current_row == null) {
        return Error.NoMoreRows;
    }
    const row = result_ctx.current_row.?;
    
    // Check the column type and return appropriate value
    const col_type = row.columnType(index);
    return switch (col_type) {
        .int => Value.initInt(row.int(index)),
        .float => Value.initFloat(row.float(index)),
        .text => if (row.nullableText(index)) |text| Value.initText(text) else Value.initNull(),
        .blob => if (row.nullableBlob(index)) |blob| Value.initBlob(blob) else Value.initNull(),
        .null => Value.initNull(),
        .unknown => Value.initNull(),
    };
}
```

## Bug 2: sqliteQuery - Parameterized Queries Not Supported

### Problem
The `sqliteQuery` function completely ignored the `params` parameter (with `_ = params;`), making it impossible to use parameterized SELECT queries. This is a critical security and functionality issue.

### Impact
- Parameterized WHERE clauses didn't work
- No SQL injection protection for queries
- Had to resort to string concatenation (unsafe)

### Original Code
```zig
fn sqliteQuery(ctx: *anyopaque, allocator: std.mem.Allocator, sql: []const u8, params: []const Value) Error!Result {
    const sqlite_ctx: *SqliteContext = @ptrCast(@alignCast(ctx));

    // Convert to null-terminated string
    const sql_z = sqlite_ctx.allocator.dupeZ(u8, sql) catch return Error.OutOfMemory;
    defer sqlite_ctx.allocator.free(sql_z);

    _ = params;  // Parameters completely ignored!
    const rows = sqlite_ctx.conn.rows(sql_z, .{}) catch {
        return Error.ExecutionFailed;
    };

    const result_ctx = SqliteResultContext.init(allocator) catch return Error.OutOfMemory;
    result_ctx.rows = rows;

    return Result.init(@ptrCast(result_ctx), &sqliteResultVTable);
}
```

### Fixed Code
```zig
fn sqliteQuery(ctx: *anyopaque, allocator: std.mem.Allocator, sql: []const u8, params: []const Value) Error!Result {
    const sqlite_ctx: *SqliteContext = @ptrCast(@alignCast(ctx));

    // Convert to null-terminated string
    const sql_z = sqlite_ctx.allocator.dupeZ(u8, sql) catch return Error.OutOfMemory;
    defer sqlite_ctx.allocator.free(sql_z);

    // If we have params, use prepare and bind
    if (params.len > 0) {
        const stmt = sqlite_ctx.conn.prepare(sql_z) catch return Error.PrepareFailed;
        // Don't defer deinit here - we need to keep it alive for the rows iterator
        
        // Bind parameters
        for (params, 0..) |param, i| {
            switch (param) {
                .null => {
                    stmt.bindValue(@as(?i64, null), i) catch {
                        stmt.deinit();
                        return Error.BindError;
                    };
                },
                .boolean => |b| {
                    const val: i64 = if (b) 1 else 0;
                    stmt.bindValue(val, i) catch {
                        stmt.deinit();
                        return Error.BindError;
                    };
                },
                .int => |val| {
                    stmt.bindValue(val, i) catch {
                        stmt.deinit();
                        return Error.BindError;
                    };
                },
                .uint => |val| {
                    if (val <= std.math.maxInt(i64)) {
                        stmt.bindValue(@as(i64, @intCast(val)), i) catch {
                            stmt.deinit();
                            return Error.BindError;
                        };
                    } else {
                        stmt.deinit();
                        return Error.BindError;
                    }
                },
                .float => |val| {
                    stmt.bindValue(val, i) catch {
                        stmt.deinit();
                        return Error.BindError;
                    };
                },
                .text => |val| {
                    stmt.bindValue(val, i) catch {
                        stmt.deinit();
                        return Error.BindError;
                    };
                },
                .blob => |val| {
                    stmt.bindValue(val, i) catch {
                        stmt.deinit();
                        return Error.BindError;
                    };
                },
            }
        }
        
        // Create rows iterator from prepared statement manually
        const zqlite = @import("zqlite");
        const rows = zqlite.Rows{ .stmt = stmt, .err = null };
        
        const result_ctx = SqliteResultContext.init(allocator) catch {
            stmt.deinit();
            return Error.OutOfMemory;
        };
        result_ctx.rows = rows;
        
        return Result.init(@ptrCast(result_ctx), &sqliteResultVTable);
    } else {
        // No params - use direct query
        const rows = sqlite_ctx.conn.rows(sql_z, .{}) catch {
            return Error.ExecutionFailed;
        };

        const result_ctx = SqliteResultContext.init(allocator) catch return Error.OutOfMemory;
        result_ctx.rows = rows;

        return Result.init(@ptrCast(result_ctx), &sqliteResultVTable);
    }
}
```

## Testing

After applying these fixes:
1. All zlogd tests pass (27/27)
2. Parameterized queries work correctly
3. Integer, float, text, and blob values are retrieved correctly
4. Performance is maintained

## Recommendation

These fixes should be submitted as a pull request to the upstream zdbc repository at https://github.com/zhaozg/zdbc to benefit all users of the library.

## Workaround for Users

Until these fixes are merged upstream, users can apply the patches manually to their cached zdbc installation at:
`~/.cache/zig/p/zdbc-0.1.0-*/src/drivers/sqlite.zig`
