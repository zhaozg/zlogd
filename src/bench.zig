//! Performance Benchmark for zlogd
//! Measures throughput and latency for log insertion operations

const std = @import("std");
const storage = @import("storage.zig");
const LogEntry = storage.LogEntry;
const LogLevel = storage.LogLevel;
const LogSource = storage.LogSource;
const writer = @import("writer.zig");

const BenchmarkResult = struct {
    name: []const u8,
    iterations: u64,
    total_time_ns: u64,
    ops_per_sec: f64,
    avg_latency_us: f64,
    min_latency_ns: u64,
    max_latency_ns: u64,
};

fn formatNumber(buf: []u8, num: f64) []const u8 {
    return std.fmt.bufPrint(buf, "{d:.2}", .{num}) catch "N/A";
}

fn runBenchmark(
    name: []const u8,
    iterations: u64,
    comptime benchFn: fn (*storage.LogStorage, std.mem.Allocator) anyerror!void,
    store: *storage.LogStorage,
    allocator: std.mem.Allocator,
) !BenchmarkResult {
    var timer = std.time.Timer.start() catch unreachable;
    var min_latency: u64 = std.math.maxInt(u64);
    var max_latency: u64 = 0;

    var i: u64 = 0;
    while (i < iterations) : (i += 1) {
        const start = timer.read();
        try benchFn(store, allocator);
        const elapsed = timer.read() - start;

        if (elapsed < min_latency) min_latency = elapsed;
        if (elapsed > max_latency) max_latency = elapsed;
    }

    const total_time = timer.read();
    const ops_per_sec = @as(f64, @floatFromInt(iterations)) / (@as(f64, @floatFromInt(total_time)) / 1_000_000_000.0);
    const avg_latency_us = @as(f64, @floatFromInt(total_time)) / @as(f64, @floatFromInt(iterations)) / 1000.0;

    return BenchmarkResult{
        .name = name,
        .iterations = iterations,
        .total_time_ns = total_time,
        .ops_per_sec = ops_per_sec,
        .avg_latency_us = avg_latency_us,
        .min_latency_ns = min_latency,
        .max_latency_ns = max_latency,
    };
}

fn benchSingleInsert(store: *storage.LogStorage, allocator: std.mem.Allocator) !void {
    _ = allocator;
    const entry = LogEntry{
        .timestamp = std.time.timestamp(),
        .level = .info,
        .source = .rest_api,
        .host = "benchmark-host",
        .app_name = "bench",
        .message = "Benchmark test message for performance measurement",
    };
    _ = try store.insert(entry);
}

fn benchBatchInsert10(store: *storage.LogStorage, allocator: std.mem.Allocator) !void {
    _ = allocator;
    var entries: [10]LogEntry = undefined;
    const now = std.time.timestamp();
    for (&entries, 0..) |*e, i| {
        e.* = LogEntry{
            .timestamp = now + @as(i64, @intCast(i)),
            .level = .info,
            .source = .syslog,
            .host = "batch-host",
            .app_name = "batch-bench",
            .message = "Batch benchmark test message",
        };
    }
    _ = try store.insertBatch(&entries);
}

fn benchBatchInsert100(store: *storage.LogStorage, allocator: std.mem.Allocator) !void {
    _ = allocator;
    var entries: [100]LogEntry = undefined;
    const now = std.time.timestamp();
    for (&entries, 0..) |*e, i| {
        e.* = LogEntry{
            .timestamp = now + @as(i64, @intCast(i)),
            .level = .info,
            .source = .snmp,
            .host = "batch-host-100",
            .app_name = "batch-bench-100",
            .message = "Large batch benchmark test message for throughput testing",
        };
    }
    _ = try store.insertBatch(&entries);
}

fn printResult(result: BenchmarkResult) void {
    var buf1: [32]u8 = undefined;
    var buf2: [32]u8 = undefined;
    var buf3: [32]u8 = undefined;
    var buf4: [32]u8 = undefined;

    std.debug.print("  {s}:\n", .{result.name});
    std.debug.print("    Iterations:     {}\n", .{result.iterations});
    std.debug.print("    Total time:     {s} ms\n", .{formatNumber(&buf1, @as(f64, @floatFromInt(result.total_time_ns)) / 1_000_000.0)});
    std.debug.print("    Ops/sec:        {s}\n", .{formatNumber(&buf2, result.ops_per_sec)});
    std.debug.print("    Avg latency:    {s} µs\n", .{formatNumber(&buf3, result.avg_latency_us)});
    std.debug.print("    Min latency:    {s} µs\n", .{formatNumber(&buf4, @as(f64, @floatFromInt(result.min_latency_ns)) / 1000.0)});
    std.debug.print("    Max latency:    {} µs\n", .{result.max_latency_ns / 1000});
    std.debug.print("\n", .{});
}

fn saveResultsJson(allocator: std.mem.Allocator, results: []const BenchmarkResult) !void {
    var file = try std.fs.cwd().createFile("benchmark_results.json", .{});
    defer file.close();

    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    const w = buf.writer();
    try w.writeAll("{\n  \"benchmarks\": [\n");

    for (results, 0..) |result, i| {
        try w.print("    {{\n", .{});
        try w.print("      \"name\": \"{s}\",\n", .{result.name});
        try w.print("      \"iterations\": {},\n", .{result.iterations});
        try w.print("      \"total_time_ns\": {},\n", .{result.total_time_ns});
        try w.print("      \"ops_per_sec\": {d:.2},\n", .{result.ops_per_sec});
        try w.print("      \"avg_latency_us\": {d:.2},\n", .{result.avg_latency_us});
        try w.print("      \"min_latency_ns\": {},\n", .{result.min_latency_ns});
        try w.print("      \"max_latency_ns\": {}\n", .{result.max_latency_ns});
        if (i < results.len - 1) {
            try w.writeAll("    },\n");
        } else {
            try w.writeAll("    }\n");
        }
    }

    try w.writeAll("  ]\n}\n");
    try file.writeAll(buf.items);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n", .{});
    std.debug.print("╔══════════════════════════════════════════════════════════════╗\n", .{});
    std.debug.print("║           zlogd Performance Benchmark (ReleaseFast)          ║\n", .{});
    std.debug.print("╚══════════════════════════════════════════════════════════════╝\n", .{});
    std.debug.print("\n", .{});

    // Use in-memory database for consistent benchmarking
    var store = try storage.LogStorage.initInMemory(allocator);
    defer store.deinit();

    std.debug.print("Running benchmarks...\n\n", .{});

    var results: [3]BenchmarkResult = undefined;

    // Benchmark 1: Single insert operations
    std.debug.print("Benchmark 1: Single Insert (10,000 iterations)\n", .{});
    results[0] = try runBenchmark("Single Insert", 10_000, benchSingleInsert, &store, allocator);
    printResult(results[0]);

    // Benchmark 2: Batch insert (10 entries per batch)
    std.debug.print("Benchmark 2: Batch Insert x10 (1,000 iterations = 10,000 entries)\n", .{});
    results[1] = try runBenchmark("Batch Insert x10", 1_000, benchBatchInsert10, &store, allocator);
    printResult(results[1]);

    // Benchmark 3: Batch insert (100 entries per batch)
    std.debug.print("Benchmark 3: Batch Insert x100 (100 iterations = 10,000 entries)\n", .{});
    results[2] = try runBenchmark("Batch Insert x100", 100, benchBatchInsert100, &store, allocator);
    printResult(results[2]);

    // Summary
    std.debug.print("═══════════════════════════════════════════════════════════════\n", .{});
    std.debug.print("                        SUMMARY\n", .{});
    std.debug.print("═══════════════════════════════════════════════════════════════\n", .{});

    var buf: [32]u8 = undefined;
    for (results) |result| {
        std.debug.print("  {s}: {s} ops/sec\n", .{ result.name, formatNumber(&buf, result.ops_per_sec) });
    }

    // Calculate effective throughput (entries per second)
    const single_throughput = results[0].ops_per_sec;
    const batch10_throughput = results[1].ops_per_sec * 10.0;
    const batch100_throughput = results[2].ops_per_sec * 100.0;

    std.debug.print("\nEffective Throughput (entries/sec):\n", .{});
    std.debug.print("  Single:      {s}\n", .{formatNumber(&buf, single_throughput)});
    var buf2: [32]u8 = undefined;
    std.debug.print("  Batch x10:   {s}\n", .{formatNumber(&buf2, batch10_throughput)});
    var buf3: [32]u8 = undefined;
    std.debug.print("  Batch x100:  {s}\n", .{formatNumber(&buf3, batch100_throughput)});

    // Save results to JSON
    try saveResultsJson(allocator, &results);
    std.debug.print("\nResults saved to: benchmark_results.json\n", .{});

    // Final log count
    const count = try store.getLogCount();
    std.debug.print("Total logs in database: {}\n", .{count});
    std.debug.print("\n", .{});
}
