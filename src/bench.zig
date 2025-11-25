//! Performance Benchmark for zlogd
//! Measures throughput and latency for log insertion, syslog/JSON parsing, and full pipeline operations

const std = @import("std");
const storage = @import("storage.zig");
const LogEntry = storage.LogEntry;
const LogLevel = storage.LogLevel;
const LogSource = storage.LogSource;
const writer = @import("writer.zig");
const syslog = @import("syslog.zig");
const rest_api = @import("rest_api.zig");

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
        .raw_data = "Benchmark raw data for performance testing",
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
            .raw_data = "Batch raw data for benchmark",
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
            .raw_data = "Large batch raw data for high throughput benchmark testing",
        };
    }
    _ = try store.insertBatch(&entries);
}

// Syslog message samples for benchmarking
const SYSLOG_MESSAGES = [_][]const u8{
    "<134>Jan 15 12:34:56 server1 myapp[1234]: User login successful",
    "<131>Feb 20 08:15:30 web-node-01 nginx[5678]: Connection timeout from 192.168.1.100",
    "<132>Mar 10 23:45:00 db-primary mysql[9012]: Query execution time exceeded threshold",
    "<133>Apr 05 14:22:15 app-server java[3456]: NullPointerException in UserService.java:42",
    "<134>May 18 09:30:45 cache-01 redis[7890]: Memory usage at 85%",
    "<135>Jun 25 16:55:20 lb-main haproxy[2345]: Backend server recovered",
    "<130>Jul 12 11:40:10 monitor-01 prometheus[6789]: Alert: High CPU usage detected",
    "<134>Aug 30 07:20:35 k8s-worker-01 kubelet[1234]: Pod scheduled successfully",
};

// JSON message samples for benchmarking
const JSON_MESSAGES = [_][]const u8{
    "{\"message\":\"User authentication successful\",\"level\":\"info\",\"host\":\"auth-server\",\"app_name\":\"auth-service\"}",
    "{\"message\":\"Database connection established\",\"level\":\"debug\",\"host\":\"db-primary\",\"timestamp\":1700000000}",
    "{\"message\":\"Payment processed successfully\",\"level\":\"info\",\"host\":\"payment-gw\",\"app_name\":\"payment\"}",
    "{\"message\":\"Cache miss for key user_123\",\"level\":\"warning\",\"host\":\"cache-01\",\"app_name\":\"redis-proxy\"}",
    "{\"message\":\"HTTP request completed\",\"level\":\"info\",\"host\":\"api-server\",\"app_name\":\"rest-api\"}",
    "{\"message\":\"File upload completed\",\"level\":\"info\",\"host\":\"storage-01\",\"app_name\":\"file-service\"}",
    "{\"message\":\"Email sent successfully\",\"level\":\"info\",\"host\":\"mail-server\",\"app_name\":\"mailer\"}",
    "{\"message\":\"Background job finished\",\"level\":\"debug\",\"host\":\"worker-01\",\"app_name\":\"job-runner\"}",
};

/// Benchmark for syslog message parsing
fn runSyslogParseBenchmark(iterations: u64) !BenchmarkResult {
    var timer = std.time.Timer.start() catch unreachable;
    var min_latency: u64 = std.math.maxInt(u64);
    var max_latency: u64 = 0;

    var i: u64 = 0;
    while (i < iterations) : (i += 1) {
        const msg_idx = i % SYSLOG_MESSAGES.len;
        const start = timer.read();
        const result = try syslog.parseSyslogMessage(SYSLOG_MESSAGES[msg_idx]);
        _ = result.toLogEntry();
        const elapsed = timer.read() - start;

        if (elapsed < min_latency) min_latency = elapsed;
        if (elapsed > max_latency) max_latency = elapsed;
    }

    const total_time = timer.read();
    const ops_per_sec = @as(f64, @floatFromInt(iterations)) / (@as(f64, @floatFromInt(total_time)) / 1_000_000_000.0);
    const avg_latency_us = @as(f64, @floatFromInt(total_time)) / @as(f64, @floatFromInt(iterations)) / 1000.0;

    return BenchmarkResult{
        .name = "Syslog Parse",
        .iterations = iterations,
        .total_time_ns = total_time,
        .ops_per_sec = ops_per_sec,
        .avg_latency_us = avg_latency_us,
        .min_latency_ns = min_latency,
        .max_latency_ns = max_latency,
    };
}

/// Benchmark for JSON message parsing
fn runJsonParseBenchmark(allocator: std.mem.Allocator, iterations: u64) !BenchmarkResult {
    var timer = std.time.Timer.start() catch unreachable;
    var min_latency: u64 = std.math.maxInt(u64);
    var max_latency: u64 = 0;

    var i: u64 = 0;
    while (i < iterations) : (i += 1) {
        const msg_idx = i % JSON_MESSAGES.len;
        const start = timer.read();
        const result = try rest_api.parseJsonLog(allocator, JSON_MESSAGES[msg_idx]);
        _ = result.toLogEntry();
        const elapsed = timer.read() - start;

        if (elapsed < min_latency) min_latency = elapsed;
        if (elapsed > max_latency) max_latency = elapsed;
    }

    const total_time = timer.read();
    const ops_per_sec = @as(f64, @floatFromInt(iterations)) / (@as(f64, @floatFromInt(total_time)) / 1_000_000_000.0);
    const avg_latency_us = @as(f64, @floatFromInt(total_time)) / @as(f64, @floatFromInt(iterations)) / 1000.0;

    return BenchmarkResult{
        .name = "JSON Parse",
        .iterations = iterations,
        .total_time_ns = total_time,
        .ops_per_sec = ops_per_sec,
        .avg_latency_us = avg_latency_us,
        .min_latency_ns = min_latency,
        .max_latency_ns = max_latency,
    };
}

/// Benchmark for full syslog processing pipeline (parse + insert)
fn runSyslogFullPipelineBenchmark(store: *storage.LogStorage, iterations: u64) !BenchmarkResult {
    var timer = std.time.Timer.start() catch unreachable;
    var min_latency: u64 = std.math.maxInt(u64);
    var max_latency: u64 = 0;

    var i: u64 = 0;
    while (i < iterations) : (i += 1) {
        const msg_idx = i % SYSLOG_MESSAGES.len;
        const start = timer.read();

        // Parse syslog message
        const parsed = try syslog.parseSyslogMessage(SYSLOG_MESSAGES[msg_idx]);
        const entry = parsed.toLogEntry();

        // Insert into storage
        _ = try store.insert(entry);

        const elapsed = timer.read() - start;

        if (elapsed < min_latency) min_latency = elapsed;
        if (elapsed > max_latency) max_latency = elapsed;
    }

    const total_time = timer.read();
    const ops_per_sec = @as(f64, @floatFromInt(iterations)) / (@as(f64, @floatFromInt(total_time)) / 1_000_000_000.0);
    const avg_latency_us = @as(f64, @floatFromInt(total_time)) / @as(f64, @floatFromInt(iterations)) / 1000.0;

    return BenchmarkResult{
        .name = "Syslog Full Pipeline",
        .iterations = iterations,
        .total_time_ns = total_time,
        .ops_per_sec = ops_per_sec,
        .avg_latency_us = avg_latency_us,
        .min_latency_ns = min_latency,
        .max_latency_ns = max_latency,
    };
}

/// Benchmark for full JSON REST API processing pipeline (parse + insert)
fn runJsonFullPipelineBenchmark(allocator: std.mem.Allocator, store: *storage.LogStorage, iterations: u64) !BenchmarkResult {
    var timer = std.time.Timer.start() catch unreachable;
    var min_latency: u64 = std.math.maxInt(u64);
    var max_latency: u64 = 0;

    var i: u64 = 0;
    while (i < iterations) : (i += 1) {
        const msg_idx = i % JSON_MESSAGES.len;
        const start = timer.read();

        // Parse JSON message
        const parsed = try rest_api.parseJsonLog(allocator, JSON_MESSAGES[msg_idx]);
        const entry = parsed.toLogEntry();

        // Insert into storage
        _ = try store.insert(entry);

        const elapsed = timer.read() - start;

        if (elapsed < min_latency) min_latency = elapsed;
        if (elapsed > max_latency) max_latency = elapsed;
    }

    const total_time = timer.read();
    const ops_per_sec = @as(f64, @floatFromInt(iterations)) / (@as(f64, @floatFromInt(total_time)) / 1_000_000_000.0);
    const avg_latency_us = @as(f64, @floatFromInt(total_time)) / @as(f64, @floatFromInt(iterations)) / 1000.0;

    return BenchmarkResult{
        .name = "JSON Full Pipeline",
        .iterations = iterations,
        .total_time_ns = total_time,
        .ops_per_sec = ops_per_sec,
        .avg_latency_us = avg_latency_us,
        .min_latency_ns = min_latency,
        .max_latency_ns = max_latency,
    };
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

    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(allocator);

    const w = buf.writer(allocator);
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

    var results: [7]BenchmarkResult = undefined;

    // =============== Storage Benchmarks ===============
    std.debug.print("═══════════════════════════════════════════════════════════════\n", .{});
    std.debug.print("                    STORAGE BENCHMARKS\n", .{});
    std.debug.print("═══════════════════════════════════════════════════════════════\n\n", .{});

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

    // =============== Message Processing Benchmarks ===============
    std.debug.print("═══════════════════════════════════════════════════════════════\n", .{});
    std.debug.print("                MESSAGE PROCESSING BENCHMARKS\n", .{});
    std.debug.print("═══════════════════════════════════════════════════════════════\n\n", .{});

    // Benchmark 4: Syslog message parsing
    std.debug.print("Benchmark 4: Syslog Message Parsing (100,000 iterations)\n", .{});
    results[3] = try runSyslogParseBenchmark(100_000);
    printResult(results[3]);

    // Benchmark 5: JSON message parsing
    std.debug.print("Benchmark 5: JSON Message Parsing (100,000 iterations)\n", .{});
    results[4] = try runJsonParseBenchmark(allocator, 100_000);
    printResult(results[4]);

    // =============== Full Pipeline Benchmarks ===============
    std.debug.print("═══════════════════════════════════════════════════════════════\n", .{});
    std.debug.print("               FULL PIPELINE BENCHMARKS (Parse + Insert)\n", .{});
    std.debug.print("═══════════════════════════════════════════════════════════════\n\n", .{});

    // Benchmark 6: Full syslog pipeline
    std.debug.print("Benchmark 6: Syslog Full Pipeline (10,000 iterations)\n", .{});
    results[5] = try runSyslogFullPipelineBenchmark(&store, 10_000);
    printResult(results[5]);

    // Benchmark 7: Full JSON REST API pipeline
    std.debug.print("Benchmark 7: JSON Full Pipeline (10,000 iterations)\n", .{});
    results[6] = try runJsonFullPipelineBenchmark(allocator, &store, 10_000);
    printResult(results[6]);

    // Summary
    std.debug.print("═══════════════════════════════════════════════════════════════\n", .{});
    std.debug.print("                        SUMMARY\n", .{});
    std.debug.print("═══════════════════════════════════════════════════════════════\n", .{});

    std.debug.print("\nStorage Operations:\n", .{});
    var buf: [32]u8 = undefined;
    for (results[0..3]) |result| {
        std.debug.print("  {s}: {s} ops/sec\n", .{ result.name, formatNumber(&buf, result.ops_per_sec) });
    }

    std.debug.print("\nMessage Processing:\n", .{});
    for (results[3..5]) |result| {
        std.debug.print("  {s}: {s} ops/sec\n", .{ result.name, formatNumber(&buf, result.ops_per_sec) });
    }

    std.debug.print("\nFull Pipeline (Parse + Insert):\n", .{});
    for (results[5..7]) |result| {
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
