//! Async Log Writer
//! Provides asynchronous, batched database writes for high performance

const std = @import("std");
const storage = @import("storage.zig");
const LogEntry = storage.LogEntry;

pub const WriteQueue = struct {
    queue: std.ArrayList(LogEntry),
    mutex: std.Thread.Mutex,
    storage_ptr: *storage.LogStorage,
    allocator: std.mem.Allocator,
    batch_size: usize,
    flush_interval_ns: u64,
    last_flush: i128,

    const DEFAULT_BATCH_SIZE = 100;
    const DEFAULT_FLUSH_INTERVAL_MS = 1000;

    pub fn init(allocator: std.mem.Allocator, store: *storage.LogStorage) WriteQueue {
        return WriteQueue{
            .queue = std.ArrayList(LogEntry).empty,
            .mutex = std.Thread.Mutex{},
            .storage_ptr = store,
            .allocator = allocator,
            .batch_size = DEFAULT_BATCH_SIZE,
            .flush_interval_ns = DEFAULT_FLUSH_INTERVAL_MS * std.time.ns_per_ms,
            .last_flush = std.time.nanoTimestamp(),
        };
    }

    pub fn deinit(self: *WriteQueue) void {
        // Flush remaining items
        _ = self.forceFlush() catch {};
        self.queue.deinit(self.allocator);
    }

    pub fn setBatchSize(self: *WriteQueue, batch_size: usize) void {
        self.batch_size = batch_size;
    }

    pub fn setFlushInterval(self: *WriteQueue, ms: u64) void {
        self.flush_interval_ns = ms * std.time.ns_per_ms;
    }

    /// Add a log entry to the queue
    pub fn enqueue(self: *WriteQueue, entry: LogEntry) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        try self.queue.append(self.allocator, entry);

        // Check if we should flush
        if (self.queue.items.len >= self.batch_size) {
            _ = try self.flushUnlocked();
        }
    }

    /// Add multiple log entries to the queue
    pub fn enqueueBatch(self: *WriteQueue, entries: []const LogEntry) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (entries) |entry| {
            try self.queue.append(self.allocator, entry);
        }

        // Check if we should flush
        if (self.queue.items.len >= self.batch_size) {
            _ = try self.flushUnlocked();
        }
    }

    /// Check if it's time to flush based on interval
    pub fn shouldFlush(self: *WriteQueue) bool {
        const now = std.time.nanoTimestamp();
        const elapsed = now - self.last_flush;
        return elapsed >= self.flush_interval_ns or self.queue.items.len >= self.batch_size;
    }

    /// Try to flush if conditions are met
    pub fn tryFlush(self: *WriteQueue) !usize {
        if (!self.shouldFlush()) return 0;
        return self.flush();
    }

    /// Flush the queue to storage
    pub fn flush(self: *WriteQueue) !usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.flushUnlocked();
    }

    /// Force flush regardless of conditions
    pub fn forceFlush(self: *WriteQueue) !usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.flushUnlocked();
    }

    fn flushUnlocked(self: *WriteQueue) !usize {
        if (self.queue.items.len == 0) return 0;

        const count = try self.storage_ptr.insertBatch(self.queue.items);
        self.queue.clearRetainingCapacity();
        self.last_flush = std.time.nanoTimestamp();

        return count;
    }

    /// Get current queue size
    pub fn size(self: *WriteQueue) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.queue.items.len;
    }
};

/// Statistics for monitoring
pub const Stats = struct {
    total_received: std.atomic.Value(u64),
    total_written: std.atomic.Value(u64),
    total_errors: std.atomic.Value(u64),
    batch_count: std.atomic.Value(u64),

    pub fn init() Stats {
        return Stats{
            .total_received = std.atomic.Value(u64).init(0),
            .total_written = std.atomic.Value(u64).init(0),
            .total_errors = std.atomic.Value(u64).init(0),
            .batch_count = std.atomic.Value(u64).init(0),
        };
    }

    pub fn recordReceived(self: *Stats, count: u64) void {
        _ = self.total_received.fetchAdd(count, .seq_cst);
    }

    pub fn recordWritten(self: *Stats, count: u64) void {
        _ = self.total_written.fetchAdd(count, .seq_cst);
        _ = self.batch_count.fetchAdd(1, .seq_cst);
    }

    pub fn recordError(self: *Stats) void {
        _ = self.total_errors.fetchAdd(1, .seq_cst);
    }

    pub fn getReceived(self: *Stats) u64 {
        return self.total_received.load(.seq_cst);
    }

    pub fn getWritten(self: *Stats) u64 {
        return self.total_written.load(.seq_cst);
    }

    pub fn getErrors(self: *Stats) u64 {
        return self.total_errors.load(.seq_cst);
    }

    pub fn getBatchCount(self: *Stats) u64 {
        return self.batch_count.load(.seq_cst);
    }
};

test "write queue basic operations" {
    const allocator = std.testing.allocator;
    var store = try storage.LogStorage.initInMemory(allocator);
    defer store.deinit();

    var queue = WriteQueue.init(allocator, &store);
    defer queue.deinit();

    // Set small batch size for testing
    queue.setBatchSize(5);

    // Add entries
    for (0..3) |i| {
        try queue.enqueue(LogEntry{
            .timestamp = std.time.timestamp() + @as(i64, @intCast(i)),
            .level = .info,
            .source = .syslog,
            .host = "test",
            .message = "Test message",
            .raw_data = "raw test data",
        });
    }

    try std.testing.expect(queue.size() == 3);

    // Force flush
    const flushed = try queue.forceFlush();
    try std.testing.expect(flushed == 3);
    try std.testing.expect(queue.size() == 0);

    // Verify in storage
    const count = try store.getLogCount();
    try std.testing.expect(count == 3);
}

test "write queue auto flush on batch size" {
    const allocator = std.testing.allocator;
    var store = try storage.LogStorage.initInMemory(allocator);
    defer store.deinit();

    var queue = WriteQueue.init(allocator, &store);
    defer queue.deinit();

    queue.setBatchSize(5);

    // Add entries to trigger auto flush
    for (0..6) |i| {
        try queue.enqueue(LogEntry{
            .timestamp = std.time.timestamp() + @as(i64, @intCast(i)),
            .level = .info,
            .source = .rest_api,
            .host = "test",
            .message = "Batch test",
            .raw_data = "raw batch data",
        });
    }

    // Queue should have been flushed automatically
    // 5 entries flushed, 1 remaining
    try std.testing.expect(queue.size() == 1);

    // Verify flushed entries in storage
    const count = try store.getLogCount();
    try std.testing.expect(count == 5);
}

test "stats tracking" {
    var stats = Stats.init();

    stats.recordReceived(10);
    stats.recordReceived(5);
    try std.testing.expect(stats.getReceived() == 15);

    stats.recordWritten(8);
    try std.testing.expect(stats.getWritten() == 8);
    try std.testing.expect(stats.getBatchCount() == 1);

    stats.recordError();
    try std.testing.expect(stats.getErrors() == 1);
}
