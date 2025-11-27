//! zlogd - High Performance Log Collection System
//! A log collection and storage server implemented in Zig
//!
//! Features:
//! - SYSLOG receiver (UDP port 514)
//! - RESTful API (HTTP port 8080)
//! - SNMP trap receiver (UDP port 162)
//! - SQLite3 storage with WAL mode
//! - Async batched writes for high performance

const std = @import("std");
pub const sqlite = @import("sqlite.zig");
pub const storage = @import("storage.zig");
pub const syslog = @import("syslog.zig");
pub const rest_api = @import("rest_api.zig");
pub const snmp = @import("snmp.zig");
pub const writer = @import("writer.zig");

pub const LogEntry = storage.LogEntry;
pub const LogLevel = storage.LogLevel;
pub const LogSource = storage.LogSource;
pub const LogStorage = storage.LogStorage;
pub const WriteQueue = writer.WriteQueue;
pub const Stats = writer.Stats;

/// Configuration for zlogd
pub const Config = struct {
    db_path: [:0]const u8 = "logs.db",
    syslog_port: u16 = 514,
    rest_port: u16 = 8080,
    snmp_port: u16 = 162,
    batch_size: usize = 100,
    flush_interval_ms: u64 = 1000,
    enable_syslog: bool = true,
    enable_rest: bool = true,
    enable_snmp: bool = true,
};

/// Main server structure
pub const Server = struct {
    config: Config,
    storage_inst: LogStorage,
    write_queue: ?WriteQueue,
    stats: Stats,
    syslog_server: ?syslog.SyslogServer,
    rest_server: ?rest_api.RestApiServer,
    snmp_server: ?snmp.SnmpServer,
    allocator: std.mem.Allocator,
    running: std.atomic.Value(bool),

    pub fn init(allocator: std.mem.Allocator, config: Config) !Server {
        const store = try LogStorage.init(allocator, config.db_path);
        errdefer store.deinit();

        return Server{
            .config = config,
            .storage_inst = store,
            // write_queue is initialized in start() with correct pointer to storage_inst
            .write_queue = null,
            .stats = Stats.init(),
            .syslog_server = null,
            .rest_server = null,
            .snmp_server = null,
            .allocator = allocator,
            .running = std.atomic.Value(bool).init(false),
        };
    }

    pub fn deinit(self: *Server) void {
        self.stop();
        if (self.write_queue) |*wq| {
            wq.deinit();
        }
        self.storage_inst.deinit();
    }

    pub fn start(self: *Server) !void {
        self.running.store(true, .seq_cst);

        // Initialize write queue with correct pointer to storage_inst
        // (must be done after Server is in its final memory location)
        self.write_queue = WriteQueue.init(self.allocator, &self.storage_inst);
        self.write_queue.?.setBatchSize(self.config.batch_size);
        self.write_queue.?.setFlushInterval(self.config.flush_interval_ms);

        // Initialize servers
        if (self.config.enable_syslog) {
            self.syslog_server = try syslog.SyslogServer.init(
                self.allocator,
                self.config.syslog_port,
                &self.storage_inst,
            );
            try self.syslog_server.?.startUDP();
            std.log.info("Syslog server started on port {}", .{self.config.syslog_port});
        }

        if (self.config.enable_rest) {
            self.rest_server = rest_api.RestApiServer.init(
                self.allocator,
                self.config.rest_port,
                &self.storage_inst,
            );
            try self.rest_server.?.start();
            std.log.info("REST API server started on port {}", .{self.config.rest_port});
        }

        if (self.config.enable_snmp) {
            self.snmp_server = try snmp.SnmpServer.init(
                self.allocator,
                self.config.snmp_port,
                &self.storage_inst,
            );
            // Note: SNMP port 162 requires root privileges
            self.snmp_server.?.start() catch |err| {
                std.log.warn("Failed to start SNMP server: {}", .{err});
                if (self.snmp_server) |*srv| {
                    srv.deinit();
                }
                self.snmp_server = null;
            };
            if (self.snmp_server != null) {
                std.log.info("SNMP trap server started on port {}", .{self.config.snmp_port});
            }
        }
    }

    pub fn stop(self: *Server) void {
        self.running.store(false, .seq_cst);

        if (self.syslog_server) |*srv| {
            srv.deinit();
            self.syslog_server = null;
        }
        if (self.rest_server) |*srv| {
            srv.deinit();
            self.rest_server = null;
        }
        if (self.snmp_server) |*srv| {
            srv.deinit();
            self.snmp_server = null;
        }
    }

    pub fn isRunning(self: *Server) bool {
        return self.running.load(.seq_cst);
    }

    /// Process one iteration of all servers
    pub fn poll(self: *Server) !void {
        // Process syslog
        if (self.syslog_server) |*srv| {
            if (try srv.receiveOne()) |entry| {
                try self.write_queue.?.enqueue(entry);
                self.stats.recordReceived(1);
            }
        }

        // Process REST API
        if (self.rest_server) |*srv| {
            srv.acceptAndHandle() catch {};
        }

        // Process SNMP
        if (self.snmp_server) |*srv| {
            if (try srv.receiveOne()) |entry| {
                try self.write_queue.?.enqueue(entry);
                self.stats.recordReceived(1);
            }
        }

        // Try to flush write queue
        const flushed = try self.write_queue.?.tryFlush();
        if (flushed > 0) {
            self.stats.recordWritten(flushed);
        }
    }

    /// Get current statistics
    pub fn getStats(self: *Server) struct {
        received: u64,
        written: u64,
        errors: u64,
        queued: usize,
        batches: u64,
    } {
        return .{
            .received = self.stats.getReceived(),
            .written = self.stats.getWritten(),
            .errors = self.stats.getErrors(),
            .queued = if (self.write_queue) |*wq| wq.size() else 0,
            .batches = self.stats.getBatchCount(),
        };
    }
};

fn printUsage() void {
    const usage =
        \\zlogd - High Performance Log Collection System
        \\
        \\Usage: zlogd [options]
        \\
        \\Options:
        \\  -d, --database <path>   SQLite database path (default: logs.db)
        \\  --syslog-port <port>    Syslog UDP port (default: 514)
        \\  --rest-port <port>      REST API HTTP port (default: 8080)
        \\  --snmp-port <port>      SNMP trap UDP port (default: 162)
        \\  --batch-size <n>        Write batch size (default: 100)
        \\  --no-syslog             Disable syslog receiver
        \\  --no-rest               Disable REST API
        \\  --no-snmp               Disable SNMP trap receiver
        \\  -h, --help              Show this help
        \\
        \\Signals:
        \\  SIGINT, SIGTERM         Graceful shutdown
        \\
    ;
    std.debug.print("{s}", .{usage});
}

fn parseArgs(allocator: std.mem.Allocator) !Config {
    _ = allocator;
    var config = Config{};

    var args = std.process.args();
    _ = args.skip(); // Skip program name

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printUsage();
            std.process.exit(0);
        } else if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--database")) {
            if (args.next()) |path| {
                config.db_path = path;
            }
        } else if (std.mem.eql(u8, arg, "--syslog-port")) {
            if (args.next()) |port_str| {
                config.syslog_port = std.fmt.parseInt(u16, port_str, 10) catch 514;
            }
        } else if (std.mem.eql(u8, arg, "--rest-port")) {
            if (args.next()) |port_str| {
                config.rest_port = std.fmt.parseInt(u16, port_str, 10) catch 8080;
            }
        } else if (std.mem.eql(u8, arg, "--snmp-port")) {
            if (args.next()) |port_str| {
                config.snmp_port = std.fmt.parseInt(u16, port_str, 10) catch 162;
            }
        } else if (std.mem.eql(u8, arg, "--batch-size")) {
            if (args.next()) |size_str| {
                config.batch_size = std.fmt.parseInt(usize, size_str, 10) catch 100;
            }
        } else if (std.mem.eql(u8, arg, "--no-syslog")) {
            config.enable_syslog = false;
        } else if (std.mem.eql(u8, arg, "--no-rest")) {
            config.enable_rest = false;
        } else if (std.mem.eql(u8, arg, "--no-snmp")) {
            config.enable_snmp = false;
        }
    }

    return config;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = try parseArgs(allocator);

    std.log.info("Starting zlogd log collection server...", .{});
    std.log.info("Database: {s}", .{config.db_path});

    var server = try Server.init(allocator, config);
    defer server.deinit();

    try server.start();

    std.log.info("Server is running. Press Ctrl+C to stop.", .{});

    // Main loop
    var last_stats_time = std.time.milliTimestamp();
    while (server.isRunning()) {
        try server.poll();

        // Print stats every 10 seconds
        const now = std.time.milliTimestamp();
        if (now - last_stats_time >= 10000) {
            const stats = server.getStats();
            std.log.info("Stats: received={}, written={}, queued={}, batches={}, errors={}", .{
                stats.received,
                stats.written,
                stats.queued,
                stats.batches,
                stats.errors,
            });
            last_stats_time = now;
        }

        // Small sleep to prevent busy loop
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }

    std.log.info("Shutting down...", .{});
}

// Run all module tests
test {
    _ = sqlite;
    _ = storage;
    _ = syslog;
    _ = rest_api;
    _ = snmp;
    _ = writer;
}
