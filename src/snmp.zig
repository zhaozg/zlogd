//! SNMP Trap Receiver
//! Receives SNMP trap messages and converts them to log entries

const std = @import("std");
const net = std.net;
const storage = @import("storage.zig");
const LogEntry = storage.LogEntry;
const LogLevel = storage.LogLevel;
const LogSource = storage.LogSource;

pub const SnmpError = error{
    InvalidPacket,
    InvalidVersion,
    InvalidPdu,
    BufferTooSmall,
    InvalidAsn1,
};

/// ASN.1 BER tag types
const Asn1Tag = struct {
    pub const BOOLEAN = 0x01;
    pub const INTEGER = 0x02;
    pub const BIT_STRING = 0x03;
    pub const OCTET_STRING = 0x04;
    pub const NULL = 0x05;
    pub const OBJECT_IDENTIFIER = 0x06;
    pub const SEQUENCE = 0x30;
    pub const IP_ADDRESS = 0x40;
    pub const COUNTER = 0x41;
    pub const GAUGE = 0x42;
    pub const TIMETICKS = 0x43;
    pub const OPAQUE = 0x44;
    pub const COUNTER64 = 0x46;

    // PDU types
    pub const GET_REQUEST = 0xA0;
    pub const GET_NEXT_REQUEST = 0xA1;
    pub const GET_RESPONSE = 0xA2;
    pub const SET_REQUEST = 0xA3;
    pub const TRAP_V1 = 0xA4;
    pub const GET_BULK_REQUEST = 0xA5;
    pub const INFORM_REQUEST = 0xA6;
    pub const TRAP_V2 = 0xA7;
};

/// SNMP versions
pub const SnmpVersion = enum(u8) {
    v1 = 0,
    v2c = 1,
    v3 = 3,
};

/// SNMP Trap message structure
pub const SnmpTrap = struct {
    version: SnmpVersion,
    community: []const u8,
    enterprise_oid: ?[]const u8,
    agent_addr: ?[4]u8,
    generic_trap: ?u8,
    specific_trap: ?u32,
    timestamp: ?u32,
    varbinds: []const VarBind,
    raw_data: []const u8,

    pub fn toLogEntry(self: SnmpTrap, allocator: std.mem.Allocator) !LogEntry {
        // Build message from varbinds
        var msg_buf = std.ArrayList(u8).init(allocator);
        defer msg_buf.deinit();

        const writer = msg_buf.writer();

        if (self.generic_trap) |gt| {
            try writer.print("Trap Type: {} ", .{gt});
        }
        if (self.specific_trap) |st| {
            try writer.print("Specific: {} ", .{st});
        }

        for (self.varbinds) |vb| {
            try writer.print("[{s}={s}] ", .{ vb.oid, vb.value });
        }

        const message = try msg_buf.toOwnedSlice();
        errdefer allocator.free(message);

        // Format agent address as host
        var host_buf: [16]u8 = undefined;
        const host = if (self.agent_addr) |addr|
            std.fmt.bufPrint(&host_buf, "{}.{}.{}.{}", .{ addr[0], addr[1], addr[2], addr[3] }) catch "unknown"
        else
            "unknown";

        // Duplicate host string for storage
        const host_dup = try allocator.dupe(u8, host);

        return LogEntry{
            .timestamp = if (self.timestamp) |ts| @divTrunc(@as(i64, ts), 100) + std.time.timestamp() else std.time.timestamp(),
            .level = .notice,
            .source = .snmp,
            .host = host_dup,
            .app_name = "snmptrapd",
            .message = message,
            .raw_data = self.raw_data,
        };
    }
};

/// SNMP Variable Binding
pub const VarBind = struct {
    oid: []const u8,
    value: []const u8,
};

/// Parse ASN.1 BER length
fn parseAsn1Length(data: []const u8) SnmpError!struct { len: usize, bytes: usize } {
    if (data.len == 0) return SnmpError.InvalidAsn1;

    const first = data[0];
    if (first < 0x80) {
        return .{ .len = first, .bytes = 1 };
    }

    const num_octets = first & 0x7F;
    if (num_octets == 0 or num_octets > 4 or data.len < num_octets + 1) {
        return SnmpError.InvalidAsn1;
    }

    var len: usize = 0;
    for (1..num_octets + 1) |i| {
        len = (len << 8) | data[i];
    }

    return .{ .len = len, .bytes = num_octets + 1 };
}

/// Parse ASN.1 integer
fn parseAsn1Integer(data: []const u8) SnmpError!struct { value: i64, consumed: usize } {
    if (data.len < 2 or data[0] != Asn1Tag.INTEGER) {
        return SnmpError.InvalidAsn1;
    }

    const len_info = try parseAsn1Length(data[1..]);
    const start = 1 + len_info.bytes;
    const end = start + len_info.len;

    if (end > data.len) return SnmpError.InvalidAsn1;

    var value: i64 = 0;
    const bytes = data[start..end];

    // Handle signed integers
    if (bytes.len > 0 and bytes[0] >= 0x80) {
        value = -1;
    }

    for (bytes) |b| {
        value = (value << 8) | b;
    }

    return .{ .value = value, .consumed = end };
}

/// Parse ASN.1 octet string
fn parseAsn1OctetString(data: []const u8) SnmpError!struct { value: []const u8, consumed: usize } {
    if (data.len < 2 or data[0] != Asn1Tag.OCTET_STRING) {
        return SnmpError.InvalidAsn1;
    }

    const len_info = try parseAsn1Length(data[1..]);
    const start = 1 + len_info.bytes;
    const end = start + len_info.len;

    if (end > data.len) return SnmpError.InvalidAsn1;

    return .{ .value = data[start..end], .consumed = end };
}

/// Parse ASN.1 sequence
fn parseAsn1Sequence(data: []const u8) SnmpError!struct { content: []const u8, consumed: usize } {
    if (data.len < 2 or data[0] != Asn1Tag.SEQUENCE) {
        return SnmpError.InvalidAsn1;
    }

    const len_info = try parseAsn1Length(data[1..]);
    const start = 1 + len_info.bytes;
    const end = start + len_info.len;

    if (end > data.len) return SnmpError.InvalidAsn1;

    return .{ .content = data[start..end], .consumed = end };
}

/// Parse OID to string representation
fn parseOidToString(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    if (data.len < 2) return allocator.dupe(u8, "");

    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    const writer = result.writer();

    // First two components are encoded in first byte
    const first = data[0];
    try writer.print("{}.{}", .{ first / 40, first % 40 });

    // Parse remaining components
    var i: usize = 1;
    while (i < data.len) {
        var component: u32 = 0;
        while (i < data.len) {
            const b = data[i];
            i += 1;
            component = (component << 7) | (b & 0x7F);
            if (b < 0x80) break;
        }
        try writer.print(".{}", .{component});
    }

    return result.toOwnedSlice();
}

/// Parse SNMP trap packet
pub fn parseSnmpTrap(allocator: std.mem.Allocator, data: []const u8) !SnmpTrap {
    var varbinds_list = std.ArrayList(VarBind).init(allocator);
    errdefer varbinds_list.deinit();

    // Parse outer sequence
    const seq = try parseAsn1Sequence(data);

    // Parse version
    const ver = try parseAsn1Integer(seq.content);
    const version: SnmpVersion = switch (ver.value) {
        0 => .v1,
        1 => .v2c,
        3 => .v3,
        else => return SnmpError.InvalidVersion,
    };

    // Parse community string
    const remaining = seq.content[ver.consumed..];
    const community = try parseAsn1OctetString(remaining);

    var trap = SnmpTrap{
        .version = version,
        .community = community.value,
        .enterprise_oid = null,
        .agent_addr = null,
        .generic_trap = null,
        .specific_trap = null,
        .timestamp = null,
        .varbinds = &[_]VarBind{},
        .raw_data = data,
    };

    // Parse PDU - simplified for SNMPv2c traps
    const pdu_data = remaining[community.consumed..];
    if (pdu_data.len < 2) return trap;

    const pdu_type = pdu_data[0];
    if (pdu_type != Asn1Tag.TRAP_V2 and pdu_type != Asn1Tag.TRAP_V1) {
        return trap;
    }

    // For v1 traps, parse additional fields
    if (pdu_type == Asn1Tag.TRAP_V1 and pdu_data.len > 10) {
        // Simplified parsing - just extract basic info
        trap.generic_trap = 6; // Enterprise specific
    }

    // Return parsed trap
    trap.varbinds = try varbinds_list.toOwnedSlice();
    return trap;
}

/// SNMP Trap Receiver Server
pub const SnmpServer = struct {
    socket: ?std.posix.socket_t,
    port: u16,
    running: std.atomic.Value(bool),
    storage_ptr: *storage.LogStorage,
    allocator: std.mem.Allocator,
    recv_buffer: []u8,

    const BUFFER_SIZE = 65536;
    const DEFAULT_PORT = 162;

    pub fn init(allocator: std.mem.Allocator, port: u16, store: *storage.LogStorage) !SnmpServer {
        const buffer = try allocator.alloc(u8, BUFFER_SIZE);
        errdefer allocator.free(buffer);

        return SnmpServer{
            .socket = null,
            .port = port,
            .running = std.atomic.Value(bool).init(false),
            .storage_ptr = store,
            .allocator = allocator,
            .recv_buffer = buffer,
        };
    }

    pub fn deinit(self: *SnmpServer) void {
        self.stop();
        self.allocator.free(self.recv_buffer);
    }

    pub fn start(self: *SnmpServer) !void {
        const address = net.Address.initIp4(.{ 0, 0, 0, 0 }, self.port);
        const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
        errdefer std.posix.close(sock);

        // Allow binding to privileged ports if running as root
        const reuse: c_int = 1;
        try std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&reuse));

        try std.posix.bind(sock, &address.any, @sizeOf(@TypeOf(address.in)));
        self.socket = sock;
        self.running.store(true, .seq_cst);
    }

    pub fn receiveOne(self: *SnmpServer) !?LogEntry {
        if (self.socket == null) return null;

        var src_addr: std.posix.sockaddr = undefined;
        var addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);

        const len = std.posix.recvfrom(
            self.socket.?,
            self.recv_buffer,
            0,
            &src_addr,
            &addr_len,
        ) catch |err| {
            if (err == error.WouldBlock) return null;
            return err;
        };

        if (len == 0) return null;

        const trap = parseSnmpTrap(self.allocator, self.recv_buffer[0..len]) catch return null;

        return try trap.toLogEntry(self.allocator);
    }

    pub fn stop(self: *SnmpServer) void {
        self.running.store(false, .seq_cst);
        if (self.socket) |sock| {
            std.posix.close(sock);
            self.socket = null;
        }
    }
};

test "parse ASN.1 length short form" {
    const data = [_]u8{ 0x05, 0x01, 0x02, 0x03, 0x04, 0x05 };
    const result = try parseAsn1Length(&data);
    try std.testing.expect(result.len == 5);
    try std.testing.expect(result.bytes == 1);
}

test "parse ASN.1 length long form" {
    const data = [_]u8{ 0x82, 0x01, 0x00 };
    const result = try parseAsn1Length(&data);
    try std.testing.expect(result.len == 256);
    try std.testing.expect(result.bytes == 3);
}

test "parse ASN.1 integer" {
    const data = [_]u8{ 0x02, 0x01, 0x05 };
    const result = try parseAsn1Integer(&data);
    try std.testing.expect(result.value == 5);
}

test "parse ASN.1 octet string" {
    const data = [_]u8{ 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c' };
    const result = try parseAsn1OctetString(&data);
    try std.testing.expectEqualStrings("public", result.value);
}
