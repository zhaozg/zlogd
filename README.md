# zlogd

[![CI](https://github.com/zhaozg/zlogd/actions/workflows/ci.yml/badge.svg)](https://github.com/zhaozg/zlogd/actions/workflows/ci.yml)

A high-performance log collection and storage server implemented in Zig.

## Features

- **SYSLOG receiver** (UDP port 514) - Supports RFC 3164 (BSD) syslog format
- **RESTful API** (HTTP port 8080) - JSON-based log submission via [http.zig](https://github.com/karlseguin/http.zig)
- **SNMP trap receiver** (UDP port 162) - SNMP v1/v2c trap messages
- **SQLite3 storage** - WAL mode for high-performance concurrent writes
- **Async batched writes** - Configurable batch size and flush intervals
- **Performance optimized** - Designed for high-throughput log ingestion

## Building

### Prerequisites

- Zig compiler (0.15.0+)
- SQLite3 development libraries

### Ubuntu/Debian
```bash
sudo apt-get install libsqlite3-dev
```

### Build
```bash
zig build
```

### Run tests
```bash
zig build test
```

### Build optimized release
```bash
zig build -Doptimize=ReleaseFast
```

### Run performance benchmark
```bash
zig build -Doptimize=ReleaseFast
./zig-out/bin/zlogd-bench
```

## Technical Implementation

### Database Layer - zdbc Integration

The storage layer uses [zdbc](https://github.com/zhaozg/zdbc) for type-safe database operations:

**Key Features:**
- **Parameterized queries**: All database operations use `zdbc.Value` for parameter binding, preventing SQL injection
- **Transaction-based batching**: Batch inserts are wrapped in transactions for ACID guarantees and performance
- **Connection abstraction**: Clean abstraction over SQLite with potential for other backends
- **Prepared statement reuse**: zdbc automatically manages prepared statements for efficiency

**Example batch insert with zdbc:**
```zig
try conn.begin();
errdefer conn.rollback() catch {};

for (entries) |entry| {
    _ = try conn.exec(INSERT_SQL, &.{
        zdbc.Value.initInt(entry.timestamp),
        zdbc.Value.initText(entry.host),
        zdbc.Value.initBlob(entry.raw_data),
        // ... more parameters
    });
}

try conn.commit();
```

**Performance optimizations:**
- WAL (Write-Ahead Logging) mode enabled for concurrent writes
- Batch size tuning for optimal throughput vs latency trade-off
- Mutex-protected HMAC chain for secure tamper detection
- Cached next-ID prediction to avoid extra queries

## Performance Baseline

Benchmark results in ReleaseFast mode with zdbc (in-memory SQLite):

### Storage Operations (zdbc implementation)

| Operation | Ops/sec | Avg Latency | Effective Throughput |
|-----------|---------|-------------|----------------------|
| Single Insert | ~86,000 | ~11.6 µs | 86K entries/sec |
| Batch Insert x10 | ~11,000 | ~91 µs | **110K entries/sec** |
| Batch Insert x100 | ~1,200 | ~829 µs | **121K entries/sec** |

### Message Processing

| Operation | Ops/sec | Avg Latency |
|-----------|---------|-------------|
| Syslog Parse | ~9,100,000 | ~0.11 µs |
| JSON Parse | ~2,300,000 | ~0.44 µs |

### Full Pipeline (Parse + Insert)

| Operation | Ops/sec | Avg Latency |
|-----------|---------|-------------|
| Syslog Full Pipeline | ~76,800 | ~13.0 µs |
| JSON Full Pipeline | ~76,300 | ~13.1 µs |

**Key observations:**
- **Batch x100 provides best throughput**: 121K entries/second effective rate
- Batching provides significant throughput improvements (40% boost over single inserts)
- Message parsing is extremely fast (~9M syslog / ~2M JSON ops/sec)
- Full pipeline throughput limited by storage, not parsing
- Using **zdbc with parameterized queries and transactions** for safety and performance

**Performance optimization notes:**
- Transaction-wrapped batch inserts provide optimal throughput
- HMAC chain computation adds security with minimal overhead (~1-2 µs per entry)
- WAL mode enabled for better concurrent write performance
- Parameterized queries prevent SQL injection while maintaining speed


## Usage

```bash
# Start with default settings
./zig-out/bin/zlogd

# Custom configuration
./zig-out/bin/zlogd --database /var/log/zlogd.db --rest-port 9090 --batch-size 200

# Disable specific receivers
./zig-out/bin/zlogd --no-snmp --no-syslog
```

### Command Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `-d, --database` | logs.db | SQLite database file path |
| `--syslog-port` | 514 | UDP port for syslog receiver |
| `--rest-port` | 8080 | HTTP port for REST API |
| `--snmp-port` | 162 | UDP port for SNMP trap receiver |
| `--batch-size` | 100 | Number of logs to batch before writing |
| `--no-syslog` | - | Disable syslog receiver |
| `--no-rest` | - | Disable REST API |
| `--no-snmp` | - | Disable SNMP trap receiver |
| `-h, --help` | - | Show help message |

## API Reference

### REST API

#### Submit a log entry
```bash
POST /api/logs
Content-Type: application/json

{
  "message": "Application started",
  "level": "info",
  "host": "server1",
  "app_name": "myapp",
  "timestamp": 1700000000
}
```

Response:
```json
{
  "id": 1,
  "status": "created"
}
```

#### Get log count
```bash
GET /api/logs
```

Response:
```json
{
  "count": 42
}
```

#### Health check
```bash
GET /health
```

Response:
```json
{
  "status": "ok"
}
```

### Syslog (RFC 3164)

Send logs via UDP:
```bash
echo "<134>Jan 15 12:34:56 myhost myapp[1234]: Test message" | nc -u localhost 514
```

## Database Schema

```sql
CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    level INTEGER NOT NULL,
    source INTEGER NOT NULL,
    host TEXT NOT NULL,
    facility INTEGER,
    app_name TEXT,
    proc_id TEXT,
    msg_id TEXT,
    message TEXT NOT NULL,
    raw_data BLOB NOT NULL,
    hmac BLOB NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Indexes for common queries
CREATE INDEX idx_logs_timestamp ON logs(timestamp);
CREATE INDEX idx_logs_level ON logs(level);
CREATE INDEX idx_logs_source ON logs(source);
CREATE INDEX idx_logs_host ON logs(host);
CREATE INDEX idx_logs_app_name ON logs(app_name);
```

### Data Integrity (HMAC)

Each log entry includes a chain-based HMAC for tamper detection:
- `raw_data`: Required BLOB field containing the original binary message data
- `hmac`: Required 32-byte BLOB field storing SHA-256 based chain digest

The HMAC is computed using: `current_hmac = SHA256(raw_data || id) XOR previous_hmac`

This chain algorithm ensures:
1. **Tamper detection**: Any modification to a log entry will invalidate its HMAC
2. **Deletion detection**: Removing any entry breaks the chain
3. **Order verification**: The chain validates the sequence of entries

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Syslog    │     │  REST API   │     │    SNMP     │
│  Receiver   │     │   Server    │     │  Receiver   │
│  (UDP 514)  │     │ (HTTP 8080) │     │  (UDP 162)  │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
                    ┌──────▼──────┐
                    │   Write     │
                    │   Queue     │
                    │  (Batched)  │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  SQLite3    │
                    │ (WAL Mode)  │
                    └─────────────┘
```

## Performance

- **Batched writes**: Logs are buffered and written in batches to reduce I/O
- **WAL mode**: SQLite Write-Ahead Logging for concurrent read/write
- **Thread-safe**: All components use proper synchronization
- **Memory efficient**: Reuses buffers where possible

## Log Levels

| Level | Code | Description |
|-------|------|-------------|
| emergency | 0 | System is unusable |
| alert | 1 | Action must be taken immediately |
| critical | 2 | Critical conditions |
| error | 3 | Error conditions |
| warning | 4 | Warning conditions |
| notice | 5 | Normal but significant |
| info | 6 | Informational messages |
| debug | 7 | Debug-level messages |

## Log Sources

| Source | Code | Description |
|--------|------|-------------|
| syslog | 0 | SYSLOG UDP receiver |
| rest_api | 1 | REST API HTTP endpoint |
| snmp | 2 | SNMP trap receiver |

## License

MIT
