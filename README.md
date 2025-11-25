# zlogd

A high-performance log collection and storage server implemented in Zig.

## Features

- **SYSLOG receiver** (UDP port 514) - Supports RFC 3164 (BSD) syslog format
- **RESTful API** (HTTP port 8080) - JSON-based log submission
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
    raw_data TEXT,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Indexes for common queries
CREATE INDEX idx_logs_timestamp ON logs(timestamp);
CREATE INDEX idx_logs_level ON logs(level);
CREATE INDEX idx_logs_source ON logs(source);
CREATE INDEX idx_logs_host ON logs(host);
CREATE INDEX idx_logs_app_name ON logs(app_name);
```

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
