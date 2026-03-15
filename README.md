# tcpdump-grpc

A gRPC service that provides remote packet capture via tcpdump, designed to run
in a Docker container with defence-in-depth against shell injection and resource
exhaustion.

## Quick Start

```bash
# Generate TLS certs (self-signed, for lab use)
make tls

# Build and run
make docker
docker compose up -d

# Capture HTTP traffic for 30 seconds
./bin/capture-client \
  -server localhost:50051 \
  -filter "tcp port 80" \
  -duration 30 \
  -text \
  -no-resolve
```

## Building

```bash
# Install protobuf tools
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Build everything
make all

# Run tests
make test
```

---

## gRPC API Reference

**Package:** `capture`
**Service:** `CaptureService`
**Default port:** `50051`
**Proto file:** `proto/capture/capture.proto`
**Reflection:** Enabled — tools like `grpcurl` can discover services without the proto file.

The service exposes four RPCs. All accept standard gRPC metadata. When TLS is
enabled on the server, clients must use a TLS channel (use `-insecure` with
grpcurl for self-signed certs).

---

### RPC: `StartCapture`

```protobuf
rpc StartCapture(CaptureRequest) returns (stream CaptureResponse);
```

Begins a packet capture on the server and streams results back to the client.
This is a **server-streaming** RPC — the client sends one request and receives
a stream of response messages until the capture ends.

**The stream terminates when any of these occur (whichever comes first):**

1. The requested `duration_seconds` expires
2. The client cancels the RPC or disconnects
3. The `max_packets` limit is reached
4. An error occurs (invalid interface, permission denied, etc.)

In **all** cases the server kills the underlying tcpdump process (SIGTERM → 2s
grace → SIGKILL). There are no orphaned processes.

#### CaptureRequest

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `bpf_filter` | `string` | `""` (capture all) | BPF filter expression. Standard tcpdump/libpcap syntax. Validated server-side before use. Examples: `"tcp port 80"`, `"host 10.0.0.1 and udp"`, `"net 192.168.1.0/24"`, `"tcp port 443 and host 10.0.0.1"`, `"icmp or icmp6"`, `"vlan 100 and tcp port 22"`. **Max length: 2048 characters.** Shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `{`, `}`, `\`) are rejected as defence-in-depth. |
| `interface` | `string` | `""` (server default, usually first non-lo) | Network interface to capture on. Must match `[a-zA-Z0-9._-]+`. If the server is configured with `-allowed-interfaces`, only those interfaces are permitted. Use `ListInterfaces` to discover available interfaces. |
| `duration_seconds` | `uint32` | Server default (typically `60`) | How long to capture. Hard-capped server-side (typically max `300`). The server will silently clamp values above its maximum. `0` means use the server default. |
| `snap_len` | `uint32` | `65535` (full packet) | Maximum bytes to capture per packet. Maps to tcpdump `-s`. `0` means full packet. Clamped to server max. |
| `max_packets` | `uint64` | `0` (unlimited, duration-bound) | Stop after this many packets. Maps to tcpdump `-c`. `0` means no packet limit (capture runs until duration expires or client disconnects). |
| `text_output` | `bool` | `false` | If `true`, the server decodes packets and streams human-readable text lines (like running `tcpdump` on a terminal). If `false`, the server streams raw pcap binary data suitable for writing to a `.pcap` file or piping to Wireshark. |
| `verbosity` | `uint32` | `0` | Verbosity level for text output mode. `0` = default, `1` = `-v`, `2` = `-vv`, `3` = `-vvv`. Clamped to 3. Only meaningful when `text_output = true`. |
| `no_resolve` | `bool` | `false` | If `true`, don't resolve hostnames (tcpdump `-n`). Recommended for performance and to avoid DNS lookups during capture. |

#### CaptureResponse

Each response message contains exactly one of three payload types, plus a
monotonic sequence number. The stream typically starts with a `status` INFO
message, followed by `pcap_data` or `text_line` messages, and ends with a
final `status` message that includes capture statistics.

| Field | Type | Description |
|-------|------|-------------|
| `pcap_data` | `bytes` | Raw pcap data chunk. Only present when `text_output = false`. Concatenate all chunks in sequence order to produce a valid pcap file. The first chunk contains the pcap file header. |
| `text_line` | `string` | One decoded packet line. Only present when `text_output = true`. Each message is one line of tcpdump text output (timestamp, protocol, addresses, flags, etc.). |
| `status` | `StatusMessage` | Informational, warning, or error message from the server. Always sent at capture start and end. The final status message includes `CaptureStats`. |
| `sequence` | `uint64` | Monotonic sequence number starting at 1. Use for ordering and gap detection. Present on every response message regardless of payload type. |

#### StatusMessage

| Field | Type | Description |
|-------|------|-------------|
| `level` | `enum Level` | `INFO` (0), `WARNING` (1), or `ERROR` (2). |
| `message` | `string` | Human-readable description. Examples: `"starting capture on eth0 (duration: 30s)"`, `"capture complete"`, `"capture terminated (client disconnect or timeout)"`. |
| `stats` | `CaptureStats` | Populated only on the **final** status message of a capture. `null`/absent on non-final messages. |

#### CaptureStats

| Field | Type | Description |
|-------|------|-------------|
| `packets_captured` | `uint64` | Total packets captured by tcpdump. |
| `packets_dropped` | `uint64` | Packets dropped by kernel (from tcpdump stderr stats). |
| `duration_seconds` | `double` | Actual wall-clock capture duration in seconds. |
| `bytes_captured` | `uint64` | Total bytes of capture data streamed to the client. |

#### Stream Message Order

```
┌──────────────────────────────────────────────────────────────┐
│ seq=1  status  INFO   "starting capture on eth0 (dur: 30s)"  │
│ seq=2  text_line/pcap_data  ...                              │
│ seq=3  text_line/pcap_data  ...                              │
│ ...    ...                                                   │
│ seq=N  status  INFO   "capture complete"  {stats: {...}}     │
│ ── stream closes ──                                          │
└──────────────────────────────────────────────────────────────┘
```

If the client disconnects or cancels mid-stream, the final status message is
best-effort (the server sends it, but the client may not receive it). The
tcpdump process is always killed regardless.

#### gRPC Error Codes

| Code | Condition |
|------|-----------|
| `INVALID_ARGUMENT` | BPF filter failed static validation or compilation; interface name invalid or not in allowlist. |
| `RESOURCE_EXHAUSTED` | Max concurrent captures reached (global or per-IP). |
| `INTERNAL` | tcpdump failed to start or exited with an unexpected error. |

#### Example: grpcurl (text mode)

```bash
grpcurl -plaintext -d '{
  "bpf_filter": "tcp port 443",
  "interface": "eth0",
  "duration_seconds": 10,
  "text_output": true,
  "no_resolve": true,
  "verbosity": 1
}' localhost:50051 capture.CaptureService/StartCapture
```

#### Example: grpcurl (validate only)

```bash
grpcurl -plaintext -d '{
  "bpf_filter": "tcp port 80 and host 10.0.0.1"
}' localhost:50051 capture.CaptureService/ValidateFilter
```

#### Example: Go client (text mode)

```go
conn, _ := grpc.NewClient("localhost:50051",
    grpc.WithTransportCredentials(insecure.NewCredentials()))
defer conn.Close()

client := pb.NewCaptureServiceClient(conn)

stream, err := client.StartCapture(ctx, &pb.CaptureRequest{
    BpfFilter:       "tcp port 80",
    Interface:       "eth0",
    DurationSeconds: 30,
    TextOutput:      true,
    NoResolve:       true,
})
if err != nil {
    log.Fatal(err)
}

for {
    resp, err := stream.Recv()
    if err == io.EOF {
        break
    }
    if err != nil {
        log.Fatal(err)
    }
    switch p := resp.Payload.(type) {
    case *pb.CaptureResponse_TextLine:
        fmt.Println(p.TextLine)
    case *pb.CaptureResponse_Status:
        fmt.Fprintf(os.Stderr, "[%s] %s\n", p.Status.Level, p.Status.Message)
        if p.Status.Stats != nil {
            fmt.Fprintf(os.Stderr, "  captured=%d dropped=%d\n",
                p.Status.Stats.PacketsCaptured,
                p.Status.Stats.PacketsDropped)
        }
    }
}
```

#### Example: Go client (pcap binary to file)

```go
stream, _ := client.StartCapture(ctx, &pb.CaptureRequest{
    BpfFilter:       "udp port 53",
    DurationSeconds: 15,
    TextOutput:      false,   // raw pcap
    NoResolve:       true,
})

f, _ := os.Create("dns.pcap")
defer f.Close()

for {
    resp, err := stream.Recv()
    if err == io.EOF { break }
    if err != nil { log.Fatal(err) }

    if p, ok := resp.Payload.(*pb.CaptureResponse_PcapData); ok {
        f.Write(p.PcapData)
    }
}
// dns.pcap is now a valid pcap file openable by Wireshark/tcpdump
```

#### Example: Python client

```python
import grpc
import capture_pb2
import capture_pb2_grpc

channel = grpc.insecure_channel("localhost:50051")
stub = capture_pb2_grpc.CaptureServiceStub(channel)

request = capture_pb2.CaptureRequest(
    bpf_filter="tcp port 80 and host 10.0.0.1",
    interface="eth0",
    duration_seconds=30,
    text_output=True,
    no_resolve=True,
    verbosity=1,
)

for response in stub.StartCapture(request):
    payload = response.WhichOneof("payload")
    if payload == "text_line":
        print(response.text_line)
    elif payload == "status":
        print(f"[{response.status.level}] {response.status.message}")
        if response.status.stats:
            s = response.status.stats
            print(f"  captured={s.packets_captured} dropped={s.packets_dropped}")
    elif payload == "pcap_data":
        # write response.pcap_data to a file
        pass
```

#### Stopping a capture early

To stop a capture before `duration_seconds` expires, **cancel the RPC context**.
In Go, call the `cancel()` function from `context.WithCancel`. In Python, call
`cancel()` on the RPC future or iterate and break. In grpcurl, press Ctrl-C.
The server detects the broken stream and immediately kills the tcpdump process.

---

### RPC: `ValidateFilter`

```protobuf
rpc ValidateFilter(ValidateFilterRequest) returns (ValidateFilterResponse);
```

Checks whether a BPF filter expression is syntactically valid **without starting
a capture**. Useful for pre-validating user input in a UI before committing to
a capture session.

The validation performs two checks:
1. **Static analysis** — length, disallowed characters, null bytes, newlines
2. **tcpdump compilation** — runs `tcpdump -d <filter>` to compile the filter
   to BPF bytecode and checks for errors

#### ValidateFilterRequest

| Field | Type | Description |
|-------|------|-------------|
| `bpf_filter` | `string` | The BPF filter expression to validate. |

#### ValidateFilterResponse

| Field | Type | Description |
|-------|------|-------------|
| `valid` | `bool` | `true` if the filter is syntactically valid and compiles. |
| `error` | `string` | Empty when `valid = true`. When `valid = false`, contains a human-readable error message from either the static checker or tcpdump's compiler. |

#### Examples

```bash
# Valid filter
grpcurl -plaintext -d '{"bpf_filter": "tcp port 80"}' \
  localhost:50051 capture.CaptureService/ValidateFilter
# → {"valid": true}

# Invalid filter (bad syntax)
grpcurl -plaintext -d '{"bpf_filter": "tcp port"}' \
  localhost:50051 capture.CaptureService/ValidateFilter
# → {"valid": false, "error": "invalid BPF filter: ..."}

# Rejected filter (shell metacharacter)
grpcurl -plaintext -d '{"bpf_filter": "tcp port 80; rm -rf /"}' \
  localhost:50051 capture.CaptureService/ValidateFilter
# → {"valid": false, "error": "filter contains disallowed characters; ..."}

# Empty filter (valid — means capture everything)
grpcurl -plaintext -d '{"bpf_filter": ""}' \
  localhost:50051 capture.CaptureService/ValidateFilter
# → {"valid": true}
```

---

### RPC: `ListInterfaces`

```protobuf
rpc ListInterfaces(ListInterfacesRequest) returns (ListInterfacesResponse);
```

Returns the network interfaces visible to the server (i.e., inside the
container). Use this to discover what `interface` values to pass to
`StartCapture`. When the container runs with `network_mode: host`, this
returns the host's interfaces.

#### ListInterfacesRequest

Empty message — no fields.

#### ListInterfacesResponse

| Field | Type | Description |
|-------|------|-------------|
| `interfaces` | `repeated NetworkInterface` | List of network interfaces. |

#### NetworkInterface

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | Interface name (e.g., `"eth0"`, `"ens192"`, `"lo"`, `"br0"`). This is the value to pass as `interface` in `CaptureRequest`. |
| `description` | `string` | Human-readable description (may be empty). |
| `addresses` | `repeated string` | IP addresses assigned to this interface in CIDR notation (e.g., `"10.0.0.1/24"`, `"fe80::1/64"`). |
| `up` | `bool` | `true` if the interface is administratively up. You can capture on down interfaces but will see no traffic. |

#### Example

```bash
grpcurl -plaintext localhost:50051 capture.CaptureService/ListInterfaces
```

```json
{
  "interfaces": [
    {
      "name": "lo",
      "addresses": ["127.0.0.1/8", "::1/128"],
      "up": true
    },
    {
      "name": "eth0",
      "addresses": ["10.0.0.5/24", "fe80::a00:27ff:fe4e:66a1/64"],
      "up": true
    },
    {
      "name": "docker0",
      "addresses": ["172.17.0.1/16"],
      "up": true
    }
  ]
}
```

---

### RPC: `GetProcNetStats`

```protobuf
rpc GetProcNetStats(ProcNetStatsRequest) returns (ProcNetStatsResponse);
```

Returns the contents of `/proc/net` pseudo-files from the server (i.e., inside
the container) for network diagnostics. This is a **unary** RPC — one request,
one response containing all requested files.

When the container runs with `network_mode: host` or shares a network namespace
with another container, the stats reflect that namespace's network stack.

#### ProcNetStatsRequest

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `files` | `repeated string` | `[]` (all known files) | Specific `/proc/net` file names to read (e.g., `"dev"`, `"tcp"`, `"snmp"`). If empty, all known stat files are returned. File names are relative to `/proc/net` — do not include the path prefix. |

#### ProcNetStatsResponse

| Field | Type | Description |
|-------|------|-------------|
| `entries` | `repeated ProcNetFile` | One entry per requested file, sorted alphabetically by name. |

#### ProcNetFile

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | File name relative to `/proc/net` (e.g., `"dev"`, `"snmp"`, `"tcp6"`). |
| `content` | `string` | Raw text content of the file. Empty if the file could not be read. |
| `error` | `string` | Error message if the file could not be read (e.g., permission denied, file not found). Empty on success. |

#### Available Files

When no `files` are specified, the following 27 files are returned by default:

| File | Description |
|------|-------------|
| `dev` | Per-interface RX/TX bytes, packets, errors, drops, FIFO, frame, compressed, multicast counters |
| `tcp` | IPv4 TCP connection table (local/remote addr, state, queues, timers, retransmits) |
| `tcp6` | IPv6 TCP connection table |
| `udp` | IPv4 UDP socket table |
| `udp6` | IPv6 UDP socket table |
| `snmp` | IPv4 SNMP counters (Ip, Icmp, IcmpMsg, Tcp, Udp, UdpLite protocol statistics) |
| `snmp6` | IPv6 SNMP counters |
| `netstat` | Extended TCP/IP statistics (TcpExt, IpExt, MPTcpExt — retransmits, SACKs, listen overflows, etc.) |
| `sockstat` | IPv4 socket allocation summary (TCP/UDP/RAW inuse + memory) |
| `sockstat6` | IPv6 socket allocation summary |
| `softnet_stat` | Per-CPU packet processing statistics (processed, dropped, time_squeeze) |
| `route` | IPv4 routing table |
| `arp` | ARP cache |
| `icmp` | ICMP socket table |
| `icmp6` | ICMPv6 socket table |
| `igmp` | IGMP group memberships |
| `igmp6` | IGMPv6 group memberships |
| `raw` | IPv4 RAW socket table |
| `raw6` | IPv6 RAW socket table |
| `unix` | Unix domain socket table |
| `protocols` | Registered network protocols |
| `netlink` | Netlink socket table |
| `packet` | AF_PACKET socket table |
| `ptype` | Registered protocol handlers |
| `psched` | Packet scheduler clock parameters |
| `xfrm_stat` | IPsec/XFRM transformation statistics |
| `fib_triestat` | Routing trie (FIB) statistics |

You can also request any other file under `/proc/net` by name, even if it's not
in the default set. Directory traversal attempts (e.g., `"../cpuinfo"`) are
rejected.

#### Example: grpcurl (all stats)

```bash
grpcurl -plaintext -d '{}' \
  localhost:50051 capture.CaptureService/GetProcNetStats
```

#### Example: grpcurl (specific files)

```bash
grpcurl -plaintext -d '{
  "files": ["dev", "snmp", "tcp", "netstat", "sockstat"]
}' localhost:50051 capture.CaptureService/GetProcNetStats
```

#### Example: Go client

```go
resp, err := client.GetProcNetStats(ctx, &pb.ProcNetStatsRequest{
    Files: []string{"dev", "snmp", "netstat"},
})
if err != nil {
    log.Fatal(err)
}
for _, entry := range resp.Entries {
    if entry.Error != "" {
        fmt.Fprintf(os.Stderr, "/proc/net/%s: %s\n", entry.Name, entry.Error)
        continue
    }
    fmt.Printf("=== /proc/net/%s ===\n%s\n", entry.Name, entry.Content)
}
```

#### Example: Python client

```python
response = stub.GetProcNetStats(capture_pb2.ProcNetStatsRequest(
    files=["dev", "snmp", "tcp", "netstat"],
))
for entry in response.entries:
    if entry.error:
        print(f"/proc/net/{entry.name}: ERROR: {entry.error}")
    else:
        print(f"=== /proc/net/{entry.name} ===")
        print(entry.content)
```

---

## Common BPF Filter Patterns

These are standard tcpdump/libpcap filter expressions. The `bpf_filter` field
accepts any valid expression that `tcpdump` itself would accept.

| Pattern | Description |
|---------|-------------|
| `""` (empty) | Capture all traffic |
| `"tcp port 80"` | HTTP traffic |
| `"tcp port 443"` | HTTPS traffic |
| `"udp port 53"` | DNS traffic |
| `"host 10.0.0.1"` | All traffic to/from a specific host |
| `"src host 10.0.0.1"` | Traffic originating from a host |
| `"dst host 10.0.0.1"` | Traffic destined for a host |
| `"net 192.168.1.0/24"` | Traffic to/from a subnet |
| `"tcp port 80 and host 10.0.0.1"` | HTTP from a specific host |
| `"icmp or icmp6"` | Ping / ICMPv6 |
| `"tcp[tcpflags] & (tcp-syn) != 0"` | TCP SYN packets only |
| `"tcp[tcpflags] & (tcp-rst) != 0"` | TCP RST packets only |
| `"vlan 100"` | VLAN-tagged traffic |
| `"arp"` | ARP traffic |
| `"not port 22"` | Everything except SSH |
| `"portrange 8000-9000"` | Port range |
| `"greater 1000"` | Packets larger than 1000 bytes |
| `"ether host aa:bb:cc:dd:ee:ff"` | Traffic to/from a MAC address |
| `"ip6"` | IPv6 traffic only |
| `"tcp port 179"` | BGP traffic |
| `"udp port 4789"` | VXLAN traffic |
| `"proto gre"` | GRE tunneled traffic |
| `"esp or ah"` | IPsec traffic |

---

## Server Configuration

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-listen` | `:50051` | gRPC listen address (`host:port` or `:port`). |
| `-tls-cert` | `""` | Path to TLS certificate file. If empty, TLS is disabled. |
| `-tls-key` | `""` | Path to TLS private key file. |
| `-max-duration` | `300` | Hard maximum capture duration in seconds. Client requests above this are silently clamped. |
| `-default-duration` | `60` | Duration used when client sends `duration_seconds = 0`. |
| `-max-concurrent` | `10` | Maximum total concurrent captures across all clients. |
| `-rate-per-ip` | `3` | Maximum concurrent captures per client IP address. |
| `-tcpdump-path` | `/usr/bin/tcpdump` | Absolute path to the tcpdump binary. |
| `-allowed-interfaces` | `""` | Comma-separated allowlist of interface names. Empty means all interfaces are allowed. |
| `-log-json` | `false` | Emit structured JSON logs instead of text. |

---

## Process Lifecycle

The capture engine carefully manages the tcpdump process:

1. **Validate** — static filter check + `tcpdump -d` compilation
2. **Start** — `exec.Command` with discrete arguments (no shell)
3. **Monitor** — context tracks both client connection and duration timeout
4. **Stream** — stdout piped to gRPC stream (text lines or pcap chunks)
5. **Terminate on disconnect** — when the gRPC stream context is cancelled
   (client disconnect, client cancel, or timeout), SIGTERM is sent to the
   tcpdump process group
6. **Force kill** — if tcpdump doesn't exit within 2 seconds of SIGTERM,
   SIGKILL is sent to the process group
7. **Stats** — stderr is parsed for tcpdump's summary statistics

```
Client connects
  └─► Validate filter (static + compile)
       └─► Start tcpdump (exec.Command, no shell)
            └─► Stream output to client
                 └─► Context cancelled? ──► SIGTERM ──► (2s) ──► SIGKILL
                      (disconnect/timeout/cancel)
```

---

## Security Model

### 1. No Shell Invocation

The **most important** security measure: `exec.Command()` is used directly with
the filter as a discrete argument. tcpdump's own expression parser handles the
BPF filter—**no shell is ever involved**. This makes traditional shell injection
(`; rm -rf /`, `$(command)`, `` `backtick` ``) structurally impossible.

### 2. Static Filter Validation

Before any tcpdump process is spawned, the filter string is checked for:
length limits (2048 chars max), null bytes, newline characters, and shell
metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `{`, `}`, `\`, etc.).
This is defence-in-depth—even without this layer, injection wouldn't work
because there's no shell.

### 3. BPF Compilation Check

The filter is compiled via `tcpdump -d <filter>` before the actual capture
starts. This catches BPF syntax errors early.

### 4. Interface Name Validation

Interface names are restricted to `[a-zA-Z0-9._-]` and optionally constrained
to an explicit allowlist via `-allowed-interfaces`.

### 5. Container Hardening

Non-root user, `CAP_NET_RAW` only (all others dropped), read-only root
filesystem, CPU and memory resource limits. `CAP_NET_RAW` is granted to the
tcpdump binary via file capabilities (`setcap`), not to the user.

### 6. Rate Limiting

Global concurrent capture limit plus per-IP concurrent capture limit, both
configurable. Duration is hard-capped server-side regardless of what the client
requests.

---

## Docker Compose

The provided `docker-compose.yml` uses `network_mode: service:iperf3-local` so
the capture container shares the network namespace of the iperf3 service. This
means captures see the same interfaces, IPs, and `/proc/net` stats as the
iperf3 container. To capture on host interfaces instead, change to
`network_mode: host`.

## TLS

For production, use proper certificates from your PKI or ACME/Let's Encrypt.
`make tls` generates self-signed P-256 ECDSA certs for development:

```bash
make tls
# Creates tls/server.crt and tls/server.key
```

To run without TLS (dev only):

```bash
# Server
tcpdump-grpc -listen :50051

# Client
capture-client -server localhost:50051 -filter "tcp port 80" -text
```

## MCP Server (Model Context Protocol)

An MCP server (`cmd/mcp-server`) bridges the gRPC backend to the
[Model Context Protocol](https://modelcontextprotocol.io/), letting AI
assistants (Claude Code, Cursor, Windsurf, or any MCP client) capture packets,
validate filters, inspect interfaces, and read kernel network stats — all
through natural language.

See [`docs/AGENT.md`](docs/AGENT.md) for the full agent-consumable tool
reference that AI systems can use to understand available capabilities.

### Quick Setup

**1. Extract the binary from the Docker image:**

```bash
docker cp tcpdump-grpc:/usr/local/bin/mcp-server ./bin/mcp-server
```

Or build locally:

```bash
make build   # produces bin/mcp-server
```

**2. Configure your MCP client:**

Claude Code (`~/.claude/claude_code_config.json`):

```json
{
  "mcpServers": {
    "tcpdump": {
      "command": "/path/to/bin/mcp-server",
      "args": ["-server", "172.16.80.200:50051", "-insecure"]
    }
  }
}
```

VS Code / Cursor (`.vscode/mcp.json`):

```json
{
  "servers": {
    "tcpdump": {
      "command": "/path/to/bin/mcp-server",
      "args": ["-server", "172.16.80.200:50051", "-insecure"]
    }
  }
}
```

**3. Start using it:**

> "Capture TCP port 443 traffic on eth0 for 5 seconds"
> "Save a pcap of DNS traffic to /tmp/dns.pcap"
> "Show me /proc/net/dev and /proc/net/snmp counters"
> "List the network interfaces on the capture server"

### MCP Server Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-server` | `localhost:50051` | gRPC server address |
| `-tls` | `false` | Use TLS to connect to gRPC server |
| `-insecure` | `false` | Skip TLS certificate verification (self-signed certs) |
| `-max-lines` | `500` | Maximum text lines to return from a capture |

### MCP Tools

| Tool | Output | Description |
|------|--------|-------------|
| `capture` | Text | Capture packets and return decoded text lines with stats. Duration clamped to 60s. |
| `capture_pcap` | File | Capture packets and write raw pcap to a file. Returns path and stats. |
| `validate_filter` | Text | Check if a BPF filter compiles without starting a capture. |
| `list_interfaces` | Text | List network interfaces with addresses and up/down state. |
| `proc_net_stats` | Text | Read `/proc/net` pseudo-files (dev, tcp, snmp, netstat, etc.). |

---

## CLI Client

A reference client is included at `cmd/capture-client/main.go`:

```bash
# Text output with verbose decoding
capture-client -filter "host 10.0.0.1" -text -verbosity 2 -duration 60

# Binary pcap to file
capture-client -filter "port 53" -text=false -write dns.pcap -duration 30

# Validate a filter without capturing
capture-client -validate -filter "tcp port 80 and net 10.0.0.0/8"

# List available interfaces
capture-client -list-interfaces

# Dump all /proc/net stats from the server
capture-client -proc-net-stats

# Dump specific /proc/net files only
capture-client -proc-net-stats -proc-net-files "dev,snmp,tcp,netstat,sockstat"

# With TLS
capture-client -tls -tls-ca ca.crt -server myhost:50051 -filter "tcp port 80" -text
```
