# tcpdump-grpc MCP Tool Reference

> This document is designed to be consumed by AI agents and LLMs. It describes
> every MCP tool exposed by tcpdump-grpc, including parameters, return formats,
> error handling, and recommended workflows.

## Overview

tcpdump-grpc provides remote packet capture and network diagnostics via 5 MCP
tools. The MCP server connects to a gRPC backend running inside a Docker
container that has access to the target network namespace.

**Transport:** MCP JSON-RPC over stdio
**Backend:** gRPC (TLS or plaintext)

---

## Tools

### `capture`

Capture network packets and return decoded text output (like running `tcpdump`
on a terminal). Use this when you want to inspect packet contents inline.

**When to use:** Debugging connectivity issues, inspecting protocol behavior,
checking what traffic is flowing on an interface, verifying firewall rules.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `bpf_filter` | string | no | `""` (all traffic) | BPF filter expression. See [BPF Filter Reference](#bpf-filter-reference) below. |
| `interface` | string | no | server default | Network interface name. Use `list_interfaces` to discover valid names. |
| `duration_seconds` | number | no | `10` | How long to capture. Clamped to 60s max for MCP use. |
| `max_packets` | number | no | `0` (unlimited) | Stop after N packets. Useful to limit output size. |
| `verbosity` | number | no | `1` | Decode detail: 0=minimal, 1=normal (-v), 2=detailed (-vv), 3=maximum (-vvv). |
| `no_resolve` | boolean | no | `true` | Skip DNS resolution. Keep `true` for faster captures. |

**Returns:** Text block containing one decoded packet per line, followed by
capture statistics (packets captured, dropped, bytes, duration).

**Output format:**
```
2026-03-15 10:30:01.123456 IP 10.0.0.1.443 > 10.0.0.2.54321: Flags [P.], seq 1:100, ack 1, win 65535, length 99
2026-03-15 10:30:01.123789 IP 10.0.0.2.54321 > 10.0.0.1.443: Flags [.], ack 100, win 65535, length 0
...

--- Capture Stats ---
Packets captured: 42
Packets dropped:  0
Bytes captured:   12345
Duration:         10.0s
```

**If no packets match:** Returns "No packets captured matching the filter."

**If output is large:** Truncated at 500 lines (configurable via `-max-lines`
server flag) with a `--- output truncated at 500 lines ---` marker.

**Tips:**
- Always use a BPF filter to avoid capturing all traffic (noisy, slow).
- Start with short durations (5-10s) and increase if needed.
- Use `max_packets` (e.g., 50) for quick checks.
- Use `verbosity: 2` to see TCP options, TTL, IP ID, etc.
- Set `no_resolve: true` (default) to avoid DNS lookups during capture.

---

### `capture_pcap`

Capture packets and write raw pcap binary data to a file on disk. The file
is a standard pcap format readable by Wireshark, tcpdump, tshark, and any
libpcap-compatible tool.

**When to use:** When the user needs a pcap file for offline analysis, when
captures are too large for inline text, or when binary-level packet inspection
is needed.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `bpf_filter` | string | no | `""` (all traffic) | BPF filter expression. |
| `interface` | string | no | server default | Network interface name. |
| `duration_seconds` | number | no | `10` | How long to capture. Max 300s (server limit). |
| `snap_len` | number | no | `0` (65535, full) | Max bytes per packet. Use 96 for headers only. |
| `max_packets` | number | no | `0` (unlimited) | Stop after N packets. |
| `output_file` | string | no | `/tmp/capture-<timestamp>.pcap` | Where to write the pcap file. |
| `no_resolve` | boolean | no | `true` | Skip DNS resolution. |

**Returns:** Text summary with file path, size, capture stats, and commands
to open the file.

**Output format:**
```
Pcap written to: /tmp/capture-20260315-103001.pcap
File size: 54321 bytes

--- Capture Stats ---
Packets captured: 42
Packets dropped:  0
Bytes captured:   54321
Duration:         10.0s

Open with: tcpdump -r /tmp/capture-20260315-103001.pcap
     or:   tshark -r /tmp/capture-20260315-103001.pcap
     or:   wireshark /tmp/capture-20260315-103001.pcap
```

**Tips:**
- No duration clamp — pcap files can run the full 300s server max.
- Use `snap_len: 96` to capture only headers (saves disk, good for flow analysis).
- The file path is on the machine running the MCP server, not the capture server.

---

### `validate_filter`

Check whether a BPF filter expression is syntactically valid and compiles
without starting any capture. Use this before `capture` or `capture_pcap`
to catch errors early.

**When to use:** Before running a capture with a complex filter, or when the
user asks if a filter syntax is correct.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `bpf_filter` | string | **yes** | — | The BPF filter expression to validate. |

**Returns:**

- Valid: `Filter "tcp port 80" is valid.`
- Invalid syntax: `Filter "tcp port" is invalid: invalid BPF filter: ...`
- Rejected characters: `Filter "tcp port 80; rm -rf /" is invalid: filter contains disallowed characters; ...`

**Tips:**
- Empty string is technically valid (means "capture all").
- Shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `{`, `}`, `\`) are rejected.
- The filter is compiled by the server's tcpdump binary, so results match
  exactly what `capture` and `capture_pcap` will accept.

---

### `list_interfaces`

List all network interfaces visible to the capture server, including their
IP addresses and up/down state.

**When to use:** To discover what `interface` value to pass to `capture` or
`capture_pcap`. Always call this first if you don't know the interface name.

**Parameters:** None.

**Returns:** Table of interfaces with name, state, and addresses.

**Output format:**
```
lo                   UP     127.0.0.1/8, ::1/128
eth0                 UP     172.16.80.200/24, 2001:559:8585:80::200/64
```

**Tips:**
- The interfaces shown are from the container's network namespace.
- If the container uses `network_mode: service:iperf3-local` or
  `network_mode: host`, interfaces reflect that namespace.
- Only capture on interfaces marked `UP` — `DOWN` interfaces will yield
  no traffic.

---

### `proc_net_stats`

Read `/proc/net` pseudo-files from the capture server's kernel for network
diagnostics. These files contain counters, connection tables, routing info,
and protocol statistics.

**When to use:** Diagnosing packet drops, retransmits, socket exhaustion,
routing issues, ARP problems, or general network health.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `files` | string[] | no | all 27 known files | Specific file names to read. See table below. |

**Available files and what they tell you:**

| File | Use when investigating... |
|------|--------------------------|
| `dev` | Interface-level RX/TX bytes, packets, errors, drops, FIFO overruns |
| `tcp` | IPv4 TCP connections: local/remote addresses, state, queue depths, timers |
| `tcp6` | IPv6 TCP connections (same columns as tcp) |
| `udp` | IPv4 UDP sockets: local/remote addresses, queue depths, drops |
| `udp6` | IPv6 UDP sockets |
| `snmp` | Protocol-level counters: IP forwarding/errors, ICMP types, TCP segments/retransmits, UDP datagrams |
| `snmp6` | IPv6 protocol counters |
| `netstat` | Extended TCP stats: TcpExt (retransmits, SACKs, listen overflows, OFO, fast retransmit), IpExt, MPTcpExt |
| `sockstat` | Socket allocation summary: TCP/UDP/RAW inuse count and memory usage |
| `sockstat6` | IPv6 socket summary |
| `softnet_stat` | Per-CPU packet processing: packets processed, dropped, time_squeeze (CPU budget exhaustion) |
| `route` | IPv4 kernel routing table |
| `arp` | ARP cache (IP-to-MAC mappings) |
| `icmp` | ICMP socket table |
| `icmp6` | ICMPv6 socket table |
| `igmp` | IGMP group memberships |
| `igmp6` | IGMPv6 group memberships |
| `raw` | IPv4 raw sockets |
| `raw6` | IPv6 raw sockets |
| `unix` | Unix domain sockets |
| `protocols` | Registered kernel network protocols |
| `netlink` | Netlink sockets |
| `packet` | AF_PACKET sockets (raw capture sockets) |
| `ptype` | Registered protocol handlers |
| `psched` | Packet scheduler clock parameters |
| `xfrm_stat` | IPsec/XFRM transformation stats |
| `fib_triestat` | Routing trie (FIB) stats |

**Returns:** Each file's contents prefixed with `=== /proc/net/<name> ===`.
Files that cannot be read include an `ERROR:` line.

**Output format:**
```
=== /proc/net/dev ===
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1234567    5678    0    0    0     0          0         0  1234567    5678    0    0    0     0       0          0
  eth0: 9876543   12345    0    0    0     0          0       100  5432100    8765    0    0    0     0       0          0

=== /proc/net/snmp ===
Ip: Forwarding DefaultTTL InReceives ...
Ip: 1 64 123456 ...
...
```

**Recommended file sets for common tasks:**

| Task | Files |
|------|-------|
| Quick health check | `["dev", "sockstat", "snmp"]` |
| TCP debugging | `["tcp", "netstat", "snmp", "sockstat"]` |
| Drop investigation | `["dev", "softnet_stat", "snmp", "netstat"]` |
| Routing issues | `["route", "arp", "dev"]` |
| Connection audit | `["tcp", "tcp6", "udp", "udp6"]` |
| Full diagnostic | `[]` (empty = all files) |

**Tips:**
- Request only the files you need — returning all 27 files produces a lot of
  output.
- `dev` + `snmp` + `netstat` covers most debugging scenarios.
- Call twice with a delay between to compute rates (packets/sec, errors/sec).
- `softnet_stat` is per-CPU and useful for diagnosing NIC ring buffer overflows.

---

## BPF Filter Reference

BPF (Berkeley Packet Filter) expressions are the standard tcpdump/libpcap
filter syntax. Common patterns:

| Pattern | Matches |
|---------|---------|
| `tcp port 80` | HTTP traffic |
| `tcp port 443` | HTTPS/TLS traffic |
| `udp port 53` | DNS queries and responses |
| `host 10.0.0.1` | All traffic to/from an IP |
| `src host 10.0.0.1` | Traffic originating from an IP |
| `dst host 10.0.0.1` | Traffic destined for an IP |
| `net 192.168.1.0/24` | Traffic to/from a subnet |
| `tcp port 80 and host 10.0.0.1` | HTTP from a specific host |
| `icmp or icmp6` | Ping and ICMPv6 |
| `tcp[tcpflags] & (tcp-syn) != 0` | TCP SYN packets (new connections) |
| `tcp[tcpflags] & (tcp-rst) != 0` | TCP RST packets (connection resets) |
| `tcp[tcpflags] & (tcp-fin) != 0` | TCP FIN packets (connection close) |
| `vlan 100` | VLAN 100 tagged traffic |
| `arp` | ARP requests and replies |
| `not port 22` | Everything except SSH |
| `portrange 8000-9000` | Port range |
| `greater 1000` | Packets larger than 1000 bytes |
| `less 100` | Packets smaller than 100 bytes |
| `ether host aa:bb:cc:dd:ee:ff` | Traffic to/from a MAC address |
| `ip6` | IPv6 only |
| `tcp port 179` | BGP |
| `udp port 4789` | VXLAN |
| `proto gre` | GRE tunnels |
| `esp or ah` | IPsec |

**Combining filters:**
- `and` / `&&` — both conditions must match
- `or` / `||` — either condition matches
- `not` / `!` — negate a condition
- `()` — grouping (note: parentheses are **not** allowed through the MCP
  sanitizer; use `and`/`or`/`not` keywords instead)

**Restrictions:**
- Max 2048 characters
- No shell metacharacters: `;`, `&`, `|`, `` ` ``, `$`, `{`, `}`, `\`, `>`, `<`
- No null bytes or newlines
- Use `validate_filter` to check before capturing

---

## Recommended Workflows

### Workflow: Diagnose connectivity to a host

1. `list_interfaces` — find the right interface
2. `validate_filter` with `"host <target_ip>"` — verify filter
3. `capture` with the filter, 10s duration, verbosity 1 — see traffic flow
4. If no packets: `proc_net_stats` with `["route", "arp"]` — check routing/ARP
5. If packets but errors: `proc_net_stats` with `["netstat", "snmp"]` — check retransmits/drops

### Workflow: Investigate packet drops

1. `proc_net_stats` with `["dev", "softnet_stat", "snmp", "netstat"]`
2. Look for non-zero values in:
   - `dev`: drop, errs, fifo columns
   - `softnet_stat`: dropped (column 2), time_squeeze (column 3)
   - `snmp` Tcp line: RetransSegs
   - `netstat` TcpExt: TCPRetransFail, ListenOverflows, ListenDrops
3. If drops found: `capture` with targeted filter to see affected traffic

### Workflow: Capture traffic for offline analysis

1. `list_interfaces` — identify the interface
2. `validate_filter` — verify filter syntax
3. `capture_pcap` with desired filter, duration, and output path
4. Report the file path to the user for Wireshark/tshark analysis

### Workflow: Audit active connections

1. `proc_net_stats` with `["tcp", "tcp6", "udp", "udp6", "sockstat"]`
2. Parse connection tables for unexpected remote addresses or states
3. If suspicious: `capture` targeting the specific host/port

### Workflow: Check network interface health

1. `list_interfaces` — see all interfaces and their IPs
2. `proc_net_stats` with `["dev"]` — get per-interface error/drop counters
3. If issues found: `capture` on the affected interface to see traffic patterns

---

## Error Handling

Tools return errors in two forms:

1. **Tool-level errors** (in the result text): Invalid filter, interface not
   found, rate limit exceeded, capture server unreachable. The AI should
   explain the error and suggest a fix.

2. **gRPC error codes** from the backend:
   - `INVALID_ARGUMENT` — bad filter or interface name. Fix the input.
   - `RESOURCE_EXHAUSTED` — too many concurrent captures. Wait and retry.
   - `INTERNAL` — tcpdump failed. Check interface exists and is up.
   - `UNAVAILABLE` — gRPC server is down. Check if the container is running.

---

## Limits

| Limit | Value | Configurable |
|-------|-------|:------------:|
| Max capture duration (MCP text) | 60s | No (hardcoded in MCP server) |
| Max capture duration (MCP pcap) | 300s | Yes (server `-max-duration`) |
| Max text lines returned | 500 | Yes (MCP server `-max-lines`) |
| Max BPF filter length | 2048 chars | No |
| Max concurrent captures (global) | 10 | Yes (server `-max-concurrent`) |
| Max concurrent captures per IP | 3 | Yes (server `-rate-per-ip`) |
| Max snap length | 65535 bytes | No |
