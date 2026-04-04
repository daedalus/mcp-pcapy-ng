# SPEC.md — mcp-pcapy-ng

## Purpose

This project creates an MCP (Model Context Protocol) server that exposes all functionality of the pcapy-ng library for packet capture. It allows MCP clients to interact with network interfaces, capture packets, read pcap files, and compile BPF filters programmatically.

## Scope

### What IS in Scope

- All module-level functions from pcapy-ng: `open_live`, `open_offline`, `findalldevs`, `lookupdev`, `create`, `compile`
- PcapReader class methods for reading packets from live interfaces or files
- BPFProgram class for compiled filter programs
- All DLT (Data Link Type) constants
- All PCAP direction constants
- PcapError and BPFError exception handling

### What is NOT in Scope

- Actual packet writing (send functionality)
- Packet modification
- Network interface configuration
- Raw socket operations outside of pcapy-ng

## Public API / Interface

### MCP Tools

All tools are exposed via FastMCP with stdio transport.

#### Network Interface Tools

1. **`findalldevs`** - Lists all available network interfaces
   - Returns: List of interface dictionaries with name, description, addresses, flags
   - Raises: PcapError on failure

2. **`lookupdev`** - Gets the default network device
   - Returns: String device name
   - Raises: PcapError if no default device found

3. **`open_live`** - Opens a live network interface for packet capture
   - Args:
     - `device` (str): Network device name
     - `snaplen` (int): Maximum number of bytes to capture per packet (default: 65535)
     - `promisc` (bool): Put interface in promiscuous mode (default: True)
     - `to_ms` (int): Read timeout in milliseconds (default: 1000)
   - Returns: PcapReader object
   - Raises: PcapError on failure

4. **`create`** - Creates a packet capture handle (for later activation)
   - Args:
     - `device` (str): Network device name
   - Returns: PcapReader object
   - Raises: PcapError on failure

#### File Operations

5. **`open_offline`** - Opens a pcap file for reading
   - Args:
     - `filename` (str): Path to pcap file
   - Returns: PcapReader object
   - Raises: PcapError on failure

#### BPF Filter Tools

6. **`compile`** - Creates a BPF program for packet filtering
   - Args:
     - `linktype` (int): DLT link type (e.g., DLT_EN10MB=1 for Ethernet)
     - `snaplen` (int): Snapshot length
     - `filter` (str): BPF filter expression (e.g., "tcp and port 80")
     - `optimize` (bool): Optimize the filter (default: True)
     - `netmask` (int): Netmask for the filter (default: 0xFFFFFFFF)
   - Returns: BPFProgram object
   - Raises: BPFError on invalid filter

#### PcapReader Methods (available on opened pcap objects)

7. **`pcap_read`** - Read packets from a pcap handle
   - Args:
     - `pcap_reader`: PcapReader object from open_live or open_offline
     - `count` (int): Maximum number of packets to read (default: 1)
   - Returns: List of tuples (timestamp, raw_packet_data)

8. **`pcap_datalink`** - Get the data link type
   - Args:
     - `pcap_reader`: PcapReader object
   - Returns: Integer DLT value

9. **`pcap_setfilter`** - Attach a compiled BPF filter
   - Args:
     - `pcap_reader`: PcapReader object
     - `bpf_program`: BPFProgram object
   - Raises: PcapError on failure

10. **`pcap_getnonblock`** - Get non-blocking status
    - Args:
      - `pcap_reader`: PcapReader object
    - Returns: Boolean

11. **`pcap_setnonblock`** - Set non-blocking mode
    - Args:
      - `pcap_reader`: PcapReader object
      - `nonblock` (bool): True for non-blocking mode
    - Returns: Boolean

#### Constants (exposed as utilities)

12. **`get_dlt_names`** - Get mapping of DLT constants to names
13. **`get_pcap_directions`** - Get mapping of direction constants to names
14. **`get_pcap_error`** - Get error message from PcapError

### Constants Exposed

| Constant | Value | Description |
|----------|-------|-------------|
| DLT_ARCNET | 7 | ARCnet |
| DLT_ATM_RFC1483 | 8 | ATM RFC1483 |
| DLT_C_HDLC | 104 | Cisco HDLC |
| DLT_EN10MB | 1 | Ethernet (10Mb) |
| DLT_FDDI | 10 | FDDI |
| DLT_IEEE802 | 6 | IEEE 802 |
| DLT_IEEE802_11 | 105 | IEEE 802.11 |
| DLT_LINUX_SLL | 113 | Linux cooked capture |
| DLT_LOOP | 12 | OpenBSD loopback |
| DLT_LTALK | 104 | Apple LocalTalk |
| DLT_NULL | 0 | Null/loopback |
| DLT_PPP | 2 | PPP |
| DLT_PPP_ETHER | 3 | PPP over Ethernet |
| DLT_PPP_SERIAL | 50 | PPP over serial |
| DLT_RAW | 12 | Raw IP |
| DLT_SLIP | 16 | SLIP |
| PCAP_D_IN | 1 | Incoming packets |
| PCAP_D_INOUT | 0 | Both directions |
| PCAP_D_OUT | 2 | Outgoing packets |

## Data Formats

### Interface Dictionary
```python
{
    "name": "eth0",
    "description": "Ethernet device",
    "addresses": [{"family": "AF_INET", "addr": "192.168.1.1", "netmask": "255.255.255.0"}],
    "flags": ["PCAP_IF_UP", "PCAP_IF_RUNNING"]
}
```

### Packet Tuple
```python
(timestamp_unix_float, raw_packet_bytes)
```

### BPF Expression Examples
- `"tcp"` - All TCP packets
- `"tcp and port 80"` - HTTP traffic
- `"udp and port 53"` - DNS traffic
- `"icmp"` - Ping packets
- `"host 192.168.1.1"` - Traffic to/from specific host

## Edge Cases

1. **No network interfaces available** - `findalldevs` returns empty list
2. **Permission denied for live capture** - Raise PcapError with clear message
3. **Invalid pcap file** - Raise PcapError with file error details
4. **Invalid BPF filter** - Raise BPFError with parse error details
5. **Device not found** - Raise PcapError with device name
6. **Read timeout** - Return empty list (not an error)
7. **Non-existent file for offline reading** - Raise PcapError
8. **Empty filter string** - Raise BPFError

## Performance & Constraints

- Live capture requires root/elevated privileges
- Packet capture is blocking by default; use setnonblock for async handling
- BPF filter compilation is lightweight (< 1ms typically)
- Maximum snaplen: 65535 bytes (pcap limitation)

## MCP Server Configuration

- **Transport**: stdio
- **Package name**: mcp-pcapy-ng
- **mcp-name**: io.github.daedalus/mcp-pcapy-ng
