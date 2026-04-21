# MCP Pcapy-ng

MCP server exposing pcapy-ng packet capture functionality.

## When to use this skill

Use this skill when you need to:
- Capture network packets
- Read pcap files
- List network interfaces
- Apply BPF filters

## Tools

- `findalldevs` - List all network interfaces
- `lookupdev` - Get default device
- `open_live` - Open interface for live capture
- `open_offline` - Open pcap file
- `create` - Create pcap handle
- `compile` - Create BPF filter
- `pcap_read` - Read packets
- `pcap_datalink` - Get data link type
- `pcap_setfilter` - Attach filter
- `get_dlt_names`, `get_pcap_directions`, `get_constants`

## Install

```bash
pip install mcp-pcapy-ng
```