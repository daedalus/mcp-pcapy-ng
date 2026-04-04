# mcp-pcapy-ng

MCP server exposing pcapy-ng packet capture functionality.

[![PyPI](https://img.shields.io/pypi/v/mcp-pcapy-ng.svg)](https://pypi.org/project/mcp-pcapy-ng/)
[![Python](https://img.shields.io/pypi/pyversions/mcp-pcapy-ng.svg)](https://pypi.org/project/mcp-pcapy-ng/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

mcp-name: io.github.daedalus/mcp-pcapy-ng

## Install

```bash
pip install mcp-pcapy-ng
```

## Usage

The MCP server provides tools for network packet capture using pcapy-ng:

```python
from mcp_pcapy_ng import mcp
mcp.run()
```

Or via command line:

```bash
mcp-pcapy-ng
```

## Available Tools

- `findalldevs` - List all available network interfaces
- `lookupdev` - Get the default network device
- `open_live` - Open a live network interface for packet capture
- `open_offline` - Open a pcap file for reading
- `create` - Create a packet capture handle
- `compile` - Create a BPF filter program
- `pcap_read` - Read packets from a pcap handle
- `pcap_datalink` - Get the data link type
- `pcap_setfilter` - Attach a BPF filter
- `pcap_getnonblock` - Get non-blocking status
- `pcap_setnonblock` - Set non-blocking mode
- `get_dlt_names` - Get DLT constant mappings
- `get_pcap_directions` - Get direction constant mappings
- `get_constants` - Get all constants

## Development

```bash
git clone https://github.com/daedalus/mcp-pcapy-ng.git
cd mcp-pcapy-ng
pip install -e ".[test]"

# run tests
pytest

# format
ruff format src/ tests/

# lint
ruff check src/ tests/

# type check
mypy src/
```
