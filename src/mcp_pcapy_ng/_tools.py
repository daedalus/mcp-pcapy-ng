"""Tools module exposing pcapy-ng functionality via MCP."""

from typing import Any

import pcapy

from .mcp import mcp


@mcp.tool()
def findalldevs() -> list[dict[str, Any]]:
    """Lists all available network interfaces on the system.

    Returns:
        List of dictionaries, each containing interface details:
        - name: Interface name (e.g., 'eth0')
        - description: Interface description
        - addresses: List of address dictionaries
        - flags: Interface flags

    Example:
        >>> findalldevs()
        [{'name': 'eth0', 'description': 'Ethernet', 'addresses': [...], 'flags': [...]}]
    """
    devices = pcapy.findalldevs()
    result = []
    for dev in devices:
        if isinstance(dev, dict):
            result.append(dev)
        else:
            result.append(
                {"name": dev, "description": "", "addresses": [], "flags": []}
            )
    return result


@mcp.tool()
def lookupdev() -> str:
    """Gets the default network device for packet capture.

    Returns:
        String containing the default device name (e.g., 'eth0').

    Raises:
        RuntimeError: If no default device can be found.

    Example:
        >>> lookupdev()
        'eth0'
    """
    dev = pcapy.lookupdev()
    if dev is None:
        raise RuntimeError("No default device found")
    return str(dev)


@mcp.tool()
def open_live(
    device: str,
    snaplen: int = 65535,
    promisc: bool = True,
    to_ms: int = 1000,
) -> dict[str, Any]:
    """Opens a live network interface for packet capture.

    Args:
        device: Network device name (e.g., 'eth0'). Use findalldevs() to list available.
        snaplen: Maximum number of bytes to capture per packet (default: 65535).
        promisc: Put interface in promiscuous mode (default: True).
        to_ms: Read timeout in milliseconds (default: 1000).

    Returns:
        Dictionary with pcap handle info including:
        - datalink: Data link type constant
        - device: Device name
        - snaplen: Snapshot length
        - nonblock: Whether in non-blocking mode

    Raises:
        PcapError: If the device cannot be opened.

    Example:
        >>> open_live('eth0')
        {'datalink': 1, 'device': 'eth0', 'snaplen': 65535, 'nonblock': False}
    """
    p = pcapy.open_live(device, snaplen, 1 if promisc else 0, to_ms)
    return {
        "datalink": p.datalink(),
        "device": device,
        "snaplen": snaplen,
        "nonblock": p.getnonblock() != 0,
    }


@mcp.tool()
def create(device: str) -> dict[str, Any]:
    """Creates a packet capture handle to look at packets on the network.

    This creates a handle that can be configured before being activated.
    Use this for more control over the capture setup.

    Args:
        device: Network device name.

    Returns:
        Dictionary with pcap handle info.

    Raises:
        PcapError: If the device cannot be created.

    Example:
        >>> create('eth0')
        {'device': 'eth0', 'created': True}
    """
    p = pcapy.create(device)
    return {"device": device, "created": True, "datalink": p.datalink()}


@mcp.tool()
def open_offline(filename: str) -> dict[str, Any]:
    """Opens a pcap file for reading packet captures.

    Args:
        filename: Path to the pcap file.

    Returns:
        Dictionary with pcap file info including:
        - datalink: Data link type constant
        - filename: File path
        - readable: Whether file is readable

    Raises:
        PcapError: If the file cannot be opened.

    Example:
        >>> open_offline('/tmp/capture.pcap')
        {'datalink': 1, 'filename': '/tmp/capture.pcap', 'readable': True}
    """
    p = pcapy.open_offline(filename)
    return {
        "datalink": p.datalink(),
        "filename": filename,
        "readable": True,
    }


@mcp.tool()
def compile(
    linktype: int,
    snaplen: int,
    filter_str: str,
    optimize: bool = True,
    netmask: int = 0xFFFFFFFF,
) -> dict[str, Any]:
    """Creates a BPF (Berkeley Packet Filter) program for packet filtering.

    Args:
        linktype: DLT link type (e.g., DLT_EN10MB=1 for Ethernet).
        snaplen: Snapshot length.
        filter_str: BPF filter expression (e.g., 'tcp and port 80').
        optimize: Optimize the filter (default: True).
        netmask: Netmask for the filter (default: 0xFFFFFFFF).

    Returns:
        Dictionary with compiled filter info:
        - compiled: Whether successful
        - filter: Filter expression
        - linktype: DLT used

    Raises:
        BPFError: If the filter expression is invalid.

    Example:
        >>> compile(1, 65535, 'tcp and port 80')
        {'compiled': True, 'filter': 'tcp and port 80', 'linktype': 1}
    """
    pcapy.compile(linktype, snaplen, filter_str, 1 if optimize else 0, netmask)
    return {
        "compiled": True,
        "filter": filter_str,
        "linktype": linktype,
        "optimize": optimize,
    }


@mcp.tool()
def pcap_read(pcap_info: dict[str, Any], count: int = 1) -> list[tuple[float, bytes]]:
    """Read packets from a pcap handle.

    Args:
        pcap_info: Dictionary from open_live or open_offline (contains device/filename).
        count: Maximum number of packets to read (default: 1).

    Returns:
        List of tuples: (timestamp_unix_float, raw_packet_bytes).

    Example:
        >>> pcap_read({'device': 'eth0', 'datalink': 1}, count=10)
        [(1234567890.123, b'\\x00\\x01...'), ...]
    """
    if "device" in pcap_info:
        p = pcapy.open_live(pcap_info["device"], 65535, 0, 100)
    elif "filename" in pcap_info:
        p = pcapy.open_offline(pcap_info["filename"])
    else:
        raise ValueError("Invalid pcap_info: must contain 'device' or 'filename'")

    packets = p.readpkts()
    result = []
    for i, pkt in enumerate(packets[:count]):
        if isinstance(pkt, tuple) and len(pkt) >= 2:
            result.append((pkt[0], bytes(pkt[1])))
        else:
            result.append((0, bytes(pkt)))
    return result


@mcp.tool()
def pcap_datalink(pcap_info: dict[str, Any]) -> int:
    """Get the data link type from a pcap handle.

    Args:
        pcap_info: Dictionary from open_live or open_offline.

    Returns:
        Integer DLT value (e.g., 1 for Ethernet).

    Example:
        >>> pcap_datalink({'device': 'eth0'})
        1
    """
    if "device" in pcap_info:
        p = pcapy.open_live(pcap_info["device"], 65535, 0, 100)
    elif "filename" in pcap_info:
        p = pcapy.open_offline(pcap_info["filename"])
    else:
        raise ValueError("Invalid pcap_info: must contain 'device' or 'filename'")
    return int(p.datalink())


@mcp.tool()
def pcap_setfilter(pcap_info: dict[str, Any], filter_info: dict[str, Any]) -> bool:
    """Attach a compiled BPF filter to a pcap handle.

    Args:
        pcap_info: Dictionary from open_live or open_offline.
        filter_info: Dictionary from compile().

    Returns:
        True if filter was set successfully.

    Raises:
        PcapError: If filter cannot be set.

    Example:
        >>> pcap_setfilter({'device': 'eth0'}, {'filter': 'tcp', 'linktype': 1})
        True
    """
    if "device" in pcap_info:
        p = pcapy.open_live(pcap_info["device"], 65535, 0, 100)
    elif "filename" in pcap_info:
        p = pcapy.open_offline(pcap_info["filename"])
    else:
        raise ValueError("Invalid pcap_info: must contain 'device' or 'filename'")

    bpf = pcapy.compile(
        filter_info["linktype"],
        65535,
        filter_info["filter"],
        1 if filter_info.get("optimize", True) else 0,
    )
    p.setfilter(bpf)
    return True


@mcp.tool()
def pcap_getnonblock(pcap_info: dict[str, Any]) -> bool:
    """Get the non-blocking status of a pcap handle.

    Args:
        pcap_info: Dictionary from open_live or open_offline.

    Returns:
        True if in non-blocking mode, False otherwise.

    Example:
        >>> pcap_getnonblock({'device': 'eth0'})
        False
    """
    if "device" in pcap_info:
        p = pcapy.open_live(pcap_info["device"], 65535, 0, 100)
    elif "filename" in pcap_info:
        p = pcapy.open_offline(pcap_info["filename"])
    else:
        raise ValueError("Invalid pcap_info: must contain 'device' or 'filename'")
    return bool(p.getnonblock() != 0)


@mcp.tool()
def pcap_setnonblock(pcap_info: dict[str, Any], nonblock: bool) -> bool:
    """Set the non-blocking mode of a pcap handle.

    Args:
        pcap_info: Dictionary from open_live or open_offline.
        nonblock: True for non-blocking mode, False for blocking.

    Returns:
        True if mode was set successfully.

    Example:
        >>> pcap_setnonblock({'device': 'eth0'}, True)
        True
    """
    if "device" in pcap_info:
        p = pcapy.open_live(pcap_info["device"], 65535, 0, 100)
    elif "filename" in pcap_info:
        p = pcapy.open_offline(pcap_info["filename"])
    else:
        raise ValueError("Invalid pcap_info: must contain 'device' or 'filename'")
    p.setnonblock(1 if nonblock else 0)
    return True


@mcp.tool()
def get_dlt_names() -> dict[str, int]:
    """Get mapping of DLT (Data Link Type) constants to their names.

    Returns:
        Dictionary mapping DLT names to constant values.

    Example:
        >>> get_dlt_names()
        {'DLT_NULL': 0, 'DLT_EN10MB': 1, 'DLT_IEEE802_11': 105, ...}
    """
    return {
        "DLT_ARCNET": pcapy.DLT_ARCNET,
        "DLT_ATM_RFC1483": pcapy.DLT_ATM_RFC1483,
        "DLT_C_HDLC": pcapy.DLT_C_HDLC,
        "DLT_EN10MB": pcapy.DLT_EN10MB,
        "DLT_FDDI": pcapy.DLT_FDDI,
        "DLT_IEEE802": pcapy.DLT_IEEE802,
        "DLT_IEEE802_11": pcapy.DLT_IEEE802_11,
        "DLT_LINUX_SLL": pcapy.DLT_LINUX_SLL,
        "DLT_LOOP": pcapy.DLT_LOOP,
        "DLT_LTALK": pcapy.DLT_LTALK,
        "DLT_NULL": pcapy.DLT_NULL,
        "DLT_PPP": pcapy.DLT_PPP,
        "DLT_PPP_ETHER": pcapy.DLT_PPP_ETHER,
        "DLT_PPP_SERIAL": pcapy.DLT_PPP_SERIAL,
        "DLT_RAW": pcapy.DLT_RAW,
        "DLT_SLIP": pcapy.DLT_SLIP,
    }


@mcp.tool()
def get_pcap_directions() -> dict[str, int]:
    """Get mapping of PCAP direction constants to their names.

    Returns:
        Dictionary mapping direction names to constant values.

    Example:
        >>> get_pcap_directions()
        {'PCAP_D_INOUT': 0, 'PCAP_D_IN': 1, 'PCAP_D_OUT': 2}
    """
    return {
        "PCAP_D_INOUT": pcapy.PCAP_D_INOUT,
        "PCAP_D_IN": pcapy.PCAP_D_IN,
        "PCAP_D_OUT": pcapy.PCAP_D_OUT,
    }


@mcp.tool()
def get_constants() -> dict[str, Any]:
    """Get all pcapy constants (DLT types, directions, errors).

    Returns:
        Dictionary with all constants.

    Example:
        >>> get_constants()
        {'DLT_EN10MB': 1, 'PCAP_D_IN': 1, ...}
    """
    constants: dict[str, Any] = get_dlt_names()
    constants.update(get_pcap_directions())
    return constants
