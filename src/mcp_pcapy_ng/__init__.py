"""mcp-pcapy-ng - MCP server exposing pcapy-ng packet capture functionality."""

__version__ = "0.1.0"

from typing import TYPE_CHECKING

from .mcp import mcp

if TYPE_CHECKING:
    from . import _tools

__all__ = ["mcp", "__version__"]
