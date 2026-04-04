"""Pytest configuration for mcp-pcapy-ng tests."""

import pytest


@pytest.fixture
def mock_pcapy(mocker):
    """Fixture providing a mocked pcapy module."""
    mock = mocker.patch("mcp_pcapy_ng._tools.pcapy")
    mock.DLT_EN10MB = 1
    mock.DLT_IEEE802_11 = 105
    mock.PCAP_D_IN = 1
    mock.PCAP_D_OUT = 2
    mock.PCAP_D_INOUT = 0
    return mock
