"""Tests for MCP pcapy-ng tools."""

from unittest.mock import MagicMock, patch

import pytest

import mcp_pcapy_ng._tools as tools


class TestFindalldevs:
    """Tests for findalldevs tool."""

    def test_findalldevs_returns_list(self):
        """Test that findalldevs returns a list."""
        with patch("mcp_pcapy_ng._tools.pcapy") as mock_pcapy:
            mock_pcapy.findalldevs.return_value = [{"name": "eth0"}]
            result = tools.findalldevs()
            assert isinstance(result, list)

    def test_findalldevs_with_string_devices(self):
        """Test findalldevs handles string device names."""
        with patch("mcp_pcapy_ng._tools.pcapy") as mock_pcapy:
            mock_pcapy.findalldevs.return_value = ["eth0", "lo"]
            result = tools.findalldevs()
            assert len(result) == 2
            assert result[0]["name"] == "eth0"

    def test_findalldevs_empty(self):
        """Test findalldevs handles empty device list."""
        with patch("mcp_pcapy_ng._tools.pcapy") as mock_pcapy:
            mock_pcapy.findalldevs.return_value = []
            result = tools.findalldevs()
            assert result == []


class TestLookupdev:
    """Tests for lookupdev tool."""

    def test_lookupdev_returns_string(self):
        """Test that lookupdev returns a device string."""
        with patch("mcp_pcapy_ng._tools.pcapy") as mock_pcapy:
            mock_pcapy.lookupdev.return_value = "eth0"
            result = tools.lookupdev()
            assert result == "eth0"

    def test_lookupdev_raises_on_none(self):
        """Test lookupdev raises RuntimeError when no device found."""
        with patch("mcp_pcapy_ng._tools.pcapy") as mock_pcapy:
            mock_pcapy.lookupdev.return_value = None
            with pytest.raises(RuntimeError):
                tools.lookupdev()


class TestOpenLive:
    """Tests for open_live tool."""

    def test_open_live_returns_dict(self):
        """Test that open_live returns expected dictionary."""
        with patch("mcp_pcapy_ng._tools.pcapy") as mock_pcapy:
            mock_p = MagicMock()
            mock_p.datalink.return_value = 1
            mock_p.getnonblock.return_value = 0
            mock_pcapy.open_live.return_value = mock_p

            result = tools.open_live("eth0")
            assert result["device"] == "eth0"
            assert result["datalink"] == 1

    def test_open_live_default_parameters(self):
        """Test open_live works with default parameters."""
        with patch("mcp_pcapy_ng._tools.pcapy") as mock_pcapy:
            mock_p = MagicMock()
            mock_p.datalink.return_value = 1
            mock_p.getnonblock.return_value = 0
            mock_pcapy.open_live.return_value = mock_p

            result = tools.open_live("eth0")
            mock_pcapy.open_live.assert_called_once_with("eth0", 65535, 1, 1000)

    def test_open_live_non_promisc(self):
        """Test open_live with promisc=False."""
        with patch("mcp_pcapy_ng._tools.pcapy") as mock_pcapy:
            mock_p = MagicMock()
            mock_p.datalink.return_value = 1
            mock_p.getnonblock.return_value = 0
            mock_pcapy.open_live.return_value = mock_p

            tools.open_live("eth0", promisc=False)
            mock_pcapy.open_live.assert_called_once_with("eth0", 65535, 0, 1000)

    def test_open_live_custom_parameters(self):
        """Test open_live with custom parameters."""
        with patch("mcp_pcapy_ng._tools.pcapy") as mock_pcapy:
            mock_p = MagicMock()
            mock_p.datalink.return_value = 1
            mock_p.getnonblock.return_value = 0
            mock_pcapy.open_live.return_value = mock_p

            tools.open_live("eth0", snaplen=1500, promisc=False, to_ms=500)
            mock_pcapy.open_live.assert_called_once_with("eth0", 1500, 0, 500)


class TestCreate:
    """Tests for create tool."""

    def test_create_returns_dict(self):
        """Test that create returns expected dictionary."""
        with patch("mcp_pcapy_ng._tools.pcapy") as mock_pcapy:
            mock_p = MagicMock()
            mock_p.datalink.return_value = 1
            mock_pcapy.create.return_value = mock_p

            result = tools.create("eth0")
            assert result["device"] == "eth0"
            assert result["created"] is True


class TestOpenOffline:
    """Tests for open_offline tool."""

    def test_open_offline_returns_dict(self):
        """Test that open_offline returns expected dictionary."""
        with patch("mcp_pcapy_ng._tools.pcapy") as mock_pcapy:
            mock_p = MagicMock()
            mock_p.datalink.return_value = 1
            mock_pcapy.open_offline.return_value = mock_p

            result = tools.open_offline("/tmp/capture.pcap")
            assert result["filename"] == "/tmp/capture.pcap"
            assert result["readable"] is True


class TestCompile:
    """Tests for compile tool."""

    def test_compile_returns_dict(self):
        """Test that compile returns expected dictionary."""
        with patch("mcp_pcapy_ng._tools.pcapy") as mock_pcapy:
            mock_pcapy.compile.return_value = MagicMock()

            result = tools.compile(1, 65535, "tcp")
            assert result["compiled"] is True
            assert result["filter"] == "tcp"
            assert result["linktype"] == 1

    def test_compile_no_optimize(self):
        """Test compile with optimize=False."""
        with patch("mcp_pcapy_ng._tools.pcapy") as mock_pcapy:
            mock_pcapy.compile.return_value = MagicMock()

            result = tools.compile(1, 65535, "tcp", optimize=False)
            assert result["optimize"] is False


class TestPcapRead:
    """Tests for pcap_read tool."""

    def test_pcap_read_from_device(self):
        """Test pcap_read from device."""
        with patch("mcp_pcapy_ng._tools.pcapy") as mock_pcapy:
            mock_p = MagicMock()
            mock_p.readpkts.return_value = [(123456.0, b"\\x00\\x01")]
            mock_pcapy.open_live.return_value = mock_p

            result = tools.pcap_read({"device": "eth0"}, count=1)
            assert len(result) == 1

    def test_pcap_read_from_file(self):
        """Test pcap_read from file."""
        with patch("mcp_pcapy_ng._tools.pcapy") as mock_pcapy:
            mock_p = MagicMock()
            mock_p.readpkts.return_value = []
            mock_pcapy.open_offline.return_value = mock_p

            result = tools.pcap_read({"filename": "/tmp/test.pcap"})
            assert result == []

    def test_pcap_read_invalid_pcap_info(self):
        """Test pcap_read raises on invalid pcap_info."""
        with pytest.raises(ValueError):
            tools.pcap_read({})


class TestPcapDatalink:
    """Tests for pcap_datalink tool."""

    def test_pcap_datalink_from_device(self):
        """Test pcap_datalink from device."""
        with patch("mcp_pcapy_ng._tools.pcapy") as mock_pcapy:
            mock_p = MagicMock()
            mock_p.datalink.return_value = 1
            mock_pcapy.open_live.return_value = mock_p

            result = tools.pcap_datalink({"device": "eth0"})
            assert result == 1

    def test_pcap_datalink_invalid_pcap_info(self):
        """Test pcap_datalink raises on invalid pcap_info."""
        with pytest.raises(ValueError):
            tools.pcap_datalink({})


class TestPcapSetfilter:
    """Tests for pcap_setfilter tool."""

    def test_pcap_setfilter_success(self):
        """Test pcap_setfilter successful."""
        with patch("mcp_pcapy_ng._tools.pcapy") as mock_pcapy:
            mock_p = MagicMock()
            mock_pcapy.open_live.return_value = mock_p
            mock_pcapy.compile.return_value = MagicMock()

            result = tools.pcap_setfilter(
                {"device": "eth0"},
                {"filter": "tcp", "linktype": 1},
            )
            assert result is True

    def test_pcap_setfilter_invalid_pcap_info(self):
        """Test pcap_setfilter raises on invalid pcap_info."""
        with pytest.raises(ValueError):
            tools.pcap_setfilter({}, {})


class TestPcapGetnonblock:
    """Tests for pcap_getnonblock tool."""

    def test_pcap_getnonblock_from_device(self):
        """Test pcap_getnonblock from device."""
        with patch("mcp_pcapy_ng._tools.pcapy") as mock_pcapy:
            mock_p = MagicMock()
            mock_p.getnonblock.return_value = 1
            mock_pcapy.open_live.return_value = mock_p

            result = tools.pcap_getnonblock({"device": "eth0"})
            assert result is True

    def test_pcap_getnonblock_invalid_pcap_info(self):
        """Test pcap_getnonblock raises on invalid pcap_info."""
        with pytest.raises(ValueError):
            tools.pcap_getnonblock({})


class TestPcapSetnonblock:
    """Tests for pcap_setnonblock tool."""

    def test_pcap_setnonblock_true(self):
        """Test pcap_setnonblock with nonblock=True."""
        with patch("mcp_pcapy_ng._tools.pcapy") as mock_pcapy:
            mock_p = MagicMock()
            mock_pcapy.open_live.return_value = mock_p

            result = tools.pcap_setnonblock({"device": "eth0"}, True)
            assert result is True
            mock_p.setnonblock.assert_called_once_with(1)

    def test_pcap_setnonblock_false(self):
        """Test pcap_setnonblock with nonblock=False."""
        with patch("mcp_pcapy_ng._tools.pcapy") as mock_pcapy:
            mock_p = MagicMock()
            mock_pcapy.open_live.return_value = mock_p

            result = tools.pcap_setnonblock({"device": "eth0"}, False)
            assert result is True
            mock_p.setnonblock.assert_called_once_with(0)

    def test_pcap_setnonblock_invalid_pcap_info(self):
        """Test pcap_setnonblock raises on invalid pcap_info."""
        with pytest.raises(ValueError):
            tools.pcap_setnonblock({}, True)


class TestConstants:
    """Tests for constant tools."""

    def test_get_dlt_names_returns_dict(self):
        """Test get_dlt_names returns DLT constants."""
        with patch("mcp_pcapy_ng._tools.pcapy") as mock_pcapy:
            mock_pcapy.DLT_EN10MB = 1
            mock_pcapy.DLT_IEEE802_11 = 105
            result = tools.get_dlt_names()
            assert "DLT_EN10MB" in result
            assert result["DLT_EN10MB"] == 1

    def test_get_pcap_directions_returns_dict(self):
        """Test get_pcap_directions returns direction constants."""
        with patch("mcp_pcapy_ng._tools.pcapy") as mock_pcapy:
            mock_pcapy.PCAP_D_IN = 1
            mock_pcapy.PCAP_D_OUT = 2
            result = tools.get_pcap_directions()
            assert "PCAP_D_IN" in result

    def test_get_constants_combines(self):
        """Test get_constants combines all constants."""
        with patch("mcp_pcapy_ng._tools.pcapy") as mock_pcapy:
            mock_pcapy.DLT_EN10MB = 1
            mock_pcapy.PCAP_D_IN = 1
            result = tools.get_constants()
            assert "DLT_EN10MB" in result
            assert "PCAP_D_IN" in result
