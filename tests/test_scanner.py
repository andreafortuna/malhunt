"""Tests for scanner modules."""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from malhunt.scanner import YaraScanner, MalfindScanner, NetworkScanner
from malhunt.models import SuspiciousProcess
from malhunt.volatility import VolatilityWrapper


class TestYaraScanner:
    """Test YARA scanner."""
    
    def test_initialization(self):
        """Test YARA scanner initialization."""
        mock_vol = Mock(spec=VolatilityWrapper)
        rules_file = Path("rules.yar")
        
        scanner = YaraScanner(mock_vol, rules_file)
        
        assert scanner.vol == mock_vol
        assert scanner.rule_file == rules_file
        assert YaraScanner.DEFAULT_EXCLUDED_WORDS[0] == "Str_Win32_"
    
    def test_scan_parsing(self):
        """Test YARA scan output parsing."""
        mock_vol = Mock(spec=VolatilityWrapper)
        mock_vol.yarascan.return_value = """
Rule: Trojan.Generic
Owner: test.exe [PID: 1234]
Address: 0x12345678

Rule: Backdoor.Win32
Owner: svchost.exe [PID: 5678]
Address: 0x87654321
"""
        rules_file = Path("rules.yar")
        rules_file.touch()
        
        try:
            scanner = YaraScanner(mock_vol, rules_file)
            results = scanner.scan()
            
            assert len(results) == 2
            assert results[0].rule == "Trojan.Generic"
            assert results[0].process == "test.exe"
            assert results[0].pid == "1234"
        finally:
            rules_file.unlink()
    
    def test_excluded_words_filtering(self):
        """Test exclusion of rules."""
        mock_vol = Mock(spec=VolatilityWrapper)
        mock_vol.yarascan.return_value = """
Rule: Str_Win32_Valid
Owner: test.exe [PID: 1234]
Address: 0x12345678

Rule: Malware.Generic
Owner: svchost.exe [PID: 5678]
Address: 0x87654321
"""
        rules_file = Path("rules.yar")
        rules_file.touch()
        
        try:
            excluded = ["Str_Win32_"]
            scanner = YaraScanner(mock_vol, rules_file, excluded_words=excluded)
            results = scanner.scan()
            
            assert len(results) == 1
            assert results[0].rule == "Malware.Generic"
        finally:
            rules_file.unlink()
    
    def test_deduplication(self):
        """Test that duplicate PIDs are deduplicated."""
        mock_vol = Mock(spec=VolatilityWrapper)
        mock_vol.yarascan.return_value = """
Rule: Rule1
Owner: test.exe [PID: 1234]

Rule: Rule2
Owner: test.exe [PID: 1234]
"""
        rules_file = Path("rules.yar")
        rules_file.touch()
        
        try:
            scanner = YaraScanner(mock_vol, rules_file)
            results = scanner.scan()
            
            assert len(results) == 1
        finally:
            rules_file.unlink()


class TestMalfindScanner:
    """Test Malfind scanner."""
    
    def test_initialization(self):
        """Test Malfind scanner initialization."""
        mock_vol = Mock(spec=VolatilityWrapper)
        scanner = MalfindScanner(mock_vol)
        
        assert scanner.vol == mock_vol
    
    def test_scan_parsing(self):
        """Test Malfind scan output parsing."""
        mock_vol = Mock(spec=VolatilityWrapper)
        mock_vol.malfind.return_value = """
Process: test.exe [PID: 1234]
Address: 0x12345678

Process: svchost.exe [PID: 5678]
Address: 0x87654321
"""
        scanner = MalfindScanner(mock_vol)
        results = scanner.scan()
        
        assert len(results) == 2
        assert all(r.rule == "malfind" for r in results)
        assert results[0].pid == "1234"
        assert results[1].pid == "5678"


class TestNetworkScanner:
    """Test Network scanner."""
    
    def test_initialization(self):
        """Test Network scanner initialization."""
        mock_vol = Mock(spec=VolatilityWrapper)
        scanner = NetworkScanner(mock_vol)
        
        assert scanner.vol == mock_vol
        assert scanner.ip_checker is None
    
    def test_initialization_with_checker(self):
        """Test Network scanner with custom IP checker."""
        mock_vol = Mock(spec=VolatilityWrapper)
        checker = Mock(return_value=True)
        
        scanner = NetworkScanner(mock_vol, ip_checker=checker)
        
        assert scanner.ip_checker == checker
    
    def test_scan_parsing(self):
        """Test network scan output parsing."""
        mock_vol = Mock(spec=VolatilityWrapper)
        mock_vol.netscan.return_value = """
Protocol: TCPv4
Local: 192.168.1.100:49320
Remote: 10.0.0.1:443
PID: 1234

Protocol: TCPv4
Local: 192.168.1.100:49321
Remote: 172.16.0.1:80
PID: 5678
"""
        scanner = NetworkScanner(mock_vol)
        results = scanner.scan()
        
        # Without IP checker, should accept all
        assert len(results) == 2
        assert all(r.rule == "network" for r in results)
    
    def test_filters_by_ip_checker(self):
        """Test filtering by IP checker."""
        mock_vol = Mock(spec=VolatilityWrapper)
        mock_vol.netscan.return_value = """
Protocol: TCPv4
Local: 192.168.1.100:49320
Remote: 10.0.0.1:443
PID: 1234

Protocol: TCPv4
Local: 192.168.1.100:49321
Remote: 192.168.1.1:80
PID: 5678
"""
        # Only mark 10.0.0.1 as malicious
        def checker(ip):
            return ip == "10.0.0.1"
        
        scanner = NetworkScanner(mock_vol, ip_checker=checker)
        results = scanner.scan()
        
        assert len(results) == 1
        assert results[0].pid == "1234"
    
    def test_deduplication(self):
        """Test that duplicate PIDs are deduplicated."""
        mock_vol = Mock(spec=VolatilityWrapper)
        mock_vol.netscan.return_value = """
Protocol: TCPv4
Local: 192.168.1.100:49320
Remote: 10.0.0.1:443
PID: 1234

Protocol: TCPv4
Local: 192.168.1.100:49321
Remote: 10.0.0.2:443
PID: 1234
"""
        scanner = NetworkScanner(mock_vol)
        results = scanner.scan()
        
        assert len(results) == 1
        assert results[0].pid == "1234"


class TestScannerErrorHandling:
    """Test scanner error handling."""
    
    def test_yara_scanner_handles_exception(self):
        """Test YARA scanner handles exceptions gracefully."""
        mock_vol = Mock(spec=VolatilityWrapper)
        mock_vol.yarascan.side_effect = Exception("Test error")
        
        rules_file = Path("rules.yar")
        rules_file.touch()
        
        try:
            scanner = YaraScanner(mock_vol, rules_file)
            results = scanner.scan()
            
            assert results == []
        finally:
            rules_file.unlink()
    
    def test_malfind_scanner_handles_exception(self):
        """Test Malfind scanner handles exceptions gracefully."""
        mock_vol = Mock(spec=VolatilityWrapper)
        mock_vol.malfind.side_effect = Exception("Test error")
        
        scanner = MalfindScanner(mock_vol)
        results = scanner.scan()
        
        assert results == []
    
    def test_network_scanner_handles_exception(self):
        """Test Network scanner handles exceptions gracefully."""
        mock_vol = Mock(spec=VolatilityWrapper)
        mock_vol.netscan.side_effect = Exception("Test error")
        
        scanner = NetworkScanner(mock_vol)
        results = scanner.scan()
        
        assert results == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
