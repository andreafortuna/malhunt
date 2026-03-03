"""Scanning modules for malware detection."""

from pathlib import Path
from typing import List

from loguru import logger

from .models import SuspiciousProcess
from .volatility import VolatilityWrapper


class YaraScanner:
    """YARA-based malware scanner."""
    
    def __init__(self, vol: VolatilityWrapper, rule_file: Path, 
                 excluded_words: List[str] = None):
        """Initialize YARA scanner.
        
        Args:
            vol: Volatility wrapper instance
            rule_file: Path to YARA rules file
            excluded_words: Words to filter from rule names
        """
        self.vol = vol
        self.rule_file = rule_file
        self.excluded_words = excluded_words or []
    
    def scan(self) -> List[SuspiciousProcess]:
        """Run YARA scan on memory dump.
        
        Returns:
            List of suspicious processes found
        """
        logger.info(f"Starting YARA scan with {self.rule_file.name}")
        logger.debug(f"Rules file size: {self.rule_file.stat().st_size / 1024:.1f} KB")
        
        try:
            output = self.vol.yarascan(self.rule_file)
        except Exception as e:
            logger.error(f"YARA scan execution failed: {e}")
            return []
        
        processes = []
        current_rule = ""
        match_count = 0
        
        for line in output.split('\n'):
            if line.startswith("Rule"):
                current_rule = line.split(":")[1].strip()
            
            if line.startswith("Owner"):
                # Parse owner line to extract process info
                parts = line.split()
                if len(parts) >= 4:
                    process = parts[1]
                    pid = parts[3]
                    
                    # Check exclusions
                    if any(word in current_rule for word in self.excluded_words):
                        logger.debug(f"Filtered excluded rule: {current_rule}")
                        continue
                    
                    proc = SuspiciousProcess(
                        rule=current_rule,
                        process=process,
                        pid=pid
                    )
                    
                    if not any(p.pid == pid for p in processes):
                        processes.append(proc)
                        match_count += 1
                        logger.debug(f"YARA match #{match_count}: {proc.rule} in {proc.process}")
        
        logger.info(f"YARA scan complete: {len(processes)} suspicious processes found")
        return processes


class MalfindScanner:
    """Malfind-based injected code scanner.
    
    Detects:
    - Injected code in process memory
    - Suspicious memory allocations
    - Allocated but not executed memory
    """
    
    def __init__(self, vol: VolatilityWrapper):
        """Initialize Malfind scanner.
        
        Args:
            vol: Volatility wrapper instance
        """
        self.vol = vol
    
    def scan(self) -> List[SuspiciousProcess]:
        """Scan for injected code.
        
        Returns:
            List of suspicious processes found
        """
        logger.info("Starting Malfind scan for code injection...")
        
        try:
            output = self.vol.malfind()
        except Exception as e:
            logger.error(f"Malfind scan execution failed: {e}")
            return []
        
        processes = []
        process_count = 0
        
        for line in output.split('\n'):
            if "Process:" in line:
                parts = line.split()
                if len(parts) >= 4:
                    process = parts[1]
                    pid = parts[3]
                    
                    proc = SuspiciousProcess(
                        rule="malfind",
                        process=process,
                        pid=pid
                    )
                    
                    if not any(p.pid == pid for p in processes):
                        processes.append(proc)
                        process_count += 1
                        logger.debug(f"Malfind detection #{process_count}: {process} (PID: {pid})")
        
        logger.info(f"Malfind scan complete: {len(processes)} suspicious processes found")
        return processes


class NetworkScanner:
    """Network connection scanner.
    
    Detects:
    - Connections to malicious IP addresses
    - Unusual port usage
    - Suspicious outbound connections
    """
    
    def __init__(self, vol: VolatilityWrapper, ip_checker=None):
        """Initialize Network scanner.
        
        Args:
            vol: Volatility wrapper instance
            ip_checker: Optional callable to check if IP is malicious
        """
        self.vol = vol
        self.ip_checker = ip_checker
    
    def scan(self) -> List[SuspiciousProcess]:
        """Scan for suspicious network connections.
        
        Returns:
            List of suspicious processes found
        """
        logger.info("Starting network connection scan...")
        
        try:
            output = self.vol.netscan()
        except Exception as e:
            logger.error(f"Network scan execution failed: {e}")
            return []
        
        processes = []
        connection_count = 0
        malicious_count = 0
        
        for line in output.split('\n'):
            if not line.strip() or "LISTENING" in line:
                continue
            
            parts = line.split()
            if len(parts) >= 5:
                try:
                    ip = parts[2].split(':')[0]
                    pid = parts[4]
                    
                    # Check if IP is malicious (if checker provided)
                    if self.ip_checker:
                        is_malicious = False
                        try:
                            is_malicious = self.ip_checker(ip)
                        except Exception as e:
                            logger.debug(f"Error checking IP {ip}: {e}")
                        
                        if not is_malicious:
                            connection_count += 1
                            continue
                    
                    malicious_count += 1
                    proc = SuspiciousProcess(
                        rule="network",
                        process="N.A.",
                        pid=pid
                    )
                    
                    if not any(p.pid == pid for p in processes):
                        processes.append(proc)
                        logger.warning(f"Suspicious connection #{malicious_count}: {ip} (PID: {pid})")
                
                except (IndexError, ValueError) as e:
                    logger.debug(f"Failed to parse connection line: {line[:50]}...")
        
        total_checked = connection_count + malicious_count
        logger.info(f"Network scan complete: checked {total_checked} connections, "
                   f"found {len(processes)} suspicious")
        return processes
