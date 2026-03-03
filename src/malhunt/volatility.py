"""Volatility3 wrapper and integration."""

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import time

from loguru import logger


class VolatilityError(Exception):
    """Exception raised for Volatility-related errors."""
    pass


@dataclass
class VolatilityConfig:
    """Configuration for Volatility execution."""
    timeout: int = 300  # 5 minutes default
    retry_count: int = 1
    retry_delay: float = 1.0
    cache_results: bool = True


class VolatilityWrapper:
    """Wrapper around Volatility3 CLI for memory analysis.
    
    This class provides a high-level interface to Volatility3 for memory dump analysis.
    Current implementation uses the CLI; future versions may use direct API integration.
    
    Features:
    - Automatic volatility binary detection
    - Command execution with timeout and retry logic
    - Output parsing and caching
    - Comprehensive error handling and logging
    """
    
    def __init__(self, dump_path: Path, config: Optional[VolatilityConfig] = None):
        """Initialize Volatility wrapper.
        
        Args:
            dump_path: Path to the memory dump file
            config: Optional VolatilityConfig for customization
            
        Raises:
            VolatilityError: If dump file doesn't exist or Volatility is not installed
        """
        self.dump_path = Path(dump_path)
        if not self.dump_path.exists():
            raise VolatilityError(f"Memory dump not found: {dump_path}")
        
        self.config = config or VolatilityConfig()
        self._volatility_bin = self._find_volatility()
        if not self._volatility_bin:
            raise VolatilityError("Volatility3 not found in PATH")
        
        self._cache: Dict[str, str] = {}
        
        logger.debug(f"Using Volatility3 binary: {self._volatility_bin}")
        logger.debug(f"Memory dump: {self.dump_path.name} ({self.dump_path.stat().st_size / (1024**3):.1f} GB)")
        logger.debug(f"Config: timeout={self.config.timeout}s, retry={self.config.retry_count}x")
    
    @staticmethod
    def _find_volatility() -> Optional[Path]:
        """Find Volatility3 executable in PATH.
        
        Tries multiple common names:
        - vol (most common)
        - volatility3
        - vol.py
        
        Returns:
            Path to volatility binary, or None if not found
        """
        candidates = ["vol", "volatility3", "vol.py"]
        
        for cmd in candidates:
            try:
                result = subprocess.run(
                    ["which", cmd],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    binary = Path(result.stdout.strip())
                    logger.debug(f"Found volatility binary: {binary} ({cmd})")
                    return binary
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        return None
    
    def _run_command(self, *args: str, use_cache: bool = True) -> Tuple[str, str]:
        """Run a volatility command with retry and caching.
        
        Args:
            *args: Arguments to pass to volatility
            use_cache: Whether to use cached results if available
            
        Returns:
            Tuple of (stdout, stderr)
            
        Raises:
            VolatilityError: If command fails after retries
        """
        cache_key = " ".join(args)
        
        # Check cache
        if use_cache and cache_key in self._cache:
            logger.debug(f"Cache hit for: {cache_key}")
            return self._cache[cache_key], ""
        
        cmd = [str(self._volatility_bin), "-f", str(self.dump_path)] + list(args)
        
        last_error = None
        
        for attempt in range(self.config.retry_count):
            try:
                logger.debug(f"Attempt {attempt + 1}/{self.config.retry_count}: {' '.join(cmd[:3])} {' '.join(cmd[5:8])}")
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.config.timeout
                )
                
                if result.returncode != 0:
                    logger.warning(
                        f"Volatility returned code {result.returncode} for: {args[0]}"
                    )
                    if result.stderr:
                        logger.debug(f"stderr: {result.stderr[:200]}")
                
                # Cache successful result
                if self.config.cache_results:
                    self._cache[cache_key] = result.stdout
                
                return result.stdout, result.stderr
            
            except subprocess.TimeoutExpired as e:
                last_error = VolatilityError(
                    f"Volatility command timed out after {self.config.timeout}s: {args[0]}"
                )
                logger.warning(f"Timeout on attempt {attempt + 1}")
                
                if attempt < self.config.retry_count - 1:
                    logger.debug(f"Retrying after {self.config.retry_delay}s...")
                    time.sleep(self.config.retry_delay)
            
            except Exception as e:
                last_error = VolatilityError(f"Failed to run volatility: {e}")
                logger.error(f"Error on attempt {attempt + 1}: {e}")
                
                if attempt < self.config.retry_count - 1:
                    time.sleep(self.config.retry_delay)
        
        if last_error:
            raise last_error
        
        raise VolatilityError(f"Volatility command failed: {' '.join(args)}")
    
    def imageinfo(self) -> Dict[str, Any]:
        """Get image identification information using windows.info plugin.
        
        Returns:
            Dictionary with OS information and detected properties
        """
        logger.info("Analyzing memory dump profile...")
        
        try:
            # Use windows.info plugin (Volatility3)
            stdout, stderr = self._run_command("windows.info")
            
            # Parse key-value pairs from output
            info = {}
            for line in stdout.split('\n'):
                if '\t' in line:
                    key, value = line.split('\t', 1)
                    key = key.strip()
                    value = value.strip()
                    info[key] = value
            
            # Deduce OS information
            is_64bit = info.get('Is64Bit', 'False').lower() == 'true'
            nt_major = info.get('NtMajorVersion', '')
            nt_minor = info.get('NtMinorVersion', '')
            nt_build = info.get('NTBuildLab', '')
            
            logger.debug(f"Windows info: {nt_major}.{nt_minor}, 64bit={is_64bit}, build={nt_build}")
            
            # Build profile suggestion
            profiles = []
            if nt_major and nt_minor:
                # Map Windows versions to common profiles
                version_key = f"{nt_major}.{nt_minor}"
                arch = "x64" if is_64bit else "x86"
                
                profile_map = {
                    "5.1": "WinXP",      # Windows XP
                    "5.2": "Win2003",    # Windows 2003
                    "6.0": "Vista",      # Vista
                    "6.1": "Win7",       # Windows 7
                    "6.2": "Win8",       # Windows 8
                    "6.3": "Win81",      # Windows 8.1
                    "10.0": "Win10",     # Windows 10
                }
                
                base_profile = profile_map.get(version_key)
                if base_profile:
                    profiles.append(f"{base_profile}{arch}")
                    logger.info(f"Inferred profile: {base_profile}{arch}")
            
            return {
                "raw": stdout,
                "profiles": profiles,
                "is_windows": bool(nt_major),
                "is_linux": False,
                "info": info
            }
        
        except VolatilityError as e:
            logger.warning(f"Profile identification failed: {e}")
            return {"raw": "", "profiles": [], "error": str(e)}
    
    def pslist(self) -> str:
        """List processes in memory dump.
        
        Returns:
            Process list output
        """
        logger.debug("Fetching process list...")
        stdout, _ = self._run_command("windows.pslist")
        return stdout
    
    def yarascan(self, rule_file: Path) -> str:
        """Run YARA scan on memory dump.
        
        Args:
            rule_file: Path to YARA rule file
            
        Returns:
            Scan output
            
        Raises:
            VolatilityError: If rule file doesn't exist
        """
        if not rule_file.exists():
            raise VolatilityError(f"YARA rule file not found: {rule_file}")
        
        logger.info(f"Running YARA scan with {rule_file.name}")
        stdout, _ = self._run_command("windows.vadyarascan", f"--yara-file={rule_file}")
        
        match_count = stdout.count("Rule:")
        logger.debug(f"YARA scan found {match_count} rule matches")
        
        return stdout
    
    def malfind(self) -> str:
        """Scan for suspicious injected code.
        
        Returns:
            Malfind output
        """
        logger.info("Running Malfind scan...")
        stdout, _ = self._run_command("windows.malfind")
        
        process_count = stdout.count("Process:")
        logger.debug(f"Malfind found {process_count} suspicious processes")
        
        return stdout
    
    def netscan(self) -> str:
        """Scan network connections.
        
        Returns:
            Network scan output
        """
        logger.info("Running network scan (netscan)...")
        stdout, _ = self._run_command("windows.netscan")
        
        connection_count = len([l for l in stdout.split('\n') if l.strip()])
        logger.debug(f"Found {connection_count} network connections")
        
        return stdout
    
    def connscan(self) -> str:
        """Scan for connection objects (legacy, older Windows versions).
        
        Returns:
            Connection scan output
        """
        logger.info("Running legacy connection scan (connscan)...")
        stdout, _ = self._run_command("windows.connscan")
        return stdout
    
    def procdump(self, pid: str, output_dir: Path) -> Optional[Path]:
        """Dump process memory.
        
        Args:
            pid: Process ID to dump
            output_dir: Directory to save dump
            
        Returns:
            Path to dumped file, or None if failed
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Dumping process {pid}...")
        stdout, _ = self._run_command(
            "windows.procdump",
            f"--pid={pid}",
            f"--dump-dir={output_dir}"
        )
        
        # Parse output to find the dumped file
        # Vol3 output typically contains the saved filename
        for line in stdout.split('\n'):
            if 'Dumped' in line or 'Saved' in line or pid in line:
                logger.debug(f"Procdump output: {line}")
                
                # Try to extract file path
                if output_dir.name in line:
                    parts = line.split()
                    for part in parts:
                        if part.endswith('.dmp') or part.endswith('.bin'):
                            dump_file = output_dir / part
                            if dump_file.exists():
                                logger.success(f"Dumped to {dump_file}")
                                return dump_file
        
        logger.warning(f"Could not locate dumped file for PID {pid}")
        return None
    
    def handles(self, pid: str) -> str:
        """Get process handles.
        
        Args:
            pid: Process ID
            
        Returns:
            Handles output
        """
        logger.debug(f"Collecting handles for PID {pid}...")
        stdout, _ = self._run_command("windows.handles", f"--pid={pid}")
        
        handle_count = stdout.count('0x')  # Rough count of handles
        logger.debug(f"Found ~{handle_count} handles for PID {pid}")
        
        return stdout
    
    def clear_cache(self) -> None:
        """Clear the result cache."""
        self._cache.clear()
        logger.debug("Cache cleared")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics.
        
        Returns:
            Dictionary with cache info
        """
        return {
            "size": len(self._cache),
            "entries": list(self._cache.keys()),
            "memory_bytes": sum(len(v) for v in self._cache.values())
        }
