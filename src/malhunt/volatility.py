"""Volatility3 wrapper and integration."""

import json
import os
import re
import shlex
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import time

from loguru import logger


class VolatilityError(Exception):
    """Exception raised for Volatility-related errors."""

    def __init__(
        self,
        message: str,
        plugin: Optional[str] = None,
        returncode: Optional[int] = None,
        stdout: str = "",
        stderr: str = "",
    ):
        super().__init__(message)
        self.plugin = plugin
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@dataclass
class VolatilityConfig:
    """Configuration for Volatility execution."""
    timeout: int = 300  # 5 minutes default
    retry_count: int = 1
    retry_delay: float = 1.0
    cache_results: bool = True
    # optional directories where symbol tables are stored; will be passed to
    # Volatility via ``--symbol-dirs`` joined using os.pathsep
    symbol_dirs: List[Path] = None


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
        if self.config.symbol_dirs:
            logger.debug(f"Symbol dirs: {[str(p) for p in self.config.symbol_dirs]}")
    
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
        
        cmd = [str(self._volatility_bin), "-f", str(self.dump_path)]
        # include symbol directories if configured
        if self.config.symbol_dirs:
            dirs = os.pathsep.join(str(p) for p in self.config.symbol_dirs)
            cmd.append(f"--symbol-dirs={dirs}")
        cmd += list(args)
        
        last_error = None
        
        for attempt in range(self.config.retry_count):
            try:
                logger.debug(
                    f"Attempt {attempt + 1}/{self.config.retry_count}: {shlex.join(cmd)}"
                )
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.config.timeout
                )
                
                if result.returncode != 0:
                    plugin_name = args[0] if args else "<unknown-plugin>"
                    stdout_excerpt = (result.stdout or "")[:4000]
                    stderr_excerpt = (result.stderr or "")[:4000]
                    logger.warning(
                        f"Volatility returned code {result.returncode} for: {plugin_name}"
                    )
                    if stdout_excerpt:
                        logger.debug(f"stdout: {stdout_excerpt}")
                    if stderr_excerpt:
                        logger.debug(f"stderr: {stderr_excerpt}")

                    last_error = VolatilityError(
                        f"Volatility command failed ({result.returncode}) for {plugin_name}",
                        plugin=plugin_name,
                        returncode=result.returncode,
                        stdout=result.stdout or "",
                        stderr=result.stderr or "",
                    )
                    if attempt < self.config.retry_count - 1:
                        logger.debug(f"Retrying after {self.config.retry_delay}s...")
                        time.sleep(self.config.retry_delay)
                        continue
                    raise last_error

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
            
            except VolatilityError:
                raise

            except Exception as e:
                last_error = VolatilityError(f"Failed to run volatility: {e}")
                logger.error(f"Error on attempt {attempt + 1}: {e}")
                
                if attempt < self.config.retry_count - 1:
                    time.sleep(self.config.retry_delay)
        
        if last_error:
            raise last_error
        
        raise VolatilityError(f"Volatility command failed: {' '.join(args)}")

    @staticmethod
    def is_symbol_requirement_error(error: Exception) -> bool:
        """Return True if error indicates missing/unsatisfied Volatility symbols."""
        if not isinstance(error, VolatilityError):
            return False
        combined = "\n".join([str(error), error.stdout or "", error.stderr or ""]).lower()
        return (
            "symbol table requirement" in combined
            or "unsatisfied requirement" in combined
            or "symbol_table_name" in combined
        )

    @staticmethod
    def _extract_symbol_download_urls(text: str) -> List[str]:
        """Extract symbol-server download URLs from Volatility output text."""
        pattern = re.compile(r"https?://[^\s]+/download/symbols/[^\s]+", re.IGNORECASE)
        urls = pattern.findall(text or "")
        seen = []
        for url in urls:
            cleaned = url.strip().rstrip(")]")
            if cleaned not in seen:
                seen.append(cleaned)
        return seen

    @staticmethod
    def _alternate_symbol_url(url: str) -> Optional[str]:
        """Build alternate symbol URL variant (.pdb <-> .pd_) if possible."""
        if url.endswith(".pd_"):
            return url[:-1] + "b"
        if url.endswith(".pdb"):
            return url[:-1] + "_"
        return None

    def auto_recover_windows_symbols(self, error: VolatilityError) -> bool:
        """Best-effort recovery of missing Windows symbol files.

        Attempts to download referenced symbol files from URLs present in
        Volatility output and place them under the local symbol directory tree.

        Returns:
            True if at least one symbol file was downloaded, False otherwise.
        """
        payload = "\n".join([str(error), error.stdout or "", error.stderr or ""])
        urls = self._extract_symbol_download_urls(payload)
        if not urls:
            logger.warning("No downloadable symbol URLs found in Volatility output")
            return False

        symbol_root = None
        for directory in self.config.symbol_dirs or []:
            directory = Path(directory)
            if directory.name == "windows":
                symbol_root = directory
                break
        if symbol_root is None:
            base = Path.home() / ".malhunt" / "symbols"
            symbol_root = base / "windows"
        symbol_root.mkdir(parents=True, exist_ok=True)

        downloaded_any = False

        for url in urls:
            candidates = [url]
            alternate = self._alternate_symbol_url(url)
            if alternate and alternate not in candidates:
                candidates.append(alternate)

            # Expected layout: .../download/symbols/<pdb_name>/<GUIDAGE>/<filename>
            parts = [p for p in url.split("/") if p]
            if len(parts) < 3:
                continue
            pdb_name = parts[-3]
            guidage = parts[-2]
            target_dir = symbol_root / pdb_name / guidage
            target_dir.mkdir(parents=True, exist_ok=True)

            for candidate_url in candidates:
                filename = candidate_url.rsplit("/", 1)[-1]
                target_file = target_dir / filename
                if target_file.exists() and target_file.stat().st_size > 0:
                    logger.debug(f"Symbol file already present: {target_file}")
                    downloaded_any = True
                    continue

                try:
                    logger.info(f"Attempting symbol download: {candidate_url}")
                    with urllib.request.urlopen(candidate_url, timeout=60) as response:
                        data = response.read()
                    if not data:
                        logger.debug(f"No data returned for {candidate_url}")
                        continue
                    target_file.write_bytes(data)
                    logger.success(f"Downloaded symbol candidate: {target_file}")
                    downloaded_any = True
                except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
                    logger.debug(f"Symbol download failed for {candidate_url}: {exc}")

        if not downloaded_any:
            logger.warning("Automatic symbol recovery did not download any files")
        return downloaded_any

    def get_symbol_diagnostics(self, error: VolatilityError) -> Dict[str, Any]:
        """Build a human-friendly diagnostics report for symbol failures.

        Args:
            error: VolatilityError raised by a plugin invocation

        Returns:
            Dictionary with plugin name, missing requirements and PDB hints.
        """
        payload = "\n".join([str(error), error.stdout or "", error.stderr or ""])
        urls = self._extract_symbol_download_urls(payload)

        # collect unsatisfied requirement names when present
        requirement_matches = re.findall(
            r"Unsatisfied requirement\s+([^:]+):",
            payload,
            flags=re.IGNORECASE,
        )
        requirements = []
        for req in requirement_matches:
            req = req.strip()
            if req and req not in requirements:
                requirements.append(req)

        missing_symbols = []
        for url in urls:
            parts = [p for p in url.split("/") if p]
            if len(parts) < 3:
                continue
            pdb_name = parts[-3]
            guidage = parts[-2]
            filename = parts[-1]
            missing_symbols.append(
                {
                    "pdb_name": pdb_name,
                    "guidage": guidage,
                    "filename": filename,
                    "url": url,
                }
            )

        return {
            "plugin": error.plugin or "unknown",
            "returncode": error.returncode,
            "requirements": requirements,
            "missing_symbols": missing_symbols,
            "auto_symbols_enabled": True,
        }
    
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
            # Format: "Variable        Value" (older versions also printed
            # "Suggested : <profile>,…")
            info: dict[str, str] = {}
            suggested: list[str] = []
            for line in stdout.split('\n'):
                # Skip headers and empty lines
                if not line.strip() or line.startswith('Variable') or line.startswith('---'):
                    continue

                # detect any suggested profile line (case‑insensitive)
                if line.lower().startswith('suggested'):
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        suggested = [p.strip() for p in parts[1].split(',') if p.strip()]
                    continue

                # Split on whitespace - key is first word(s), value is last word
                parts = line.split()
                if len(parts) >= 2:
                    # For multi-word keys like "Major/Minor", "PE MajorOperatingSystemVersion"
                    # Value is the last part, rest is the key
                    value = parts[-1]
                    key = ' '.join(parts[:-1])

                    # Store in lowercase for easier access
                    info[key.lower()] = value

            # Deduce OS information
            is_64bit = info.get('is64bit', 'False').lower() == 'true'
            nt_major = info.get('ntmajorversion', '')
            nt_minor = info.get('ntminorversion', '')
            build_lab = info.get('ntbuildlab', '')
            nt_product = info.get('ntproducttype', '')
            
            logger.debug(f"Windows version: {nt_major}.{nt_minor}, 64bit={is_64bit}, build={build_lab}")
            
            # Build OS description
            os_name = "Unknown"
            if nt_major and nt_minor:
                # Map Windows versions to common names
                version_key = f"{nt_major}.{nt_minor}"
                arch = "x64" if is_64bit else "x86"
                
                version_map = {
                    "5.1": "Windows XP",      # Windows XP
                    "5.2": "Windows 2003",    # Windows 2003
                    "6.0": "Windows Vista",   # Vista
                    "6.1": "Windows 7",       # Windows 7
                    "6.2": "Windows 8",       # Windows 8
                    "6.3": "Windows 8.1",     # Windows 8.1
                    "10.0": "Windows 10",     # Windows 10
                }
                
                base_name = version_map.get(version_key, f"Windows {version_key}")
                os_name = f"{base_name} ({arch})"
                logger.info(f"Detected OS: {os_name}")
            
            return {
                "raw": stdout,
                "os_name": os_name,
                "is_64bit": is_64bit,
                "is_windows": bool(nt_major),
                "is_linux": False,
                "version": f"{nt_major}.{nt_minor}" if nt_major else "",
                "build": build_lab,
                "info": info,
                "suggested_profiles": suggested
            }
        
        except VolatilityError as e:
            logger.warning(f"Profile identification failed: {e}")
            return {
                "raw": "", 
                "os_name": "Unknown",
                "error": str(e)
            }
    
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

        attempt_file = rule_file
        for attempt in range(5):
            try:
                stdout, _ = self._run_command("windows.vadyarascan", f"--yara-file={attempt_file}")
                match_count = stdout.count("Rule:")
                logger.debug(f"YARA scan found {match_count} rule matches")
                return stdout
            except VolatilityError as error:
                line_number = self._extract_yara_syntax_error_line(error)
                if line_number is None:
                    raise

                sanitized_candidate = attempt_file.with_suffix(f".retry{attempt + 1}.yar")
                removed = self._drop_rule_block_at_line(attempt_file, sanitized_candidate, line_number)
                if not removed:
                    raise

                logger.warning(
                    f"Retrying YARA scan after removing incompatible rule around line {line_number}"
                )
                attempt_file = sanitized_candidate

        raise VolatilityError("YARA scan failed after repeated syntax-error recovery attempts")

    @staticmethod
    def _extract_yara_syntax_error_line(error: VolatilityError) -> Optional[int]:
        payload = "\n".join([error.stdout or "", error.stderr or "", str(error)])
        match = re.search(r"yara\.SyntaxError:\s*line\s*(\d+)\s*:", payload)
        if not match:
            return None
        try:
            return int(match.group(1))
        except ValueError:
            return None

    @staticmethod
    def _drop_rule_block_at_line(source: Path, destination: Path, line_number: int) -> bool:
        """Drop the YARA rule block around a 1-based line number.

        Returns True if a block (or at least a line) was removed.
        """
        lines = source.read_text(errors="ignore").splitlines(keepends=True)
        if not lines:
            return False

        index = max(0, min(len(lines) - 1, line_number - 1))
        rule_start = re.compile(r"^\s*(?:(?:private|global)\s+)*rule\s+[A-Za-z0-9_]+\b")

        start = None
        for i in range(index, -1, -1):
            if rule_start.match(lines[i]):
                start = i
                break

        if start is None:
            # fallback: drop the offending line only
            trimmed = lines[:index] + lines[index + 1 :]
            destination.write_text("".join(trimmed))
            return True

        depth = 0
        seen_open = False
        end = start
        for j in range(start, len(lines)):
            depth += lines[j].count("{") - lines[j].count("}")
            if "{" in lines[j]:
                seen_open = True
            end = j
            if seen_open and depth <= 0:
                break

        trimmed = lines[:start] + lines[end + 1 :]
        destination.write_text("".join(trimmed))
        return True
    
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
        try:
            stdout, _ = self._run_command("windows.netscan")
        except VolatilityError as error:
            details = "\n".join([str(error), error.stdout or "", error.stderr or ""]).lower()
            if "notimplementederror" in details or "not supported" in details:
                logger.warning("windows.netscan unsupported for this image - falling back to windows.netstat")
                try:
                    stdout, _ = self._run_command("windows.netstat")
                except VolatilityError as netstat_error:
                    netstat_details = "\n".join(
                        [str(netstat_error), netstat_error.stdout or "", netstat_error.stderr or ""]
                    ).lower()
                    if "notimplementederror" in netstat_details or "not supported" in netstat_details:
                        logger.warning("windows.netstat is also unsupported for this image")
                        return ""
                    raise
            else:
                raise
        
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
