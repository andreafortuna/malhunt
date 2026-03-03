"""Artifact collection and antivirus scanning."""

from pathlib import Path
from typing import Optional

from loguru import logger

from .models import SuspiciousProcess
from .volatility import VolatilityWrapper


class ArtifactCollector:
    """Collect and manage process artifacts."""
    
    def __init__(self, vol: VolatilityWrapper, output_dir: Path):
        """Initialize artifact collector.
        
        Args:
            vol: Volatility wrapper instance
            output_dir: Directory to save artifacts
        """
        self.vol = vol
        self.output_dir = Path(output_dir)
        self.artifacts_dir = self.output_dir / f"{output_dir.name}_artifacts"
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
    
    def dump_process(self, process: SuspiciousProcess) -> Optional[Path]:
        """Dump suspicious process memory.
        
        Args:
            process: Suspicious process to dump
            
        Returns:
            Path to dumped file, or None if failed
        """
        logger.info(f"Dumping process: {process.process} (PID: {process.pid})")
        
        try:
            dumped_file = self.vol.procdump(process.pid, self.artifacts_dir)
            
            if dumped_file:
                size_mb = dumped_file.stat().st_size / (1024 * 1024)
                logger.success(f"✅ Dumped {dumped_file.name} ({size_mb:.2f} MB)")
                return Path(dumped_file)
            else:
                logger.warning(f"Procdump did not return a file path for PID {process.pid}")
                return None
        
        except Exception as e:
            logger.error(f"Process dump failed: {e}")
            return None
    
    def collect_handles(self, process: SuspiciousProcess) -> Optional[Path]:
        """Collect process handles information.
        
        Args:
            process: Process to collect handles for
            
        Returns:
            Path to handles file, or None if failed
        """
        logger.debug(f"Collecting handles for PID {process.pid}...")
        
        try:
            handles_output = self.vol.handles(process.pid)
            
            handles_file = self.artifacts_dir / f"{process.pid}.handles"
            handles_file.write_text(handles_output)
            
            lines = len(handles_output.split('\n'))
            logger.debug(f"Handles saved: {handles_file.name} ({lines} lines)")
            return handles_file
        
        except Exception as e:
            logger.error(f"Handles collection failed: {e}")
            return None


class ClamavScanner:
    """Antivirus scanning using ClamAV.
    
    Integrates with ClamAV for scanning dumped process artifacts.
    Provides detection results and malware identification.
    """
    
    def __init__(self):
        """Initialize ClamAV scanner."""
        self._clamscan_bin = self._find_clamscan()
        
        if self._clamscan_bin:
            logger.success(f"ClamAV found: {self._clamscan_bin}")
        else:
            logger.warning("ClamAV (clamscan) not found in PATH - antivirus scanning disabled")
    
    @staticmethod
    def _find_clamscan() -> Optional[Path]:
        """Find clamscan executable.
        
        Returns:
            Path to clamscan, or None if not found
        """
        import subprocess
        
        try:
            result = subprocess.run(
                ["which", "clamscan"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return Path(result.stdout.strip())
        except Exception as e:
            logger.debug(f"Error finding clamscan: {e}")
        
        return None
    
    def is_available(self) -> bool:
        """Check if ClamAV is available.
        
        Returns:
            True if clamscan is available
        """
        return self._clamscan_bin is not None
    
    def scan(self, file_path: Path) -> Optional[str]:
        """Scan file with ClamAV.
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            Scan result (OK, INFECTED, or detection name), or None if ClamAV not available
        """
        if not self.is_available():
            logger.debug("ClamAV not available, skipping scan")
            return None
        
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return None
        
        file_size_mb = file_path.stat().st_size / (1024 * 1024)
        logger.debug(f"Scanning {file_path.name} ({file_size_mb:.2f} MB) with ClamAV")
        
        import subprocess
        
        try:
            result = subprocess.run(
                [str(self._clamscan_bin), "--no-summary", str(file_path)],
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes for antivirus scan
            )
            
            # Parse result line
            # Format: "filename: INFECTION/OK"
            if result.stdout:
                parts = result.stdout.split(":")
                if len(parts) >= 2:
                    status = parts[1].strip().split()[0]
                    logger.debug(f"ClamAV result: {status}")
                    return status
            
            return "UNKNOWN"
        
        except subprocess.TimeoutExpired:
            logger.error(f"ClamAV scan timed out for {file_path.name}")
            return "TIMEOUT"
        except Exception as e:
            logger.error(f"ClamAV scan failed: {e}")
            return None
