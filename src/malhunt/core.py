"""Core malhunt orchestration logic."""

import subprocess
from pathlib import Path
from typing import Callable, List, Optional

from loguru import logger

from .artifacts import ArtifactCollector, ClamavScanner
from .models import SuspiciousProcess
from .scanner import MalfindScanner, NetworkScanner, YaraScanner
from .utils import (
    banner_logo, clean_up, get_malhunt_home,
    list_yara_files, merge_rules, remove_incompatible_imports
)
from .volatility import VolatilityWrapper, VolatilityConfig, VolatilityError


class Malhunt:
    """Main malhunt orchestrator for malware hunting in memory dumps.
    
    Coordinates the analysis pipeline:
    1. Environment setup and validation
    2. YARA rule preparation
    3. Memory profile identification
    4. Multi-phase scanning (YARA, Malfind, Network)
    5. Artifact collection and analysis
    6. Results reporting
    """
    
    DEFAULT_EXCLUDED_WORDS = ['Str_Win32_', 'SurtrStrings']
    
    def __init__(self, dump_path: Path, rules_file: Optional[Path] = None,
                 vol_config: Optional[VolatilityConfig] = None):
        """Initialize Malhunt.
        
        Args:
            dump_path: Path to memory dump file
            rules_file: Optional path to custom YARA rules file
            vol_config: Optional VolatilityConfig for customization
            
        Raises:
            VolatilityError: If Volatility is not available
        """
        self.dump_path = Path(dump_path)
        self.malhunt_home = get_malhunt_home()
        self.rules_file = rules_file or (self.malhunt_home / "malware_rules.yar")
        
        logger.info(f"Initializing Malhunt for {dump_path.name}")
        logger.debug(f"Dump size: {dump_path.stat().st_size / (1024**3):.2f} GB")
        logger.debug(f"Malhunt home: {self.malhunt_home}")
        
        # Initialize Volatility wrapper
        try:
            self.vol = VolatilityWrapper(dump_path, vol_config)
        except VolatilityError as e:
            logger.error(f"Volatility initialization failed: {e}")
            raise
        
        # Initialize scanners
        self.yara_scanner: Optional[YaraScanner] = None
        self.malfind_scanner = MalfindScanner(self.vol)
        self.network_scanner = NetworkScanner(self.vol, self._check_malicious_ip)
        
        # Initialize artifact collector
        artifacts_parent = dump_path.parent / dump_path.stem
        self.artifacts = ArtifactCollector(self.vol, artifacts_parent)
        
        # Initialize antivirus
        self.antivirus = ClamavScanner()
        
        self.scan_results: List[SuspiciousProcess] = []
        
        logger.success("Malhunt initialized successfully")
    
    def prepare_rules(self) -> bool:
        """Prepare YARA rules, downloading if necessary.
        
        Returns:
            True if rules are available, False otherwise
        """
        if self.rules_file.exists():
            file_age = self.rules_file.stat().st_mtime
            import time
            age_days = (time.time() - file_age) / (60 * 60 * 24)
            logger.info(f"Using cached YARA rules ({age_days:.1f} days old)")
            return True
        
        logger.info("Preparing YARA rules - downloading from repository...")
        
        try:
            rules_dir = self.malhunt_home / "rules"
            
            # Clone rules repository
            logger.debug("Cloning Yara-Rules/rules repository...")
            result = subprocess.run(
                [
                    "git", "clone",
                    "--depth", "1",  # Shallow clone to save bandwidth
                    "https://github.com/Yara-Rules/rules.git",
                    str(rules_dir)
                ],
                capture_output=True,
                timeout=300
            )
            
            if result.returncode != 0:
                logger.error("Failed to download rules")
                if result.stderr:
                    logger.debug(f"Git error: {result.stderr.decode()}")
                return False
            
            logger.info("Processing YARA rules...")
            
            # Process rules
            all_files = list_yara_files(self.malhunt_home)
            logger.info(f"Found {len(all_files)} YARA files")
            
            filtered_files = remove_incompatible_imports(all_files)
            logger.info(f"Filtered to {len(filtered_files)} compatible files")
            
            merge_rules(filtered_files, self.rules_file)
            
            logger.success(f"YARA rules prepared: {self.rules_file}")
            return True
        
        except subprocess.TimeoutExpired:
            logger.error("YARA rules download timed out")
            return False
        except Exception as e:
            logger.error(f"Error preparing rules: {e}")
            return False
    
    def identify_profile(self) -> Optional[str]:
        """Identify the memory dump profile.
        
        Returns:
            Profile name (e.g., "Windows.7"), or None if identification failed
        """
        logger.info("Identifying memory dump profile...")
        
        try:
            imageinfo = self.vol.imageinfo()
            
            if imageinfo.get("profiles"):
                profile = imageinfo["profiles"][0]
                logger.success(f"Memory profile: {profile}")
                return profile
            else:
                logger.warning("Could not determine memory profile - will attempt generic scans")
                return None
        
        except Exception as e:
            logger.error(f"Profile identification failed: {e}")
            return None
    
    def run_scans(self) -> List[SuspiciousProcess]:
        """Run all configured scans.
        
        Returns:
            List of suspicious processes found
        """
        logger.info("=" * 70)
        logger.info("Starting comprehensive malware scan")
        logger.info("=" * 70)
        
        results = []
        scan_phases = []
        
        # YARA scan
        if self.rules_file.exists() and self.yara_scanner is None:
            self.yara_scanner = YaraScanner(
                self.vol,
                self.rules_file,
                self.DEFAULT_EXCLUDED_WORDS
            )
        
        if self.yara_scanner:
            try:
                logger.info("📊 Phase 1/3: YARA Rule Scanning")
                yara_results = self.yara_scanner.scan()
                results.extend(yara_results)
                scan_phases.append(f"YARA: {len(yara_results)} findings")
            except Exception as e:
                logger.error(f"YARA scan failed: {e}")
                scan_phases.append(f"YARA: ERROR")
        else:
            logger.warning("YARA rules not available - skipping YARA scan")
        
        # Malfind scan
        try:
            logger.info("💉 Phase 2/3: Code Injection Scanning (Malfind)")
            malfind_results = self.malfind_scanner.scan()
            results.extend(malfind_results)
            scan_phases.append(f"Malfind: {len(malfind_results)} findings")
        except Exception as e:
            logger.error(f"Malfind scan failed: {e}")
            scan_phases.append(f"Malfind: ERROR")
        
        # Network scan
        try:
            logger.info("🌐 Phase 3/3: Network Analysis")
            network_results = self.network_scanner.scan()
            results.extend(network_results)
            scan_phases.append(f"Network: {len(network_results)} findings")
        except Exception as e:
            logger.error(f"Network scan failed: {e}")
            scan_phases.append(f"Network: ERROR")
        
        # Deduplicate by PID
        seen_pids = set()
        unique_results = []
        for proc in results:
            if proc.pid not in seen_pids:
                unique_results.append(proc)
                seen_pids.add(proc.pid)
            else:
                logger.debug(f"Deduplicated: {proc}")
        
        self.scan_results = unique_results
        
        logger.info("=" * 70)
        logger.info(f"Scan Summary:")
        for phase in scan_phases:
            logger.info(f"  - {phase}")
        logger.info(f"Total suspicious processes: {len(self.scan_results)}")
        logger.info("=" * 70)
        
        return self.scan_results
    
    def collect_artifacts(self) -> None:
        """Collect artifacts for all suspicious processes."""
        if not self.scan_results:
            logger.info("No suspicious processes to analyze")
            return
        
        logger.info("=" * 70)
        logger.info(f"Collecting artifacts for {len(self.scan_results)} processes")
        logger.info("=" * 70)
        
        successful = 0
        failed = 0
        infected = 0
        
        for idx, proc in enumerate(self.scan_results, 1):
            logger.info(f"\n[{idx}/{len(self.scan_results)}] {proc.process} (PID: {proc.pid})")
            logger.info(f"    Detection: {proc.rule}")
            
            # Dump process memory
            dump_file = self.artifacts.dump_process(proc)
            if not dump_file:
                logger.error(f"Failed to dump process")
                failed += 1
                continue
            
            successful += 1
            
            # Collect handles
            self.artifacts.collect_handles(proc)
            
            # Scan with antivirus
            if self.antivirus.is_available():
                logger.info(f"    Scanning with ClamAV...")
                result = self.antivirus.scan(dump_file)
                if result:
                    if result == "OK":
                        logger.success(f"    ClamAV: {result}")
                    else:
                        logger.error(f"    ClamAV: {result} ⚠️ INFECTED")
                        infected += 1
            else:
                logger.debug("ClamAV not available")
        
        logger.info("=" * 70)
        logger.info(f"Artifact Collection Summary:")
        logger.info(f"  ✅ Successful: {successful}")
        logger.info(f"  ❌ Failed: {failed}")
        if infected > 0:
            logger.error(f"  ⚠️  Infected: {infected}")
        logger.info(f"  📁 Location: {self.artifacts.artifacts_dir}")
        logger.info("=" * 70)
    
    def run_full_analysis(self) -> None:
        """Run the complete malhunt analysis workflow."""
        logger.info("╔" + "═" * 68 + "╗")
        logger.info("║  MALHUNT v0.4 - Malware Hunting with Volatility3" + " " * 16 + "║")
        logger.info("╚" + "═" * 68 + "╝")
        
        print("\n" + banner_logo())
        
        # Clean up old caches
        clean_up(self.malhunt_home)
        
        # Prepare YARA rules
        if not self.prepare_rules():
            logger.error("Failed to prepare YARA rules")
            return
        
        # Identify memory profile
        profile = self.identify_profile()
        if profile:
            logger.info(f"Identified profile: {profile}")
        
        # Run scans
        self.run_scans()
        
        # Collect artifacts
        if self.scan_results:
            self.collect_artifacts()
            logger.success(f"✅ Analysis complete - Artifacts saved to {self.artifacts.artifacts_dir}")
        else:
            logger.success("✅ Analysis complete - No artifacts found")
        
        logger.info("╔" + "═" * 68 + "╗")
        logger.info("║  Analysis finished successfully!" + " " * 34 + "║")
        logger.info("╚" + "═" * 68 + "╝")
    
    @staticmethod
    def _check_malicious_ip(ip: str) -> bool:
        """Check if IP is malicious using external service.
        
        Args:
            ip: IP address to check
            
        Returns:
            True if IP is marked as malicious
            
        Note:
            This is a placeholder. Production implementation would use
            a proper threat intelligence service with rate limiting.
        """
        try:
            import requests
            
            logger.debug(f"Checking IP: {ip}")
            response = requests.get(
                f"http://check.getipintel.net/check.php?ip={ip}&contact=abuse@getipintel.net",
                timeout=10
            )
            
            is_malicious = response.text == "1"
            if is_malicious:
                logger.warning(f"Malicious IP detected: {ip}")
            
            return is_malicious
        
        except Exception as e:
            logger.debug(f"IP check failed for {ip}: {e}")
            return False
