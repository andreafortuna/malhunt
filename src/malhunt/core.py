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
    sanitize_yara_rules_file, validate_and_prune_yara_rules_file
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
                 vol_config: Optional[VolatilityConfig] = None,
                 auto_symbols: bool = True):
        """Initialize Malhunt.
        
        Args:
            dump_path: Path to memory dump file
            rules_file: Optional path to custom YARA rules file
            vol_config: Optional VolatilityConfig for customization
            auto_symbols: Try automatic best-effort recovery of missing Windows
                kernel symbols when Volatility reports symbol requirement errors
            
        Raises:
            VolatilityError: If Volatility is not available
        """
        self.dump_path = Path(dump_path)
        self.malhunt_home = get_malhunt_home()
        self.rules_file = rules_file or (self.malhunt_home / "malware_rules.yar")
        self.auto_symbols = auto_symbols

        # prepare volatility config with symbol directory(ies)
        sym_base = self.malhunt_home / "symbols"
        default_symbol_dirs = [
            sym_base,
            sym_base / "windows",
            sym_base / "windows" / "windows",
            sym_base / "linux",
            sym_base / "linux" / "linux",
            sym_base / "mac",
        ]
        if vol_config is None:
            self.vol_cfg = VolatilityConfig(symbol_dirs=default_symbol_dirs)
        else:
            existing = list(vol_config.symbol_dirs or [])
            merged = []
            for directory in existing + default_symbol_dirs:
                if directory not in merged:
                    merged.append(directory)
            self.vol_cfg = VolatilityConfig(
                timeout=vol_config.timeout,
                retry_count=vol_config.retry_count,
                retry_delay=vol_config.retry_delay,
                cache_results=vol_config.cache_results,
                symbol_dirs=merged,
            )

        logger.info(f"Initializing Malhunt for {dump_path.name}")
        logger.debug(f"Dump size: {dump_path.stat().st_size / (1024**3):.2f} GB")
        logger.debug(f"Malhunt home: {self.malhunt_home}")

        # Initialize Volatility wrapper with correct config
        try:
            self.vol = VolatilityWrapper(dump_path, self.vol_cfg)
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
        """Backward-compatible helper to prepare only YARA rules.

        Returns:
            True if YARA rules are available, False otherwise
        """
        import time, requests, zipfile, io, shutil

        if self.rules_file.exists():
            sanitized_tmp = self.rules_file.with_suffix(self.rules_file.suffix + ".tmp")
            removed_rules = sanitize_yara_rules_file(self.rules_file, sanitized_tmp)
            parsed_tmp = self.rules_file.with_suffix(self.rules_file.suffix + ".parsed")
            removed_parse = validate_and_prune_yara_rules_file(sanitized_tmp, parsed_tmp)
            parsed_tmp.replace(self.rules_file)
            if sanitized_tmp.exists():
                sanitized_tmp.unlink(missing_ok=True)
            total_removed = removed_rules + removed_parse
            if total_removed:
                logger.warning(f"Removed {total_removed} incompatible YARA rules from cache")
            file_age = self.rules_file.stat().st_mtime
            age_days = (time.time() - file_age) / (60 * 60 * 24)
            logger.info(f"Using cached YARA rules ({age_days:.1f} days old)")
            return True

        logger.info("Preparing YARA rules - downloading from YaraForge zip...")
        try:
            rules_dir = self.malhunt_home / "rules"
            rules_dir.mkdir(parents=True, exist_ok=True)
            url = (
                "https://github.com/YARAHQ/yara-forge/releases/latest/"
                "download/yara-forge-rules-full.zip"
            )
            logger.debug(f"Downloading rules from {url}")
            resp = requests.get(url, timeout=300)
            resp.raise_for_status()
            with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
                extracted_path: Optional[Path] = None
                for name in z.namelist():
                    if name.lower().endswith(".yar"):
                        z.extract(name, rules_dir)
                        extracted_path = rules_dir / name
                        break
            if not extracted_path or not extracted_path.exists():
                logger.error("No YARA file found in archive")
                return False

            logger.info("Processing downloaded YARA rules...")
            sanitized_tmp = self.rules_file.with_suffix(self.rules_file.suffix + ".tmp")
            removed_rules = sanitize_yara_rules_file(extracted_path, sanitized_tmp)
            removed_parse = validate_and_prune_yara_rules_file(sanitized_tmp, self.rules_file)
            if sanitized_tmp.exists():
                sanitized_tmp.unlink(missing_ok=True)
            total_removed = removed_rules + removed_parse
            if total_removed:
                logger.warning(f"Removed {total_removed} incompatible YARA rules")
            logger.success(f"YARA rules prepared: {self.rules_file}")
            return True
        except Exception as e:
            logger.error(f"Error preparing rules: {e}")
            return False
    
    def prepare_rules_and_symbols(self) -> bool:
        """Prepare YARA rules and Volatility symbol tables, downloading if necessary.
        Returns:
            True if both rules and symbols are available, False otherwise
        """
        import time, requests, zipfile, io, shutil
        # --- YARA rules ---
        if self.rules_file.exists():
            sanitized_tmp = self.rules_file.with_suffix(self.rules_file.suffix + ".tmp")
            removed_rules = sanitize_yara_rules_file(self.rules_file, sanitized_tmp)
            parsed_tmp = self.rules_file.with_suffix(self.rules_file.suffix + ".parsed")
            removed_parse = validate_and_prune_yara_rules_file(sanitized_tmp, parsed_tmp)
            parsed_tmp.replace(self.rules_file)
            if sanitized_tmp.exists():
                sanitized_tmp.unlink(missing_ok=True)
            total_removed = removed_rules + removed_parse
            if total_removed:
                logger.warning(f"Removed {total_removed} incompatible YARA rules from cache")
            file_age = self.rules_file.stat().st_mtime
            age_days = (time.time() - file_age) / (60 * 60 * 24)
            logger.info(f"Using cached YARA rules ({age_days:.1f} days old)")
            yara_ok = True
        else:
            logger.info("Preparing YARA rules - downloading from YaraForge zip...")
            try:
                rules_dir = self.malhunt_home / "rules"
                rules_dir.mkdir(parents=True, exist_ok=True)
                url = (
                    "https://github.com/YARAHQ/yara-forge/releases/latest/"
                    "download/yara-forge-rules-full.zip"
                )
                logger.debug(f"Downloading rules from {url}")
                resp = requests.get(url, timeout=300)
                resp.raise_for_status()
                with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
                    extracted_path: Optional[Path] = None
                    for name in z.namelist():
                        if name.lower().endswith(".yar"):
                            z.extract(name, rules_dir)
                            extracted_path = rules_dir / name
                            break
                if not extracted_path or not extracted_path.exists():
                    logger.error("No YARA file found in archive")
                    yara_ok = False
                else:
                    logger.info("Processing downloaded YARA rules...")
                    sanitized_tmp = self.rules_file.with_suffix(self.rules_file.suffix + ".tmp")
                    removed_rules = sanitize_yara_rules_file(extracted_path, sanitized_tmp)
                    removed_parse = validate_and_prune_yara_rules_file(sanitized_tmp, self.rules_file)
                    if sanitized_tmp.exists():
                        sanitized_tmp.unlink(missing_ok=True)
                    total_removed = removed_rules + removed_parse
                    if total_removed:
                        logger.warning(f"Removed {total_removed} incompatible YARA rules")
                    logger.success(f"YARA rules prepared: {self.rules_file}")
                    yara_ok = True
            except Exception as e:
                logger.error(f"Error preparing rules: {e}")
                yara_ok = False

        # --- Symbol tables ---
        urls = {
            "windows": "https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip",
            "mac": "https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip",
            "linux": "https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip",
        }
        base = self.malhunt_home / "symbols"
        base.mkdir(parents=True, exist_ok=True)

        def _normalize_symbol_layout(os_name: str) -> None:
            dest_dir = base / os_name
            nested_dir = dest_dir / os_name
            if not nested_dir.exists() or not nested_dir.is_dir():
                return
            logger.debug(f"Normalizing nested symbol layout in {nested_dir}")
            for child in nested_dir.iterdir():
                target = dest_dir / child.name
                if target.exists():
                    continue
                shutil.move(str(child), str(target))
            shutil.rmtree(nested_dir, ignore_errors=True)

        symbols_ok = True
        for name, url in urls.items():
            dest = base / name
            if dest.exists():
                _normalize_symbol_layout(name)
                logger.debug(f"Symbol directory already present: {dest}")
                continue
            try:
                logger.info(f"Downloading {name} symbols...")
                resp = requests.get(url, timeout=300)
                resp.raise_for_status()
                with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
                    members = [m for m in z.namelist() if not m.endswith("/")]
                    if members and all(m.startswith(f"{name}/") for m in members):
                        z.extractall(base)
                    else:
                        z.extractall(dest)
                _normalize_symbol_layout(name)
                logger.success(f"Symbols for {name} installed in {dest}")
            except Exception as e:
                logger.error(f"Failed to fetch {name} symbols: {e}")
                symbols_ok = False
        return yara_ok and symbols_ok

    # prepare_symbols is now integrated in prepare_rules_and_symbols

    def _preflight_volatility_symbols(self) -> bool:
        """Validate symbol availability before running scanning plugins.

        Returns:
            True when Volatility can resolve kernel symbol table requirements,
            False otherwise.
        """
        logger.info("Validating Volatility symbol requirements...")
        try:
            self.vol._run_command("windows.info", use_cache=False)
            logger.success("Volatility symbol requirements satisfied")
            return True
        except VolatilityError as error:
            if self.auto_symbols and self.vol.is_symbol_requirement_error(error):
                logger.warning("Missing symbols detected - attempting automatic recovery")
                recovered = self.vol.auto_recover_windows_symbols(error)
                if recovered:
                    logger.info("Retrying symbol preflight after recovery...")
                    self.vol.clear_cache()
                    try:
                        self.vol._run_command("windows.info", use_cache=False)
                        logger.success("Symbol recovery successful")
                        return True
                    except VolatilityError as retry_error:
                        logger.error(f"Symbol recovery did not resolve issue: {retry_error}")

            diagnostics = self.vol.get_symbol_diagnostics(error)
            diagnostics = self.vol.enrich_symbol_diagnostics(diagnostics)
            missing_symbols = diagnostics.get("missing_symbols", [])
            requirements = diagnostics.get("requirements", [])

            logger.error("Volatility symbol diagnostics:")
            logger.error(f"  Plugin: {diagnostics.get('plugin')}")
            if requirements:
                logger.error(f"  Unsatisfied requirements: {', '.join(requirements)}")
            if missing_symbols:
                for item in missing_symbols:
                    logger.error(
                        "  Missing symbol: "
                        f"{item.get('pdb_name')} / {item.get('guidage')} "
                        f"({item.get('filename')})"
                    )
                    logger.error(f"    Source URL: {item.get('url')}")
                    if item.get("is_locally_available"):
                        logger.error(f"    Local files: {', '.join(item.get('local_files', []))}")
                    else:
                        logger.error(f"    Local path: {item.get('local_dir')} (missing)")
            else:
                logger.error(
                    "  No symbol-server URL found in Volatility output. "
                    "Check image type, plugin compatibility, and symbol dirs."
                )

            helper_script = diagnostics.get("helper_script")
            if helper_script:
                logger.error(f"  Helper script generated: {helper_script}")
                logger.error(f"  Run: {helper_script}")

            if not self.auto_symbols:
                logger.error("  Tip: rerun with --auto-symbols to attempt best-effort recovery")
            else:
                logger.error(
                    "  Tip: provide the matching PDB/ISF manually in ~/.malhunt/symbols/windows"
                )

            logger.error(
                "Volatility symbol table requirements are not satisfied. "
                "Analysis cannot continue reliably."
            )
            return False
    
    def _validate_profile(self, profile: str) -> bool:
        """Check whether a given Windows profile works against the dump.

        Runs a lightweight command (`pslist`) with `--profile` and returns
        True if Volatility executed successfully and produced output. This
        follows the mechanism suggested in the official Volatility3
        documentation for troubleshooting profile detection.
        """
        try:
            stdout, _ = self.vol._run_command("windows.pslist", f"--profile={profile}", use_cache=False)
            # if anything sensible was returned we assume the profile is valid
            return bool(stdout and "PID" in stdout)
        except Exception:
            return False

    def identify_profile(self) -> Optional[str]:
        """Identify the memory dump OS and version.

        The method consults the output of the `windows.info` plugin and
        applies several heuristics:

        1. If the plugin already reports an `os_name`, use it.
        2. Otherwise, attempt to construct a profile string from the
           reported `ntmajorversion`, `ntminorversion` and architecture
           and validate it by running a trivial command.
        3. Scan for any "Suggested" profiles printed by the plugin and
           try them in order.
        4. Finally, fall back to a small hard‑coded list of common
           profiles if all else fails.

        Returns:
            A human‑readable string (e.g. "Windows 7 (x64)") or None
            if automatic detection could not determine anything.
        """
        logger.info("Identifying memory dump OS and version...")

        try:
            imageinfo = self.vol.imageinfo()
            os_name = imageinfo.get("os_name")
            if os_name:
                logger.success(f"Memory OS: {os_name}")
                return os_name

            info = imageinfo.get("info", {})
            # try to guess profile string from numeric fields
            nt_major = info.get('ntmajorversion', '')
            nt_minor = info.get('ntminorversion', '')
            is_64bit = info.get('is64bit', 'False').lower() == 'true'
            if nt_major and nt_minor:
                arch = 'x64' if is_64bit else 'x86'
                candidate = f"Windows.{nt_major}{nt_minor}{arch}"
                if self._validate_profile(candidate):
                    logger.success(f"Guessed valid profile: {candidate}")
                    return candidate

            # try suggested profiles from plugin
            for cand in imageinfo.get('suggested_profiles', []):
                if self._validate_profile(cand):
                    logger.success(f"Using suggested profile: {cand}")
                    return cand

            # last‑ditch fallbacks
            for cand in ["Windows.7SP1x64", "Windows.10x64", "Windows.8.1x64"]:
                if self._validate_profile(cand):
                    logger.success(f"Fallback profile worked: {cand}")
                    return cand

            logger.warning("Could not determine memory OS - will attempt with Volatility3 autodetection")
            return None

        except Exception as e:
            logger.error(f"OS identification failed: {e}")
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

        # Prepare YARA rules and Volatility symbol tables
        if not self.prepare_rules_and_symbols():
            logger.error("Failed to prepare YARA rules or symbol tables")
            raise VolatilityError("Failed to prepare YARA rules or symbol tables")

        # Fail-fast preflight for symbols (with optional auto-recovery)
        if not self._preflight_volatility_symbols():
            logger.error("Stopping analysis due to unresolved Volatility symbol requirements")
            raise VolatilityError("Unresolved Volatility symbol requirements")

        # Identify memory profile
        profile = self.identify_profile()
        if profile:
            logger.info(f"Identified OS: {profile}")
        else:
            logger.info("Proceeding with Volatility3 autodetection of OS")

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
