"""Tests for core Malhunt functionality."""

import pytest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch, MagicMock

from malhunt.models import SuspiciousProcess
from malhunt.utils import (
    check_exclusions, remove_incompatible_imports,
    fix_duplicated_rules, banner_logo, sanitize_yara_rules_file
)
from malhunt.volatility import VolatilityConfig, VolatilityError


class TestSuspiciousProcess:
    """Test SuspiciousProcess model."""
    
    def test_creation(self):
        """Test creating a SuspiciousProcess."""
        proc = SuspiciousProcess(
            rule="TestRule",
            process="test.exe",
            pid="1234"
        )
        
        assert proc.rule == "TestRule"
        assert proc.process == "test.exe"
        assert proc.pid == "1234"
    
    def test_repr(self):
        """Test string representation."""
        proc = SuspiciousProcess("Rule", "process", "123")
        repr_str = repr(proc)
        
        assert "Rule" in repr_str
        assert "process" in repr_str
        assert "123" in repr_str
    
    def test_with_profile(self):
        """Test with optional profile."""
        proc = SuspiciousProcess("rule", "proc", "123", profile="Windows.7")
        assert proc.profile == "Windows.7"


class TestCheckExclusions:
    """Test exclusion filtering."""
    
    def test_excluded_word_found(self):
        """Test filtering excluded words."""
        excluded = ['Str_Win32_', 'SurtrStrings']
        
        assert not check_exclusions("Str_Win32_virus", excluded)
        assert not check_exclusions("SurtrStrings_test", excluded)
    
    def test_normal_rule(self):
        """Test non-excluded rule passes."""
        excluded = ['Str_Win32_', 'SurtrStrings']
        
        assert check_exclusions("Trojan.Generic", excluded)
        assert check_exclusions("Malware.A", excluded)
    
    def test_case_sensitive(self):
        """Test that filtering is case-sensitive."""
        excluded = ['Test']
        assert not check_exclusions("Test_rule", excluded)
        assert check_exclusions("test_rule", excluded)  # lowercase doesn't match


class TestFixDuplicatedRules:
    """Test duplicate rule removal."""
    
    def test_removes_duplicate_elf_rules(self):
        """Test removal of duplicate is__elf definitions."""
        content = """
rule test1 { condition: true }
private rule is__elf {
  strings: $a = "test"
  condition: $a
}
rule test2 { condition: true }
private rule is__elf {
  strings: $b = "test2"
  condition: $b
}
"""
        result = fix_duplicated_rules(content)
        
        # Should have only one is__elf
        count = result.count("private rule is__elf")
        assert count == 1
    
    def test_preserves_other_rules(self):
        """Test that other rules are preserved."""
        content = """
private rule is__elf { condition: true }
rule test1 { condition: true }
rule test2 { condition: true }
"""
        result = fix_duplicated_rules(content)
        
        assert "rule test1" in result
        assert "rule test2" in result
    
    def test_handles_multiple_duplicates(self):
        """Test handling multiple duplicate sections."""
        content = """
private rule is__elf {
  condition: true
}
rule other { condition: true }
private rule is__elf {
  condition: true
}
"""
        result = fix_duplicated_rules(content)
        assert result.count("private rule is__elf") == 1


class TestPrepareRules:
    """Ensure prepare_rules downloads and unpacks YARA rules."""

    def test_prepare_rules_download(self, tmp_path, monkeypatch):
        # create dummy dump file
        dump = tmp_path / "dump.vmem"
        dump.write_text("dummy")

        from malhunt.core import Malhunt
        mh = Malhunt(dump)
        mh.malhunt_home = tmp_path / ".malhunt"
        mh.malhunt_home.mkdir()
        mh.rules_file = mh.malhunt_home / "malware_rules.yar"

        # build fake zip archive in memory
        import io, zipfile
        fake = io.BytesIO()
        with zipfile.ZipFile(fake, 'w') as zf:
            zf.writestr('packages/full/yara-rules-full.yar', 'rule test { condition: true }')
        fake.seek(0)

        class DummyResp:
            status_code = 200
            content = fake.getvalue()
            def raise_for_status(self):
                return

        import requests
        monkeypatch.setattr(requests, 'get', lambda url, timeout: DummyResp())

        success = mh.prepare_rules()
        assert success
        assert mh.rules_file.exists()
        assert 'rule test' in mh.rules_file.read_text()

    def test_prepare_rules_download_failed(self, tmp_path, monkeypatch):
        """Simulate HTTP error during download."""
        dump = tmp_path / "dump.vmem"
        dump.write_text("dummy")

        from malhunt.core import Malhunt
        mh = Malhunt(dump)
        mh.malhunt_home = tmp_path / ".malhunt"
        mh.malhunt_home.mkdir()
        mh.rules_file = mh.malhunt_home / "malware_rules.yar"

        class DummyResp:
            status_code = 404
            content = b""
            def raise_for_status(self):
                raise Exception("Not found")

        import requests
        monkeypatch.setattr(requests, 'get', lambda url, timeout: DummyResp())

        success = mh.prepare_rules()
        assert not success
        assert not mh.rules_file.exists()

    def test_prepare_rules_bad_archive(self, tmp_path, monkeypatch):
        """Simulate downloading a non-zip or corrupted file."""
        dump = tmp_path / "dump.vmem"
        dump.write_text("dummy")

        from malhunt.core import Malhunt
        mh = Malhunt(dump)
        mh.malhunt_home = tmp_path / ".malhunt"
        mh.malhunt_home.mkdir()
        mh.rules_file = mh.malhunt_home / "malware_rules.yar"

        class DummyResp:
            status_code = 200
            content = b"not a zip"
            def raise_for_status(self):
                return

        import requests
        monkeypatch.setattr(requests, 'get', lambda url, timeout: DummyResp())

        success = mh.prepare_rules()
        assert not success
        assert not mh.rules_file.exists()




class TestRemoveIncompatibleImports:
    """Test filtering incompatible rule imports."""
    
    def test_filters_math_import(self):
        """Test filtering rules with math import."""
        with TemporaryDirectory() as tmpdir:
            rules_dir = Path(tmpdir)
            
            # Compatible rule
            good = rules_dir / "good.yar"
            good.write_text('rule Test { condition: true }')
            
            # Incompatible rule with math
            bad = rules_dir / "bad.yar"
            bad.write_text('import "math"\nrule Test2 { condition: true }')
            
            files = [good, bad]
            filtered = remove_incompatible_imports(files)
            
            assert len(filtered) == 1
            assert filtered[0] == good
    
    def test_filters_cuckoo_import(self):
        """Test filtering rules with cuckoo import."""
        with TemporaryDirectory() as tmpdir:
            rules_dir = Path(tmpdir)
            
            good = rules_dir / "good.yar"
            good.write_text('rule Test { condition: true }')
            
            bad = rules_dir / "bad.yar"
            bad.write_text('import "cuckoo"\nrule Test2 { condition: true }')
            
            files = [good, bad]
            filtered = remove_incompatible_imports(files)
            
            assert len(filtered) == 1
            assert filtered[0] == good
    
    def test_filters_hash_import(self):
        """Test filtering rules with hash import."""
        with TemporaryDirectory() as tmpdir:
            rules_dir = Path(tmpdir)
            
            bad = rules_dir / "bad.yar"
            bad.write_text('import "hash"\nrule Test { condition: true }')
            
            files = [bad]
            filtered = remove_incompatible_imports(files)
            
            assert len(filtered) == 0
    
    def test_filters_imphash(self):
        """Test filtering rules with imphash."""
        with TemporaryDirectory() as tmpdir:
            rules_dir = Path(tmpdir)
            
            bad = rules_dir / "bad.yar"
            bad.write_text('rule Test { condition: imphash == "abc" }')
            
            files = [bad]
            filtered = remove_incompatible_imports(files)
            
            assert len(filtered) == 0

    def test_sanitize_yara_rules_file_removes_imphash_rule(self):
        """Sanitizer should drop rule blocks containing imphash references."""
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source = root / "in.yar"
            dest = root / "out.yar"

            source.write_text(
                'import "hash"\n'
                'rule KeepMe { condition: true }\n'
                'rule DropMe { condition: pe.imphash() == "abc" }\n'
            )

            removed = sanitize_yara_rules_file(source, dest)

            content = dest.read_text()
            assert removed >= 1
            assert "DropMe" not in content
            assert "KeepMe" in content
            assert 'import "hash"' not in content


class TestVolatilityConfig:
    """Test VolatilityConfig settings."""
    
    def test_default_config(self):
        """Test default configuration."""
        config = VolatilityConfig()
        
        assert config.timeout == 300
        assert config.retry_count == 1
        assert config.retry_delay == 1.0
        assert config.cache_results is True
    
    def test_custom_config(self):
        """Test custom configuration."""
        config = VolatilityConfig(
            timeout=600,
            retry_count=3,
            retry_delay=2.0,
            cache_results=False
        )
        
        assert config.timeout == 600
        assert config.retry_count == 3
        assert config.retry_delay == 2.0
        assert config.cache_results is False


class TestIdentifyProfile:
    """Ensure memory profile detection uses multiple heuristics."""

    def _make_mh(self, tmp_path):
        from malhunt.core import Malhunt
        dump = tmp_path / "dump.vmem"
        dump.write_text("dummy")
        mh = Malhunt(dump)
        return mh

    def test_os_name_present(self, tmp_path, monkeypatch):
        mh = self._make_mh(tmp_path)
        monkeypatch.setattr(mh.vol, "imageinfo", lambda: {"os_name": "Windows 7 (x64)",
                                                               "info": {},
                                                               "suggested_profiles": []})
        assert mh.identify_profile() == "Windows 7 (x64)"

    def test_guess_profile_success(self, tmp_path, monkeypatch):
        mh = self._make_mh(tmp_path)
        mh_input = {"os_name": "",
                    "info": {"ntmajorversion": "6",
                             "ntminorversion": "1",
                             "is64bit": "True"},
                    "suggested_profiles": []}
        monkeypatch.setattr(mh.vol, "imageinfo", lambda: mh_input)

        def fake_run(*args, **kwargs):
            if any("--profile=Windows.61x64" in arg for arg in args):
                return ("PID    1\n", "")
            raise VolatilityError("bad")
        monkeypatch.setattr(mh.vol, "_run_command", fake_run)

        assert mh.identify_profile() == "Windows.61x64"

    def test_suggested_profiles(self, tmp_path, monkeypatch):
        mh = self._make_mh(tmp_path)
        mh_input = {"os_name": "",
                    "info": {},
                    "suggested_profiles": ["Windows.10x64", "Windows.7SP1x64"]}
        monkeypatch.setattr(mh.vol, "imageinfo", lambda: mh_input)

        def fake_run(*args, **kwargs):
            # first candidate fails, second succeeds
            if any("Windows.10x64" in arg for arg in args):
                raise VolatilityError("nope")
            return ("PID 1", "")
        monkeypatch.setattr(mh.vol, "_run_command", fake_run)

        assert mh.identify_profile() == "Windows.7SP1x64"

    def test_no_profile_found(self, tmp_path, monkeypatch):
        mh = self._make_mh(tmp_path)
        monkeypatch.setattr(mh.vol, "imageinfo", lambda: {"os_name": "",
                                                            "info": {},
                                                            "suggested_profiles": []})
        monkeypatch.setattr(mh.vol, "_run_command", lambda *a, **k: (_ for _ in ()).throw(VolatilityError("fail")))
        assert mh.identify_profile() is None


class TestBannerLogo:
    """Test banner logo generation."""
    
    def test_banner_contains_title(self):
        """Test banner contains expected text."""
        banner = banner_logo()
        
        # banner text changed; ensure it contains the slogan instead
        assert "Hunt malware" in banner
        assert "Andrea Fortuna" in banner
    
    def test_banner_not_empty(self):
        """Test banner is not empty."""
        banner = banner_logo()
        assert len(banner) > 0
        assert '\n' in banner


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
