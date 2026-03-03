"""Tests for core Malhunt functionality."""

import pytest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch, MagicMock

from malhunt.models import SuspiciousProcess
from malhunt.utils import (
    check_exclusions, list_yara_files, remove_incompatible_imports,
    fix_duplicated_rules, banner_logo
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


class TestYaraFileDiscovery:
    """Test YARA file discovery."""
    
    def test_list_yara_files_empty_dir(self):
        """Test with empty directory."""
        with TemporaryDirectory() as tmpdir:
            malhunt_home = Path(tmpdir)
            files = list_yara_files(malhunt_home)
            
            assert files == []
    
    def test_list_yara_files_finds_yar(self):
        """Test finding .yar files."""
        with TemporaryDirectory() as tmpdir:
            malhunt_home = Path(tmpdir)
            rules_dir = malhunt_home / "rules" / "malware"
            rules_dir.mkdir(parents=True)
            
            # Create test files
            (rules_dir / "test.yar").touch()
            (rules_dir / "test.yara").touch()
            (rules_dir / "test.txt").touch()
            
            files = list_yara_files(malhunt_home)
            
            assert len(files) == 2
            assert any(f.name == "test.yar" for f in files)
            assert any(f.name == "test.yara" for f in files)
            assert not any(f.name == "test.txt" for f in files)
    
    def test_list_yara_files_recursive(self):
        """Test recursive search in subdirectories."""
        with TemporaryDirectory() as tmpdir:
            malhunt_home = Path(tmpdir)
            
            # Create nested structure
            (malhunt_home / "rules" / "malware" / "subdir").mkdir(parents=True)
            (malhunt_home / "rules" / "malware" / "test1.yar").touch()
            (malhunt_home / "rules" / "malware" / "subdir" / "test2.yar").touch()
            
            files = list_yara_files(malhunt_home)
            
            assert len(files) == 2


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


class TestBannerLogo:
    """Test banner logo generation."""
    
    def test_banner_contains_title(self):
        """Test banner contains expected text."""
        banner = banner_logo()
        
        assert "Malhunt" in banner or "MALHUNT" in banner
        assert "Andrea Fortuna" in banner
    
    def test_banner_not_empty(self):
        """Test banner is not empty."""
        banner = banner_logo()
        assert len(banner) > 0
        assert '\n' in banner


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
