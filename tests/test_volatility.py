"""Tests for Volatility wrapper."""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import subprocess

from malhunt.volatility import VolatilityWrapper, VolatilityConfig, VolatilityError


class TestVolatilityWrapperInitialization:
    """Test VolatilityWrapper initialization."""
    
    def test_init_with_nonexistent_dump(self):
        """Test initialization with nonexistent dump file."""
        with pytest.raises(VolatilityError, match="Memory dump not found"):
            VolatilityWrapper(Path("/nonexistent/dump.raw"))
    
    @patch('malhunt.volatility.VolatilityWrapper._find_volatility')
    def test_init_without_volatility(self, mock_find):
        """Test initialization when Volatility is not found."""
        mock_find.return_value = None
        
        with pytest.raises(VolatilityError, match="Volatility3 not found"):
            import tempfile
            with tempfile.NamedTemporaryFile() as tmp:
                VolatilityWrapper(Path(tmp.name))
    
    @patch('malhunt.volatility.VolatilityWrapper._find_volatility')
    def test_init_success(self, mock_find):
        """Test successful initialization."""
        mock_find.return_value = Path("/usr/bin/vol")
        
        import tempfile
        with tempfile.NamedTemporaryFile() as tmp:
            wrapper = VolatilityWrapper(Path(tmp.name))
            
            assert wrapper.dump_path == Path(tmp.name)
            assert wrapper._volatility_bin == Path("/usr/bin/vol")
            assert wrapper.config.timeout == 300
    
    @patch('malhunt.volatility.VolatilityWrapper._find_volatility')
    def test_init_with_custom_config(self, mock_find):
        """Test initialization with custom config."""
        mock_find.return_value = Path("/usr/bin/vol")
        config = VolatilityConfig(timeout=600, retry_count=2)
        
        import tempfile
        with tempfile.NamedTemporaryFile() as tmp:
            wrapper = VolatilityWrapper(Path(tmp.name), config)
            
            assert wrapper.config.timeout == 600
            assert wrapper.config.retry_count == 2


class TestVolatilityFindBinary:
    """Test finding Volatility binary."""
    
    @patch('subprocess.run')
    def test_find_volatility_with_vol(self, mock_run):
        """Test finding 'vol' command."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "/usr/bin/vol"
        mock_run.return_value = mock_result
        
        result = VolatilityWrapper._find_volatility()
        
        assert result == Path("/usr/bin/vol")
    
    @patch('subprocess.run')
    def test_find_volatility_not_found(self, mock_run):
        """Test when volatility is not installed."""
        mock_run.return_value.returncode = 1
        
        result = VolatilityWrapper._find_volatility()
        
        assert result is None


class TestVolatilityCommand:
    """Test Volatility command execution."""
    
    @patch('subprocess.run')
    @patch('malhunt.volatility.VolatilityWrapper._find_volatility')
    def test_run_command_success(self, mock_find, mock_run):
        """Test successful command execution."""
        mock_find.return_value = Path("/usr/bin/vol")
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "test output"
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        import tempfile
        with tempfile.NamedTemporaryFile() as tmp:
            wrapper = VolatilityWrapper(Path(tmp.name))
            stdout, stderr = wrapper._run_command("windows.pslist")
            
            assert stdout == "test output"
            assert stderr == ""
    
    @patch('subprocess.run')
    @patch('malhunt.volatility.VolatilityWrapper._find_volatility')
    def test_run_command_with_cache(self, mock_find, mock_run):
        """Test command caching."""
        mock_find.return_value = Path("/usr/bin/vol")
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "cached output"
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        import tempfile
        with tempfile.NamedTemporaryFile() as tmp:
            config = VolatilityConfig(cache_results=True)
            wrapper = VolatilityWrapper(Path(tmp.name), config)
            
            # First call
            stdout1, _ = wrapper._run_command("windows.pslist")
            assert mock_run.call_count == 1
            
            # Second call should use cache
            stdout2, _ = wrapper._run_command("windows.pslist", use_cache=True)
            assert stdout1 == stdout2
            assert mock_run.call_count == 1  # Not called again
    
    @patch('subprocess.run')
    @patch('malhunt.volatility.VolatilityWrapper._find_volatility')
    def test_run_command_timeout_retry(self, mock_find, mock_run):
        """Test timeout with retry."""
        mock_find.return_value = Path("/usr/bin/vol")
        
        # First attempt times out, second succeeds
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "success"
        mock_result.stderr = ""
        
        mock_run.side_effect = [
            subprocess.TimeoutExpired("cmd", 60),
            mock_result
        ]
        
        import tempfile
        with tempfile.NamedTemporaryFile() as tmp:
            config = VolatilityConfig(timeout=300, retry_count=2, retry_delay=0.1)
            wrapper = VolatilityWrapper(Path(tmp.name), config)
            
            stdout, _ = wrapper._run_command("windows.pslist")
            
            assert stdout == "success"
            assert mock_run.call_count == 2
    
    @patch('subprocess.run')
    @patch('malhunt.volatility.VolatilityWrapper._find_volatility')
    def test_run_command_timeout_exceeds_retries(self, mock_find, mock_run):
        """Test timeout exceeds retry limit."""
        mock_find.return_value = Path("/usr/bin/vol")
        mock_run.side_effect = subprocess.TimeoutExpired("cmd", 60)
        
        import tempfile
        with tempfile.NamedTemporaryFile() as tmp:
            config = VolatilityConfig(timeout=300, retry_count=1)
            wrapper = VolatilityWrapper(Path(tmp.name), config)
            
            with pytest.raises(VolatilityError, match="timed out"):
                wrapper._run_command("windows.pslist")

    @patch.object(VolatilityWrapper, '_run_command')
    @patch('malhunt.volatility.VolatilityWrapper._find_volatility')
    def test_netscan_fallback_to_connscan(self, mock_find, mock_run_cmd):
        """Fallback to netstat when netscan is unsupported."""
        mock_find.return_value = Path("/usr/bin/vol")
        mock_run_cmd.side_effect = [
            VolatilityError(
                "Volatility command failed",
                plugin="windows.netscan",
                returncode=1,
                stdout="",
                stderr="NotImplementedError: This version of Windows is not supported",
            ),
            ("netstat output", ""),
        ]

        import tempfile
        with tempfile.NamedTemporaryFile() as tmp:
            wrapper = VolatilityWrapper(Path(tmp.name))
            result = wrapper.netscan()

            assert result == "netstat output"


class TestVolatilityImageInfo:
    """Test imageinfo parsing."""
    
    @patch.object(VolatilityWrapper, '_run_command')
    @patch('malhunt.volatility.VolatilityWrapper._find_volatility')
    def test_imageinfo_parsing(self, mock_find, mock_run_cmd):
        """Test parsing imageinfo output."""
        mock_find.return_value = Path("/usr/bin/vol")
        mock_run_cmd.return_value = ("Windows.7 Windows.7SP1", "")
        
        import tempfile
        with tempfile.NamedTemporaryFile() as tmp:
            wrapper = VolatilityWrapper(Path(tmp.name))
            result = wrapper.imageinfo()
            
            assert "raw" in result
            # result now contains detailed info dictionary instead of profiles list
            assert "info" in result
            assert "is_windows" in result

    @patch.object(VolatilityWrapper, '_run_command')
    @patch('malhunt.volatility.VolatilityWrapper._find_volatility')
    def test_imageinfo_suggested_parsing(self, mock_find, mock_run_cmd):
        """Ensure suggested profiles are extracted from plugin output."""
        mock_find.return_value = Path("/usr/bin/vol")
        mock_run_cmd.return_value = ("Suggested : Windows.7SP1x64, Windows.10x64\n", "")

        import tempfile
        with tempfile.NamedTemporaryFile() as tmp:
            wrapper = VolatilityWrapper(Path(tmp.name))
            result = wrapper.imageinfo()

            assert "suggested_profiles" in result
            assert result["suggested_profiles"] == ["Windows.7SP1x64", "Windows.10x64"]


class TestVolatilityYaraTimeout:
    """Test YARA-specific timeout behavior."""

    @patch.object(VolatilityWrapper, '_run_command')
    @patch('malhunt.volatility.VolatilityWrapper._find_volatility')
    def test_yarascan_uses_dedicated_timeout(self, mock_find, mock_run_cmd):
        mock_find.return_value = Path("/usr/bin/vol")
        mock_run_cmd.return_value = ("", "")

        import tempfile
        with tempfile.NamedTemporaryFile() as dump, tempfile.NamedTemporaryFile(suffix=".yar") as rules:
            config = VolatilityConfig(timeout=300, yara_timeout=1200)
            wrapper = VolatilityWrapper(Path(dump.name), config)

            wrapper.yarascan(Path(rules.name))

            _, kwargs = mock_run_cmd.call_args
            assert kwargs.get("timeout") == 1200
            assert kwargs.get("use_cache") is False

    @patch.object(VolatilityWrapper, '_run_command')
    @patch('malhunt.volatility.VolatilityWrapper._find_volatility')
    def test_yarascan_escalates_timeout_after_timeout_error(self, mock_find, mock_run_cmd):
        mock_find.return_value = Path("/usr/bin/vol")
        mock_run_cmd.side_effect = [
            VolatilityError("Volatility command timed out after 900s: windows.vadyarascan"),
            ("", ""),
        ]

        import tempfile
        with tempfile.NamedTemporaryFile() as dump, tempfile.NamedTemporaryFile(suffix=".yar") as rules:
            config = VolatilityConfig(timeout=300, yara_timeout=900)
            wrapper = VolatilityWrapper(Path(dump.name), config)

            wrapper.yarascan(Path(rules.name))

            first_call = mock_run_cmd.call_args_list[0]
            second_call = mock_run_cmd.call_args_list[1]
            assert first_call.kwargs.get("timeout") == 900
            assert second_call.kwargs.get("timeout") == 1800


class TestVolatilityYaraDependencyErrors:
    """Test missing YARA backend handling."""

    @patch('malhunt.volatility.VolatilityWrapper._find_volatility')
    def test_detects_yara_dependency_error_signature(self, mock_find):
        mock_find.return_value = Path("/usr/bin/vol")

        error = VolatilityError(
            "Volatility command failed",
            plugin="windows.vadyarascan",
            returncode=1,
            stderr=(
                "Neither yara-x nor yara-python (>3.8.0) module was found, "
                "plugin (and dependent plugins) not available"
            ),
        )

        assert VolatilityWrapper.is_yara_dependency_error(error) is True

    @patch.object(VolatilityWrapper, '_run_command')
    @patch('malhunt.volatility.VolatilityWrapper._find_volatility')
    def test_yarascan_raises_actionable_error_on_missing_yara_backend(self, mock_find, mock_run_cmd):
        mock_find.return_value = Path("/usr/bin/vol")
        mock_run_cmd.side_effect = VolatilityError(
            "Volatility command failed",
            plugin="windows.vadyarascan",
            returncode=1,
            stderr=(
                "Neither yara-x nor yara-python (>3.8.0) module was found, "
                "plugin (and dependent plugins) not available"
            ),
        )

        import tempfile
        with tempfile.NamedTemporaryFile() as dump, tempfile.NamedTemporaryFile(suffix=".yar") as rules:
            wrapper = VolatilityWrapper(Path(dump.name))

            with pytest.raises(VolatilityError, match="YARA backend not available"):
                wrapper.yarascan(Path(rules.name))


class TestVolatilityCache:
    """Test caching functionality."""
    
    @patch('malhunt.volatility.VolatilityWrapper._find_volatility')
    def test_clear_cache(self, mock_find):
        """Test clearing cache."""
        mock_find.return_value = Path("/usr/bin/vol")
        
        import tempfile
        with tempfile.NamedTemporaryFile() as tmp:
            wrapper = VolatilityWrapper(Path(tmp.name))
            wrapper._cache["test"] = "data"
            
            wrapper.clear_cache()
            
            assert len(wrapper._cache) == 0
    
    @patch('malhunt.volatility.VolatilityWrapper._find_volatility')
    def test_cache_stats(self, mock_find):
        """Test cache statistics."""
        mock_find.return_value = Path("/usr/bin/vol")
        
        import tempfile
        with tempfile.NamedTemporaryFile() as tmp:
            wrapper = VolatilityWrapper(Path(tmp.name))
            wrapper._cache["test"] = "data" * 100
            
            stats = wrapper.get_cache_stats()
            
            assert stats["size"] == 1
            assert "entries" in stats
            assert stats["memory_bytes"] > 0


class TestYaraRecoveryHelpers:
    """Test helpers used for syntax-error recovery in YARA scans."""

    def test_drop_rule_block_with_loose_rule_header(self, tmp_path):
        source = tmp_path / "rules.yar"
        dest = tmp_path / "rules.fixed.yar"

        source.write_text(
            'global rule Good : TAG {\n'
            '  condition:\n'
            '    true\n'
            '}\n'
            'rule Bad : FILE {\n'
            '  strings:\n'
            '    $a = "x"\n'
            '  condition:\n'
            '    true\n'
            '}\n'
        )

        removed = VolatilityWrapper._drop_rule_block_at_line(source, dest, 6)

        assert removed is True
        content = dest.read_text()
        assert "rule Bad" not in content
        assert "rule Good" in content

    def test_drop_orphan_block_when_rule_header_missing(self, tmp_path):
        source = tmp_path / "rules.yar"
        dest = tmp_path / "rules.fixed.yar"

        source.write_text(
            'rule Good {\n'
            '  condition:\n'
            '    true\n'
            '}\n'
            '\n'
            '  strings:\n'
            '    $a = "oops"\n'
            '  condition:\n'
            '    true\n'
            '}\n'
            '\n'
            'rule Tail {\n'
            '  condition:\n'
            '    true\n'
            '}\n'
        )

        removed = VolatilityWrapper._drop_rule_block_at_line(source, dest, 7)

        assert removed is True
        content = dest.read_text()
        assert '$a = "oops"' not in content
        assert "rule Good" in content
        assert "rule Tail" in content


class TestVolatilitySymbolDiagnostics:
    """Test symbol diagnostics extraction helpers."""

    @patch('malhunt.volatility.VolatilityWrapper._find_volatility')
    def test_extract_missing_symbol_details(self, mock_find):
        mock_find.return_value = Path("/usr/bin/vol")

        import tempfile
        with tempfile.NamedTemporaryFile() as tmp:
            wrapper = VolatilityWrapper(Path(tmp.name))

            payload = (
                "Unsatisfied requirement plugins.Info.kernel.symbol_table_name:\n"
                "Downloading http://msdl.microsoft.com/download/symbols/"
                "ntkrnlmp.pdb/ABCDEF1234/ntkrnlmp.pd_\n"
            )
            err = VolatilityError(
                "Volatility command failed",
                plugin="windows.info",
                returncode=1,
                stdout=payload,
                stderr="",
            )

            diagnostics = wrapper.get_symbol_diagnostics(err)

            assert diagnostics["plugin"] == "windows.info"
            assert diagnostics["requirements"] == ["plugins.Info.kernel.symbol_table_name"]
            assert len(diagnostics["missing_symbols"]) == 1
            assert diagnostics["missing_symbols"][0]["pdb_name"] == "ntkrnlmp.pdb"
            assert diagnostics["missing_symbols"][0]["guidage"] == "ABCDEF1234"

    @patch('malhunt.volatility.VolatilityWrapper._find_volatility')
    def test_enrich_diagnostics_generates_helper_script(self, mock_find, tmp_path):
        mock_find.return_value = Path("/usr/bin/vol")

        dump = tmp_path / "dump.raw"
        dump.write_text("dummy")
        wrapper = VolatilityWrapper(
            dump,
            VolatilityConfig(symbol_dirs=[tmp_path / "symbols" / "windows"]),
        )

        diagnostics = {
            "plugin": "windows.info",
            "missing_symbols": [
                {
                    "pdb_name": "ntkrnlmp.pdb",
                    "guidage": "ABCDEF1234",
                    "filename": "ntkrnlmp.pd_",
                    "url": "http://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/ABCDEF1234/ntkrnlmp.pd_",
                }
            ],
            "requirements": ["plugins.Info.kernel.symbol_table_name"],
        }

        enriched = wrapper.enrich_symbol_diagnostics(diagnostics)

        assert "helper_script" in enriched
        helper_path = Path(enriched["helper_script"])
        assert helper_path.exists()
        content = helper_path.read_text()
        assert "ntkrnlmp.pdb" in content
        assert "curl -fL" in content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
