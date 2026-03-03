# Troubleshooting Guide

## Common Issues & Solutions

### Installation Issues

#### Problem: "volatility3 command not found" or "vol not in PATH"

**Symptoms:**
```
VolatilityError: Volatility3 not found in PATH
```

**Solutions:**

1. **Verify installation:**
   ```bash
   which vol
   pip show volatility3
   ```

2. **Reinstall:**
   ```bash
   pip uninstall volatility3 -y
   pip install volatility3
   ```

3. **Add to PATH (Linux/macOS):**
   ```bash
   export PATH="$HOME/.local/bin:$PATH"
   ```

4. **Manual installation:**
   ```bash
   git clone https://github.com/volatilityfoundation/volatility3.git
   cd volatility3
   pip install -e .
   ```

#### Problem: Python version mismatch

**Symptoms:**
```
ERROR: malhunt requires Python >=3.10
```

**Solutions:**

1. **Check Python version:**
   ```bash
   python --version
   python3.10 --version
   ```

2. **Use virtual environment:**
   ```bash
   python3.10 -m venv venv
   source venv/bin/activate
   pip install malhunt
   ```

3. **Use pyenv (recommended):**
   ```bash
   pyenv install 3.10.0
   pyenv local 3.10.0
   ```

#### Problem: "No module named 'volatility3'"

**Symptoms:**
```
ModuleNotFoundError: No module named 'volatility3'
```

**Solutions:**

```bash
# Install dependencies
pip install volatility3 yara-python requests pyclamd loguru

# Or install with extras
pip install 'malhunt[dev]'
```

### Analysis Issues

#### Problem: "Memory dump not found"

**Symptoms:**
```
Error: Memory dump not found: /path/to/dump.raw
```

**Solutions:**

1. **Verify file exists:**
   ```bash
   ls -lh /path/to/dump.raw
   ```

2. **Use absolute path:**
   ```bash
   malhunt /absolute/path/to/dump.raw
   # Instead of
   malhunt ./dump.raw
   ```

3. **Check permissions:**
   ```bash
   # Ensure readable
   chmod +r /path/to/dump.raw
   ```

#### Problem: "Profile identification failed"

**Symptoms:**
```
WARN: Volatility3 profile identification not implemented
```

**Status:** Feature is being improved

**Workaround:**
```python
from malhunt import Malhunt
from pathlib import Path

mh = Malhunt(Path("memory.dump"))

# Skip profile detection, run scans directly
mh.run_scans()

# Or specify profile manually if known
mh.vol.pslist()
```

#### Problem: YARA scan hangs or times out

**Symptoms:**
```
ERROR: Volatility command timed out after 300s
```

**Solutions:**

1. **Increase timeout:**
   ```python
   # Modify src/malhunt/volatility.py
   # Change timeout parameter (default 300s = 5 min)
   timeout: int = 600  # 10 minutes
   ```

2. **Check system resources:**
   ```bash
   # Monitor RAM/CPU
   top
   # or
   htop
   ```

3. **Run individual scans:**
   ```python
   from malhunt import Malhunt
   
   mh = Malhunt(Path("memory.dump"))
   
   # Run only YARA
   if mh.rules_file.exists():
       yara_results = mh.yara_scanner.scan()
   ```

4. **Use simpler rules:**
   ```bash
   # Custom lightweight rules
   malhunt memory.dump --rules simple_rules.yar
   ```

#### Problem: High memory usage

**Symptoms:**
- System becomes unresponsive
- "Out of memory" errors
- Analysis stops unexpectedly

**Solutions:**

1. **Check system specs:**
   ```bash
   # Linux
   free -h
   cat /proc/cpuinfo | grep processor | wc -l
   
   # macOS
   vm_stat
   system_profiler SPHardwareDataType
   ```

2. **Close unnecessary programs:**
   - Close large applications
   - Free up RAM

3. **Use smaller YARA rule sets:**
   ```bash
   # Create subset of rules
   malhunt memory.dump --rules essential_rules.yar
   ```

4. **Analyze in stages:**
   ```python
   mh = Malhunt(Path("memory.dump"))
   
   # YARA only
   yara_results = mh.yara_scanner.scan()
   print(f"YARA: {len(yara_results)} findings")
   
   # Malfind only (fresh instance)
   mh2 = Malhunt(Path("memory.dump"))
   malfind_results = mh2.malfind_scanner.scan()
   ```

### YARA Rules Issues

#### Problem: "Failed to download YARA rules"

**Symptoms:**
```
ERROR: Failed to download rules
```

**Solutions:**

1. **Check internet connection:**
   ```bash
   ping github.com
   ```

2. **Manual download:**
   Instead of relying on the automatic ZIP fetch, you can manually place a merged YARA file:
   ```bash
   mkdir -p ~/.malhunt
   # download the latest yara-rules-full.yar from
   # https://github.com/YARAHQ/yara-forge/releases/latest/
   # and save it as ~/.malhunt/malware_rules.yar
   ```

3. **Use local rules:**
   ```bash
   malhunt memory.dump --rules /path/to/local/rules.yar
   ```

#### Problem: "Incompatible YARA imports"

**Symptoms:**
```
WARN: Skipping rule with incompatible imports
```

**Note:** This is expected and normal

**Exclusions:**
- Rules using `import "math"`
- Rules using `import "cuckoo"`
- Rules using `import "hash"`
- Rules using `imphash`

These are filtered automatically.

### ClamAV Issues

#### Problem: "ClamAV not found"

**Symptoms:**
```
WARN: ClamAV (clamscan) not found in PATH
```

**Status:** Optional - analysis continues without it

**To install:**
```bash
# macOS
brew install clamav

# Linux (Debian/Ubuntu)
sudo apt-get install clamav

# Linux (Fedora/RHEL)
sudo dnf install clamav

# Verify
clamscan --version
```

#### Problem: ClamAV database outdated

**Symptoms:**
```
WARN: ClamAV signature database may be outdated
```

**Solution:**
```bash
# Update signature database
sudo freshclam
```

### Output/Artifact Issues

#### Problem: "Artifacts saved to permission denied"

**Symptoms:**
```
ERROR: Permission denied creating artifacts directory
```

**Solutions:**

1. **Check output directory permissions:**
   ```bash
   # Run from writable directory
   cd ~/Desktop
   malhunt /path/to/memory.dump
   ```

2. **Create output directory manually:**
   ```bash
   mkdir -p ~/malhunt_output
   cd ~/malhunt_output
   malhunt /path/to/memory.dump
   ```

3. **Check disk space:**
   ```bash
   # Ensure ~10GB free for large dumps
   df -h
   ```

#### Problem: "Incomplete artifact collection"

**Symptoms:**
```
WARN: Failed to dump process {pid}
```

**Solutions:**

1. **Check memory dump validity:**
   ```bash
   vol -f memory.dump windows.pslist | head
   ```

2. **Ensure sufficient disk space:**
   ```bash
   # Artifacts dir needs 2-3x dump size
   du -sh memory.dump
   df -h .
   ```

3. **Run with verbose logging:**
   ```bash
   malhunt memory.dump --verbose
   ```

### Performance Issues

#### Problem: Analysis is very slow

**Factors:**
- Dump size (analysis time increases with size)
- YARA rule complexity
- System performance
- Network latency (for IP checks)

**Optimization Tips:**

1. **Disable network checks:**
   ```python
   from malhunt.scanner import NetworkScanner
   
   # Use dummy checker
   network_scanner = NetworkScanner(vol, ip_checker=lambda x: False)
   ```

2. **Use faster YARA rules:**
   Smaller, focused rule sets

3. **Parallel processing** (future feature):
   Currently sequential, would improve with parallelization

4. **SSD storage:**
   Use SSD for dump and artifacts

## Getting Help

### Debug Information

When reporting issues, include:

```bash
# System information
python --version
pip show malhunt volatility3 yara-python
which vol
vol --help | head -5

# Run analysis with debug output
malhunt memory.dump --verbose 2>&1 | tee malhunt_debug.log
```

### Resources

- 📖 [Usage Guide](USAGE.md)
- 🏗️ [Architecture](ARCHITECTURE.md)
- 🔄 [Migration Guide](MIGRATION.md)
- 🐛 [GitHub Issues](https://github.com/andreafortuna/malhunt/issues)
- 💬 [Discussions](https://github.com/andreafortuna/malhunt/discussions)

### Reporting Bugs

Include:
1. Command executed
2. Error message (full output)
3. Debug log (`malhunt --verbose`)
4. System info (OS, Python, Volatility3 version)
5. Memory dump size and approximate profile
