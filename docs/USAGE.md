# Usage Guide

## Basic Usage

### Simple Analysis
```bash
malhunt memory.dump
```

This runs the complete analysis pipeline on the memory dump and outputs findings to the console.

### With Custom YARA Rules
```bash
malhunt memory.dump --rules /path/to/rules.yar
```

### Verbose Output
```bash
malhunt memory.dump --verbose
```

Enables debug logging to help troubleshoot issues.

### Getting Help
```bash
malhunt --help
malhunt --version
```

## Output Structure

When analyzing a memory dump, malhunt creates:
```
memory_artifacts/
├── 1234.bin              # Dumped process memory
├── 1234.handles          # Process handles information
├── 5678.bin
└── 5678.handles
```

## Understanding Results

### Suspicious Process Output

```
[SUSPICIOUS PROCESS] YARA Match: Trojan.Gen
  Process: explorer.exe (PID: 4560)
  ClamAV Result: INFECTED
```

Fields:
- **Rule**: Detection rule (YARA, malfind, or network)
- **Process**: Process name
- **PID**: Process ID
- **ClamAV Result**: Antivirus scan result (OK, INFECTED, or detection name)

## Python API Usage

### Basic Analysis

```python
from malhunt import Malhunt
from pathlib import Path

# Create malhunt instance
mh = Malhunt(Path("memory.dump"))

# Run full analysis
mh.run_full_analysis()

# Access results
for proc in mh.scan_results:
    print(f"{proc.rule}: {proc.process} (PID: {proc.pid})")
```

### Access Individual Scanners

```python
from malhunt.scanner import YaraScanner, MalfindScanner, NetworkScanner

# Just YARA scan
yara_results = mh.yara_scanner.scan()

# Just Malfind scan
malfind_results = mh.malfind_scanner.scan()

# Just Network scan
network_results = mh.network_scanner.scan()
```

### Custom Processing

```python
# Run individual phases
mh.prepare_rules()
mh.identify_profile()
suspicious_procs = mh.run_scans()

# Collect artifacts only for specific processes
for proc in suspicious_procs:
    mh.artifacts.dump_process(proc)
    mh.artifacts.collect_handles(proc)
```

### Antivirus Scanning

```python
from malhunt.artifacts import ClamavScanner

scanner = ClamavScanner()

if scanner.is_available():
    result = scanner.scan(Path("dumped_process.bin"))
    print(f"Result: {result}")  # OK, INFECTED, or detection name
```

## Working with Large Memory Dumps

For very large memory dumps (>50GB):

1. **Enable verbose logging** to monitor progress:
   ```bash
   malhunt huge.dump --verbose
   ```

2. **Run individual scans** to avoid timeout:
   ```python
   mh = Malhunt(Path("huge.dump"))
   
   # Just YARA scan
   yara_results = mh.yara_scanner.scan()
   print(f"Found {len(yara_results)} matches")
   ```

3. **Increase timeouts** if commands timeout:
   - Modify `src/malhunt/volatility.py` increase the `timeout` parameter

## Performance Tips

1. **Use SSD** for faster I/O
2. **Close other applications** to free memory
3. **Run with `--verbose`** to identify bottlenecks
4. **Cache YARA rules** - they're automatically cached after first download
5. **Profile-specific analysis** - limit scans to known profiles

## Common Workflows

### Security Incident Response

```python
from malhunt import Malhunt
from pathlib import Path

# Analyze dumped memory from suspected compromised system
mh = Malhunt(Path("suspect_machine.dump"))
mh.run_full_analysis()

# Review artifacts
print(f"Artifacts saved to: {mh.artifacts.artifacts_dir}")

# Export results
for proc in mh.scan_results:
    print(f"IOC: {proc.process} (PID: {proc.pid}) - {proc.rule}")
```

### Malware Research

```python
# Analyze with custom YARA rules
mh = Malhunt(Path("sample.dump"), rules_file=Path("research_rules.yar"))
mh.run_full_analysis()

# Extract all suspicious binaries for analysis
for proc in mh.scan_results:
    mh.artifacts.dump_process(proc)
```

## Environment Variables

- `VOLATILITY3_PATH` - Path to volatility binary (if not in PATH)
- `MALHUNT_HOME` - Override ~/.malhunt location

## Scheduling Analysis

### Cron Job (Linux/macOS)

```bash
# Add to crontab
0 2 * * * /usr/local/bin/malhunt /path/to/memory.dump >> /var/log/malhunt.log 2>&1
```

### Windows Task Scheduler

Create a batch file:
```batch
@echo off
C:\Python310\Scripts\malhunt.exe C:\dumps\memory.dump 2>&1 >> C:\logs\malhunt.log
```

Then schedule the batch file.

## Exporting Results

```python
import json
from malhunt import Malhunt

mh = Malhunt(Path("memory.dump"))
mh.run_scans()

# Export as JSON
results = [
    {
        "rule": proc.rule,
        "process": proc.process,
        "pid": proc.pid,
    }
    for proc in mh.scan_results
]

with open("results.json", "w") as f:
    json.dump(results, f, indent=2)
```
