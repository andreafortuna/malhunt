# Architecture Guide

## Project Structure

```
malhunt/
├── src/malhunt/              # Main package
│   ├── __init__.py           # Package exports
│   ├── __main__.py           # CLI entry point
│   ├── core.py               # Main orchestrator (Malhunt class)
│   ├── models.py             # Data models (SuspiciousProcess)
│   ├── volatility.py         # Volatility3 wrapper
│   ├── scanner.py            # Scanning modules
│   ├── artifacts.py          # Artifact collection & antivirus
│   └── utils.py              # Utility functions
├── tests/                    # Test suite
│   └── __init__.py
├── docs/                     # Documentation
│   ├── INSTALLATION.md       # Installation guide
│   ├── USAGE.md              # Usage guide
│   ├── ARCHITECTURE.md       # This file
│   └── TROUBLESHOOTING.md    # Common issues
├── pyproject.toml            # Project configuration (Poetry)
├── README.md                 # Main documentation
├── LICENSE                   # MIT License
└── img/                      # Images/screenshots
    └── malhunt.gif           # Demo GIF
```

## Core Components

### 1. Malhunt (core.py)

The main orchestrator class that coordinates all analysis phases.

**Responsibilities:**
- Initialize analysis environment
- Prepare YARA rules
- Identify memory profile (with improved heuristics)
- Coordinate scanners
- Manage artifact collection
- Report findings

**Key Methods:**
- `__init__()` - Initialize analysis
- `prepare_rules()` - Download/prepare YARA rules
- `identify_profile()` - Detect memory dump profile using `windows.info`,
  guess/validate candidate profiles and honour suggested profiles
- `run_scans()` - Execute all scanners
- `collect_artifacts()` - Extract suspicious processes
- `run_full_analysis()` - Complete workflow

### 2. VolatilityWrapper (volatility.py)

High-level interface to Volatility3 CLI.

**Responsibilities:**
- Locate Volatility3 binary
- Execute volatility commands
- Parse command output
- Handle errors
- Manage timeouts

**Key Methods:**
- `imageinfo()` - Get memory profile suggestions
- `pslist()` - List processes
- `yarascan()` - Run YARA scan
- `malfind()` - Detect code injection
- `netscan()` / `connscan()` - Analyze network connections
- `procdump()` - Dump process memory
- `handles()` - Extract process handles

### 3. Scanners (scanner.py)

Three independent scanner classes:

#### YaraScanner
```python
YaraScanner(vol, rule_file, excluded_words)
├── scan() -> List[SuspiciousProcess]
```

Applies YARA rules to memory dump.

#### MalfindScanner
```python
MalfindScanner(vol)
├── scan() -> List[SuspiciousProcess]
```

Detects injected code and suspicious allocations.

#### NetworkScanner
```python
NetworkScanner(vol, ip_checker)
├── scan() -> List[SuspiciousProcess]
```

Identifies suspicious network connections.

### 4. Artifact Collection (artifacts.py)

Two complementary classes:

#### ArtifactCollector
```python
ArtifactCollector(vol, output_dir)
├── dump_process() -> Path
└── collect_handles() -> Path
```

Extracts process memory and handles information.

#### ClamavScanner
```python
ClamavScanner()
├── is_available() -> bool
└── scan(file) -> str
```

Scans artifacts with antivirus.

### 5. Data Models (models.py)

#### SuspiciousProcess
```python
@dataclass
class SuspiciousProcess:
    rule: str           # Detection rule name
    process: str        # Process name
    pid: str            # Process ID
    profile: str        # Memory profile
```

### 6. Utilities (utils.py)

Helper functions:
- `get_malhunt_home()` - Get cache directory
- `check_exclusions()` - Filter excluded rules
- `clean_up()` - Remove old caches
- `remove_incompatible_imports()` - Filter incompatible rules
- `fix_duplicated_rules()` - Remove duplicate definitions (used internally for sanity)

The previous list and merge helpers were removed after switching to compressed rule downloads.

## Execution Flow

### Complete Analysis Workflow

```
main()
├── Setup logging
├── Parse arguments
├── Create Malhunt instance
└── malhunt.run_full_analysis()
    ├── clean_up()
    ├── prepare_rules()
    │   ├── Clone Yara-Rules repository
    │   ├── Filter incompatible imports
    │   ├── Fix duplicate rule definitions
    │   └── Merge into single file
    ├── identify_profile()
    │   └── Parse imageinfo output
    ├── run_scans()
    │   ├── yara_scanner.scan()
    │   │   └── Parse YARA matches
    │   ├── malfind_scanner.scan()
    │   │   └── Parse injection detection
    │   └── network_scanner.scan()
    │       └── Parse connections, check IPs
    ├── collect_artifacts()
    │   ├── For each suspicious process:
    │   │   ├── dump_process()
    │   │   ├── collect_handles()
    │   │   └── antivirus.scan()
    └── Report results
```

## Key Design Decisions

### 1. CLI-Based Volatility Integration

**Why:** Current version uses CLI (`os.popen`/`subprocess`) rather than direct API.

**Justification:**
- Volatility3 API is still evolving
- CLI is stable and widely supported
- Easier error handling and timeouts
- Better compatibility across versions

**Future:** Could migrate to direct API when it stabilizes.

### 2. Separated Scanner Classes

**Why:** YARA, Malfind, and Network scanners are independent classes.

**Justification:**
- Single responsibility principle
- Easier to test independently
- Allows selective scanning
- Reusable for custom workflows

### 3. Model-Based Process Representation

**Why:** Use `SuspiciousProcess` dataclass instead of raw strings.

**Justification:**
- Type safety
- Extensible for additional metadata
- Better IDE support
- Easier serialization (JSON export)

## Extension Points

### Adding a New Scanner

```python
from .scanner import BaseScannerProtocol

class CustomScanner:
    def __init__(self, vol: VolatilityWrapper):
        self.vol = vol
    
    def scan(self) -> List[SuspiciousProcess]:
        """Run scan, return suspicious processes."""
        pass

# In core.py
self.custom_scanner = CustomScanner(self.vol)
self.scan_results.extend(self.custom_scanner.scan())
```

### Custom IP Checking

```python
def my_ip_checker(ip: str) -> bool:
    """Return True if IP is malicious."""
    return check_threat_intel_api(ip)

scanner = NetworkScanner(vol, ip_checker=my_ip_checker)
```

### Custom Output Formatting

```python
from malhunt import Malhunt

mh = Malhunt(dump_path)
mh.run_scans()

# Export as JSON
import json
results = [
    asdict(proc) for proc in mh.scan_results
]
print(json.dumps(results, indent=2))
```

## Thread Safety

**Current Status:** NOT thread-safe

- Volatility execution is sequential
- Global state in caches

**Future Improvement:** Would require:
- Separate Volatility instances per thread
- Lock-protected cache access
- Concurrent scanning of large dumps

## Performance Characteristics

| Operation | Typical Time | Bottleneck |
|-----------|-------------|-----------|
| Profile ID | 30-60s | Volatility plugin load |
| YARA scan | 5-30m | Rule complexity, dump size |
| Malfind | 2-10m | Memory scanning |
| Network scan | 1-5m | Connection count |
| ClamAV | 2-5m per process | Pattern matching |

## Error Handling Strategy

```
VolatilityError
└── If Volatility command fails
    └── Log & continue with next scan type

Generic Exception
└── Log with full traceback
└── Attempt to continue
└── Exit with code 1 if critical
```

## Logging Architecture

Uses **loguru** for unified logging:

```python
from loguru import logger

logger.info("Information message")
logger.warning("Warning message")
logger.error("Error message")
logger.success("Success message")
```

Log levels:
- `DEBUG` - Verbose internal state
- `INFO` - Scan progress
- `SUCCESS` - Completed phases
- `WARNING` - Non-critical issues
- `ERROR` - Operation failures
