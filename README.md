# Malhunt

**Hunt malware in memory dumps with Volatility3**

Malhunt is an automated malware hunting tool that analyzes memory dumps using Volatility3, applying YARA rules, code injection scanning, and network analysis to identify suspicious processes.

## Features

- 🔍 **Memory Profile Detection** - Automatic identification of Windows/Linux memory dumps
- 📋 **YARA Rule Scanning** - Apply multiple YARA rules for malware detection
- 💉 **Injection Detection** - Identify injected code and suspiciously allocated memory
- 🌐 **Network Analysis** - Detect suspicious network connections
- 📦 **Artifact Collection** - Extract and preserve suspicious process memory
- 🛡️ **Antivirus Integration** - Scan artifacts with ClamAV
- 📊 **Comprehensive Reporting** - Detailed logs and findings

## Quick Start

### Installation

#### Requirements
- Python 3.9+
- Volatility3 (≥2.0.0)
- Git (for downloading and managing YARA rules)
- ClamAV (optional, for antivirus scanning)
- Poetry (for development; users can use pip)

#### Via pip (Recommended for Users)
```bash
pip install volatility3 yara-python ruff loguru pyclamd requests pydantic
pip install malhunt
```

#### From source with Poetry (For Development)
```bash
git clone https://github.com/andreafortuna/malhunt.git
cd malhunt
poetry install
poetry run malhunt --help
```

#### From source with pip
```bash
git clone https://github.com/andreafortuna/malhunt.git
cd malhunt
pip install -e .
malhunt --help
```

### Usage

#### With Poetry (Development)
```bash
poetry run malhunt /path/to/memory.dump
poetry run malhunt /path/to/memory.dump --rules custom_rules.yar
poetry run malhunt /path/to/memory.dump --verbose
```

#### With pip (Direct Installation)
```bash
malhunt /path/to/memory.dump
malhunt /path/to/memory.dump --rules custom_rules.yar
malhunt /path/to/memory.dump --verbose
```

#### Help and Version
```bash
malhunt --help      # Show all options
malhunt --version   # Show version
```

## How It Works

Malhunt applies a systematic approach for malware discovery in memory:

1. **Initialization** - Validates memory dump and locates Volatility3 binary
2. **Cache Cleanup** - Removes old YARA rules (> 1 day) and temporary files
3. **Rule Preparation** - Downloads latest YARA rules from GitHub or uses cached version
   - Performs shallow git clone for efficiency
   - Filters incompatible YARA rules
   - Deduplicates and merges into single malware_rules.yar
4. **Profile Identification** - Detects OS variant from memory dump using `windows.info`
5. **Phase 1: YARA Scanning** - 📊 Applies comprehensive YARA rules (3310+ rules) to memory
6. **Phase 2: Malfind Scanning** - 💉 Detects injected code and suspicious memory allocations
7. **Phase 3: Network Scanning** - 🌐 Analyzes network connections for malicious IPs
8. **Artifact Collection** - Dumps suspicious process memory and extracts handle information
9. **Antivirus Scanning** - 🛡️ Scans artifacts with ClamAV (if available)
10. **Reporting** - Generates structured logs and preserves artifacts for investigation

## Architecture

```
src/malhunt/
├── __init__.py          # Package initialization
├── __main__.py          # CLI entry point
├── core.py              # Main orchestration logic
├── volatility.py        # Volatility3 wrapper
├── scanner.py           # YARA/Malfind/Network scanners
├── artifacts.py         # Artifact collection & antivirus
├── models.py            # Data models
└── utils.py             # Utility functions
```

## Output

Malhunt creates an `<dump_name>_artifacts/` directory containing:
- Process memory dumps (`.bin` files)
- Process handles information (`.handles` files)
- Scan results and logs

## Migration from Volatility2

If you're using the older v0.1 version with Volatility2, see [MIGRATION.md](docs/MIGRATION.md) for upgrade instructions.

## Development

### Setting Up Dev Environment

```bash
cd /path/to/malhunt

# Install all dependencies including dev tools
poetry install

# Run tests
poetry run pytest tests/ -v

# Run with coverage
poetry run pytest tests/ --cov=src/malhunt --cov-report=html

# Code quality checks
poetry run black src/malhunt tests/
poetry run ruff check src/malhunt tests/
poetry run mypy src/malhunt
```

### Building Documentation

```bash
# Install docs dependencies
poetry install --with docs

# Build Sphinx documentation
cd docs
make html
# Open _build/html/index.html
```

### Running Malhunt in Development

```bash
# Via Poetry
poetry run malhunt /path/to/dump.vmem

# Via Python module
poetry run python3 -m malhunt /path/to/dump.vmem
```

## Requirements

### Core Dependencies
- **Python** 3.9+ (tested with 3.9, 3.10, 3.11)
- **Volatility3** (≥2.0.0) - Memory forensics framework
- **YARA-Python** (≥4.3.0) - Malware identification engine
- **Pydantic** (≥2.0.0) - Data validation
- **Loguru** (≥0.7.0) - Structured logging
- **Requests** (≥2.32.0) - HTTP client for IP checking
- **PyClamd** (≥0.4.0) - ClamAV integration

### System Requirements
- **Git** - For downloading YARA rules repository
- **ClamAV** (optional) - Antivirus scanning support

### Build & Development
- **Poetry** (≥1.0.0) - Project/dependency management
- **Pytest** (≥7.0.0) - Testing framework
- **Black** (≥23.0.0) - Code formatting
- **Ruff** (≥0.1.0) - Linting
- **MyPy** (≥1.0.0) - Type checking

## Configuration

Malhunt stores configuration and cached data in `~/.malhunt/`:

### Cache Files
- **`malware_rules.yar`** - Merged YARA rules (auto-updated if > 1 day old)
- **`rules/`** - Downloaded YARA rule repository (shallow git clone)

### Customization
Volatility3 execution can be customized via `VolatilityConfig`:

```python
from pathlib import Path
from malhunt import Malhunt
from malhunt.volatility import VolatilityConfig

# Custom timeout and retry settings
config = VolatilityConfig(
    timeout=600,        # 10 minutes
    retry_count=3,      # Retry up to 3 times
    retry_delay=2.0,    # 2 seconds between retries
    cache_results=True  # Cache command results
)

mh = Malhunt(Path("dump.vmem"), vol_config=config)
mh.run_full_analysis()
```

## Troubleshooting

See [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for common issues and solutions.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - See LICENSE file for details

## Author

**Andrea Fortuna** - [@andreafortuna](https://twitter.com/andreafortuna)

- Website: https://andreafortuna.org
- Email: andrea@andreafortuna.org

## References

- [Volatility3 Documentation](https://volatility3.readthedocs.io/)
- [YARA Documentation](https://yara.readthedocs.io/)
- [ClamAV Documentation](https://www.clamav.net/documents)

## Disclaimer

This tool is intended for authorized security testing and malware analysis only. Ensure you have proper authorization before analyzing memory dumps. The authors are not responsible for misuse or damage caused by this tool.

