# Installation Guide

## Requirements

Before installing malhunt, ensure you have the following:

- **Python 3.10 or later**
- **Git** (optional; previously used for cloning YARA rules)
- **Volatility3** (≥2.0.0)
- ClamAV (optional, for antivirus scanning)

## Platform-Specific Installation

### macOS

Using Homebrew:
```bash
# Install Volatility3
brew install volatility3

# Install ClamAV (optional)
brew install clamav

# Install malhunt
pip install malhunt
```

### Linux (Ubuntu/Debian)

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y python3.10 python3-pip volatility3

# Install ClamAV (optional)
sudo apt-get install -y clamav

# Install malhunt
pip install &lt;malhunt
```

### Linux (Fedora/RHEL)

```bash
# Install system dependencies
sudo dnf install -y python3.10 python3-pip volatility3

# Install ClamAV (optional)
sudo dnf install -y clamav

# Install malhunt
pip install malhunt
```

### Windows

Using Chocolatey:
```powershell
# Install Volatility3
choco install volatility3

# Install ClamAV (optional)
choco install clamav

# Install malhunt
pip install malhunt
```

Or manually:
1. Download and install Python 3.10+ from python.org
2. Download Volatility3 from https://github.com/volatilityfoundation/volatility3
3. Install malhunt: `pip install malhunt`

## Development Installation

For development and contribution:

```bash
# Clone the repository
git clone https://github.com/andreafortuna/malhunt.git
cd malhunt

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode with all dependencies
pip install -e ".[dev]"

# Run tests
pytest -v
```

## Docker

A Docker image is available:

```bash
# Build
docker build -t malhunt .

# Run
docker run -v /path/to/dumps:/dumps malhunt /dumps/memory.dump
```

## Verifying Installation

```bash
# Check malhunt version
malhunt --version

# Test volatility3 installation
vol --help

# Test clamscan (optional)
clamscan --version
```

## Troubleshooting

### "Volatility3 not found"
Ensure Volatility3 is installed and in your PATH:
```bash
which vol
# or on Windows
where vol.exe
```

### "ClamAV not available"
This is optional. Install it using your package manager or skip antivirus scanning with `--no-clamscan` flag.

### Permission errors on Linux
You may need to add your user to the appropriate group or use `sudo`:
```bash
sudo usermod -a -G your_group $USER
