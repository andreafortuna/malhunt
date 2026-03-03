# Contributing to Malhunt

Thank you for your interest in contributing to malhunt! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Focus on the code, not the person
- Help others learn

## Getting Started

### Development Setup

```bash
# Clone the repository
git clone https://github.com/andreafortuna/malhunt.git
cd malhunt

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Verify setup
pytest --version
black --version
ruff --version
```

### Project Structure

```
src/malhunt/          # Main package
tests/                # Test suite
docs/                 # Documentation
pyproject.toml        # Project configuration
```

## Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b feature/my-feature
# or for bug fixes:
git checkout -b bugfix/my-bug
```

### 2. Make Changes

Follow the coding style:
- Use type hints
- Write descriptive docstrings
- Keep functions focused and small
- Add tests for new functionality

### 3. Run Tests & Quality Checks

```bash
# Format code
black src/malhunt tests/

# Check style
ruff check src/malhunt tests/

# Type checking
mypy src/malhunt/

# Run tests
pytest -v

# Check coverage
pytest --cov=malhunt tests/
```

### 4. Commit Changes

```bash
git add .
git commit -m "feat: add feature description"
# or
git commit -m "fix: resolve bug description"
```

### 5. Push and Create Pull Request

```bash
git push origin feature/my-feature
```

Then create a PR on GitHub with:
- Clear title: `feat: add feature` or `fix: resolve issue`
- Description of changes
- Link to related issues

## Contribution Areas

### Code Contributions

#### High Priority
- [ ] Fix Volatility3 profile identification
- [ ] Improve error handling and logging
- [ ] Add more comprehensive tests
- [ ] Optimize performance for large dumps

#### Good First Issues
- [ ] Improve docstrings
- [ ] Add type annotations
- [ ] Create test fixtures
- [ ] Update documentation

### Documentation Contributions

- Improve existing docs
- Add usage examples
- Fix typos
- Add troubleshooting tips
- Translate to other languages

### Testing Contributions

- Write unit tests
- Add integration tests
- Create test fixtures
- Improve test coverage

## Coding Standards

### Style Guide

```python
# Imports: Standard library, third party, local
import os
import sys
from pathlib import Path
from typing import Optional, List

import requests
from loguru import logger

from .models import SuspiciousProcess
from .volatility import VolatilityWrapper

# Type hints on all functions
def analyze(dump_path: Path, rules: Optional[Path] = None) -> List[str]:
    """Analyze memory dump and return findings.
    
    Args:
        dump_path: Path to memory dump file
        rules: Optional path to custom YARA rules
        
    Returns:
        List of finding descriptions
        
    Raises:
        FileNotFoundError: If dump file doesn't exist
    """
    pass

# Use dataclasses for data models
from dataclasses import dataclass

@dataclass
class Finding:
    """A malware finding in the memory dump."""
    rule: str
    process: str
    confidence: float
```

### Docstring Format

Use Google-style docstrings:

```python
def function(param1: str, param2: int = 0) -> bool:
    """Brief one-line description.
    
    Longer description explaining what the function does,
    any important details, and special behavior.
    
    Args:
        param1: Description of param1
        param2: Description of param2 (optional)
        
    Returns:
        Description of return value
        
    Raises:
        ValueError: When value is invalid
        FileNotFoundError: When file not found
        
    Example:
        >>> result = function("test", 42)
        >>> print(result)
        True
    """
    pass
```

### Logging

```python
from loguru import logger

# Use appropriate levels
logger.debug("Detailed diagnostic info")
logger.info("Informational messages")
logger.success("Successful operations")
logger.warning("Warning messages")
logger.error("Error messages")
logger.critical("Critical failures")
```

## Testing Guidelines

### Write Tests For

- New features
- Bug fixes
- Edge cases
- Error conditions

### Test Structure

```python
# tests/test_scanner.py
import pytest
from pathlib import Path

from malhunt.scanner import YaraScanner
from malhunt.volatility import VolatilityWrapper

def test_yara_scanner_initialization():
    """Test YaraScanner initialization."""
    # Setup
    vol = VolatilityWrapper(Path("test_dump.raw"))
    rules_file = Path("test_rules.yar")
    
    # Execute
    scanner = YaraScanner(vol, rules_file)
    
    # Assert
    assert scanner.vol == vol
    assert scanner.rule_file == rules_file

def test_yara_scanner_with_excluded_words():
    """Test YARA scanner filters excluded words."""
    # Setup
    excluded = ["test_rule"]
    scanner = YaraScanner(vol, rules, excluded_words=excluded)
    
    # Execute
    results = scanner.scan()
    
    # Assert
    assert not any(r.rule == "test_rule" for r in results)

@pytest.mark.parametrize("rule_name,should_pass", [
    ("legitimate_rule", True),
    ("Str_Win32_virus", False),
])
def test_check_exclusions(rule_name, should_pass):
    """Test exclusion filtering with various rule names."""
    from malhunt.utils import check_exclusions
    
    excluded = ["Str_Win32_", "SurtrStrings"]
    result = check_exclusions(rule_name, excluded)
    assert result == should_pass
```

## Issue Reporting

### Bug Reports

Include:
1. **Environment:** OS, Python version, malhunt version
2. **Reproduction steps:** How to trigger the bug
3. **Expected vs actual:** What should happen vs what does
4. **Full error trace:** Complete error message
5. **Debug output:** Run with `--verbose` flag

### Feature Requests

Include:
1. **Use case:** Why this feature is needed
2. **Proposed solution:** How it should work
3. **Alternatives:** Other possible approaches
4. **Examples:** Concrete usage examples

## Documentation

### Guidelines

- Keep doc examples runnable
- Include Python 3.10+ compatible code
- Add type hints to all examples
- Include expected output
- Link to related docs

### Example Template

```markdown
## Feature Name

Brief description of what this feature does.

### Basic Usage

```bash
malhunt memory.dump
```

### Advanced Usage

```python
from malhunt import Malhunt

mh = Malhunt(Path("memory.dump"))
# Your example here
```

### See Also

- [Related Feature](link)
- [API Reference](link)
```

## Pull Request Process

1. **Before submitting:**
   - [ ] Code follows style guide
   - [ ] All tests pass
   - [ ] Documentation updated
   - [ ] No unresolved conflicts
   - [ ] Commit history is clean

2. **PR description should include:**
   - [ ] What problem does this solve?
   - [ ] How was it tested?
   - [ ] Any breaking changes?
   - [ ] Related issues/PRs

3. **Code review:**
   - [ ] Respond to feedback promptly
   - [ ] Make requested changes
   - [ ] Request re-review after changes

## Release Process

Maintainers only:

```bash
# Update version in src/malhunt/__init__.py
# Update CHANGELOG.md
git tag -a v0.5.0 -m "Release 0.5.0"
git push origin v0.5.0
# Build and upload to PyPI
```

## Getting Help

- **Questions:** Open a Discussion
- **Bugs:** Open an Issue with bug label
- **Features:** Open an Issue with enhancement label
- **Security:** Email security@example.com privately

## Acknowledgments

Thank you for contributing! Your efforts make malhunt better for everyone.

Contributors are credited in:
- CONTRIBUTORS.md file
- GitHub contributors page
- Release notes

## License

By contributing, you agree that your contributions are licensed under the MIT License.
