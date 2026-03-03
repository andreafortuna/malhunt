"""Configuration for pytest."""

import sys
from pathlib import Path

# Add src to path so imports work
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Suppress loguru output during tests
import logging
logging.getLogger("loguru").setLevel(logging.ERROR)
