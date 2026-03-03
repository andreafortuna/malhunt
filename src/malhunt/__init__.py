"""
Malhunt - Hunt malware in memory dumps with Volatility3

A tool for automated malware discovery in memory dumps using Volatility3,
YARA rules, and ClamAV.
"""

__version__ = "0.4.0"
__author__ = "Andrea Fortuna"
__email__ = "andrea@andreafortuna.org"
__license__ = "MIT"

from .core import Malhunt

__all__ = ["Malhunt", "__version__"]
