"""Data models for malhunt."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class SuspiciousProcess:
    """Model for a suspicious process found during scanning.
    
    Attributes:
        rule: Name of the detection rule that triggered
        process: Process name
        pid: Process ID
        profile: Memory profile used (e.g., "Windows.7")
    """
    rule: str
    process: str
    pid: str
    profile: Optional[str] = None
    
    def __repr__(self) -> str:
        return f"SuspiciousProcess(rule={self.rule}, process={self.process}, pid={self.pid})"
