"""Utility functions for malhunt."""

import os
import shutil
import time
from pathlib import Path
from typing import Optional

from loguru import logger


def get_malhunt_home() -> Path:
    """Get malhunt home directory, creating it if necessary."""
    home = Path.home() / ".malhunt"
    home.mkdir(exist_ok=True)
    return home


def check_exclusions(line: str, excluded_words: list[str]) -> bool:
    """Check if line contains excluded words.
    
    Args:
        line: The line to check
        excluded_words: List of words to filter out
        
    Returns:
        True if line should be included, False if it should be filtered
    """
    return not any(word in line for word in excluded_words)


def clean_up(malhunt_home: Path) -> None:
    """Clean up old cache files.
    
    Args:
        malhunt_home: Path to malhunt home directory
    """
    rules_dir = malhunt_home / "rules"
    shutil.rmtree(rules_dir, ignore_errors=True)
    
    rules_file = malhunt_home / "malware_rules.yar"
    if rules_file.exists():
        st = rules_file.stat()
        max_age = time.time() - (60 * 60 * 24)  # One day
        if st.st_mtime < max_age:
            rules_file.unlink()
            logger.info("Cleaned up old YARA rules cache")


def list_yara_files(malhunt_home: Path) -> list[Path]:
    """Recursively find all YARA rule files.
    
    Args:
        malhunt_home: Path to malhunt home directory
        
    Returns:
        List of paths to YARA files
    """
    yara_files = []
    
    for search_dir in ["malware", "Webshells"]:
        rules_path = malhunt_home / "rules" / search_dir
        if not rules_path.exists():
            continue
            
        for yara_file in rules_path.rglob("*.yar"):
            yara_files.append(yara_file)
        for yara_file in rules_path.rglob("*.yara"):
            yara_files.append(yara_file)
    
    return sorted(yara_files)


def remove_incompatible_imports(files: list[Path]) -> list[Path]:
    """Filter out YARA files with incompatible imports.
    
    Args:
        files: List of YARA file paths
        
    Returns:
        Filtered list of compatible YARA files
    """
    incompatible_imports = [
        'import "math"',
        'import "cuckoo"',
        'import "hash"',
        'imphash'
    ]
    
    filtered = []
    for yara_file in files:
        content = yara_file.read_text()
        if not any(imp in content for imp in incompatible_imports):
            filtered.append(yara_file)
    
    return filtered


def fix_duplicated_rules(content: str) -> str:
    """Remove duplicate rule definitions from merged YARA content.
    
    Args:
        content: Merged YARA rules content
        
    Returns:
        Cleaned content with duplicates removed
    """
    lines = content.split('\n')
    filtered = []
    first_elf = True
    skip_block = False
    
    for line in lines:
        if line.strip() == "private rule is__elf {":
            if first_elf:
                first_elf = False
                filtered.append(line)
            else:
                skip_block = True
        elif skip_block and line.strip() == "}":
            skip_block = False
        elif not skip_block:
            filtered.append(line)
    
    return '\n'.join(filtered)


def merge_rules(yara_files: list[Path], output_path: Path) -> None:
    """Merge multiple YARA files into a single file.
    
    Args:
        yara_files: List of YARA file paths
        output_path: Output file path
    """
    merged_content = ""
    
    for yara_file in yara_files:
        merged_content += yara_file.read_text() + "\n\n"
    
    merged_content = fix_duplicated_rules(merged_content)
    output_path.write_text(merged_content)
    logger.info(f"Merged {len(yara_files)} YARA rules into {output_path}")


def banner_logo() -> str:
    """Return malhunt ASCII banner."""
    return """  __  __       _ _                 _   
 |  \/  |     | | |               | |  
 | \  / | __ _| | |__  _   _ _ __ | |_ 
 | |\/| |/ _` | | '_ \| | | | '_ \| __|
 | |  | | (_| | | | | | |_| | | | | |_ 
 |_|  |_|\__,_|_|_| |_|\__,_|_| |_|\__|
                                       
Hunt malware with Volatility3!

Andrea Fortuna
andrea@andreafortuna.org
https://andreafortuna.org
"""
