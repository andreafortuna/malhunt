"""Utility functions for malhunt."""

import os
import re
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


def sanitize_yara_rules_file(source: Path, destination: Path) -> int:
    """Sanitize a merged YARA file by removing unsupported imports/rules.

    This is designed for very large merged rule files where dropping the whole
    file due to a single incompatible token is undesirable.

    Args:
        source: Input YARA file path
        destination: Output sanitized YARA file path

    Returns:
        Number of removed rule blocks
    """
    incompatible_tokens = [
        'import "math"',
        'import "cuckoo"',
        'import "hash"',
        'imphash',
    ]

    content = source.read_text(errors="ignore")
    lines = content.splitlines(keepends=True)

    output_lines: list[str] = []
    rule_buffer: list[str] = []
    in_rule = False
    seen_open_brace = False
    brace_depth = 0
    removed_rules = 0

    rule_start = re.compile(r"^\s*(?:(?:private|global)\s+)*rule\s+[A-Za-z0-9_]+\b")

    def flush_rule_block() -> None:
        nonlocal in_rule, seen_open_brace, brace_depth, rule_buffer, removed_rules
        block_text = "".join(rule_buffer).lower()
        if any(token in block_text for token in incompatible_tokens):
            removed_rules += 1
        else:
            output_lines.extend(rule_buffer)
        in_rule = False
        seen_open_brace = False
        brace_depth = 0
        rule_buffer = []

    for line in lines:
        lowered = line.lower()

        if not in_rule and rule_start.match(line):
            in_rule = True
            seen_open_brace = "{" in line
            brace_depth = line.count("{") - line.count("}")
            rule_buffer = [line]
            if seen_open_brace and brace_depth <= 0:
                flush_rule_block()
            continue

        if in_rule:
            rule_buffer.append(line)
            if "{" in line:
                seen_open_brace = True
            brace_depth += line.count("{") - line.count("}")
            if seen_open_brace and brace_depth <= 0:
                flush_rule_block()
            continue

        # keep non-rule line unless it's a known incompatible import
        if any(token == lowered.strip() for token in incompatible_tokens[:3]):
            continue
        output_lines.append(line)

    if in_rule and rule_buffer:
        flush_rule_block()

    sanitized_content = "".join(output_lines)

    # Aggressive fallback: remove any remaining imphash-containing rule blocks
    # that may have escaped the state machine due to unusual rule formatting.
    if "imphash" in sanitized_content.lower():
        lines2 = sanitized_content.splitlines(keepends=True)
        drop_indexes: set[int] = set()

        def find_rule_start(index: int) -> Optional[int]:
            for i in range(index, -1, -1):
                if rule_start.match(lines2[i]):
                    return i
            return None

        for idx, line in enumerate(lines2):
            if "imphash" not in line.lower():
                continue

            start = find_rule_start(idx)
            if start is None:
                drop_indexes.add(idx)
                continue

            depth = 0
            seen_open = False
            end = start
            for j in range(start, len(lines2)):
                depth += lines2[j].count("{") - lines2[j].count("}")
                if "{" in lines2[j]:
                    seen_open = True
                end = j
                if seen_open and depth <= 0:
                    break

            for j in range(start, end + 1):
                drop_indexes.add(j)
            removed_rules += 1

        sanitized_content = "".join(
            line for i, line in enumerate(lines2) if i not in drop_indexes
        )

    destination.write_text(sanitized_content)
    return removed_rules


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
