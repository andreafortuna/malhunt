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
        'imphash',
        'pe.number_of_signatures',
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
        'pe.number_of_signatures',
    ]

    content = source.read_text(errors="ignore")
    lines = content.splitlines(keepends=True)

    output_lines: list[str] = []
    rule_buffer: list[str] = []
    in_rule = False
    seen_open_brace = False
    brace_depth = 0
    removed_rules = 0

    rule_start = re.compile(r"^\s*(?:(?:private|global)\s+)*rule\b")

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


def validate_and_prune_yara_rules_file(source: Path, destination: Path, max_iterations: int = 2000) -> int:
    """Validate a YARA file by compiling it and pruning failing rule blocks.

    Args:
        source: Input YARA file path
        destination: Output validated YARA file path
        max_iterations: Max number of pruning passes

    Returns:
        Number of removed blocks/lines required to reach a compilable file
    """
    try:
        import yara  # type: ignore
    except Exception as exc:
        logger.warning(f"yara-python unavailable for validation, skipping parse pass: {exc}")
        shutil.copyfile(source, destination)
        return 0

    lines = source.read_text(errors="ignore").splitlines(keepends=True)
    removed = 0

    for _ in range(max_iterations):
        if not lines:
            break

        candidate = "".join(lines)
        try:
            yara.compile(source=candidate)
            destination.write_text(candidate)
            return removed
        except Exception as exc:
            message = str(exc)
            line_match = re.search(r"line\s*(\d+)", message, flags=re.IGNORECASE)

            if not line_match:
                logger.warning(f"Unable to map YARA compile error to line, stopping parse pass: {message}")
                break

            try:
                line_number = int(line_match.group(1))
            except ValueError:
                logger.warning(f"Invalid YARA compile error line, stopping parse pass: {message}")
                break

            index = max(0, min(len(lines) - 1, line_number - 1))
            bounds = _find_yara_block_bounds(lines, index)
            if bounds is None:
                del lines[index]
                removed += 1
                continue

            start, end = bounds
            del lines[start : end + 1]
            removed += 1

    if lines:
        destination.write_text("".join(lines))
    else:
        destination.write_text("")

    if removed >= max_iterations:
        logger.warning("YARA parse pass hit max iterations before reaching a clean compile")

    return removed


def _find_yara_block_bounds(lines: list[str], index: int) -> Optional[tuple[int, int]]:
    """Find bounds of a rule/orphan block around a 0-based line index."""
    rule_start = re.compile(r"^\s*(?:(?:private|global)\s+)*rule\b")

    for i in range(index, -1, -1):
        if not rule_start.match(lines[i]):
            continue

        depth = 0
        seen_open = False
        end = i
        for j in range(i, len(lines)):
            depth += lines[j].count("{") - lines[j].count("}")
            if "{" in lines[j]:
                seen_open = True
            end = j
            if seen_open and depth <= 0:
                break

        if i <= index <= end:
            return (i, end)

        if seen_open and depth <= 0 and end < index:
            break

        if i <= index and (not seen_open or depth > 0):
            for j in range(i + 1, len(lines)):
                if rule_start.match(lines[j]):
                    return (i, j - 1)
            return (i, len(lines) - 1)

    orphan_start = index
    while orphan_start > 0 and lines[orphan_start - 1].strip() != "}":
        orphan_start -= 1

    orphan_end = index
    while orphan_end < len(lines) and lines[orphan_end].strip() != "}":
        orphan_end += 1
    if orphan_end >= len(lines):
        orphan_end = len(lines) - 1

    chunk = "".join(lines[orphan_start : orphan_end + 1]).lower()
    if not any(token in chunk for token in ("rule ", "meta:", "strings:", "condition:", "$")):
        return None

    return (orphan_start, orphan_end)


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
