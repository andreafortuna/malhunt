"""Command-line interface for malhunt."""

import sys
from pathlib import Path

from loguru import logger

from . import __version__
from .core import Malhunt
from .utils import banner_logo
from .volatility import VolatilityError


def setup_logging(verbose: bool = False) -> None:
    """Configure logging.
    
    Args:
        verbose: Enable debug logging
    """
    log_level = "DEBUG" if verbose else "INFO"
    
    logger.remove()  # Remove default handler
    logger.add(
        sys.stderr,
        level=log_level,
        format="<level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
    )


def print_usage(prog: str) -> None:
    """Print usage information.
    
    Args:
        prog: Program name
    """
    print(f"Usage: {prog} <memory_dump> [--rules <yara_rules>] [--verbose] [--auto-symbols]")
    print()
    print("Arguments:")
    print("  memory_dump      Path to memory dump file")
    print("  --rules FILE     Path to custom YARA rules file")
    print("  --verbose        Enable verbose output")
    print("  --auto-symbols   Try best-effort recovery of missing Windows symbols")
    print("  --version        Show version and exit")
    print("  --help           Show this help message")


def main(args: list[str] = None) -> int:
    """Main entry point.
    
    Args:
        args: Command-line arguments (defaults to sys.argv[1:])
        
    Returns:
        Exit code (0 for success, 1 for error)
    """
    if args is None:
        args = sys.argv[1:]
    
    # Parse arguments
    verbose = "--verbose" in args
    auto_symbols = "--auto-symbols" in args
    setup_logging(verbose)
    
    if "--version" in args:
        print(f"malhunt {__version__}")
        return 0
    
    if "--help" in args or "-h" in args:
        print_usage(sys.argv[0])
        return 0
    
    # Get dump file
    if not args or args[0].startswith("--"):
        print_usage(sys.argv[0])
        return 1
    
    dump_path = Path(args[0])
    
    if not dump_path.exists():
        logger.error(f"Memory dump not found: {dump_path}")
        return 1
    
    # Get optional rules file
    rules_file = None
    if "--rules" in args:
        try:
            idx = args.index("--rules")
            rules_file = Path(args[idx + 1])
            if not rules_file.exists():
                logger.error(f"YARA rules file not found: {rules_file}")
                return 1
        except (IndexError, ValueError):
            logger.error("--rules requires a file path argument")
            return 1
    
    # Run analysis
    try:
        malhunt = Malhunt(dump_path, rules_file, auto_symbols=auto_symbols)
        malhunt.run_full_analysis()
        return 0
    
    except VolatilityError as e:
        logger.error(f"Volatility error: {e}")
        return 1
    except KeyboardInterrupt:
        logger.warning("Analysis interrupted by user")
        return 1
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
