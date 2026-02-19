"""
Sroq Logging Configuration

Provides minimal, clean logging setup for the CLI.
"""

import logging
import sys


def setup_logging(verbose: bool = False, debug: bool = False) -> logging.Logger:
    """
    Configure logging for Sroq.

    Args:
        verbose: If True, enable DEBUG level; if False, use INFO.
        debug: Alias for verbose (for backwards compatibility).

    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger("sroq")
    logger.handlers = []  # Clear any existing handlers

    # Determine log level
    if verbose or debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logger.setLevel(log_level)

    # Create console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)

    # Create formatter (minimal, no timestamp for CLI output)
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)

    logger.addHandler(handler)

    return logger


def get_logger(name: str = "sroq") -> logging.Logger:
    """Get or create logger instance."""
    return logging.getLogger(name)
