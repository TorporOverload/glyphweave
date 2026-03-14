"""Logging configuration for GlyphWeave.

Debug logging is controlled via GLYPHWEAVE_DEBUG environment variable:
- When not set or '0', the logging is disabled by default
- '1': Basic debug logging (INFO level)
- '2': Detailed debug logging (DEBUG level)
- '3': Verbose debug logging (DEBUG level + timed operations)
"""

import logging
import os
import sys
from functools import wraps
from time import perf_counter
from typing import Any, Callable, ParamSpec, TypeVar

from app.config import ensure_app_data_layout, get_app_data_dir

P = ParamSpec("P")
T = TypeVar("T")

# Check environment variable once at import
DEBUG_LEVEL = int(os.environ.get("GLYPHWEAVE_DEBUG", "3"))  # TODO Chaneg back to 0
DEBUG_ENABLED = DEBUG_LEVEL > 0
APP_DATA_DIR = ensure_app_data_layout(get_app_data_dir())
DEFAULT_LOG_DIR = APP_DATA_DIR / "logs"
GLYPHWEAVE_LOG_FILE = os.environ.get(
    "GLYPHWEAVE_LOG_FILE",
    str(DEFAULT_LOG_DIR / "debug.log"),
)
GLYPHWEAVE_ERROR_LOG_FILE = os.environ.get(
    "GLYPHWEAVE_ERROR_LOG_FILE",
    str(DEFAULT_LOG_DIR / "error.log"),
)


class _SafeConsoleStream:
    def __init__(self, stream) -> None:
        self._stream = stream

    def write(self, data: str) -> int:
        """Write data to the stream, replacing unencodable characters with escape
        sequences."""
        try:
            return self._stream.write(data)
        except UnicodeEncodeError:
            encoding = getattr(self._stream, "encoding", None) or "utf-8"
            safe_data = data.encode(encoding, errors="backslashreplace").decode(
                encoding
            )
            return self._stream.write(safe_data)

    def flush(self) -> None:
        """Flush the underlying stream."""
        self._stream.flush()

    def __getattr__(self, name: str):
        """Delegate attribute access to the underlying stream."""
        return getattr(self._stream, name)


def _build_console_stream():
    """Return a stderr stream configured to handle Unicode encoding errors safely."""
    stream: Any = sys.stderr
    reconfigure = getattr(stream, "reconfigure", None)
    if callable(reconfigure):
        try:
            reconfigure(errors="backslashreplace")
            return stream
        except Exception:
            pass

    return _SafeConsoleStream(stream)


def setup_logging() -> logging.Logger:
    """Configure application logging based on environment."""
    logger = logging.getLogger("glyphweave")

    # Prevent duplicate handlers if called multiple times
    if logger.handlers:
        return logger

    if DEBUG_ENABLED:
        # Determine log level based on DEBUG_LEVEL
        if DEBUG_LEVEL == 1:
            log_level = logging.INFO
        else:  # DEBUG_LEVEL >= 2
            log_level = logging.DEBUG

        logger.setLevel(log_level)
        formatter = logging.Formatter(
            "%(asctime)s | %(name)s | %(levelname)s | %(message)s", datefmt="%H:%M:%S"
        )

        # Console handler
        console_handler = logging.StreamHandler(stream=_build_console_stream())
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        # File handler
        file_handler = logging.FileHandler(
            GLYPHWEAVE_LOG_FILE,
            encoding="utf-8",
            errors="backslashreplace",
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        error_handler = logging.FileHandler(
            GLYPHWEAVE_ERROR_LOG_FILE,
            encoding="utf-8",
            errors="backslashreplace",
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(formatter)
        logger.addHandler(error_handler)

    else:
        # Production: disable all logging
        logger.setLevel(logging.CRITICAL)
        logger.addHandler(logging.NullHandler())

    return logger


# Global logger instance
logger = setup_logging()


def timed_operation(operation_name: str) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """Decorator to log operation timing.

    Only logs timing information when DEBUG_LEVEL >= 3 (verbose mode).
    """

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            # Only time operations when DEBUG_LEVEL is 3 or higher
            if DEBUG_LEVEL < 3:
                return func(*args, **kwargs)

            start = perf_counter()
            try:
                result = func(*args, **kwargs)
                duration = perf_counter() - start
                logger.debug(f"{operation_name} completed in {duration:.3f}s")
                return result
            except Exception as e:
                duration = perf_counter() - start
                logger.error(f"{operation_name} failed after {duration:.3f}s: {e}")
                raise

        return wrapper

    return decorator
