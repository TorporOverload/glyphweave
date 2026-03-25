"""Logging configuration for GlyphWeave."""

import logging
import sys
from functools import wraps
from time import perf_counter
from typing import Any, Callable, ParamSpec, TypeVar

from app.common.config import (
    get_debug_level,
    get_error_log_file_path,
    get_log_file_path,
    is_event_encryption_enabled,
)

P = ParamSpec("P")
T = TypeVar("T")

# Check configuration once at import
DEBUG_LEVEL = get_debug_level()
DEBUG_ENABLED = DEBUG_LEVEL > 0
GLYPHWEAVE_LOG_FILE = get_log_file_path()
GLYPHWEAVE_ERROR_LOG_FILE = get_error_log_file_path()


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
        except Exception as e:
            print(f"Error building coonsole stream: {e}")
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
        GLYPHWEAVE_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(
            GLYPHWEAVE_LOG_FILE,
            encoding="utf-8",
            errors="backslashreplace",
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        GLYPHWEAVE_ERROR_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
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

    if not is_event_encryption_enabled():
        warning = (
            "WARNING: GlyphWeave event encryption is disabled via "
            "GLYPHWEAVE_EVENT_ENCRYPTION. Event objects will be written in plaintext."
        )
        print(warning, file=_build_console_stream())
        if DEBUG_ENABLED:
            logger.warning(warning)

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
