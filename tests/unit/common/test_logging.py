import logging
from unittest.mock import patch

import pytest

import app.common.logging as log_mod
from app.common.logging import _SafeConsoleStream, _build_console_stream, timed_operation


class TestSafeConsoleStream:
    def test_write_delegates_to_underlying_stream(self) -> None:
        class MockStream:
            def __init__(self):
                self.written = ""

            def write(self, data):
                self.written = data
                return len(data)

            def flush(self):
                pass

            @property
            def encoding(self):
                return "utf-8"

        mock = MockStream()
        stream = _SafeConsoleStream(mock)
        result = stream.write("Hello")

        assert result == 5
        assert mock.written == "Hello"

    def test_flush_delegates_to_underlying_stream(self) -> None:
        class MockStream:
            def __init__(self):
                self.flushed = False

            def write(self, data):
                return len(data)

            def flush(self):
                self.flushed = True

            @property
            def encoding(self):
                return "utf-8"

        mock = MockStream()
        stream = _SafeConsoleStream(mock)
        stream.flush()

        assert mock.flushed is True


class TestBuildConsoleStream:
    def test_returns_stream_with_write_method(self) -> None:
        stream = _build_console_stream()
        assert hasattr(stream, "write")
        assert hasattr(stream, "flush")


class TestTimedOperation:
    def test_timed_operation_decorator_returns_result(self) -> None:
        @timed_operation("test operation")
        def sample_func(x):
            return x * 2

        result = sample_func(5)
        assert result == 10

    def test_timed_operation_raises_on_exception(self) -> None:
        @timed_operation("failing operation")
        def failing_func():
            raise ValueError("test error")

        with pytest.raises(ValueError, match="test error"):
            failing_func()


class TestSetupLogging:
    def test_setup_logging_returns_logger(self) -> None:
        logger = logging.getLogger("glyphweave")
        logger.handlers.clear()

        result = log_mod.setup_logging()
        assert isinstance(result, logging.Logger)
