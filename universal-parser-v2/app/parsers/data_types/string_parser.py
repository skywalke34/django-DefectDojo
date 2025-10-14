"""
String data type parser.

Handles string field transformations including:
- Direct string conversion
- Default value substitution
- Whitespace normalization
- HTML stripping (optional)
"""

import logging
import re
from typing import Any

from app.parsers.base import DataTypeParser

logger = logging.getLogger(__name__)


class StringParser(DataTypeParser):
    """
    Parser for string fields.

    Converts values to strings with optional transformations.
    """

    def parse(self, value: Any, config: dict = None) -> str:
        """
        Parse value into string format.

        Args:
            value: Raw value from scan file
            config: Optional configuration with:
                - default: Default value if value is None/empty
                - strip_html: Whether to remove HTML tags
                - normalize_whitespace: Whether to normalize whitespace

        Returns:
            Parsed string value

        Examples:
            >>> parser = StringParser()
            >>> parser.parse("Hello World")
            'Hello World'
            >>> parser.parse(None, {"default": "Unknown"})
            'Unknown'
            >>> parser.parse("<p>Test</p>", {"strip_html": True})
            'Test'
            >>> parser.parse("  Multiple   spaces  ", {"normalize_whitespace": True})
            'Multiple spaces'
        """
        config = config or {}

        # Handle None or empty values
        if value is None or value == "":
            default = config.get('default')
            return default if default is not None else ""

        # Convert to string
        if not isinstance(value, str):
            value = str(value)

        # Strip HTML tags if requested
        if config.get('strip_html', False):
            value = self._strip_html(value)

        # Normalize whitespace if requested
        if config.get('normalize_whitespace', False):
            value = self._normalize_whitespace(value)

        # Trim leading/trailing whitespace (always)
        value = value.strip()

        # Apply default if result is empty after processing
        if not value:
            default = config.get('default')
            return default if default is not None else ""

        return value

    @staticmethod
    def _strip_html(text: str) -> str:
        """
        Remove HTML tags from text.

        Args:
            text: Text potentially containing HTML

        Returns:
            Text with HTML tags removed

        Example:
            >>> StringParser._strip_html("<p>Hello <b>World</b></p>")
            'Hello World'
        """
        # Simple HTML tag removal (not HTML parser)
        # For production, consider using html2text or beautifulsoup
        clean = re.sub(r'<[^>]+>', '', text)

        # Decode common HTML entities
        clean = clean.replace('&nbsp;', ' ')
        clean = clean.replace('&lt;', '<')
        clean = clean.replace('&gt;', '>')
        clean = clean.replace('&amp;', '&')
        clean = clean.replace('&quot;', '"')
        clean = clean.replace('&#39;', "'")

        return clean

    @staticmethod
    def _normalize_whitespace(text: str) -> str:
        """
        Normalize whitespace by collapsing multiple spaces into one.

        Args:
            text: Text with potentially irregular whitespace

        Returns:
            Text with normalized whitespace

        Example:
            >>> StringParser._normalize_whitespace("Hello    World\\n\\n  Test")
            'Hello World Test'
        """
        # Replace newlines and tabs with spaces
        text = text.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')

        # Collapse multiple spaces into one
        text = re.sub(r'\s+', ' ', text)

        return text.strip()

    @staticmethod
    def truncate(text: str, max_length: int, suffix: str = "...") -> str:
        """
        Truncate text to maximum length.

        Args:
            text: Text to truncate
            max_length: Maximum length
            suffix: Suffix to add if truncated

        Returns:
            Truncated text

        Example:
            >>> StringParser.truncate("Long text here", 10)
            'Long te...'
        """
        if len(text) <= max_length:
            return text

        return text[:max_length - len(suffix)] + suffix
