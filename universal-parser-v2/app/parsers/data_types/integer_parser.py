"""
Integer data type parser.

Handles integer field transformations including:
- Safe integer conversion from strings and numbers
- Range validation (min/max values)
- Null/empty value handling
- Default value substitution
- CWE number validation
- Line number validation
"""

import logging
import re
from typing import Any, Union

from app.parsers.base import DataTypeParser

logger = logging.getLogger(__name__)


class IntegerParser(DataTypeParser):
    """
    Parser for integer fields.

    Converts values to integers with validation and range checking.
    Supports CWE numbers, line numbers, and general integer fields.
    """

    # CWE number ranges (Common Weakness Enumeration)
    CWE_MIN = 1
    CWE_MAX = 9999  # Current CWE database goes up to ~8000s

    # Common line number ranges
    LINE_MIN = 1
    LINE_MAX = 10000000  # 10 million lines should be sufficient

    def parse(self, value: Any, config: dict = None) -> Union[int, None]:
        """
        Parse value into integer format.

        Args:
            value: Raw value from scan file
            config: Optional configuration with:
                - default: Default integer if value is None/empty/invalid
                - min_value: Minimum allowed value
                - max_value: Maximum allowed value
                - validate_cwe: Whether to validate as CWE number
                - validate_line: Whether to validate as line number
                - allow_negative: Whether to allow negative numbers

        Returns:
            Parsed integer value or None

        Examples:
            >>> parser = IntegerParser()
            >>> parser.parse("123")
            123
            >>> parser.parse("89.5")  # Float gets truncated
            89
            >>> parser.parse(None, {"default": 0})
            0
            >>> parser.parse("invalid", {"default": 0})
            0
            >>> parser.parse("89", {"validate_cwe": True})
            89
        """
        config = config or {}

        # Handle None or empty values
        if value is None or value == "":
            default = config.get('default')
            return default if default is not None else None

        # Convert to string if not already
        if not isinstance(value, str):
            value = str(value)

        value = value.strip()
        if not value:
            default = config.get('default')
            return default if default is not None else None

        # Extract integer from string (handle cases like "CWE-89", "Line 123", etc.)
        integer_value = self._extract_integer(value)
        if integer_value is None:
            logger.warning(f"Could not extract integer from '{value}'")
            default = config.get('default')
            return default if default is not None else None

        # Apply range validation
        min_value = config.get('min_value')
        max_value = config.get('max_value')

        # Set default ranges based on validation type
        if config.get('validate_cwe', False):
            min_value = min_value or self.CWE_MIN
            max_value = max_value or self.CWE_MAX
        elif config.get('validate_line', False):
            min_value = min_value or self.LINE_MIN
            max_value = max_value or self.LINE_MAX
        elif not config.get('allow_negative', True):
            min_value = min_value or 0

        # Validate range
        if min_value is not None and integer_value < min_value:
            logger.warning(f"Integer {integer_value} below minimum {min_value}")
            default = config.get('default')
            return default if default is not None else None

        if max_value is not None and integer_value > max_value:
            logger.warning(f"Integer {integer_value} above maximum {max_value}")
            default = config.get('default')
            return default if default is not None else None

        logger.debug(f"Parsed integer '{value}' → {integer_value}")
        return integer_value

    def _extract_integer(self, value: str) -> Union[int, None]:
        """
        Extract integer from string, handling various formats.

        Args:
            value: String that may contain an integer

        Returns:
            Extracted integer or None if not found

        Examples:
            >>> parser = IntegerParser()
            >>> parser._extract_integer("123")
            123
            >>> parser._extract_integer("CWE-89")
            89
            >>> parser._extract_integer("Line 123")
            123
            >>> parser._extract_integer("89.5")
            89
            >>> parser._extract_integer("invalid")
            None
        """
        try:
            # First try direct conversion
            return int(float(value))  # Handle "89.5" -> 89
        except (ValueError, TypeError):
            pass

        # Try to extract integer from text patterns
        patterns = [
            r'CWE-?(\d+)',           # CWE-89, CWE89
            r'CWE\s*(\d+)',          # CWE 89
            r'Line\s*(\d+)',         # Line 123
            r'line\s*(\d+)',         # line 123
            r'(\d+)',                # Any sequence of digits
        ]

        for pattern in patterns:
            match = re.search(pattern, value, re.IGNORECASE)
            if match:
                try:
                    return int(match.group(1))
                except (ValueError, TypeError):
                    continue

        return None

    @staticmethod
    def is_valid_cwe(cwe_number: int) -> bool:
        """
        Check if number is a valid CWE number.

        Args:
            cwe_number: CWE number to validate

        Returns:
            True if valid CWE, False otherwise

        Example:
            >>> IntegerParser.is_valid_cwe(89)
            True
            >>> IntegerParser.is_valid_cwe(99999)
            False
        """
        return IntegerParser.CWE_MIN <= cwe_number <= IntegerParser.CWE_MAX

    @staticmethod
    def is_valid_line_number(line_number: int) -> bool:
        """
        Check if number is a valid line number.

        Args:
            line_number: Line number to validate

        Returns:
            True if valid line number, False otherwise

        Example:
            >>> IntegerParser.is_valid_line_number(123)
            True
            >>> IntegerParser.is_valid_line_number(-1)
            False
        """
        return IntegerParser.LINE_MIN <= line_number <= IntegerParser.LINE_MAX

    @staticmethod
    def format_cwe(cwe_number: int) -> str:
        """
        Format CWE number as standard string.

        Args:
            cwe_number: CWE number to format

        Returns:
            Formatted CWE string

        Example:
            >>> IntegerParser.format_cwe(89)
            'CWE-89'
        """
        return f"CWE-{cwe_number}"

    @staticmethod
    def parse_cwe_string(cwe_string: str) -> Union[int, None]:
        """
        Parse CWE string to integer.

        Args:
            cwe_string: CWE string (e.g., "CWE-89", "CWE89", "89")

        Returns:
            CWE number or None if invalid

        Example:
            >>> IntegerParser.parse_cwe_string("CWE-89")
            89
            >>> IntegerParser.parse_cwe_string("89")
            89
        """
        parser = IntegerParser()
        return parser._extract_integer(cwe_string)

    @staticmethod
    def validate_integer_range(value: int, min_value: int = None, max_value: int = None) -> bool:
        """
        Validate integer is within specified range.

        Args:
            value: Integer to validate
            min_value: Minimum allowed value
            max_value: Maximum allowed value

        Returns:
            True if within range, False otherwise

        Example:
            >>> IntegerParser.validate_integer_range(50, 0, 100)
            True
            >>> IntegerParser.validate_integer_range(150, 0, 100)
            False
        """
        if min_value is not None and value < min_value:
            return False
        if max_value is not None and value > max_value:
            return False
        return True

    @staticmethod
    def clamp_integer(value: int, min_value: int = None, max_value: int = None) -> int:
        """
        Clamp integer to specified range.

        Args:
            value: Integer to clamp
            min_value: Minimum allowed value
            max_value: Maximum allowed value

        Returns:
            Clamped integer value

        Example:
            >>> IntegerParser.clamp_integer(150, 0, 100)
            100
            >>> IntegerParser.clamp_integer(-10, 0, 100)
            0
        """
        if min_value is not None and value < min_value:
            return min_value
        if max_value is not None and value > max_value:
            return max_value
        return value

    @staticmethod
    def safe_int_conversion(value: Any, default: int = 0) -> int:
        """
        Safely convert any value to integer.

        Args:
            value: Value to convert
            default: Default value if conversion fails

        Returns:
            Converted integer or default

        Example:
            >>> IntegerParser.safe_int_conversion("123")
            123
            >>> IntegerParser.safe_int_conversion("invalid", 0)
            0
            >>> IntegerParser.safe_int_conversion(None, -1)
            -1
        """
        if value is None:
            return default

        try:
            if isinstance(value, (int, float)):
                return int(value)
            elif isinstance(value, str):
                # Try to extract integer from string
                parser = IntegerParser()
                result = parser._extract_integer(value.strip())
                return result if result is not None else default
            else:
                return int(value)
        except (ValueError, TypeError, OverflowError):
            return default
