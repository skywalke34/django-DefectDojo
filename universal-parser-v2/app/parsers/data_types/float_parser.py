"""
Float data type parser.

Handles float field transformations including:
- EPSS Score parsing (0.0 to 1.0 range)
- EPSS Percentile parsing (0.0 to 100.0 range)
- General float conversion with range validation
- Percentage parsing and conversion
- Decimal place rounding
- Safe conversion from strings, integers, and floats
"""

import logging
import re
from typing import Any, Union

from app.parsers.base import DataTypeParser

logger = logging.getLogger(__name__)


class FloatParser(DataTypeParser):
    """
    Parser for float fields.

    Converts values to floats with validation, range checking, and percentage handling.
    Supports EPSS scores, CVSS scores, and general float fields.
    """

    # Common float ranges for security tools
    EPSS_SCORE_MIN = 0.0
    EPSS_SCORE_MAX = 1.0
    EPSS_PERCENTILE_MIN = 0.0
    EPSS_PERCENTILE_MAX = 100.0
    CVSS_SCORE_MIN = 0.0
    CVSS_SCORE_MAX = 10.0

    def parse(self, value: Any, config: dict = None) -> Union[float, None]:
        """
        Parse value into float format.

        Args:
            value: Raw value from scan file
            config: Optional configuration with:
                - default: Default float if value is None/empty/invalid
                - min_value: Minimum allowed value
                - max_value: Maximum allowed value
                - decimal_places: Number of decimal places to round to
                - is_percentage: Whether to treat as percentage (divide by 100)
                - is_epss_score: Whether to validate as EPSS score (0.0-1.0)
                - is_epss_percentile: Whether to validate as EPSS percentile (0.0-100.0)
                - is_cvss_score: Whether to validate as CVSS score (0.0-10.0)

        Returns:
            Parsed float value or None

        Examples:
            >>> parser = FloatParser()
            >>> parser.parse("0.75")
            0.75
            >>> parser.parse("75.5%", {"is_percentage": True})
            0.755
            >>> parser.parse("invalid", {"default": 0.0})
            0.0
            >>> parser.parse("0.85", {"is_epss_score": True})
            0.85
            >>> parser.parse("85.0", {"is_epss_percentile": True})
            85.0
        """
        config = config or {}

        # Handle None or empty values
        if value is None or value == "":
            default = config.get('default')
            return float(default) if default is not None else None

        # Convert to string if not already
        if not isinstance(value, str):
            value = str(value)

        value = value.strip()
        if not value:
            default = config.get('default')
            return float(default) if default is not None else None

        # Extract float from string (handle percentages, units, etc.)
        float_value = self._extract_float(value)
        if float_value is None:
            logger.warning(f"Could not extract float from '{value}'")
            default = config.get('default')
            return float(default) if default is not None else None

        # Handle percentage conversion
        if config.get('is_percentage', False) or value.endswith('%'):
            float_value = float_value / 100.0
            logger.debug(f"Converted percentage '{value}' to decimal: {float_value}")

        # Apply range validation based on type
        min_value = config.get('min_value')
        max_value = config.get('max_value')

        # Set default ranges based on validation type
        if config.get('is_epss_score', False):
            min_value = min_value or self.EPSS_SCORE_MIN
            max_value = max_value or self.EPSS_SCORE_MAX
        elif config.get('is_epss_percentile', False):
            min_value = min_value or self.EPSS_PERCENTILE_MIN
            max_value = max_value or self.EPSS_PERCENTILE_MAX
        elif config.get('is_cvss_score', False):
            min_value = min_value or self.CVSS_SCORE_MIN
            max_value = max_value or self.CVSS_SCORE_MAX

        # Validate range
        if min_value is not None and float_value < min_value:
            logger.warning(f"Float {float_value} below minimum {min_value}")
            default = config.get('default')
            return float(default) if default is not None else None

        if max_value is not None and float_value > max_value:
            logger.warning(f"Float {float_value} above maximum {max_value}")
            default = config.get('default')
            return float(default) if default is not None else None

        # Apply decimal place rounding
        decimal_places = config.get('decimal_places')
        if decimal_places is not None:
            float_value = round(float_value, decimal_places)

        logger.debug(f"Parsed float '{value}' → {float_value}")
        return float_value

    def _extract_float(self, value: str) -> Union[float, None]:
        """
        Extract float from string, handling various formats.

        Args:
            value: String that may contain a float

        Returns:
            Extracted float or None if not found

        Examples:
            >>> parser = FloatParser()
            >>> parser._extract_float("0.75")
            0.75
            >>> parser._extract_float("75.5%")
            75.5
            >>> parser._extract_float("Score: 8.5")
            8.5
            >>> parser._extract_float("invalid")
            None
        """
        try:
            # First try direct conversion
            return float(value)
        except (ValueError, TypeError):
            pass

        # Try to extract float from text patterns
        patterns = [
            r'(\d+\.?\d*)\s*%',        # 75.5%, 75%
            r'score\s*:?\s*(\d+\.?\d*)',  # score: 8.5, score 8.5
            r'(\d+\.?\d*)',            # Any decimal number
        ]

        for pattern in patterns:
            match = re.search(pattern, value, re.IGNORECASE)
            if match:
                try:
                    return float(match.group(1))
                except (ValueError, TypeError):
                    continue

        return None

    @staticmethod
    def is_valid_epss_score(score: float) -> bool:
        """
        Check if float is a valid EPSS score (0.0-1.0).

        Args:
            score: EPSS score to validate

        Returns:
            True if valid EPSS score, False otherwise

        Example:
            >>> FloatParser.is_valid_epss_score(0.75)
            True
            >>> FloatParser.is_valid_epss_score(1.5)
            False
        """
        return FloatParser.EPSS_SCORE_MIN <= score <= FloatParser.EPSS_SCORE_MAX

    @staticmethod
    def is_valid_epss_percentile(percentile: float) -> bool:
        """
        Check if float is a valid EPSS percentile (0.0-100.0).

        Args:
            percentile: EPSS percentile to validate

        Returns:
            True if valid EPSS percentile, False otherwise

        Example:
            >>> FloatParser.is_valid_epss_percentile(85.0)
            True
            >>> FloatParser.is_valid_epss_percentile(150.0)
            False
        """
        return FloatParser.EPSS_PERCENTILE_MIN <= percentile <= FloatParser.EPSS_PERCENTILE_MAX

    @staticmethod
    def is_valid_cvss_score(score: float) -> bool:
        """
        Check if float is a valid CVSS score (0.0-10.0).

        Args:
            score: CVSS score to validate

        Returns:
            True if valid CVSS score, False otherwise

        Example:
            >>> FloatParser.is_valid_cvss_score(8.5)
            True
            >>> FloatParser.is_valid_cvss_score(12.0)
            False
        """
        return FloatParser.CVSS_SCORE_MIN <= score <= FloatParser.CVSS_SCORE_MAX

    @staticmethod
    def format_percentage(value: float, decimal_places: int = 1) -> str:
        """
        Format float as percentage string.

        Args:
            value: Float value to format (0.0-1.0 range)
            decimal_places: Number of decimal places

        Returns:
            Formatted percentage string

        Example:
            >>> FloatParser.format_percentage(0.755, 1)
            '75.5%'
            >>> FloatParser.format_percentage(0.8, 0)
            '80%'
        """
        percentage = value * 100.0
        return f"{percentage:.{decimal_places}f}%"

    @staticmethod
    def parse_percentage(percentage_str: str) -> Union[float, None]:
        """
        Parse percentage string to decimal float.

        Args:
            percentage_str: Percentage string (e.g., "75.5%", "75%")

        Returns:
            Decimal float (0.0-1.0) or None if invalid

        Example:
            >>> FloatParser.parse_percentage("75.5%")
            0.755
            >>> FloatParser.parse_percentage("75%")
            0.75
        """
        parser = FloatParser()
        return parser._extract_float(percentage_str) / 100.0 if parser._extract_float(percentage_str) is not None else None

    @staticmethod
    def validate_float_range(value: float, min_value: float = None, max_value: float = None) -> bool:
        """
        Validate float is within specified range.

        Args:
            value: Float to validate
            min_value: Minimum allowed value
            max_value: Maximum allowed value

        Returns:
            True if within range, False otherwise

        Example:
            >>> FloatParser.validate_float_range(0.5, 0.0, 1.0)
            True
            >>> FloatParser.validate_float_range(1.5, 0.0, 1.0)
            False
        """
        if min_value is not None and value < min_value:
            return False
        if max_value is not None and value > max_value:
            return False
        return True

    @staticmethod
    def clamp_float(value: float, min_value: float = None, max_value: float = None) -> float:
        """
        Clamp float to specified range.

        Args:
            value: Float to clamp
            min_value: Minimum allowed value
            max_value: Maximum allowed value

        Returns:
            Clamped float value

        Example:
            >>> FloatParser.clamp_float(1.5, 0.0, 1.0)
            1.0
            >>> FloatParser.clamp_float(-0.1, 0.0, 1.0)
            0.0
        """
        if min_value is not None and value < min_value:
            return min_value
        if max_value is not None and value > max_value:
            return max_value
        return value

    @staticmethod
    def safe_float_conversion(value: Any, default: float = 0.0) -> float:
        """
        Safely convert any value to float.

        Args:
            value: Value to convert
            default: Default value if conversion fails

        Returns:
            Converted float or default

        Example:
            >>> FloatParser.safe_float_conversion("0.75")
            0.75
            >>> FloatParser.safe_float_conversion("invalid", 0.0)
            0.0
            >>> FloatParser.safe_float_conversion(None, -1.0)
            -1.0
        """
        if value is None:
            return default

        try:
            if isinstance(value, (int, float)):
                return float(value)
            elif isinstance(value, str):
                # Try to extract float from string
                parser = FloatParser()
                result = parser._extract_float(value.strip())
                return result if result is not None else default
            else:
                return float(value)
        except (ValueError, TypeError, OverflowError):
            return default

    @staticmethod
    def round_to_places(value: float, decimal_places: int) -> float:
        """
        Round float to specified decimal places.

        Args:
            value: Float to round
            decimal_places: Number of decimal places

        Returns:
            Rounded float

        Example:
            >>> FloatParser.round_to_places(0.756789, 2)
            0.76
            >>> FloatParser.round_to_places(0.754321, 2)
            0.75
        """
        return round(value, decimal_places)
