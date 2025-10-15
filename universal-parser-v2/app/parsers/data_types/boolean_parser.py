"""
Boolean data type parser.

Handles boolean field transformations including:
- String to boolean conversion (true/false, yes/no, 1/0)
- Case-insensitive matching
- Custom true/false value mappings
- Default value substitution
- Numeric boolean conversion
"""

import logging
from typing import Any

from app.parsers.base import DataTypeParser

logger = logging.getLogger(__name__)


class BooleanParser(DataTypeParser):
    """
    Parser for boolean fields.

    Converts various string and numeric representations to boolean values.
    Supports multiple formats and custom true/false mappings.
    """

    # Default true/false value mappings
    DEFAULT_TRUE_VALUES = {
        # English
        'true', 'yes', 'y', 'on', 'enabled', 'active',
        # Numeric
        '1', 1,
        # Other common representations
        'ok', 'okay', 'valid', 'correct', 'success'
    }

    DEFAULT_FALSE_VALUES = {
        # English
        'false', 'no', 'n', 'off', 'disabled', 'inactive',
        # Numeric
        '0', 0,
        # Other common representations
        'invalid', 'incorrect', 'fail', 'failed', 'error'
    }

    def parse(self, value: Any, config: dict = None) -> bool:
        """
        Parse value into boolean format.

        Args:
            value: Raw value from scan file
            config: Optional configuration with:
                - default: Default boolean if value is None/empty/invalid
                - true_values: Custom set of values considered true
                - false_values: Custom set of values considered false
                - case_sensitive: Whether matching is case sensitive (default: False)

        Returns:
            Parsed boolean value

        Examples:
            >>> parser = BooleanParser()
            >>> parser.parse("true")
            True
            >>> parser.parse("yes")
            True
            >>> parser.parse("1")
            True
            >>> parser.parse("false")
            False
            >>> parser.parse("no")
            False
            >>> parser.parse("0")
            False
            >>> parser.parse(None, {"default": True})
            True
            >>> parser.parse("invalid", {"default": False})
            False
        """
        config = config or {}

        # Handle None or empty values
        if value is None or value == "":
            default = config.get('default')
            return default if default is not None else False

        # Get custom true/false value sets
        true_values = config.get('true_values', self.DEFAULT_TRUE_VALUES)
        false_values = config.get('false_values', self.DEFAULT_FALSE_VALUES)
        case_sensitive = config.get('case_sensitive', False)

        # Convert value for comparison
        if isinstance(value, bool):
            return value

        if isinstance(value, (int, float)):
            # Handle numeric values
            if value == 1 or value == 1.0:
                return True
            elif value == 0 or value == 0.0:
                return False
            else:
                # Non-zero numbers are considered True
                return bool(value)

        # Convert to string for string comparison
        value_str = str(value).strip()

        if not value_str:
            default = config.get('default')
            return default if default is not None else False

        # Prepare value sets for comparison
        if case_sensitive:
            comparison_value = value_str
            comparison_true_values = {str(v) for v in true_values}
            comparison_false_values = {str(v) for v in false_values}
        else:
            comparison_value = value_str.lower()
            comparison_true_values = {str(v).lower() for v in true_values}
            comparison_false_values = {str(v).lower() for v in false_values}

        # Check against true values
        if comparison_value in comparison_true_values:
            logger.debug(f"Parsed boolean '{value}' → True")
            return True

        # Check against false values
        if comparison_value in comparison_false_values:
            logger.debug(f"Parsed boolean '{value}' → False")
            return False

        # If no match found, use default
        logger.warning(f"Could not parse boolean from '{value}', using default")
        default = config.get('default')
        return default if default is not None else False

    @staticmethod
    def is_true_value(value: Any, true_values: set = None) -> bool:
        """
        Check if value is considered true.

        Args:
            value: Value to check
            true_values: Set of values considered true (uses default if None)

        Returns:
            True if value is considered true, False otherwise

        Example:
            >>> BooleanParser.is_true_value("yes")
            True
            >>> BooleanParser.is_true_value("no")
            False
        """
        if true_values is None:
            true_values = BooleanParser.DEFAULT_TRUE_VALUES

        if isinstance(value, bool):
            return value

        if isinstance(value, (int, float)):
            return value == 1 or value == 1.0

        value_str = str(value).strip().lower()
        comparison_values = {str(v).lower() for v in true_values}

        return value_str in comparison_values

    @staticmethod
    def is_false_value(value: Any, false_values: set = None) -> bool:
        """
        Check if value is considered false.

        Args:
            value: Value to check
            false_values: Set of values considered false (uses default if None)

        Returns:
            True if value is considered false, False otherwise

        Example:
            >>> BooleanParser.is_false_value("no")
            True
            >>> BooleanParser.is_false_value("yes")
            False
        """
        if false_values is None:
            false_values = BooleanParser.DEFAULT_FALSE_VALUES

        if isinstance(value, bool):
            return not value

        if isinstance(value, (int, float)):
            return value == 0 or value == 0.0

        value_str = str(value).strip().lower()
        comparison_values = {str(v).lower() for v in false_values}

        return value_str in comparison_values

    @staticmethod
    def format_boolean(value: bool, format_str: str = "true/false") -> str:
        """
        Format boolean to string representation.

        Args:
            value: Boolean value to format
            format_str: Format type ("true/false", "yes/no", "1/0", "on/off")

        Returns:
            Formatted string

        Example:
            >>> BooleanParser.format_boolean(True, "yes/no")
            'yes'
            >>> BooleanParser.format_boolean(False, "1/0")
            '0'
        """
        if format_str == "true/false":
            return "true" if value else "false"
        elif format_str == "yes/no":
            return "yes" if value else "no"
        elif format_str == "1/0":
            return "1" if value else "0"
        elif format_str == "on/off":
            return "on" if value else "off"
        elif format_str == "enabled/disabled":
            return "enabled" if value else "disabled"
        elif format_str == "active/inactive":
            return "active" if value else "inactive"
        else:
            # Default to true/false
            return "true" if value else "false"

    @staticmethod
    def safe_bool_conversion(value: Any, default: bool = False) -> bool:
        """
        Safely convert any value to boolean.

        Args:
            value: Value to convert
            default: Default value if conversion fails

        Returns:
            Converted boolean or default

        Example:
            >>> BooleanParser.safe_bool_conversion("yes")
            True
            >>> BooleanParser.safe_bool_conversion("invalid", False)
            False
            >>> BooleanParser.safe_bool_conversion(None, True)
            True
        """
        if value is None:
            return default

        parser = BooleanParser()
        try:
            return parser.parse(value, {'default': default})
        except Exception:
            return default

    @staticmethod
    def get_boolean_mappings() -> tuple[set, set]:
        """
        Get default true and false value mappings.

        Returns:
            Tuple of (true_values_set, false_values_set)

        Example:
            >>> true_vals, false_vals = BooleanParser.get_boolean_mappings()
            >>> "yes" in true_vals
            True
            >>> "no" in false_vals
            True
        """
        return BooleanParser.DEFAULT_TRUE_VALUES.copy(), BooleanParser.DEFAULT_FALSE_VALUES.copy()

    @staticmethod
    def create_custom_mappings(true_strings: list[str], false_strings: list[str]) -> dict:
        """
        Create custom boolean mappings configuration.

        Args:
            true_strings: List of strings considered true
            false_strings: List of strings considered false

        Returns:
            Configuration dictionary for use with parser

        Example:
            >>> config = BooleanParser.create_custom_mappings(
            ...     ["enabled", "active", "1"],
            ...     ["disabled", "inactive", "0"]
            ... )
            >>> parser = BooleanParser()
            >>> parser.parse("enabled", config)
            True
        """
        return {
            'true_values': set(true_strings),
            'false_values': set(false_strings)
        }
