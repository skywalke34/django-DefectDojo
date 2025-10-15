"""
Date data type parser.

Handles date field transformations including:
- ISO 8601 format parsing (2024-10-14, 2024-10-14T10:30:00Z)
- Common date format parsing (10/14/2024, 14-Oct-2024)
- Timezone handling
- Invalid date graceful handling
- Default value substitution
"""

import logging
from datetime import datetime, date
from typing import Any

from app.parsers.base import DataTypeParser

logger = logging.getLogger(__name__)


class DateParser(DataTypeParser):
    """
    Parser for date fields.

    Converts various date formats to Python date objects.
    Supports ISO 8601, common formats, and custom format strings.
    """

    # Common date format patterns
    COMMON_FORMATS = [
        # ISO 8601 formats
        "%Y-%m-%d",                    # 2024-10-14
        "%Y-%m-%dT%H:%M:%S",          # 2024-10-14T10:30:00
        "%Y-%m-%dT%H:%M:%SZ",         # 2024-10-14T10:30:00Z
        "%Y-%m-%dT%H:%M:%S.%fZ",      # 2024-10-14T10:30:00.123Z
        "%Y-%m-%dT%H:%M:%S%z",        # 2024-10-14T10:30:00+00:00
        
        # US formats
        "%m/%d/%Y",                    # 10/14/2024
        "%m-%d-%Y",                    # 10-14-2024
        "%m.%d.%Y",                    # 10.14.2024
        
        # European formats
        "%d/%m/%Y",                    # 14/10/2024
        "%d-%m-%Y",                    # 14-10-2024
        "%d.%m.%Y",                    # 14.10.2024
        
        # Long formats
        "%B %d, %Y",                   # October 14, 2024
        "%d %B %Y",                    # 14 October 2024
        "%b %d, %Y",                   # Oct 14, 2024
        "%d %b %Y",                    # 14 Oct 2024
        
        # With time
        "%Y-%m-%d %H:%M:%S",          # 2024-10-14 10:30:00
        "%m/%d/%Y %H:%M:%S",          # 10/14/2024 10:30:00
        "%d/%m/%Y %H:%M:%S",          # 14/10/2024 10:30:00
        
        # Unix timestamp (seconds since epoch)
        "%s",                          # 1728892800
    ]

    def parse(self, value: Any, config: dict = None) -> date:
        """
        Parse value into date format.

        Args:
            value: Raw value from scan file
            config: Optional configuration with:
                - default: Default date if value is None/empty/invalid
                - date_format: Specific format string to use
                - timezone: Timezone to use for parsing (default: UTC)

        Returns:
            Parsed date object

        Examples:
            >>> parser = DateParser()
            >>> parser.parse("2024-10-14")
            datetime.date(2024, 10, 14)
            >>> parser.parse("10/14/2024")
            datetime.date(2024, 10, 14)
            >>> parser.parse(None, {"default": "2024-01-01"})
            datetime.date(2024, 1, 1)
            >>> parser.parse("invalid", {"default": "2024-01-01"})
            datetime.date(2024, 1, 1)
        """
        config = config or {}

        # Handle None or empty values
        if value is None or value == "":
            default = config.get('default')
            if default:
                return self._parse_default_date(default, config)
            return None

        # Convert to string if not already
        if not isinstance(value, str):
            value = str(value)

        value = value.strip()
        if not value:
            default = config.get('default')
            if default:
                return self._parse_default_date(default, config)
            return None

        # Try parsing with custom format first
        custom_format = config.get('date_format')
        if custom_format:
            try:
                parsed_date = self._parse_with_format(value, custom_format)
                if parsed_date:
                    logger.debug(f"Parsed date '{value}' using custom format '{custom_format}' → {parsed_date}")
                    return parsed_date
            except Exception as e:
                logger.debug(f"Custom format '{custom_format}' failed for '{value}': {str(e)}")

        # Try common formats
        for format_str in self.COMMON_FORMATS:
            try:
                parsed_date = self._parse_with_format(value, format_str)
                if parsed_date:
                    logger.debug(f"Parsed date '{value}' using format '{format_str}' → {parsed_date}")
                    return parsed_date
            except Exception:
                continue

        # If all parsing attempts failed, use default
        logger.warning(f"Failed to parse date '{value}' with any known format")
        default = config.get('default')
        if default:
            return self._parse_default_date(default, config)

        return None

    def _parse_with_format(self, value: str, format_str: str) -> date:
        """
        Parse date string using specific format.

        Args:
            value: Date string to parse
            format_str: Format string to use

        Returns:
            Parsed date object or None if parsing fails
        """
        try:
            if format_str == "%s":
                # Handle Unix timestamp
                timestamp = float(value)
                dt = datetime.fromtimestamp(timestamp)
                return dt.date()
            else:
                # Handle regular format strings
                dt = datetime.strptime(value, format_str)
                return dt.date()
        except (ValueError, TypeError, OverflowError) as e:
            logger.debug(f"Format '{format_str}' failed for '{value}': {str(e)}")
            return None

    def _parse_default_date(self, default_value: str, config: dict) -> date:
        """
        Parse default date value.

        Args:
            default_value: Default date string
            config: Configuration dict

        Returns:
            Parsed date object

        Raises:
            ValueError: If default date cannot be parsed
        """
        try:
            return self.parse(default_value, config)
        except Exception as e:
            raise ValueError(f"Invalid default date '{default_value}': {str(e)}")

    @staticmethod
    def format_date(date_obj: date, format_str: str = "%Y-%m-%d") -> str:
        """
        Format date object to string.

        Args:
            date_obj: Date object to format
            format_str: Format string (default: YYYY-MM-DD)

        Returns:
            Formatted date string

        Example:
            >>> DateParser.format_date(date(2024, 10, 14))
            '2024-10-14'
            >>> DateParser.format_date(date(2024, 10, 14), "%m/%d/%Y")
            '10/14/2024'
        """
        if not date_obj:
            return ""
        
        return date_obj.strftime(format_str)

    @staticmethod
    def is_valid_date(date_str: str, format_str: str = "%Y-%m-%d") -> bool:
        """
        Check if date string is valid for given format.

        Args:
            date_str: Date string to validate
            format_str: Format string to use

        Returns:
            True if valid, False otherwise

        Example:
            >>> DateParser.is_valid_date("2024-10-14")
            True
            >>> DateParser.is_valid_date("invalid")
            False
        """
        try:
            datetime.strptime(date_str, format_str)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def get_date_range_days(start_date: date, end_date: date) -> int:
        """
        Get number of days between two dates.

        Args:
            start_date: Start date
            end_date: End date

        Returns:
            Number of days between dates

        Example:
            >>> start = date(2024, 10, 1)
            >>> end = date(2024, 10, 14)
            >>> DateParser.get_date_range_days(start, end)
            13
        """
        if not start_date or not end_date:
            return 0
        
        return (end_date - start_date).days

    @staticmethod
    def parse_relative_date(relative_str: str, base_date: date = None) -> date:
        """
        Parse relative date expressions.

        Args:
            relative_str: Relative date string (e.g., "7 days ago", "1 week ago")
            base_date: Base date to calculate from (default: today)

        Returns:
            Calculated date

        Example:
            >>> DateParser.parse_relative_date("7 days ago")
            datetime.date(2024, 10, 7)  # Assuming today is 2024-10-14
        """
        if not base_date:
            base_date = date.today()

        relative_str = relative_str.lower().strip()
        
        # Simple relative date parsing (can be extended)
        if "today" in relative_str:
            return base_date
        elif "yesterday" in relative_str:
            from datetime import timedelta
            return base_date - timedelta(days=1)
        elif "days ago" in relative_str:
            try:
                days = int(relative_str.split()[0])
                from datetime import timedelta
                return base_date - timedelta(days=days)
            except (ValueError, IndexError):
                pass
        elif "weeks ago" in relative_str:
            try:
                weeks = int(relative_str.split()[0])
                from datetime import timedelta
                return base_date - timedelta(weeks=weeks)
            except (ValueError, IndexError):
                pass

        # If parsing fails, return None
        return None
