"""
Array data type parser.

Handles array field transformations including:
- Multiple input formats (JSON, comma-separated, space-separated, etc.)
- Tag parsing and deduplication
- Endpoint URL/hostname parsing
- Vulnerability ID array parsing (CVE, CWE, etc.)
- Array validation and item type checking
- Empty array handling and default values
"""

import json
import logging
import re
from typing import Any, List, Union

from app.parsers.base import DataTypeParser

logger = logging.getLogger(__name__)


class ArrayParser(DataTypeParser):
    """
    Parser for array fields.

    Converts various formats to lists of strings with validation and deduplication.
    Supports tags, endpoints, vulnerability IDs, and general string arrays.
    """

    # Common array separators
    COMMON_SEPARATORS = [',', ';', '|', '\n', '\r\n', ' ', '\t']
    
    # URL patterns for endpoint validation
    URL_PATTERN = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)?$', re.IGNORECASE)

    def parse(self, value: Any, config: dict = None) -> Union[List[str], None]:
        """
        Parse value into array format.

        Args:
            value: Raw value from scan file
            config: Optional configuration with:
                - default: Default array if value is None/empty/invalid
                - separator: Specific separator to use (auto-detect if None)
                - deduplicate: Remove duplicates (default: True)
                - max_items: Maximum array length (default: None)
                - item_type: Validate each item type (string, url, cve, etc.)
                - strip_whitespace: Strip whitespace from items (default: True)
                - remove_empty: Remove empty items (default: True)

        Returns:
            Parsed array of strings or None

        Examples:
            >>> parser = ArrayParser()
            >>> parser.parse("tag1, tag2, tag3")
            ['tag1', 'tag2', 'tag3']
            >>> parser.parse('["tag1", "tag2", "tag3"]')
            ['tag1', 'tag2', 'tag3']
            >>> parser.parse("tag1|tag2|tag3", {"separator": "|"})
            ['tag1', 'tag2', 'tag3']
            >>> parser.parse(None, {"default": ["default-tag"]})
            ['default-tag']
        """
        config = config or {}

        # Handle None or empty values
        if value is None or value == "":
            default = config.get('default', [])
            return default if isinstance(default, list) else None

        # Handle already parsed lists
        if isinstance(value, list):
            return self._process_list(value, config)

        # Convert to string if not already
        if not isinstance(value, str):
            value = str(value)

        value = value.strip()
        if not value:
            default = config.get('default', [])
            return default if isinstance(default, list) else None

        # Try parsing as JSON array first
        json_array = self._try_parse_json(value)
        if json_array is not None:
            return self._process_list(json_array, config)

        # Parse as delimited string
        separator = config.get('separator')
        if separator:
            items = value.split(separator)
        else:
            items = self._auto_detect_separator(value)

        return self._process_list(items, config)

    def _try_parse_json(self, value: str) -> Union[List[str], None]:
        """
        Try to parse value as JSON array.

        Args:
            value: String that might be JSON array

        Returns:
            Parsed list or None if not valid JSON array
        """
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                # Convert all items to strings
                return [str(item) for item in parsed]
        except (json.JSONDecodeError, TypeError):
            pass
        return None

    def _auto_detect_separator(self, value: str) -> List[str]:
        """
        Auto-detect separator and split string.

        Args:
            value: String to split

        Returns:
            List of items
        """
        # Try common separators in order of preference
        for separator in self.COMMON_SEPARATORS:
            if separator in value:
                # Check if separator appears consistently
                parts = value.split(separator)
                if len(parts) > 1:
                    # Validate that this looks like intentional separation
                    # (not just a separator that appears in content)
                    if all(len(part.strip()) > 0 for part in parts if part.strip()):
                        return parts

        # If no separator found, treat as single item
        return [value]

    def _process_list(self, items: List[str], config: dict) -> List[str]:
        """
        Process list of items with configuration options.

        Args:
            items: List of items to process
            config: Processing configuration

        Returns:
            Processed list of strings
        """
        processed_items = []

        strip_whitespace = config.get('strip_whitespace', True)
        remove_empty = config.get('remove_empty', True)
        deduplicate = config.get('deduplicate', True)
        max_items = config.get('max_items')
        item_type = config.get('item_type')

        for item in items:
            # Strip whitespace if requested
            if strip_whitespace and isinstance(item, str):
                item = item.strip()

            # Skip empty items if requested
            if remove_empty and not item:
                continue

            # Validate item type if specified
            if item_type and not self._validate_item_type(item, item_type):
                logger.warning(f"Item '{item}' failed {item_type} validation")
                continue

            processed_items.append(item)

        # Deduplicate if requested
        if deduplicate:
            # Preserve order while removing duplicates
            seen = set()
            unique_items = []
            for item in processed_items:
                if item not in seen:
                    seen.add(item)
                    unique_items.append(item)
            processed_items = unique_items

        # Limit to max items if specified
        if max_items is not None and len(processed_items) > max_items:
            logger.warning(f"Array truncated to {max_items} items (was {len(processed_items)})")
            processed_items = processed_items[:max_items]

        logger.debug(f"Processed array: {len(processed_items)} items")
        return processed_items

    def _validate_item_type(self, item: str, item_type: str) -> bool:
        """
        Validate item against specified type.

        Args:
            item: Item to validate
            item_type: Type to validate against

        Returns:
            True if valid, False otherwise
        """
        if item_type == 'string':
            return True  # All strings are valid
        elif item_type == 'url':
            return self._is_valid_url(item)
        elif item_type == 'cve':
            return self._is_valid_cve(item)
        elif item_type == 'cwe':
            return self._is_valid_cwe(item)
        elif item_type == 'hostname':
            return self._is_valid_hostname(item)
        else:
            logger.warning(f"Unknown item type: {item_type}")
            return True

    def _is_valid_url(self, item: str) -> bool:
        """Check if item is a valid URL."""
        return self.URL_PATTERN.match(item) is not None

    def _is_valid_cve(self, item: str) -> bool:
        """Check if item is a valid CVE identifier."""
        cve_pattern = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)
        return cve_pattern.match(item) is not None

    def _is_valid_cwe(self, item: str) -> bool:
        """Check if item is a valid CWE identifier."""
        cwe_pattern = re.compile(r'^CWE-?\d{1,4}$', re.IGNORECASE)
        return cwe_pattern.match(item) is not None

    def _is_valid_hostname(self, item: str) -> bool:
        """Check if item is a valid hostname."""
        hostname_pattern = re.compile(
            r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        )
        return hostname_pattern.match(item) is not None

    @staticmethod
    def join_array(items: List[str], separator: str = ', ') -> str:
        """
        Join array items into string.

        Args:
            items: List of strings to join
            separator: Separator to use

        Returns:
            Joined string

        Example:
            >>> ArrayParser.join_array(['tag1', 'tag2', 'tag3'])
            'tag1, tag2, tag3'
            >>> ArrayParser.join_array(['tag1', 'tag2'], '|')
            'tag1|tag2'
        """
        return separator.join(str(item) for item in items)

    @staticmethod
    def deduplicate_array(items: List[str], preserve_order: bool = True) -> List[str]:
        """
        Remove duplicates from array.

        Args:
            items: List of items to deduplicate
            preserve_order: Whether to preserve original order

        Returns:
            Deduplicated list

        Example:
            >>> ArrayParser.deduplicate_array(['a', 'b', 'a', 'c'])
            ['a', 'b', 'c']
        """
        if preserve_order:
            seen = set()
            unique_items = []
            for item in items:
                if item not in seen:
                    seen.add(item)
                    unique_items.append(item)
            return unique_items
        else:
            return list(set(items))

    @staticmethod
    def filter_array(items: List[str], filter_func) -> List[str]:
        """
        Filter array items using a function.

        Args:
            items: List of items to filter
            filter_func: Function to use for filtering

        Returns:
            Filtered list

        Example:
            >>> ArrayParser.filter_array(['http://a.com', 'not-url'], lambda x: x.startswith('http'))
            ['http://a.com']
        """
        return [item for item in items if filter_func(item)]

    @staticmethod
    def safe_array_conversion(value: Any, default: List[str] = None) -> List[str]:
        """
        Safely convert any value to array.

        Args:
            value: Value to convert
            default: Default value if conversion fails

        Returns:
            Converted array or default

        Example:
            >>> ArrayParser.safe_array_conversion("a,b,c")
            ['a', 'b', 'c']
            >>> ArrayParser.safe_array_conversion(None, [])
            []
        """
        if default is None:
            default = []

        if value is None:
            return default

        if isinstance(value, list):
            return [str(item) for item in value]

        parser = ArrayParser()
        try:
            result = parser.parse(value, {'default': default})
            return result if result is not None else default
        except Exception:
            return default

    @staticmethod
    def validate_array_length(items: List[str], min_length: int = None, max_length: int = None) -> bool:
        """
        Validate array length.

        Args:
            items: Array to validate
            min_length: Minimum allowed length
            max_length: Maximum allowed length

        Returns:
            True if length is valid, False otherwise

        Example:
            >>> ArrayParser.validate_array_length(['a', 'b'], min_length=1, max_length=5)
            True
            >>> ArrayParser.validate_array_length(['a', 'b'], max_length=1)
            False
        """
        length = len(items)
        if min_length is not None and length < min_length:
            return False
        if max_length is not None and length > max_length:
            return False
        return True
