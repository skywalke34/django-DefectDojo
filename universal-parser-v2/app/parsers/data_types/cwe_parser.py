"""
CWE (Common Weakness Enumeration) data type parser.

Extracts CWE numbers from various formats commonly found in security scanners.
Used by parsers that output CWE references in their findings.

Supported formats:
- "CWE-89" (standard format)
- "CWE89" (no hyphen)
- "CWE 89" (with space)
- "89" (just the number)
- "https://cwe.mitre.org/data/definitions/89.html" (CWE URL)
- ["CWE-89", "CWE-79"] (array, takes first)
- {"cwe-id": "CWE-89"} (dict with cwe-id key)
"""

import logging
import re
from typing import Any

from app.parsers.base import DataTypeParser

logger = logging.getLogger(__name__)


class CWEParser(DataTypeParser):
    """
    Parser that extracts CWE numbers from various formats.

    Configuration options:
        - default: Default CWE number if parsing fails (e.g., 0 or None)
        - min_cwe: Minimum valid CWE number (default: 1)
        - max_cwe: Maximum valid CWE number (default: 9999)
        - take_first: For arrays, take first valid CWE (default: True)
        - return_formatted: Return "CWE-89" string instead of int (default: False)

    Example YAML config:
        - source_field: "info.classification.cwe-id"
          target_field: "cwe"
          data_type: "cwe"
          default: null
    """

    # CWE number ranges
    CWE_MIN = 1
    CWE_MAX = 9999

    # Common patterns for CWE extraction
    CWE_PATTERNS = [
        r'CWE[\-\s]?(\d+)',                              # CWE-89, CWE89, CWE 89
        r'cwe[_\-\s]?id[:\s=]+["\']?(\d+)',              # cwe-id: 89, cwe_id="89"
        r'cwe\.mitre\.org/data/definitions/(\d+)',       # CWE URL
        r'^(\d+)$',                                       # Just the number
    ]

    def parse(self, value: Any, config: dict = None) -> int | str | None:
        """
        Parse value to extract CWE number.

        Args:
            value: Raw value that may contain CWE reference(s)
            config: Optional configuration with:
                - default: Default CWE if extraction fails
                - min_cwe: Minimum valid CWE number
                - max_cwe: Maximum valid CWE number
                - take_first: For arrays, take first valid (default: True)
                - return_formatted: Return "CWE-89" string (default: False)

        Returns:
            CWE number as integer (or formatted string), or None/default

        Examples:
            >>> parser = CWEParser()
            >>> parser.parse("CWE-89")
            89
            >>> parser.parse(["CWE-89", "CWE-79"])
            89
            >>> parser.parse("https://cwe.mitre.org/data/definitions/89.html")
            89
            >>> parser.parse("CWE-89", {"return_formatted": True})
            'CWE-89'
        """
        config = config or {}

        # Handle None or empty
        if value is None or value == "":
            return config.get('default')

        # Handle arrays/lists
        if isinstance(value, list):
            return self._parse_list(value, config)

        # Handle dicts (like {"cwe-id": "CWE-89"})
        if isinstance(value, dict):
            return self._parse_dict(value, config)

        # Handle single value
        cwe_num = self._extract_cwe(value)
        if cwe_num is not None:
            if self._is_valid_cwe(cwe_num, config):
                return self._format_result(cwe_num, config)

        return config.get('default')

    def _parse_list(self, values: list, config: dict) -> int | str | None:
        """
        Parse list of CWE values, returning first valid.

        Args:
            values: List of potential CWE values
            config: Configuration dictionary

        Returns:
            First valid CWE or default
        """
        if not config.get('take_first', True):
            # Return all valid CWEs as list
            results = []
            for v in values:
                if isinstance(v, dict):
                    cwe = self._parse_dict(v, config)
                else:
                    cwe = self._extract_cwe(v)
                    if cwe and self._is_valid_cwe(cwe, config):
                        cwe = self._format_result(cwe, config)
                if cwe is not None:
                    results.append(cwe)
            return results[0] if results else config.get('default')

        # Take first valid CWE
        for v in values:
            if isinstance(v, dict):
                cwe = self._parse_dict(v, config)
                if cwe is not None:
                    return cwe
            else:
                cwe = self._extract_cwe(v)
                if cwe and self._is_valid_cwe(cwe, config):
                    return self._format_result(cwe, config)

        return config.get('default')

    def _parse_dict(self, data: dict, config: dict) -> int | str | None:
        """
        Parse dictionary looking for CWE fields.

        Args:
            data: Dictionary that may contain CWE
            config: Configuration dictionary

        Returns:
            CWE number or default
        """
        # Common keys for CWE in various formats
        cwe_keys = ['cwe-id', 'cwe_id', 'cweid', 'cwe', 'CWE', 'CWE-ID']

        for key in cwe_keys:
            if key in data:
                cwe = self._extract_cwe(data[key])
                if cwe and self._is_valid_cwe(cwe, config):
                    return self._format_result(cwe, config)

        # Try all string values in the dict
        for v in data.values():
            if isinstance(v, str):
                cwe = self._extract_cwe(v)
                if cwe and self._is_valid_cwe(cwe, config):
                    return self._format_result(cwe, config)

        return config.get('default')

    def _extract_cwe(self, value: Any) -> int | None:
        """
        Extract CWE number from string value.

        Args:
            value: Value to extract CWE from

        Returns:
            CWE number or None
        """
        if value is None:
            return None

        # Convert to string
        if not isinstance(value, str):
            # Handle integer directly
            if isinstance(value, int):
                return value
            # Handle float by truncating
            if isinstance(value, float):
                return int(value)
            value = str(value)

        value = value.strip()
        if not value:
            return None

        # Try each pattern
        for pattern in self.CWE_PATTERNS:
            match = re.search(pattern, value, re.IGNORECASE)
            if match:
                try:
                    return int(match.group(1))
                except (ValueError, IndexError):
                    continue

        return None

    def _is_valid_cwe(self, cwe_num: int, config: dict) -> bool:
        """
        Validate CWE number is within valid range.

        Args:
            cwe_num: CWE number to validate
            config: Configuration with min/max CWE

        Returns:
            True if valid
        """
        min_cwe = config.get('min_cwe', self.CWE_MIN)
        max_cwe = config.get('max_cwe', self.CWE_MAX)
        return min_cwe <= cwe_num <= max_cwe

    def _format_result(self, cwe_num: int, config: dict) -> int | str:
        """
        Format CWE result based on config.

        Args:
            cwe_num: CWE number
            config: Configuration dict

        Returns:
            Integer or formatted string
        """
        if config.get('return_formatted', False):
            return f"CWE-{cwe_num}"
        return cwe_num

    @staticmethod
    def format_cwe(cwe_num: int) -> str:
        """
        Format CWE number as standard string.

        Args:
            cwe_num: CWE number

        Returns:
            Formatted string "CWE-XX"

        Example:
            >>> CWEParser.format_cwe(89)
            'CWE-89'
        """
        return f"CWE-{cwe_num}"

    @staticmethod
    def extract_multiple_cwes(text: str) -> list[int]:
        """
        Extract all CWE numbers from text.

        Args:
            text: Text potentially containing multiple CWE references

        Returns:
            List of unique CWE numbers found

        Example:
            >>> CWEParser.extract_multiple_cwes("Vulnerabilities: CWE-89, CWE-79, CWE-89")
            [89, 79]
        """
        if not text:
            return []

        cwes = set()
        pattern = r'CWE-?(\d+)'
        for match in re.finditer(pattern, text, re.IGNORECASE):
            try:
                cwe_num = int(match.group(1))
                if CWEParser.CWE_MIN <= cwe_num <= CWEParser.CWE_MAX:
                    cwes.add(cwe_num)
            except ValueError:
                continue

        return sorted(cwes)

    @staticmethod
    def get_cwe_url(cwe_num: int) -> str:
        """
        Get MITRE CWE URL for a CWE number.

        Args:
            cwe_num: CWE number

        Returns:
            CWE URL

        Example:
            >>> CWEParser.get_cwe_url(89)
            'https://cwe.mitre.org/data/definitions/89.html'
        """
        return f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"

    @staticmethod
    def is_valid_cwe_number(cwe_num: int) -> bool:
        """
        Check if number is a valid CWE number.

        Args:
            cwe_num: Number to validate

        Returns:
            True if valid CWE number

        Example:
            >>> CWEParser.is_valid_cwe_number(89)
            True
            >>> CWEParser.is_valid_cwe_number(99999)
            False
        """
        return CWEParser.CWE_MIN <= cwe_num <= CWEParser.CWE_MAX
