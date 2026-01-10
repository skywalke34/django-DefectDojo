"""
Regex extractor data type parser.

Extracts values from strings using regular expression patterns.
Useful for extracting structured data from unstructured text fields.

Features:
- Named and numbered capture groups
- Multiple match handling (first, last, all, join)
- Case sensitivity options
- Default values for no matches
"""

import logging
import re
from typing import Any

from app.parsers.base import DataTypeParser

logger = logging.getLogger(__name__)


class RegexParser(DataTypeParser):
    """
    Parser that extracts values using regular expressions.

    Configuration options:
        - pattern: Required regex pattern (string)
        - group: Capture group to return (default: 0 = full match, 1 = first group)
        - match_mode: How to handle multiple matches:
            - 'first': Return first match (default)
            - 'last': Return last match
            - 'all': Return list of all matches
            - 'join': Join all matches with separator
        - join_separator: Separator for 'join' mode (default: ", ")
        - case_sensitive: Whether match is case sensitive (default: True)
        - multiline: Enable multiline mode (^ and $ match line boundaries)
        - dotall: Make . match newlines
        - default: Value if no match found

    Example YAML configs:
        # Extract CVE from text
        - source_field: "raw_output"
          target_field: "cve"
          data_type: "regex"
          pattern: "CVE-\\d{4}-\\d+"
          match_mode: "first"

        # Extract all IP addresses
        - source_field: "description"
          target_field: "affected_hosts"
          data_type: "regex"
          pattern: "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"
          match_mode: "all"

        # Extract version number
        - source_field: "output"
          target_field: "version"
          data_type: "regex"
          pattern: "version[:\\s]+([\\d.]+)"
          group: 1
    """

    def parse(self, value: Any, config: dict = None) -> str | list[str] | None:
        """
        Extract value(s) from string using regex pattern.

        Args:
            value: String to extract from
            config: Configuration dictionary with:
                - pattern: Regex pattern (required)
                - group: Capture group number/name (default: 0)
                - match_mode: 'first', 'last', 'all', 'join' (default: 'first')
                - join_separator: For join mode (default: ", ")
                - case_sensitive: Case sensitivity (default: True)
                - multiline: Multiline mode (default: False)
                - dotall: Dotall mode (default: False)
                - default: Default if no match

        Returns:
            Extracted value(s) or default

        Examples:
            >>> parser = RegexParser()
            >>> parser.parse("CVE-2021-44228", {"pattern": "CVE-\\d{4}-\\d+"})
            'CVE-2021-44228'
            >>> parser.parse("v1.2.3 and v4.5.6", {"pattern": "v([\\d.]+)", "group": 1, "match_mode": "all"})
            ['1.2.3', '4.5.6']
        """
        config = config or {}

        # Validate pattern is provided
        pattern = config.get('pattern')
        if not pattern:
            logger.error("Regex pattern not provided in config")
            return config.get('default')

        # Handle None or empty values
        if value is None or value == "":
            return config.get('default')

        # Convert to string if needed
        if not isinstance(value, str):
            value = str(value)

        # Compile regex with flags
        flags = self._get_regex_flags(config)
        try:
            regex = re.compile(pattern, flags)
        except re.error as e:
            logger.error(f"Invalid regex pattern '{pattern}': {e}")
            return config.get('default')

        # Get match mode and group
        match_mode = config.get('match_mode', 'first')
        group = config.get('group', 0)

        # Find matches
        if match_mode == 'all' or match_mode == 'join':
            matches = self._find_all_matches(regex, value, group)
            if not matches:
                return config.get('default')
            if match_mode == 'join':
                separator = config.get('join_separator', ', ')
                return separator.join(matches)
            return matches
        elif match_mode == 'last':
            matches = self._find_all_matches(regex, value, group)
            if not matches:
                return config.get('default')
            return matches[-1]
        else:  # first (default)
            match = regex.search(value)
            if not match:
                return config.get('default')
            return self._extract_group(match, group, config)

    def _get_regex_flags(self, config: dict) -> int:
        """
        Build regex flags from config.

        Args:
            config: Configuration dictionary

        Returns:
            Combined regex flags
        """
        flags = 0
        if not config.get('case_sensitive', True):
            flags |= re.IGNORECASE
        if config.get('multiline', False):
            flags |= re.MULTILINE
        if config.get('dotall', False):
            flags |= re.DOTALL
        return flags

    def _find_all_matches(self, regex: re.Pattern, value: str, group: int | str) -> list[str]:
        """
        Find all matches and extract specified group.

        Args:
            regex: Compiled regex pattern
            value: String to search
            group: Group to extract

        Returns:
            List of matched strings
        """
        results = []
        for match in regex.finditer(value):
            extracted = self._extract_group(match, group, {})
            if extracted is not None:
                results.append(extracted)
        return results

    def _extract_group(self, match: re.Match, group: int | str, config: dict) -> str | None:
        """
        Extract specified group from match.

        Args:
            match: Regex match object
            group: Group number or name
            config: Configuration dict

        Returns:
            Extracted string or None
        """
        try:
            if isinstance(group, str):
                # Named group
                return match.group(group)
            else:
                # Numbered group
                return match.group(group)
        except IndexError:
            logger.warning(f"Group {group} not found in match")
            return config.get('default')

    @staticmethod
    def validate_pattern(pattern: str) -> tuple[bool, str]:
        """
        Validate a regex pattern.

        Args:
            pattern: Regex pattern to validate

        Returns:
            Tuple of (is_valid, error_message)

        Example:
            >>> RegexParser.validate_pattern("CVE-\\d+")
            (True, '')
            >>> RegexParser.validate_pattern("CVE-[")
            (False, 'unterminated character set...')
        """
        try:
            re.compile(pattern)
            return True, ''
        except re.error as e:
            return False, str(e)

    @staticmethod
    def escape_for_literal(text: str) -> str:
        """
        Escape a string for use as a literal in regex.

        Args:
            text: String to escape

        Returns:
            Escaped string safe for regex

        Example:
            >>> RegexParser.escape_for_literal("foo.bar")
            'foo\\.bar'
        """
        return re.escape(text)

    @staticmethod
    def extract_with_pattern(text: str, pattern: str, group: int = 0) -> str | None:
        """
        Quick extraction using pattern.

        Args:
            text: Text to search
            pattern: Regex pattern
            group: Capture group (default: 0 = full match)

        Returns:
            First match or None

        Example:
            >>> RegexParser.extract_with_pattern("Version: 1.2.3", r"Version: ([\\d.]+)", 1)
            '1.2.3'
        """
        try:
            match = re.search(pattern, text)
            if match:
                return match.group(group)
        except (re.error, IndexError):
            pass
        return None

    @staticmethod
    def extract_all_with_pattern(text: str, pattern: str, group: int = 0) -> list[str]:
        """
        Extract all matches using pattern.

        Args:
            text: Text to search
            pattern: Regex pattern
            group: Capture group

        Returns:
            List of matches

        Example:
            >>> RegexParser.extract_all_with_pattern("CVE-2021-1234, CVE-2021-5678", r"CVE-\\d+-\\d+")
            ['CVE-2021-1234', 'CVE-2021-5678']
        """
        results = []
        try:
            for match in re.finditer(pattern, text):
                try:
                    results.append(match.group(group))
                except IndexError:
                    continue
        except re.error:
            pass
        return results

    @staticmethod
    def replace_with_pattern(text: str, pattern: str, replacement: str, count: int = 0) -> str:
        """
        Replace matches in text.

        Args:
            text: Text to modify
            pattern: Regex pattern
            replacement: Replacement string (can use \\1, \\2 for groups)
            count: Max replacements (0 = all)

        Returns:
            Modified text

        Example:
            >>> RegexParser.replace_with_pattern("CVE-2021-1234", r"CVE-(\\d+)", "CVE-XXXX", 0)
            'CVE-XXXX-1234'
        """
        try:
            return re.sub(pattern, replacement, text, count=count)
        except re.error:
            return text

    @staticmethod
    def split_with_pattern(text: str, pattern: str) -> list[str]:
        """
        Split text using regex pattern.

        Args:
            text: Text to split
            pattern: Regex pattern for delimiter

        Returns:
            List of parts

        Example:
            >>> RegexParser.split_with_pattern("a,b;c|d", r"[,;|]")
            ['a', 'b', 'c', 'd']
        """
        try:
            return re.split(pattern, text)
        except re.error:
            return [text]


# Common extraction patterns for security tools
class CommonPatterns:
    """Common regex patterns for security scanner output."""

    # Vulnerability identifiers
    CVE = r'CVE-\d{4}-\d+'
    CWE = r'CWE-?\d+'
    CVSS_SCORE = r'\d+\.\d'
    CVSS_VECTOR_V3 = r'CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]'

    # Network
    IPV4 = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    IPV6 = r'[0-9a-fA-F:]{2,39}'
    URL = r'https?://[^\s<>"\']+?(?=[.,;:!?\s<>"\']|$)'
    DOMAIN = r'(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}'
    PORT = r'\d{1,5}'

    # File paths
    UNIX_PATH = r'/(?:[^/\s]+/)*[^/\s]+'
    WINDOWS_PATH = r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*'

    # Code
    FUNCTION_NAME = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
    LINE_NUMBER = r'[Ll]ine\s*(\d+)'
    FILE_LINE = r'([^:\s]+):(\d+)'

    # Version
    SEMVER = r'\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?(?:\+[a-zA-Z0-9.]+)?'
    VERSION = r'[vV]?(\d+(?:\.\d+)*)'

    # Hashes
    MD5 = r'[a-fA-F0-9]{32}'
    SHA1 = r'[a-fA-F0-9]{40}'
    SHA256 = r'[a-fA-F0-9]{64}'
