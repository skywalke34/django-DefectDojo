"""
JSON file format reader.

Parses JSON files and extracts findings using JSONPath expressions.
"""

import json
import logging
from typing import Any

try:
    from jsonpath_ng import parse as jsonpath_parse
    from jsonpath_ng.exceptions import JSONPathError
except ImportError:
    # Fallback for environments without jsonpath-ng
    jsonpath_parse = None
    JSONPathError = Exception

from app.parsers.base import FileFormatReader
from app.utils.errors import FileFormatError

logger = logging.getLogger(__name__)


class JSONReader(FileFormatReader):
    """
    Reads and parses JSON scan files.

    Supports:
    - Standard JSON format
    - JSONPath expressions for finding extraction
    - Nested JSON structures
    """

    def read(self, file_content: bytes, config: dict) -> list[dict]:
        """
        Read JSON file and extract findings array.

        Args:
            file_content: Raw JSON file content as bytes
            config: Configuration dict with 'json_root_path' key

        Returns:
            List of finding dictionaries

        Raises:
            FileFormatError: If JSON is invalid or findings cannot be extracted

        Example:
            >>> config = {"json_root_path": "$.Vulnerabilities[*]"}
            >>> json_bytes = b'{"Vulnerabilities": [{"Name": "XSS"}]}'
            >>> reader = JSONReader()
            >>> findings = reader.read(json_bytes, config)
            >>> findings[0]["Name"]
            'XSS'
        """
        try:
            # Decode bytes to string
            json_str = file_content.decode('utf-8')
        except UnicodeDecodeError as e:
            raise FileFormatError(
                f"Failed to decode JSON file as UTF-8: {str(e)}"
            )

        try:
            # Parse JSON
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise FileFormatError(
                f"Invalid JSON format: {str(e)}\n"
                f"Line {e.lineno}, Column {e.colno}"
            )

        # Get JSONPath expression from config
        json_root_path = config.get('json_root_path', '$')

        # Extract findings using JSONPath
        try:
            findings = self._extract_with_jsonpath(data, json_root_path)
        except Exception as e:
            raise FileFormatError(
                f"Failed to extract findings using JSONPath '{json_root_path}': {str(e)}"
            )

        # Validate findings is a list
        if not isinstance(findings, list):
            # If single object returned, wrap in list
            findings = [findings]

        logger.info(f"Extracted {len(findings)} findings from JSON file")
        return findings

    def _extract_with_jsonpath(self, data: Any, jsonpath_expr: str) -> list[dict]:
        """
        Extract findings using JSONPath expression.

        Args:
            data: Parsed JSON data
            jsonpath_expr: JSONPath expression (e.g., "$.Vulnerabilities[*]")

        Returns:
            List of finding dictionaries

        Raises:
            FileFormatError: If JSONPath expression is invalid or no matches found
        """
        if jsonpath_parse is None:
            raise FileFormatError(
                "jsonpath-ng library not installed. Cannot parse JSON with JSONPath."
            )

        # Special case: if path is just "$", return entire document
        if jsonpath_expr == "$":
            if isinstance(data, list):
                return data
            else:
                return [data]

        try:
            # Parse JSONPath expression
            jsonpath_obj = jsonpath_parse(jsonpath_expr)
        except (JSONPathError, Exception) as e:
            raise FileFormatError(
                f"Invalid JSONPath expression '{jsonpath_expr}': {str(e)}"
            )

        # Execute JSONPath query
        matches = jsonpath_obj.find(data)

        if not matches:
            raise FileFormatError(
                f"No findings found using JSONPath: {jsonpath_expr}\n"
                f"Make sure the path points to the vulnerabilities array in your JSON file."
            )

        # Extract values from matches
        findings = [match.value for match in matches]

        # Flatten if needed (e.g., if path returns nested arrays)
        flattened = []
        for item in findings:
            if isinstance(item, list):
                flattened.extend(item)
            else:
                flattened.append(item)

        return flattened

    @staticmethod
    def validate_json_syntax(json_str: str) -> tuple[bool, str]:
        """
        Validate JSON syntax without parsing.

        Args:
            json_str: JSON string to validate

        Returns:
            Tuple of (is_valid, error_message)

        Example:
            >>> valid, error = JSONReader.validate_json_syntax('{"valid": true}')
            >>> valid
            True
            >>> valid, error = JSONReader.validate_json_syntax('{invalid}')
            >>> valid
            False
        """
        try:
            json.loads(json_str)
            return True, ""
        except json.JSONDecodeError as e:
            return False, f"Line {e.lineno}, Column {e.colno}: {e.msg}"
