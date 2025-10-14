"""
Base classes for parsers.

This module defines abstract base classes for:
- File format readers (JSON, XML, CSV)
- Data type parsers (string, severity, date, etc.)
"""

from abc import ABC, abstractmethod
from typing import Any


class FileFormatReader(ABC):
    """
    Abstract base class for file format readers.

    File format readers are responsible for:
    1. Reading the scan file
    2. Parsing it into a Python data structure
    3. Extracting the findings array based on configuration
    """

    @abstractmethod
    def read(self, file_content: bytes, config: dict) -> list[dict]:
        """
        Read and parse file into list of finding dictionaries.

        Args:
            file_content: Raw file content as bytes
            config: Format-specific configuration from YAML

        Returns:
            List of finding dictionaries extracted from file

        Raises:
            FileFormatError: If file cannot be parsed

        Example:
            >>> reader = JSONReader()
            >>> config = {"json_root_path": "$.Vulnerabilities[*]"}
            >>> findings = reader.read(json_bytes, config)
            >>> len(findings)
            5
        """
        pass


class DataTypeParser(ABC):
    """
    Abstract base class for data type parsers.

    Data type parsers are responsible for:
    1. Extracting a value from finding data
    2. Transforming it to DefectDojo format
    3. Validating the transformed value
    """

    @abstractmethod
    def parse(self, value: Any, config: dict = None) -> Any:
        """
        Parse and transform a value.

        Args:
            value: Raw value from scan file
            config: Parser-specific configuration (e.g., severity mapping)

        Returns:
            Transformed value suitable for DefectDojo

        Raises:
            ValueError: If value cannot be parsed

        Example:
            >>> parser = SeverityParser()
            >>> config = {"severity_mapping": {"high": "High"}}
            >>> parser.parse("high", config)
            'High'
        """
        pass


class FieldExtractor:
    """
    Utility class for extracting nested fields from dictionaries.

    Supports dot notation for nested field access.
    """

    @staticmethod
    def extract(data: dict, field_path: str, default: Any = None) -> Any:
        """
        Extract value from nested dictionary using dot notation.

        Args:
            data: Dictionary to extract from
            field_path: Dot-separated path (e.g., "Classification.Cwe")
            default: Default value if field not found

        Returns:
            Extracted value or default

        Examples:
            >>> data = {"name": "SQL Injection", "info": {"cwe": 89}}
            >>> FieldExtractor.extract(data, "name")
            'SQL Injection'
            >>> FieldExtractor.extract(data, "info.cwe")
            89
            >>> FieldExtractor.extract(data, "missing", default="N/A")
            'N/A'
        """
        if not field_path:
            return default

        keys = field_path.split('.')
        current = data

        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default

        return current if current is not None else default

    @staticmethod
    def extract_all(data: dict, field_paths: list[str]) -> dict:
        """
        Extract multiple fields at once.

        Args:
            data: Dictionary to extract from
            field_paths: List of field paths to extract

        Returns:
            Dictionary mapping field paths to extracted values

        Example:
            >>> data = {"title": "XSS", "severity": "High", "cwe": 79}
            >>> paths = ["title", "severity", "cwe"]
            >>> FieldExtractor.extract_all(data, paths)
            {'title': 'XSS', 'severity': 'High', 'cwe': 79}
        """
        return {
            path: FieldExtractor.extract(data, path)
            for path in field_paths
        }
