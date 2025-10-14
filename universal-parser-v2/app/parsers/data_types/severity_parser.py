"""
Severity data type parser.

Handles severity normalization from various security tool formats
to DefectDojo's standard severity values.
"""

import logging
from typing import Any

from app.parsers.base import DataTypeParser
from app.utils.errors import SeverityMappingError

logger = logging.getLogger(__name__)


class SeverityParser(DataTypeParser):
    """
    Parser for severity fields.

    Normalizes severity values from different tools to DefectDojo format:
    - Critical
    - High
    - Medium
    - Low
    - Info
    """

    # DefectDojo standard severity values
    VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}

    # Common severity aliases (for convenience)
    DEFAULT_MAPPINGS = {
        # Capitalized versions
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
        "INFO": "Info",

        # Lowercase versions
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",

        # Common aliases
        "informational": "Info",
        "Informational": "Info",
        "INFORMATIONAL": "Info",

        "minor": "Low",
        "Minor": "Low",
        "MINOR": "Low",

        "major": "High",
        "Major": "High",
        "MAJOR": "High",

        # Numeric mappings (1=Critical, 5=Info)
        "1": "Critical",
        "2": "High",
        "3": "Medium",
        "4": "Low",
        "5": "Info",
    }

    def parse(self, value: Any, config: dict = None) -> str:
        """
        Parse severity value using mapping table.

        Args:
            value: Raw severity value from scan file
            config: Configuration dict with 'severity_mapping' key

        Returns:
            Normalized severity value (Critical/High/Medium/Low/Info)

        Raises:
            SeverityMappingError: If value cannot be mapped

        Examples:
            >>> parser = SeverityParser()
            >>> config = {"severity_mapping": {"high": "High", "medium": "Medium"}}
            >>> parser.parse("high", config)
            'High'
            >>> parser.parse("CRITICAL")  # Uses default mappings
            'Critical'
            >>> parser.parse("unknown", config)
            Traceback (most recent call last):
                ...
            SeverityMappingError: ...
        """
        if value is None:
            raise ValueError("Severity value cannot be None")

        # Convert to string if not already
        value_str = str(value).strip()

        if not value_str:
            raise ValueError("Severity value cannot be empty")

        # Get mapping table from config, or use defaults
        if config and 'severity_mapping' in config:
            severity_mapping = config['severity_mapping']
        else:
            severity_mapping = self.DEFAULT_MAPPINGS

        # Try exact match first
        if value_str in severity_mapping:
            normalized = severity_mapping[value_str]
            logger.debug(f"Mapped severity '{value_str}' → '{normalized}'")
            return normalized

        # Try case-insensitive match
        value_lower = value_str.lower()
        for source_val, target_val in severity_mapping.items():
            if str(source_val).lower() == value_lower:
                logger.debug(f"Mapped severity '{value_str}' → '{target_val}' (case-insensitive)")
                return target_val

        # Check if value is already a valid DefectDojo severity
        if value_str in self.VALID_SEVERITIES:
            logger.debug(f"Severity '{value_str}' is already valid")
            return value_str

        # No mapping found
        raise SeverityMappingError(
            unmapped_value=value_str,
            available_mappings=severity_mapping
        )

    @staticmethod
    def validate_severity(severity: str) -> bool:
        """
        Check if severity is a valid DefectDojo value.

        Args:
            severity: Severity value to validate

        Returns:
            True if valid, False otherwise

        Example:
            >>> SeverityParser.validate_severity("High")
            True
            >>> SeverityParser.validate_severity("invalid")
            False
        """
        return severity in SeverityParser.VALID_SEVERITIES

    @staticmethod
    def get_severity_weight(severity: str) -> int:
        """
        Get numeric weight for severity (for sorting).

        Args:
            severity: Severity value

        Returns:
            Numeric weight (0=Critical, 4=Info)

        Example:
            >>> SeverityParser.get_severity_weight("Critical")
            0
            >>> SeverityParser.get_severity_weight("Info")
            4
        """
        weights = {
            "Critical": 0,
            "High": 1,
            "Medium": 2,
            "Low": 3,
            "Info": 4
        }
        return weights.get(severity, 999)

    @staticmethod
    def build_mapping_table(source_values: list[str]) -> dict[str, str]:
        """
        Build a severity mapping table for unknown tool formats.

        Attempts to intelligently map source values to DefectDojo severities
        based on keywords.

        Args:
            source_values: List of severity values from source tool

        Returns:
            Mapping dictionary

        Example:
            >>> source = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            >>> mapping = SeverityParser.build_mapping_table(source)
            >>> mapping["CRITICAL"]
            'Critical'
        """
        mapping = {}

        for value in source_values:
            value_lower = str(value).lower()

            # Try to detect severity level from keywords
            if 'critical' in value_lower or 'crit' in value_lower:
                mapping[value] = "Critical"
            elif 'high' in value_lower or 'major' in value_lower:
                mapping[value] = "High"
            elif 'medium' in value_lower or 'moderate' in value_lower or 'med' in value_lower:
                mapping[value] = "Medium"
            elif 'low' in value_lower or 'minor' in value_lower:
                mapping[value] = "Low"
            elif 'info' in value_lower or 'informational' in value_lower or 'note' in value_lower:
                mapping[value] = "Info"
            else:
                # Default to Medium if unclear
                mapping[value] = "Medium"

        return mapping
