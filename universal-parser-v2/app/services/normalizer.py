"""
NormalizerService - Orchestrates the parsing and normalization process.

This service:
1. Loads YAML configuration
2. Reads scan file using appropriate file format reader
3. Extracts field values from each finding
4. Applies data type parsers to transform values
5. Builds normalized DefectDojo Finding dictionaries
6. Validates required fields are present
"""

import logging
from typing import Any

from app.models.yaml_config import YAMLConfig, FieldMapping
from app.parsers.file_formats import get_reader
from app.parsers.data_types import get_parser
from app.parsers.base import FieldExtractor
from app.utils.errors import ValidationError

logger = logging.getLogger(__name__)


class NormalizerService:
    """
    Service for normalizing scan results to DefectDojo format.

    This is the main orchestration class that combines:
    - File format readers (JSON, XML, CSV, etc.)
    - Data type parsers (String, Severity, Date, etc.)
    - Field extraction and mapping
    - Validation

    Example:
        >>> config = YAMLConfig.parse_obj(yaml_dict)
        >>> service = NormalizerService(config)
        >>> findings = service.normalize(scan_file_bytes)
        >>> findings[0]['title']
        'XSS Vulnerability'
    """

    # DefectDojo required fields for a finding
    REQUIRED_FIELDS = {'title', 'description', 'severity'}

    def __init__(self, config: YAMLConfig):
        """
        Initialize normalizer with YAML configuration.

        Args:
            config: Validated YAMLConfig object
        """
        self.config = config
        self.file_reader = None
        self._initialize_reader()

    def _initialize_reader(self):
        """
        Initialize the appropriate file format reader.

        Raises:
            ValueError: If file format is not supported
        """
        file_format = self.config.file_format.lower()
        try:
            self.file_reader = get_reader(file_format)
            logger.info(f"Initialized {file_format.upper()} reader for {self.config.parser_name}")
        except ValueError as e:
            logger.error(f"Failed to initialize reader: {str(e)}")
            raise

    def normalize(self, scan_file_content: bytes) -> list[dict[str, Any]]:
        """
        Normalize scan file to DefectDojo findings format.

        Args:
            scan_file_content: Raw scan file content as bytes

        Returns:
            List of normalized finding dictionaries

        Raises:
            FileFormatError: If file cannot be read or parsed
            ValidationError: If required fields are missing

        Example:
            >>> service = NormalizerService(config)
            >>> with open('scan.json', 'rb') as f:
            ...     findings = service.normalize(f.read())
            >>> len(findings)
            5
        """
        # Step 1: Read raw findings from file
        logger.info(f"Reading scan file using {self.config.file_format} reader")
        reader_config = self._build_reader_config()
        raw_findings = self.file_reader.read(scan_file_content, reader_config)
        logger.info(f"Extracted {len(raw_findings)} raw findings")

        # Step 2: Normalize each finding
        normalized_findings = []
        for idx, raw_finding in enumerate(raw_findings):
            try:
                normalized = self._normalize_single_finding(raw_finding)
                normalized_findings.append(normalized)
            except Exception as e:
                logger.warning(f"Failed to normalize finding {idx}: {str(e)}")
                # Continue processing other findings
                continue

        logger.info(f"Successfully normalized {len(normalized_findings)}/{len(raw_findings)} findings")
        return normalized_findings

    def _build_reader_config(self) -> dict:
        """
        Build configuration dict for file format reader.

        Returns:
            Configuration dictionary with reader-specific settings
        """
        config = {}

        # Add JSON-specific settings
        if self.config.file_format.lower() == 'json':
            config['json_root_path'] = self.config.json_root_path or '$'

        # Add XML-specific settings (future)
        # if self.config.file_format.lower() == 'xml':
        #     config['xml_root_xpath'] = self.config.xml_root_xpath

        return config

    def _normalize_single_finding(self, raw_finding: dict) -> dict[str, Any]:
        """
        Normalize a single raw finding to DefectDojo format.

        Args:
            raw_finding: Raw finding dictionary from scan file

        Returns:
            Normalized finding dictionary

        Raises:
            ValidationError: If required fields are missing
        """
        normalized = {}

        # Process each field mapping
        for field_mapping in self.config.field_mappings:
            if not field_mapping.active:
                continue

            # Handle template data type specially - it needs access to all fields
            if field_mapping.data_type == 'template':
                parsed_value = self._parse_template_field(raw_finding, field_mapping)
                if parsed_value:
                    normalized[field_mapping.target_field] = parsed_value
                continue

            # Extract raw value from source field
            raw_value = FieldExtractor.extract(
                raw_finding,
                field_mapping.source_field,
                default=None
            )

            # Skip if no value found and field is not required
            if raw_value is None and field_mapping.target_field not in self.REQUIRED_FIELDS:
                continue

            # Parse/transform the value
            parsed_value = self._parse_field_value(raw_value, field_mapping)

            # Store in normalized finding
            normalized[field_mapping.target_field] = parsed_value

        # Add metadata fields
        self._add_metadata_fields(normalized, raw_finding)

        # Validate required fields are present
        self._validate_required_fields(normalized)

        return normalized

    def _parse_field_value(self, value: Any, field_mapping: FieldMapping) -> Any:
        """
        Parse/transform a field value using appropriate data type parser.

        Args:
            value: Raw value to parse
            field_mapping: Field mapping configuration

        Returns:
            Parsed/transformed value
        """
        # Get the appropriate parser for this data type
        try:
            parser = get_parser(field_mapping.data_type)
        except ValueError as e:
            logger.warning(f"Unknown data type '{field_mapping.data_type}', using raw value")
            return value

        # Build parser configuration
        parser_config = {}

        # Add severity mapping if present
        if field_mapping.severity_mapping:
            parser_config['severity_mapping'] = field_mapping.severity_mapping

        # Add date format if present
        if field_mapping.date_format:
            parser_config['date_format'] = field_mapping.date_format

        # Add default value if present
        if field_mapping.default:
            parser_config['default'] = field_mapping.default

        # Parse the value
        try:
            return parser.parse(value, parser_config)
        except Exception as e:
            logger.warning(
                f"Failed to parse {field_mapping.source_field} "
                f"(type={field_mapping.data_type}): {str(e)}"
            )
            # Return raw value if parsing fails
            return value

    def _parse_template_field(self, raw_finding: dict, field_mapping: FieldMapping) -> Any:
        """
        Parse a template field using the template parser.

        Template fields need access to the entire raw finding dict
        to interpolate multiple field values into a single output.

        Args:
            raw_finding: Raw finding dictionary from scan file
            field_mapping: Field mapping configuration with template string

        Returns:
            Interpolated string with field values substituted
        """
        try:
            parser = get_parser('template')
        except ValueError as e:
            logger.warning(f"Template parser not available: {str(e)}")
            return None

        # Build parser configuration with template string
        parser_config = {
            'template': field_mapping.template
        }

        # Parse the template, passing the entire raw finding
        try:
            result = parser.parse(raw_finding, parser_config)
            return result if result else None
        except Exception as e:
            logger.warning(
                f"Failed to parse template for {field_mapping.target_field}: {str(e)}"
            )
            return None

    def _add_metadata_fields(self, normalized: dict, raw_finding: dict):
        """
        Add metadata fields to normalized finding.

        Args:
            normalized: Normalized finding dict (modified in place)
            raw_finding: Raw finding dict (for extracting metadata)
        """
        # Add scan_type metadata
        normalized['scan_type'] = self.config.tool_type

        # Add unique_id_from_tool if configured
        if self.config.deduplication_fields:
            # Build unique ID from deduplication fields
            id_parts = []
            for field_name in self.config.deduplication_fields:
                if field_name in normalized:
                    id_parts.append(str(normalized[field_name]))

            if id_parts:
                normalized['unique_id_from_tool'] = "|".join(id_parts)

        # Add service field if endpoint mapping is configured
        if hasattr(self.config, 'endpoint_mapping') and self.config.endpoint_mapping:
            if hasattr(self.config.endpoint_mapping, 'service_field'):
                service_value = FieldExtractor.extract(
                    raw_finding,
                    self.config.endpoint_mapping.service_field,
                    default=None
                )
                if service_value:
                    normalized['service'] = str(service_value)

    def _validate_required_fields(self, normalized: dict):
        """
        Validate that all required fields are present and have valid values.

        Args:
            normalized: Normalized finding dict

        Raises:
            ValidationError: If required fields are missing or invalid
        """
        # Check for missing fields
        missing_fields = self.REQUIRED_FIELDS - set(normalized.keys())

        if missing_fields:
            raise ValidationError(
                f"Missing required fields: {', '.join(missing_fields)}. "
                f"Found fields: {', '.join(normalized.keys())}"
            )

        # Check for None or empty values in required fields
        invalid_fields = []
        for field in self.REQUIRED_FIELDS:
            value = normalized.get(field)
            if value is None or (isinstance(value, str) and not value.strip()):
                invalid_fields.append(field)

        if invalid_fields:
            raise ValidationError(
                f"Required fields have invalid values (None or empty): {', '.join(invalid_fields)}"
            )

        # Validate severity is a valid value
        severity = normalized.get('severity')
        if severity:
            from app.parsers.data_types.severity_parser import SeverityParser
            if not SeverityParser.validate_severity(severity):
                raise ValidationError(
                    f"Invalid severity value: '{severity}'. "
                    f"Must be one of: {SeverityParser.VALID_SEVERITIES}"
                )

    def get_stats(self, findings: list[dict]) -> dict:
        """
        Get statistics about normalized findings.

        Args:
            findings: List of normalized findings

        Returns:
            Statistics dictionary

        Example:
            >>> stats = service.get_stats(findings)
            >>> stats['total_count']
            10
            >>> stats['severity_breakdown']
            {'Critical': 2, 'High': 5, 'Medium': 3}
        """
        stats = {
            'total_count': len(findings),
            'severity_breakdown': {},
            'has_cwe': 0,
            'has_cvss': 0,
            'has_endpoints': 0,
        }

        for finding in findings:
            # Count by severity
            severity = finding.get('severity', 'Unknown')
            stats['severity_breakdown'][severity] = stats['severity_breakdown'].get(severity, 0) + 1

            # Count optional fields
            if finding.get('cwe'):
                stats['has_cwe'] += 1
            if finding.get('cvssv3') or finding.get('cvssv3_score'):
                stats['has_cvss'] += 1
            if finding.get('endpoints'):
                stats['has_endpoints'] += 1

        return stats
