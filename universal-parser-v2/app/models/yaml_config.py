"""
Pydantic models for Universal Parser V2 YAML configuration schema.

These models define and validate the structure of parser-as-code YAML files.
"""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field, validator


class FieldMapping(BaseModel):
    """
    Defines how a single field from the scan file maps to a DefectDojo Finding field.

    Example:
        source_field: "Name"
        target_field: "title"
        data_type: "string"
        active: true
    """
    source_field: str = Field(
        ...,
        description="Field path in scan file (e.g., 'Name' or 'Classification.Cwe')"
    )
    target_field: str = Field(
        ...,
        description="Target DefectDojo Finding field (e.g., 'title', 'severity')"
    )
    data_type: str = Field(
        ...,
        description="Data type parser to use (string, severity, date, integer, boolean)"
    )
    active: bool = Field(
        default=True,
        description="Whether this mapping is enabled"
    )

    # Optional: Severity-specific configuration
    severity_mapping: Optional[Dict[str, str]] = Field(
        default=None,
        description="Mapping table for severity normalization (tool value → DefectDojo value)"
    )

    # Optional: Date-specific configuration
    date_format: Optional[str] = Field(
        default=None,
        description="Date format string (e.g., '%Y-%m-%d')"
    )

    # Optional: Default value if source field missing
    default: Optional[str] = Field(
        default=None,
        description="Default value if source field is missing or null"
    )

    @validator('data_type')
    def validate_data_type(cls, v):
        """Ensure data type is supported"""
        allowed = ['string', 'severity', 'date', 'integer', 'boolean', 'float', 'array']
        if v not in allowed:
            raise ValueError(
                f"data_type must be one of {allowed}, got '{v}'"
            )
        return v

    @validator('severity_mapping')
    def validate_severity_mapping(cls, v, values):
        """If data_type is severity, mapping must be provided and valid"""
        data_type = values.get('data_type')

        if data_type == 'severity':
            if not v:
                raise ValueError(
                    "severity_mapping is required when data_type='severity'"
                )

            # Validate all target values are valid DefectDojo severities
            valid_severities = {'Critical', 'High', 'Medium', 'Low', 'Info'}
            invalid = [val for val in v.values() if val not in valid_severities]
            if invalid:
                raise ValueError(
                    f"Invalid severity values in mapping: {invalid}. "
                    f"Must be one of {valid_severities}"
                )

        return v

    @validator('target_field')
    def validate_target_field(cls, v):
        """Validate target field is a known DefectDojo Finding field"""
        # List of common DefectDojo Finding fields
        # This is not exhaustive, but covers the most common fields
        known_fields = {
            'title', 'description', 'severity', 'date', 'cwe', 'cvssv3',
            'cvssv3_score', 'cvssv4', 'cvssv4_score', 'active', 'verified',
            'false_p', 'mitigation', 'impact', 'references', 'file_path',
            'line', 'unique_id_from_tool', 'component_name', 'component_version',
            'static_finding', 'dynamic_finding', 'risk_accepted', 'out_of_scope'
        }

        if v not in known_fields:
            # Warning, not error - allow custom fields
            import warnings
            warnings.warn(
                f"target_field '{v}' is not a standard DefectDojo Finding field. "
                f"Standard fields: {known_fields}"
            )

        return v


class YAMLConfig(BaseModel):
    """
    Complete YAML configuration for a security tool parser.

    This defines metadata, file format, field mappings, and deduplication strategy.
    """

    # Metadata
    parser_name: str = Field(
        ...,
        description="Unique identifier for this parser (e.g., 'Acunetix360JSON')"
    )
    parser_version: str = Field(
        ...,
        description="Version of this parser configuration (e.g., '1.0')"
    )
    tool_name: str = Field(
        ...,
        description="Human-readable tool name (e.g., 'Acunetix 360')"
    )
    tool_type: str = Field(
        ...,
        description="DefectDojo scan_type identifier (e.g., 'Acunetix_360_JSON')"
    )

    # File Format
    file_format: str = Field(
        ...,
        description="Scan file format: json, xml, or csv"
    )
    file_encoding: str = Field(
        default="utf-8",
        description="File character encoding"
    )

    # Format-specific configuration
    json_root_path: Optional[str] = Field(
        default=None,
        description="JSONPath to findings array (e.g., '$.Vulnerabilities[*]')"
    )
    xml_finding_xpath: Optional[str] = Field(
        default=None,
        description="XPath to finding elements (e.g., '//vulnerability')"
    )
    csv_delimiter: Optional[str] = Field(
        default=None,
        description="CSV delimiter character (e.g., ',')"
    )
    csv_skip_rows: Optional[int] = Field(
        default=None,
        description="Number of CSV rows to skip before header"
    )
    csv_has_header: Optional[bool] = Field(
        default=None,
        description="Whether CSV file has header row"
    )

    # Field Mappings
    field_mappings: List[FieldMapping] = Field(
        ...,
        description="List of source field → target field mappings"
    )

    # Deduplication
    deduplication_fields: List[str] = Field(
        default_factory=list,
        description="List of DefectDojo fields to use for deduplication"
    )

    @validator('file_format')
    def validate_file_format(cls, v):
        """Ensure file format is supported"""
        allowed = ['json', 'xml', 'csv']
        if v not in allowed:
            raise ValueError(
                f"file_format must be one of {allowed}, got '{v}'"
            )
        return v

    @validator('json_root_path')
    def validate_json_root_path(cls, v, values):
        """If format is JSON, json_root_path is required"""
        file_format = values.get('file_format')
        if file_format == 'json' and not v:
            raise ValueError(
                "json_root_path is required when file_format='json'"
            )
        return v

    @validator('field_mappings')
    def validate_required_fields(cls, v):
        """Ensure required DefectDojo fields are mapped and active"""
        required_fields = ['title', 'description', 'severity']
        active_targets = {
            mapping.target_field
            for mapping in v
            if mapping.active
        }

        missing = [field for field in required_fields if field not in active_targets]
        if missing:
            raise ValueError(
                f"Required DefectDojo fields not mapped: {missing}. "
                f"These fields must have active mappings: {required_fields}"
            )

        return v

    @validator('deduplication_fields')
    def validate_deduplication_fields(cls, v, values):
        """Ensure deduplication fields are actually mapped"""
        if not v:
            # Default to title if not specified
            return ['title']

        field_mappings = values.get('field_mappings', [])
        active_targets = {
            mapping.target_field
            for mapping in field_mappings
            if mapping.active
        }

        invalid = [field for field in v if field not in active_targets]
        if invalid:
            raise ValueError(
                f"Deduplication fields {invalid} are not in active field_mappings. "
                f"Available target fields: {active_targets}"
            )

        return v

    def get_active_field_mappings(self) -> List[FieldMapping]:
        """Return only active field mappings"""
        return [mapping for mapping in self.field_mappings if mapping.active]

    def get_field_mapping(self, target_field: str) -> Optional[FieldMapping]:
        """Get field mapping by target field name"""
        for mapping in self.field_mappings:
            if mapping.target_field == target_field and mapping.active:
                return mapping
        return None
