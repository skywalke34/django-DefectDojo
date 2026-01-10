"""
Pydantic models for Universal Parser V2 YAML configuration schema.

These models define and validate the structure of parser-as-code YAML files.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, validator, root_validator


class CVSSSource(BaseModel):
    """
    Single CVSS source definition for priority extraction.

    Used to define where to extract CVSS vector string and optionally score
    from the source data. Multiple sources can be defined with priority order.

    Example:
        cvss_sources:
          - path: "Classification.Cvss31.Vector"
            score_path: "Classification.Cvss31.Score"
          - path: "Classification.Cvss.Vector"
            score_path: "Classification.Cvss.Score"
    """
    path: str = Field(
        ...,
        description="Field path to CVSS vector string (e.g., 'cvss.vectorString')"
    )
    score_path: Optional[str] = Field(
        default=None,
        description="Optional field path to CVSS score. Only extract if source provides it."
    )


class CVSSReconstruct(BaseModel):
    """
    Configuration for reconstructing CVSS vector from individual component fields.

    Used when the source data provides CVSS metrics as separate fields rather than
    a complete vector string (e.g., Dependency-Check XML format).

    Example:
        cvss_reconstruct:
          version: "3.1"
          components:
            attackVector: "cvssV3.attackVector"
            attackComplexity: "cvssV3.attackComplexity"
            privilegesRequired: "cvssV3.privilegesRequired"
            userInteraction: "cvssV3.userInteraction"
            scope: "cvssV3.scope"
            confidentialityImpact: "cvssV3.confidentialityImpact"
            integrityImpact: "cvssV3.integrityImpact"
            availabilityImpact: "cvssV3.availabilityImpact"
          score_path: "cvssV3.baseScore"
    """
    version: str = Field(
        default="3.1",
        description="CVSS version to use in reconstructed vector ('3.0' or '3.1')"
    )
    components: Dict[str, str] = Field(
        ...,
        description="Mapping of CVSS metric names to source field paths. "
                    "Required metrics: attackVector, attackComplexity, privilegesRequired, "
                    "userInteraction, scope, confidentialityImpact, integrityImpact, availabilityImpact"
    )
    score_path: Optional[str] = Field(
        default=None,
        description="Optional field path to CVSS score. Only extract if source provides it."
    )

    @validator('version')
    def validate_version(cls, v):
        """Ensure CVSS version is valid"""
        allowed = ['3.0', '3.1']
        if v not in allowed:
            raise ValueError(f"CVSS version must be one of {allowed}, got '{v}'")
        return v


class RequestResponseMapping(BaseModel):
    """
    Configuration for mapping request/response pairs to DefectDojo's unsaved_req_resp format.

    DAST tools often capture HTTP request/response pairs for each finding.
    DefectDojo stores these in the `unsaved_req_resp` field as a list of dicts.

    Supports three modes:
    1. Separate fields: request_field + response_field
    2. Combined field: combined_field (dict with request/response keys)
    3. Array field: array_field (list of request/response pairs)

    Example YAML configs:
        # Mode 1: Separate fields
        request_response_mapping:
          request_field: "raw_request"
          response_field: "raw_response"

        # Mode 2: Combined field (dict)
        request_response_mapping:
          combined_field: "http_exchange"
          request_key: "req"
          response_key: "resp"

        # Mode 3: Array of pairs
        request_response_mapping:
          array_field: "http_messages"
          request_key: "request"
          response_key: "response"

    Output format (DefectDojo):
        unsaved_req_resp = [
            {"req": "GET /api/...", "resp": "HTTP/1.1 200..."},
            ...
        ]
    """
    # Mode 1: Separate request/response fields
    request_field: Optional[str] = Field(
        default=None,
        description="Field path to HTTP request data"
    )
    response_field: Optional[str] = Field(
        default=None,
        description="Field path to HTTP response data"
    )

    # Mode 2/3: Combined or array field
    combined_field: Optional[str] = Field(
        default=None,
        description="Field path to combined request/response dict or array"
    )
    array_field: Optional[str] = Field(
        default=None,
        description="Field path to array of request/response pairs"
    )

    # Keys within combined/array objects
    request_key: str = Field(
        default="request",
        description="Key name for request in combined/array mode"
    )
    response_key: str = Field(
        default="response",
        description="Key name for response in combined/array mode"
    )

    @root_validator(skip_on_failure=True)
    def validate_mapping_mode(cls, values):
        """Ensure exactly one mapping mode is configured"""
        request_field = values.get('request_field')
        response_field = values.get('response_field')
        combined_field = values.get('combined_field')
        array_field = values.get('array_field')

        # Check separate mode (both request and response)
        has_separate = request_field is not None or response_field is not None
        has_combined = combined_field is not None
        has_array = array_field is not None

        mode_count = sum([has_separate, has_combined, has_array])

        if mode_count == 0:
            raise ValueError(
                "RequestResponseMapping requires one of: "
                "(request_field + response_field), combined_field, or array_field"
            )

        if mode_count > 1:
            raise ValueError(
                "RequestResponseMapping supports only one mode: "
                "separate (request_field + response_field), combined, or array"
            )

        # If using separate mode, both fields should be provided
        if has_separate and not (request_field and response_field):
            raise ValueError(
                "Separate mode requires both request_field and response_field"
            )

        return values


class ConditionalSeverity(BaseModel):
    """
    Defines a conditional severity rule for dynamic severity assignment.

    Allows severity to be determined based on field values. Used for tools
    that don't have explicit severity but where severity can be inferred
    (e.g., TruffleHog: AWS credentials = Critical, generic secrets = Medium).

    Example:
        conditional_severity:
          - source_field: "detector_name"
            condition: "contains"
            value: "AWS"
            severity: "Critical"
          - source_field: "detector_name"
            condition: "equals"
            value: "Generic Secret"
            severity: "Medium"
        default_severity: "High"
    """
    source_field: str = Field(
        ...,
        description="Field path to check for condition"
    )
    condition: str = Field(
        ...,
        description="Condition type: 'equals', 'contains', 'regex', 'in'"
    )
    value: Any = Field(
        ...,
        description="Value to compare against. String for equals/contains/regex, list for 'in'"
    )
    severity: str = Field(
        ...,
        description="Severity to assign if condition matches"
    )

    @validator('condition')
    def validate_condition(cls, v):
        """Ensure condition type is valid"""
        allowed = ['equals', 'contains', 'regex', 'in', 'starts_with', 'ends_with']
        if v not in allowed:
            raise ValueError(f"condition must be one of {allowed}, got '{v}'")
        return v

    @validator('severity')
    def validate_severity(cls, v):
        """Ensure severity is valid DefectDojo severity"""
        valid = {'Critical', 'High', 'Medium', 'Low', 'Info'}
        if v not in valid:
            raise ValueError(f"severity must be one of {valid}, got '{v}'")
        return v


class VersionDetection(BaseModel):
    """
    Configuration for detecting a specific format version.

    Version detection checks if certain conditions are met to identify
    which version of a file format is being parsed.

    Detection methods:
    - field_exists: Check if a field exists in the data
    - field_equals: Check if a field has a specific value
    - field_contains: Check if a field contains a specific string
    - field_matches: Check if a field matches a regex pattern

    Example:
        detection:
          field_exists: "DetectorName"  # TruffleHog v3
        # OR
        detection:
          field_equals:
            path: "version"
            value: "2.0"
    """
    field_exists: Optional[str] = Field(
        default=None,
        description="Field path that must exist for this version"
    )
    field_equals: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Dict with 'path' and 'value' for exact match detection"
    )
    field_contains: Optional[Dict[str, str]] = Field(
        default=None,
        description="Dict with 'path' and 'value' for contains detection"
    )
    field_matches: Optional[Dict[str, str]] = Field(
        default=None,
        description="Dict with 'path' and 'pattern' for regex detection"
    )

    @root_validator(skip_on_failure=True)
    def validate_detection_method(cls, values):
        """Ensure at least one detection method is specified"""
        methods = [
            values.get('field_exists'),
            values.get('field_equals'),
            values.get('field_contains'),
            values.get('field_matches')
        ]
        if not any(methods):
            raise ValueError(
                "VersionDetection requires at least one detection method: "
                "field_exists, field_equals, field_contains, or field_matches"
            )
        return values


class ConditionalAppend(BaseModel):
    """
    Defines a conditional append rule for building fields with optional sections.

    When the source_field exists and has a non-empty value, the prefix
    followed by the source value will be appended to the base field value.

    Example:
        source_field: "target"
        prefix: "\n**Target:** "

    If target="https://example.com", appends: "\n**Target:** https://example.com"
    If target is null/empty, nothing is appended.
    """
    source_field: str = Field(
        ...,
        description="Field path to check and extract value from"
    )
    prefix: str = Field(
        ...,
        description="Text to prepend before the source value (e.g., '\\n**Target:** ')"
    )


class FieldMapping(BaseModel):
    """
    Defines how a single field from the scan file maps to a DefectDojo Finding field.

    Supports two source field modes:
    1. Single source: source_field="Name"
    2. Priority chain: source_fields=["Name", "Plugin Name", "asset.name"]
       (first non-null value is used)

    Example (single source):
        source_field: "Name"
        target_field: "title"
        data_type: "string"
        active: true

    Example (priority chain - first available):
        source_fields: ["Name", "Plugin Name", "asset.name"]
        target_field: "title"
        data_type: "string"
        active: true
    """
    source_field: Optional[str] = Field(
        default=None,
        description="Single field path in scan file (e.g., 'Name' or 'Classification.Cwe'). "
                    "Use source_field OR source_fields, not both."
    )
    source_fields: Optional[List[str]] = Field(
        default=None,
        description="List of field paths to try in order (first non-null wins). "
                    "Use for alternative field names like ['Name', 'Plugin Name', 'asset.name']. "
                    "Use source_field OR source_fields, not both."
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

    # Optional: Template string for multi-field composition
    template: Optional[str] = Field(
        default=None,
        description="Template string with {field_path} placeholders for multi-field composition. "
                    "Required when data_type='template'. Example: '{cve} affects (version: {version})'"
    )

    # Optional: Fixed/constant value (ignores source_field)
    fixed_value: Optional[Any] = Field(
        default=None,
        description="Fixed constant value to use for this field. When set, source_field is not required. "
                    "Example: fixed_value='High' for severity, fixed_value=798 for cwe."
    )

    # Optional: Conditional append rules for building composite fields
    append_if_present: Optional[List[ConditionalAppend]] = Field(
        default=None,
        description="List of conditional append rules. Each rule appends prefix + source value "
                    "to the base field value if the source field exists and has a non-empty value. "
                    "Example: append_if_present: [{source_field: 'target', prefix: '\\n**Target:** '}]"
    )

    # Optional: State machine mapping for status/state conversion
    state_mapping: Optional[Dict[str, Dict[str, Any]]] = Field(
        default=None,
        description="State machine mapping that converts a single input value to multiple output fields. "
                    "Each key is an input state value, and the value is a dict of target_field: value pairs. "
                    "Use 'default' key for fallback when input doesn't match any defined state. "
                    "Example: state_mapping: {'not_affected': {'active': false, 'is_mitigated': true}}"
    )

    # Optional: CVSS extractor configuration
    cvss_sources: Optional[List[CVSSSource]] = Field(
        default=None,
        description="Priority-ordered list of CVSS source paths for direct extraction. "
                    "Each source defines 'path' to vector string and optional 'score_path'. "
                    "Used when data_type='cvss_extractor'."
    )
    cvss_reconstruct: Optional[CVSSReconstruct] = Field(
        default=None,
        description="Configuration for reconstructing CVSS vector from individual component fields. "
                    "Used when source provides metrics as separate fields (e.g., Dependency-Check). "
                    "Used when data_type='cvss_extractor'."
    )
    cvss_outputs: Optional[Dict[str, str]] = Field(
        default=None,
        description="Mapping of CVSS output names to target DefectDojo fields. "
                    "Keys: 'cvssv3' (vector string), 'cvssv3_score' (float). "
                    "Example: {'cvssv3': 'cvssv3', 'cvssv3_score': 'cvssv3_score'}"
    )

    # Optional: Conditional severity rules (for data_type='conditional_severity')
    conditional_severity: Optional[List[ConditionalSeverity]] = Field(
        default=None,
        description="List of conditional severity rules. First matching rule wins. "
                    "Used when data_type='conditional_severity'."
    )
    default_severity: Optional[str] = Field(
        default=None,
        description="Default severity if no conditional_severity rule matches. "
                    "Required when using data_type='conditional_severity'."
    )

    # Optional: Regex parser configuration
    pattern: Optional[str] = Field(
        default=None,
        description="Regex pattern for extraction. Used when data_type='regex'."
    )
    regex_group: Optional[Any] = Field(
        default=None,
        description="Regex capture group (number or name). Used when data_type='regex'."
    )
    match_mode: Optional[str] = Field(
        default=None,
        description="Regex match mode: 'first', 'last', 'all', 'join'. Used when data_type='regex'."
    )

    @validator('data_type')
    def validate_data_type(cls, v):
        """Ensure data type is supported"""
        allowed = [
            'string', 'severity', 'date', 'integer', 'boolean', 'float', 'array',
            'template', 'state_machine', 'cvss_extractor',
            'html_to_text', 'endpoint', 'cwe', 'regex', 'conditional_severity'
        ]
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

    @validator('state_mapping', always=True)
    def validate_state_mapping(cls, v, values):
        """If data_type is state_machine, state_mapping must be provided"""
        data_type = values.get('data_type')

        if data_type == 'state_machine':
            if not v:
                raise ValueError(
                    "state_mapping is required when data_type='state_machine'. "
                    "Provide a mapping of input states to output field dictionaries."
                )
            # Validate each state maps to a dictionary
            for state_name, outputs in v.items():
                if not isinstance(outputs, dict):
                    raise ValueError(
                        f"state_mapping['{state_name}'] must be a dictionary of "
                        f"target_field: value pairs, got {type(outputs).__name__}"
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
            'static_finding', 'dynamic_finding', 'risk_accepted', 'out_of_scope',
            'is_mitigated', 'unsaved_req_resp', 'unsaved_endpoints', 'nb_occurences'
        }

        # Allow virtual/internal target fields (prefixed with _) without warning
        # These are used for state_machine mappings where outputs go to multiple fields
        if v.startswith('_'):
            return v

        if v not in known_fields:
            # Warning, not error - allow custom fields
            import warnings
            warnings.warn(
                f"target_field '{v}' is not a standard DefectDojo Finding field. "
                f"Standard fields: {known_fields}"
            )

        return v

    @root_validator(skip_on_failure=True)
    def validate_source_field_requirements(cls, values):
        """
        Validate source field requirements based on data_type and fixed_value:

        - If fixed_value is set: no source_field/source_fields required
        - If data_type='template': template string required, no source_field/source_fields needed
        - If data_type='cvss_extractor': uses cvss_sources/cvss_reconstruct instead
        - Otherwise: EITHER source_field OR source_fields required (not both, not neither)

        This supports:
        1. Single source: source_field="Name"
        2. Priority chain: source_fields=["Name", "Plugin Name", "asset.name"]
        3. Fixed constant: fixed_value="High" (no source needed)
        4. CVSS extraction: cvss_sources or cvss_reconstruct (no source_field needed)
        """
        data_type = values.get('data_type')
        template = values.get('template')
        source_field = values.get('source_field')
        source_fields = values.get('source_fields')
        fixed_value = values.get('fixed_value')

        # If fixed_value is set, no source fields are required
        if fixed_value is not None:
            # Warn if source_field/source_fields provided with fixed_value (they're ignored)
            if source_field or source_fields:
                import warnings
                warnings.warn(
                    "source_field/source_fields are ignored when fixed_value is set. "
                    "The fixed_value will be used directly."
                )
            return values

        if data_type == 'template':
            # Template data type requires template string, not source fields
            if not template:
                raise ValueError(
                    "template is required when data_type='template'. "
                    "Provide a template string with {field_path} placeholders."
                )
            # Warn if source_field/source_fields provided with template (they're ignored)
            if source_field or source_fields:
                import warnings
                warnings.warn(
                    "source_field/source_fields are ignored when data_type='template'. "
                    "Template extracts fields from the template string placeholders."
                )
        elif data_type == 'cvss_extractor':
            # CVSS extractor uses cvss_sources/cvss_reconstruct instead of source_field
            cvss_sources = values.get('cvss_sources')
            cvss_reconstruct = values.get('cvss_reconstruct')

            # Validate at least one CVSS configuration is provided
            if not cvss_sources and not cvss_reconstruct:
                raise ValueError(
                    "cvss_extractor requires at least one of 'cvss_sources' or 'cvss_reconstruct'. "
                    "Use 'cvss_sources' for direct vector extraction or 'cvss_reconstruct' "
                    "to build vector from individual component fields."
                )

            # Warn if source_field/source_fields provided (they're ignored)
            if source_field or source_fields:
                import warnings
                warnings.warn(
                    "source_field/source_fields are ignored when data_type='cvss_extractor'. "
                    "CVSS extractor uses cvss_sources and/or cvss_reconstruct for configuration."
                )
        elif data_type == 'conditional_severity':
            # Conditional severity requires conditional_severity rules and default
            conditional_severity = values.get('conditional_severity')
            default_severity = values.get('default_severity')

            if not conditional_severity:
                raise ValueError(
                    "conditional_severity requires 'conditional_severity' list of rules. "
                    "Each rule specifies a condition and the severity to assign when matched."
                )

            if not default_severity:
                raise ValueError(
                    "conditional_severity requires 'default_severity' as fallback. "
                    "This severity is used when no conditional rules match."
                )

            # Warn if source_field/source_fields provided (they're ignored)
            if source_field or source_fields:
                import warnings
                warnings.warn(
                    "source_field/source_fields are ignored when data_type='conditional_severity'. "
                    "Conditional severity uses the conditional_severity rules configuration."
                )
        else:
            # For all other data_types, need either source_field OR source_fields
            has_source_field = source_field is not None and source_field != ""
            has_source_fields = source_fields is not None and len(source_fields) > 0

            if has_source_field and has_source_fields:
                raise ValueError(
                    "Cannot specify both 'source_field' and 'source_fields'. "
                    "Use 'source_field' for a single source, or 'source_fields' for "
                    "a priority chain of alternative field names."
                )

            if not has_source_field and not has_source_fields:
                raise ValueError(
                    f"Either 'source_field' or 'source_fields' is required when "
                    f"data_type='{data_type}'. Use 'source_field' for a single source, "
                    f"or 'source_fields' for a priority chain."
                )

            # Validate source_fields has at least one entry if provided
            if has_source_fields and len(source_fields) == 0:
                raise ValueError(
                    "source_fields must contain at least one field path"
                )

        return values

    def get_source_fields_list(self) -> List[str]:
        """
        Get list of source fields to try (for unified extraction logic).

        Returns:
            List of field paths to try in order.
            - If source_fields is set, returns that list
            - If source_field is set, returns [source_field]
            - Otherwise returns empty list
        """
        if self.source_fields:
            return self.source_fields
        elif self.source_field:
            return [self.source_field]
        else:
            return []


class FormatVersion(BaseModel):
    """
    Defines a format version with its detection rules and field mappings.

    Used when a single tool can output multiple file format versions
    (e.g., TruffleHog v2 vs v3, Semgrep 0.x vs 1.x).

    The detection rules determine which version matches a given scan file,
    and the field_mappings are used for that version.

    Example YAML:
        format_versions:
          - version: "v3"
            detection:
              field_exists: "DetectorName"
            field_mappings:
              - source_field: "DetectorName"
                target_field: "title"
                data_type: "string"

          - version: "v2"
            detection:
              field_exists: "reason"
            field_mappings:
              - source_field: "reason"
                target_field: "title"
                data_type: "string"
    """
    version: str = Field(
        ...,
        description="Version identifier (e.g., 'v2', 'v3', '1.0')"
    )
    detection: VersionDetection = Field(
        ...,
        description="Rules to detect this version"
    )
    field_mappings: List[FieldMapping] = Field(
        ...,
        description="Field mappings specific to this version"
    )
    json_root_path: Optional[str] = Field(
        default=None,
        description="Version-specific JSON root path (overrides top-level)"
    )


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
    xml_namespaces: Optional[dict[str, str]] = Field(
        default=None,
        description="XML namespace prefix to URI mappings (e.g., {'bom': 'http://cyclonedx.org/schema/bom/1.4'})"
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
    csv_quote_char: Optional[str] = Field(
        default=None,
        description="CSV quote character (default: '\"')"
    )

    # Field Mappings (required unless format_versions is provided)
    field_mappings: Optional[List[FieldMapping]] = Field(
        default=None,
        description="List of source field → target field mappings. "
                    "Required unless format_versions is provided."
    )

    # Format Version Detection (alternative to field_mappings)
    format_versions: Optional[List[FormatVersion]] = Field(
        default=None,
        description="List of format versions with detection rules and version-specific mappings. "
                    "Used when a tool can output multiple file format versions."
    )

    # Deduplication
    deduplication_fields: List[str] = Field(
        default_factory=list,
        description="List of DefectDojo fields to use for deduplication"
    )

    # Request/Response handling (for DAST tools)
    request_response_mapping: Optional[RequestResponseMapping] = Field(
        default=None,
        description="Configuration for extracting HTTP request/response pairs from findings. "
                    "Populates the DefectDojo 'unsaved_req_resp' field."
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

    @validator('xml_finding_xpath')
    def validate_xml_finding_xpath(cls, v, values):
        """If format is XML, xml_finding_xpath is required"""
        file_format = values.get('file_format')
        if file_format == 'xml' and not v:
            raise ValueError(
                "xml_finding_xpath is required when file_format='xml'"
            )
        return v

    @validator('csv_has_header', always=True)
    def validate_csv_has_header(cls, v, values):
        """If format is CSV, csv_has_header defaults to True"""
        file_format = values.get('file_format')
        if file_format == 'csv' and v is None:
            return True  # Default to True for CSV
        return v

    @validator('field_mappings')
    def validate_required_fields(cls, v):
        """Ensure required DefectDojo fields are mapped and active"""
        if v is None:
            # Will be validated by root_validator with format_versions
            return v

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

        # Skip validation if format_versions is used (mappings will vary by version)
        format_versions = values.get('format_versions')
        if format_versions:
            return v

        field_mappings = values.get('field_mappings') or []
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

    @root_validator(skip_on_failure=True)
    def validate_mappings_or_versions(cls, values):
        """Ensure either field_mappings or format_versions is provided"""
        field_mappings = values.get('field_mappings')
        format_versions = values.get('format_versions')

        if not field_mappings and not format_versions:
            raise ValueError(
                "Either 'field_mappings' or 'format_versions' must be provided. "
                "Use 'field_mappings' for single-version formats, or 'format_versions' "
                "for tools that output multiple file format versions."
            )

        if field_mappings and format_versions:
            raise ValueError(
                "Cannot specify both 'field_mappings' and 'format_versions'. "
                "Use 'field_mappings' alone for single-version formats, or "
                "'format_versions' alone for multi-version detection."
            )

        # Validate required fields in each format_version
        if format_versions:
            required_fields = ['title', 'description', 'severity']
            for fv in format_versions:
                active_targets = {
                    m.target_field for m in fv.field_mappings if m.active
                }
                missing = [f for f in required_fields if f not in active_targets]
                if missing:
                    raise ValueError(
                        f"Format version '{fv.version}' is missing required fields: {missing}. "
                        f"Each version must have mappings for: {required_fields}"
                    )

        return values

    def get_active_field_mappings(self) -> List[FieldMapping]:
        """Return only active field mappings"""
        if self.field_mappings:
            return [mapping for mapping in self.field_mappings if mapping.active]
        return []

    def get_field_mapping(self, target_field: str) -> Optional[FieldMapping]:
        """Get field mapping by target field name"""
        if not self.field_mappings:
            return None
        for mapping in self.field_mappings:
            if mapping.target_field == target_field and mapping.active:
                return mapping
        return None
