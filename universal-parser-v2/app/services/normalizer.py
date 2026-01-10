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

from app.models.yaml_config import (
    YAMLConfig, FieldMapping, RequestResponseMapping,
    FormatVersion, VersionDetection
)
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

    def _detect_format_version(self, sample_finding: dict) -> FormatVersion | None:
        """
        Detect which format version matches the sample finding.

        Tries each format_version's detection rules in order.
        Returns the first matching version.

        Args:
            sample_finding: A sample finding to test detection rules against

        Returns:
            Matching FormatVersion or None if no match
        """
        import re

        if not self.config.format_versions:
            return None

        for fv in self.config.format_versions:
            detection = fv.detection

            # field_exists: Check if field path exists and has a value
            if detection.field_exists:
                value = FieldExtractor.extract(
                    sample_finding, detection.field_exists, default=None
                )
                if value is not None:
                    logger.info(
                        f"Detected format version '{fv.version}' "
                        f"(field_exists: {detection.field_exists})"
                    )
                    return fv

            # field_equals: Check if field equals specific value
            if detection.field_equals:
                path = detection.field_equals.get('path')
                expected = detection.field_equals.get('value')
                if path:
                    value = FieldExtractor.extract(sample_finding, path, default=None)
                    if value is not None and str(value) == str(expected):
                        logger.info(
                            f"Detected format version '{fv.version}' "
                            f"(field_equals: {path}={expected})"
                        )
                        return fv

            # field_contains: Check if field contains string
            if detection.field_contains:
                path = detection.field_contains.get('path')
                substr = detection.field_contains.get('value')
                if path and substr:
                    value = FieldExtractor.extract(sample_finding, path, default=None)
                    if value is not None and substr in str(value):
                        logger.info(
                            f"Detected format version '{fv.version}' "
                            f"(field_contains: {path} contains '{substr}')"
                        )
                        return fv

            # field_matches: Check if field matches regex
            if detection.field_matches:
                path = detection.field_matches.get('path')
                pattern = detection.field_matches.get('pattern')
                if path and pattern:
                    value = FieldExtractor.extract(sample_finding, path, default=None)
                    if value is not None:
                        try:
                            if re.search(pattern, str(value)):
                                logger.info(
                                    f"Detected format version '{fv.version}' "
                                    f"(field_matches: {path} matches '{pattern}')"
                                )
                                return fv
                        except re.error:
                            logger.warning(f"Invalid regex pattern in version detection: {pattern}")

        logger.warning("No format version matched for input data")
        return None

    def _get_effective_mappings(
        self,
        raw_findings: list[dict]
    ) -> tuple[list[FieldMapping], str | None]:
        """
        Get the effective field mappings to use, potentially detecting version.

        If format_versions is configured, detect the version from the first
        finding and return that version's mappings.

        Args:
            raw_findings: List of raw findings from scan file

        Returns:
            Tuple of (field_mappings, detected_version_name)
        """
        # If using standard field_mappings
        if self.config.field_mappings:
            return self.config.field_mappings, None

        # If using format_versions, detect from sample
        if self.config.format_versions and raw_findings:
            sample = raw_findings[0]
            detected_version = self._detect_format_version(sample)

            if detected_version:
                return detected_version.field_mappings, detected_version.version

            # No version matched - use first version as fallback
            fallback = self.config.format_versions[0]
            logger.warning(
                f"No format version detected, using fallback: '{fallback.version}'"
            )
            return fallback.field_mappings, fallback.version

        return [], None

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

        # Step 2: Detect format version and get effective mappings
        self._effective_mappings, detected_version = self._get_effective_mappings(raw_findings)
        if detected_version:
            logger.info(f"Using format version: {detected_version}")

        # Step 3: Normalize each finding
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

        # Get effective mappings (either from config or detected version)
        effective_mappings = getattr(self, '_effective_mappings', None) or self.config.field_mappings or []

        # Process each field mapping
        for field_mapping in effective_mappings:
            if not field_mapping.active:
                continue

            # Handle fixed_value - use constant value, skip extraction
            if field_mapping.fixed_value is not None:
                normalized[field_mapping.target_field] = field_mapping.fixed_value
                logger.debug(
                    f"Using fixed_value '{field_mapping.fixed_value}' for "
                    f"target '{field_mapping.target_field}'"
                )
                continue

            # Handle template data type specially - it needs access to all fields
            if field_mapping.data_type == 'template':
                parsed_value = self._parse_template_field(raw_finding, field_mapping)
                if parsed_value:
                    normalized[field_mapping.target_field] = parsed_value
                continue

            # Handle state_machine data type - maps input value to multiple outputs
            if field_mapping.data_type == 'state_machine':
                self._process_state_machine(raw_finding, field_mapping, normalized)
                continue

            # Handle cvss_extractor data type - extracts CVSS to multiple fields
            if field_mapping.data_type == 'cvss_extractor':
                self._process_cvss_extractor(raw_finding, field_mapping, normalized)
                continue

            # Handle conditional_severity data type - dynamic severity based on rules
            if field_mapping.data_type == 'conditional_severity':
                self._process_conditional_severity(raw_finding, field_mapping, normalized)
                continue

            # Extract raw value using priority chain (source_fields) or single source
            raw_value, matched_field = self._extract_first_available(
                raw_finding,
                field_mapping
            )

            # Skip if no value found and field is not required
            if raw_value is None and field_mapping.target_field not in self.REQUIRED_FIELDS:
                continue

            # Parse/transform the value
            parsed_value = self._parse_field_value(raw_value, field_mapping, matched_field)

            # Apply conditional appends if configured
            if field_mapping.append_if_present and parsed_value is not None:
                parsed_value = self._apply_conditional_appends(
                    parsed_value, raw_finding, field_mapping
                )

            # Store in normalized finding
            normalized[field_mapping.target_field] = parsed_value

        # Add metadata fields
        self._add_metadata_fields(normalized, raw_finding)

        # Validate required fields are present
        self._validate_required_fields(normalized)

        return normalized

    def _extract_first_available(
        self,
        raw_finding: dict,
        field_mapping: FieldMapping
    ) -> tuple[Any, str | None]:
        """
        Extract the first available value from source_fields or source_field.

        Implements "first-available" semantics for priority chains:
        - Tries each source field in order
        - Returns the first non-null, non-empty value found
        - If all sources fail, returns (None, None)

        Args:
            raw_finding: Raw finding dictionary from scan file
            field_mapping: Field mapping configuration

        Returns:
            Tuple of (extracted_value, matched_field_name)
            - extracted_value: The first non-null value found, or None
            - matched_field_name: The field path that matched, or None

        Example:
            # With source_fields=["Name", "Plugin Name", "asset.name"]
            # If raw_finding has {"Plugin Name": "SQL Injection"}
            # Returns ("SQL Injection", "Plugin Name")
        """
        # Get list of source fields to try (handles both source_field and source_fields)
        source_fields_list = field_mapping.get_source_fields_list()

        if not source_fields_list:
            logger.debug(
                f"No source fields configured for target '{field_mapping.target_field}'"
            )
            return None, None

        # Try each source field in order
        for source_field in source_fields_list:
            value = FieldExtractor.extract(
                raw_finding,
                source_field,
                default=None
            )

            # Check if we got a valid (non-null, non-empty) value
            if value is not None:
                # For strings, also check if non-empty after stripping
                if isinstance(value, str):
                    if value.strip():
                        logger.debug(
                            f"Priority chain: matched '{source_field}' for "
                            f"target '{field_mapping.target_field}'"
                        )
                        return value, source_field
                else:
                    # Non-string values (int, dict, list, etc.) - just check not None
                    logger.debug(
                        f"Priority chain: matched '{source_field}' for "
                        f"target '{field_mapping.target_field}'"
                    )
                    return value, source_field

        # No source field had a valid value
        if len(source_fields_list) > 1:
            logger.debug(
                f"Priority chain: no match found for target '{field_mapping.target_field}' "
                f"(tried: {source_fields_list})"
            )

        return None, None

    def _parse_field_value(
        self,
        value: Any,
        field_mapping: FieldMapping,
        matched_field: str | None = None
    ) -> Any:
        """
        Parse/transform a field value using appropriate data type parser.

        Args:
            value: Raw value to parse
            field_mapping: Field mapping configuration
            matched_field: The actual source field that was matched (for logging)

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

        # Add regex-specific configuration
        if field_mapping.pattern:
            parser_config['pattern'] = field_mapping.pattern
        if field_mapping.regex_group is not None:
            parser_config['group'] = field_mapping.regex_group
        if field_mapping.match_mode:
            parser_config['match_mode'] = field_mapping.match_mode

        # Parse the value
        try:
            return parser.parse(value, parser_config)
        except Exception as e:
            # Use matched_field for logging if available, otherwise describe source
            source_desc = matched_field or field_mapping.source_field or "source_fields"
            logger.warning(
                f"Failed to parse {source_desc} "
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

    def _apply_conditional_appends(
        self,
        base_value: Any,
        raw_finding: dict,
        field_mapping: FieldMapping
    ) -> str:
        """
        Apply conditional append rules to build composite field values.

        For each rule in append_if_present, if the source field exists
        and has a non-empty value, append prefix + value to the base value.

        Args:
            base_value: The base field value to append to
            raw_finding: Raw finding dictionary from scan file
            field_mapping: Field mapping with append_if_present configuration

        Returns:
            The base value with conditional appends applied

        Example:
            base_value: "SQL Injection vulnerability"
            append_if_present:
              - source_field: "target"
                prefix: "\n**Target:** "
              - source_field: "fix_version"
                prefix: "\n**Fixed in:** "

            If target="/api/users" and fix_version is null:
            Result: "SQL Injection vulnerability\n**Target:** /api/users"
        """
        if not field_mapping.append_if_present:
            return base_value

        # Convert base value to string for appending
        result = str(base_value) if base_value is not None else ""

        for append_rule in field_mapping.append_if_present:
            # Extract the source field value
            append_value = FieldExtractor.extract(
                raw_finding,
                append_rule.source_field,
                default=None
            )

            # Check if we have a valid (non-null, non-empty) value
            if append_value is not None:
                # For strings, also check if non-empty after stripping
                if isinstance(append_value, str):
                    if append_value.strip():
                        result += append_rule.prefix + append_value
                        logger.debug(
                            f"Appended '{append_rule.source_field}' to "
                            f"'{field_mapping.target_field}'"
                        )
                else:
                    # Non-string values - convert to string and append
                    result += append_rule.prefix + str(append_value)
                    logger.debug(
                        f"Appended '{append_rule.source_field}' to "
                        f"'{field_mapping.target_field}'"
                    )

        return result

    def _process_state_machine(
        self,
        raw_finding: dict,
        field_mapping: FieldMapping,
        normalized: dict
    ) -> None:
        """
        Process a state machine mapping to set multiple output fields.

        Looks up the input value in state_mapping and merges all output
        field values into the normalized finding.

        Args:
            raw_finding: Raw finding dictionary from scan file
            field_mapping: Field mapping with state_mapping configuration
            normalized: Normalized finding dict (modified in place)

        Example:
            state_mapping:
              "not_affected":
                active: false
                verified: true
                is_mitigated: true
              "false_positive":
                false_p: true
                active: false
              default:
                active: true

            If source value is "not_affected", sets:
            - normalized["active"] = False
            - normalized["verified"] = True
            - normalized["is_mitigated"] = True
        """
        if not field_mapping.state_mapping:
            logger.warning(
                f"state_machine mapping has no state_mapping for "
                f"target '{field_mapping.target_field}'"
            )
            return

        # Extract the input value using priority chain or source_field
        raw_value, matched_field = self._extract_first_available(
            raw_finding,
            field_mapping
        )

        if raw_value is None:
            logger.debug(
                f"No source value found for state_machine "
                f"'{field_mapping.target_field}'"
            )
            return

        # Convert to string for lookup (state keys are strings)
        input_state = str(raw_value)

        # Look up the state in the mapping
        if input_state in field_mapping.state_mapping:
            outputs = field_mapping.state_mapping[input_state]
            logger.debug(
                f"State machine: '{input_state}' matched, setting {list(outputs.keys())}"
            )
        elif 'default' in field_mapping.state_mapping:
            outputs = field_mapping.state_mapping['default']
            logger.debug(
                f"State machine: '{input_state}' not matched, using default, "
                f"setting {list(outputs.keys())}"
            )
        else:
            # No match and no default - log warning and skip
            logger.warning(
                f"State machine: '{input_state}' not found in state_mapping "
                f"and no 'default' defined for '{field_mapping.target_field}'. "
                f"Available states: {list(field_mapping.state_mapping.keys())}"
            )
            return

        # Merge output values into normalized finding
        for target_field, value in outputs.items():
            normalized[target_field] = value
            logger.debug(
                f"State machine set: {target_field}={value}"
            )

    def _process_cvss_extractor(
        self,
        raw_finding: dict,
        field_mapping: FieldMapping,
        normalized: dict
    ) -> None:
        """
        Process a CVSS extractor mapping to extract CVSS data to multiple output fields.

        Extracts CVSS vector string and optionally score from source data using either
        direct extraction (cvss_sources) or reconstruction from components (cvss_reconstruct).

        Args:
            raw_finding: Raw finding dictionary from scan file
            field_mapping: Field mapping with CVSS extractor configuration
            normalized: Normalized finding dict (modified in place)

        Example:
            cvss_sources:
              - path: "Classification.Cvss31.Vector"
                score_path: "Classification.Cvss31.Score"
            cvss_outputs:
              cvssv3: "cvssv3"
              cvssv3_score: "cvssv3_score"

            Result:
            - normalized["cvssv3"] = "CVSS:3.1/AV:N/AC:L/..."
            - normalized["cvssv3_score"] = 9.8
        """
        # Build config for CVSS parser
        parser_config = {}

        # Add cvss_sources configuration
        if field_mapping.cvss_sources:
            parser_config['cvss_sources'] = [
                {
                    'path': source.path,
                    'score_path': source.score_path
                }
                for source in field_mapping.cvss_sources
            ]

        # Add cvss_reconstruct configuration
        if field_mapping.cvss_reconstruct:
            parser_config['cvss_reconstruct'] = {
                'version': field_mapping.cvss_reconstruct.version,
                'components': field_mapping.cvss_reconstruct.components,
                'score_path': field_mapping.cvss_reconstruct.score_path
            }

        if not parser_config:
            logger.warning(
                f"cvss_extractor mapping has no cvss_sources or cvss_reconstruct "
                f"for target '{field_mapping.target_field}'"
            )
            return

        # Get the CVSS parser
        try:
            parser = get_parser('cvss_extractor')
        except ValueError as e:
            logger.warning(f"CVSS extractor parser not available: {str(e)}")
            return

        # Parse CVSS data (pass entire raw finding for multi-source extraction)
        try:
            cvss_result = parser.parse(raw_finding, parser_config)
        except Exception as e:
            logger.warning(
                f"Failed to extract CVSS for '{field_mapping.target_field}': {str(e)}"
            )
            return

        if not cvss_result or not isinstance(cvss_result, dict):
            logger.debug(f"No CVSS data extracted for '{field_mapping.target_field}'")
            return

        # Distribute outputs based on cvss_outputs configuration
        cvss_outputs = field_mapping.cvss_outputs or {
            'cvssv3': 'cvssv3',
            'cvssv3_score': 'cvssv3_score'
        }

        for output_key, target_field in cvss_outputs.items():
            if output_key in cvss_result and cvss_result[output_key] is not None:
                normalized[target_field] = cvss_result[output_key]
                logger.debug(
                    f"CVSS extractor set: {target_field}={cvss_result[output_key]}"
                )

    def _process_request_response(
        self,
        raw_finding: dict,
        normalized: dict
    ) -> None:
        """
        Extract and process request/response pairs from the finding.

        Handles three modes:
        1. Separate fields (request_field + response_field)
        2. Combined field (dict with request/response keys)
        3. Array field (list of request/response pairs)

        Args:
            raw_finding: Raw finding dictionary from scan file
            normalized: Normalized finding dict (modified in place)
        """
        if not self.config.request_response_mapping:
            return

        mapping = self.config.request_response_mapping
        req_resp_list = []

        # Mode 1: Separate request/response fields
        if mapping.request_field and mapping.response_field:
            request_data = FieldExtractor.extract(
                raw_finding, mapping.request_field, default=None
            )
            response_data = FieldExtractor.extract(
                raw_finding, mapping.response_field, default=None
            )

            if request_data or response_data:
                req_resp_list.append({
                    'req': str(request_data) if request_data else '',
                    'resp': str(response_data) if response_data else ''
                })
                logger.debug(
                    f"Extracted request/response pair from separate fields"
                )

        # Mode 2: Combined field (dict)
        elif mapping.combined_field:
            combined_data = FieldExtractor.extract(
                raw_finding, mapping.combined_field, default=None
            )

            if isinstance(combined_data, dict):
                request_data = combined_data.get(mapping.request_key)
                response_data = combined_data.get(mapping.response_key)
                if request_data or response_data:
                    req_resp_list.append({
                        'req': str(request_data) if request_data else '',
                        'resp': str(response_data) if response_data else ''
                    })
                    logger.debug(
                        f"Extracted request/response pair from combined field"
                    )

        # Mode 3: Array field (list of pairs)
        elif mapping.array_field:
            array_data = FieldExtractor.extract(
                raw_finding, mapping.array_field, default=None
            )

            if isinstance(array_data, list):
                for item in array_data:
                    if isinstance(item, dict):
                        request_data = item.get(mapping.request_key)
                        response_data = item.get(mapping.response_key)
                        if request_data or response_data:
                            req_resp_list.append({
                                'req': str(request_data) if request_data else '',
                                'resp': str(response_data) if response_data else ''
                            })
                if req_resp_list:
                    logger.debug(
                        f"Extracted {len(req_resp_list)} request/response pairs from array"
                    )

        # Set unsaved_req_resp if we extracted any pairs
        if req_resp_list:
            normalized['unsaved_req_resp'] = req_resp_list

    def _process_conditional_severity(
        self,
        raw_finding: dict,
        field_mapping: FieldMapping,
        normalized: dict
    ) -> None:
        """
        Process conditional severity mapping to determine severity dynamically.

        Evaluates each conditional_severity rule in order and assigns the
        severity from the first matching rule.

        Args:
            raw_finding: Raw finding dictionary from scan file
            field_mapping: Field mapping with conditional_severity configuration
            normalized: Normalized finding dict (modified in place)
        """
        import re

        if not field_mapping.conditional_severity:
            logger.warning(
                f"conditional_severity mapping has no rules for "
                f"target '{field_mapping.target_field}'"
            )
            return

        # Try each rule in order
        for rule in field_mapping.conditional_severity:
            # Extract the source field value
            source_value = FieldExtractor.extract(
                raw_finding,
                rule.source_field,
                default=None
            )

            if source_value is None:
                continue

            # Convert to string for comparison
            source_str = str(source_value)
            matched = False

            # Evaluate condition
            if rule.condition == 'equals':
                matched = source_str == str(rule.value)
            elif rule.condition == 'contains':
                matched = str(rule.value) in source_str
            elif rule.condition == 'starts_with':
                matched = source_str.startswith(str(rule.value))
            elif rule.condition == 'ends_with':
                matched = source_str.endswith(str(rule.value))
            elif rule.condition == 'regex':
                try:
                    matched = bool(re.search(str(rule.value), source_str))
                except re.error:
                    logger.warning(f"Invalid regex pattern: {rule.value}")
            elif rule.condition == 'in':
                if isinstance(rule.value, list):
                    matched = source_str in [str(v) for v in rule.value]
                else:
                    matched = source_str == str(rule.value)

            if matched:
                normalized[field_mapping.target_field] = rule.severity
                logger.debug(
                    f"Conditional severity: matched rule "
                    f"({rule.source_field} {rule.condition} {rule.value}), "
                    f"setting severity={rule.severity}"
                )
                return

        # No rule matched, use default
        if field_mapping.default_severity:
            normalized[field_mapping.target_field] = field_mapping.default_severity
            logger.debug(
                f"Conditional severity: no rules matched, "
                f"using default_severity={field_mapping.default_severity}"
            )
        else:
            logger.warning(
                f"Conditional severity: no rules matched and no default_severity "
                f"for '{field_mapping.target_field}'"
            )

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

        # Process request/response mapping if configured
        self._process_request_response(raw_finding, normalized)

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
