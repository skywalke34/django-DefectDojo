"""
Template string parser for multi-field composition.

This parser supports template strings with {field_path} placeholders
that are interpolated from raw finding data.
"""

import re
from typing import Any, Optional

from ..base import DataTypeParser, FieldExtractor


class TemplateParser(DataTypeParser):
    """
    Parses template strings with {field_path} placeholders.

    Missing fields are skipped along with surrounding delimiters
    for cleaner output.

    Examples:
        >>> parser = TemplateParser()
        >>> data = {"cve": "CVE-2025-001", "version": "1.0"}
        >>> parser.parse(data, {"template": "{cve} - {version}"})
        'CVE-2025-001 - 1.0'

        >>> # Missing field skipped with delimiter
        >>> data = {"cve": "CVE-2025-001"}
        >>> parser.parse(data, {"template": "{cve} - {version}"})
        'CVE-2025-001'
    """

    # Regex to find {field.path} placeholders (non-greedy, no nested braces)
    PLACEHOLDER_PATTERN = re.compile(r'\{([^{}]+)\}')

    # Regex to find escaped braces {{ and }}
    ESCAPED_OPEN = re.compile(r'\{\{')
    ESCAPED_CLOSE = re.compile(r'\}\}')

    def parse(self, value: Any, config: dict = None) -> str:
        """
        Parse template string and interpolate field values.

        Args:
            value: The entire raw finding dict (not a single field value)
            config: Must contain 'template' key with the template string

        Returns:
            Interpolated string with field values substituted.
            Missing fields are skipped along with surrounding delimiters.

        Raises:
            ValueError: If config is missing or template is not provided
        """
        if config is None:
            raise ValueError("config is required for template parser")

        template = config.get('template')
        if template is None:
            raise ValueError("template is required in config")

        # Handle empty template
        if not template:
            return ""

        # Handle case where value is not a dict
        if not isinstance(value, dict):
            return str(value) if value is not None else ""

        return self._interpolate(template, value)

    def _interpolate(self, template: str, data: dict) -> str:
        """
        Replace {field.path} placeholders with values from data.

        Missing fields are skipped along with surrounding static text
        (delimiters) up to the next placeholder or boundary.

        Args:
            template: Template string with {field.path} placeholders
            data: Dictionary to extract field values from

        Returns:
            Interpolated string
        """
        # First, temporarily replace escaped braces to protect them
        template = self.ESCAPED_OPEN.sub('\x00OPEN\x00', template)
        template = self.ESCAPED_CLOSE.sub('\x00CLOSE\x00', template)

        # Parse template into segments: text and placeholders
        segments = self._parse_template(template)

        # Handle templates with no placeholders (just static text)
        if not any(s["type"] == "field" for s in segments):
            result = template
            result = result.replace('\x00OPEN\x00', '{')
            result = result.replace('\x00CLOSE\x00', '}')
            return result.strip()

        # Build result, skipping missing fields and their delimiters
        result = self._build_result(segments, data)

        # Restore escaped braces
        result = result.replace('\x00OPEN\x00', '{')
        result = result.replace('\x00CLOSE\x00', '}')

        return result.strip()

    def _parse_template(self, template: str) -> list[dict]:
        """
        Parse template into list of segments.

        Each segment is either:
        - {"type": "text", "value": "..."} - static text
        - {"type": "field", "path": "field.path"} - field placeholder

        Args:
            template: Template string to parse

        Returns:
            List of segment dictionaries
        """
        segments = []
        last_end = 0

        for match in self.PLACEHOLDER_PATTERN.finditer(template):
            # Add any text before this placeholder
            if match.start() > last_end:
                text = template[last_end:match.start()]
                segments.append({"type": "text", "value": text})

            # Add the placeholder
            field_path = match.group(1).strip()
            segments.append({"type": "field", "path": field_path})

            last_end = match.end()

        # Add any remaining text after last placeholder
        if last_end < len(template):
            text = template[last_end:]
            segments.append({"type": "text", "value": text})

        return segments

    def _build_result(self, segments: list[dict], data: dict) -> str:
        """
        Build result string from segments, handling missing fields.

        Strategy:
        - For each field, check if it exists
        - If field exists: include preceding text (delimiter) and field value
        - If field missing: skip preceding text (delimiter) but track if we need trailing text
        - Trailing text after last field: include if last field existed

        Args:
            segments: List of parsed segments
            data: Dictionary to extract field values from

        Returns:
            Interpolated result string
        """
        result_parts = []
        pending_text = ""  # Text waiting to be added (delimiter before a field)
        last_field_existed = False  # Track if the most recent field was present

        for i, segment in enumerate(segments):
            if segment["type"] == "text":
                # Store text - we'll add it only if the next field exists
                pending_text += segment["value"]

            elif segment["type"] == "field":
                field_value = self._extract_field(data, segment["path"])

                if field_value is not None:
                    # Field exists - add pending text and field value
                    if pending_text:
                        # If this is the first field with content, check if leading text is meaningful
                        if result_parts or not self._is_pure_delimiter(pending_text):
                            result_parts.append(pending_text)
                    result_parts.append(str(field_value))
                    pending_text = ""
                    last_field_existed = True
                else:
                    # Field is missing - discard pending text (the delimiter)
                    # But keep non-delimiter leading text if nothing added yet
                    if not result_parts and pending_text and not self._is_pure_delimiter(pending_text):
                        result_parts.append(pending_text)
                    pending_text = ""
                    last_field_existed = False

        # Handle trailing text after the last field
        # Include it if the last field existed (we want closing parens, etc.)
        if pending_text and last_field_existed:
            result_parts.append(pending_text)

        return "".join(result_parts)

    def _extract_field(self, data: dict, field_path: str) -> Optional[str]:
        """
        Extract field value using dot notation path.

        Args:
            data: Dictionary to extract from
            field_path: Dot-separated path (e.g., "vulnerability.id")

        Returns:
            Field value as string, or None if not found/empty
        """
        value = FieldExtractor.extract(data, field_path, default=None)

        if value is None:
            return None

        # Convert to string and check if empty
        str_value = str(value).strip()
        return str_value if str_value else None

    def _is_pure_delimiter(self, text: str) -> bool:
        """
        Check if text is purely a delimiter (separator between fields).

        Pure delimiters are things like " - ", " | ", ":", ", " that only
        make sense between two values and should be dropped if a field is missing.

        This does NOT include text that contains words or meaningful content.

        Args:
            text: Text to check

        Returns:
            True if text is purely punctuation/whitespace delimiter
        """
        # Strip whitespace to check content
        stripped = text.strip()

        # Empty or whitespace-only is a delimiter
        if not stripped:
            return True

        # Check if it's just punctuation (no letters or digits)
        # This catches: " - ", " | ", ":", ", ", " -> ", etc.
        if re.match(r'^[\s\-|:,;/\\><=~*]+$', text):
            return True

        return False
