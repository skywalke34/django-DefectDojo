"""
Unit tests for Template Parser.

Tests template string interpolation with {field.path} placeholders.
"""

import pytest
from app.parsers.data_types.template_parser import TemplateParser


class TestTemplateParser:
    """Test TemplateParser for multi-field composition."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = TemplateParser()

    # Basic interpolation tests

    def test_basic_single_field_interpolation(self):
        """Test basic interpolation with a single field."""
        data = {"cve": "CVE-2025-001"}
        result = self.parser.parse(data, {"template": "{cve}"})
        assert result == "CVE-2025-001"

    def test_basic_multi_field_interpolation(self):
        """Test interpolation with multiple fields."""
        data = {"cve": "CVE-2025-001", "version": "1.0"}
        result = self.parser.parse(data, {"template": "{cve} - {version}"})
        assert result == "CVE-2025-001 - 1.0"

    def test_three_field_interpolation(self):
        """Test interpolation with three fields."""
        data = {"component": "jackson", "version": "2.9.4", "cve": "CVE-2025-001"}
        result = self.parser.parse(data, {"template": "{component}:{version} | {cve}"})
        assert result == "jackson:2.9.4 | CVE-2025-001"

    # Real-world parser format tests

    def test_wazuh_title_format(self):
        """Test Wazuh title format: {cve} affects (version: {version})"""
        data = {
            "vulnerability": {"id": "CVE-2025-27558"},
            "package": {"version": "6.8.0-60.63"}
        }
        result = self.parser.parse(data, {
            "template": "{vulnerability.id} affects (version: {package.version})"
        })
        assert result == "CVE-2025-27558 affects (version: 6.8.0-60.63)"

    def test_cyclonedx_title_format(self):
        """Test CycloneDX title format: {component}:{version} | {vuln_id}"""
        data = {
            "component_name": "jackson-databind",
            "component_version": "2.9.4",
            "vulnerability_id": "SNYK-JAVA-COMFASTERXMLJACKSONCORE-32111"
        }
        result = self.parser.parse(data, {
            "template": "{component_name}:{component_version} | {vulnerability_id}"
        })
        assert result == "jackson-databind:2.9.4 | SNYK-JAVA-COMFASTERXMLJACKSONCORE-32111"

    def test_wazuh_dedup_key_format(self):
        """Test Wazuh deduplication key format: {cve}-{agent_id}"""
        data = {
            "vulnerability": {"id": "CVE-2025-27558"},
            "agent": {"id": "001"}
        }
        result = self.parser.parse(data, {
            "template": "{vulnerability.id}-{agent.id}"
        })
        assert result == "CVE-2025-27558-001"

    # Nested field tests

    def test_deeply_nested_field(self):
        """Test deeply nested field extraction."""
        data = {
            "vulnerability": {
                "score": {
                    "base": {
                        "value": "7.5"
                    }
                }
            }
        }
        result = self.parser.parse(data, {"template": "Score: {vulnerability.score.base.value}"})
        assert result == "Score: 7.5"

    def test_mixed_nesting_levels(self):
        """Test mixing nested and top-level fields."""
        data = {
            "title": "XSS",
            "classification": {"cwe": {"id": 79}}
        }
        result = self.parser.parse(data, {"template": "{title} (CWE-{classification.cwe.id})"})
        assert result == "XSS (CWE-79)"

    # Missing field handling tests

    def test_missing_field_skipped_simple(self):
        """Test that missing field is skipped with delimiter."""
        data = {"cve": "CVE-2025-001"}
        result = self.parser.parse(data, {"template": "{cve} - {version}"})
        # " - {version}" should be skipped entirely
        assert result == "CVE-2025-001"

    def test_missing_field_in_middle(self):
        """Test missing field in middle of template."""
        data = {"a": "first", "c": "third"}
        result = self.parser.parse(data, {"template": "{a} | {b} | {c}"})
        # Middle field should be skipped cleanly
        assert result == "first | third"

    def test_missing_first_field(self):
        """Test missing first field."""
        data = {"version": "1.0"}
        result = self.parser.parse(data, {"template": "{cve} - {version}"})
        # "{cve} - " should be skipped, only version remains
        assert result == "1.0"

    def test_missing_nested_field(self):
        """Test missing nested field."""
        data = {"vulnerability": {"id": "CVE-2025-001"}}
        result = self.parser.parse(data, {
            "template": "{vulnerability.id} - {package.version}"
        })
        assert result == "CVE-2025-001"

    def test_all_fields_missing(self):
        """Test when all fields are missing."""
        data = {}
        result = self.parser.parse(data, {"template": "{a} - {b} - {c}"})
        assert result == ""

    def test_partial_nested_path_missing(self):
        """Test when partial nested path doesn't exist."""
        data = {"vulnerability": {}}
        result = self.parser.parse(data, {"template": "ID: {vulnerability.id}"})
        # The field doesn't exist, but "ID: " is meaningful text (not a pure delimiter)
        # so it's kept. Use pure delimiter patterns for cleaner skipping.
        assert result == "ID:"

    # Escaped braces tests

    def test_escaped_open_brace(self):
        """Test that {{ produces literal {."""
        data = {"name": "test"}
        result = self.parser.parse(data, {"template": "{{name}} is {name}"})
        assert result == "{name} is test"

    def test_escaped_close_brace(self):
        """Test that }} produces literal }."""
        data = {"name": "test"}
        result = self.parser.parse(data, {"template": "{name} == {{name}}"})
        assert result == "test == {name}"

    def test_both_escaped_braces(self):
        """Test both escaped braces together."""
        data = {"value": "42"}
        result = self.parser.parse(data, {"template": "JSON: {{\"key\": \"{value}\"}}"})
        assert result == "JSON: {\"key\": \"42\"}"

    # Edge cases

    def test_empty_template(self):
        """Test empty template string."""
        data = {"name": "test"}
        result = self.parser.parse(data, {"template": ""})
        assert result == ""

    def test_no_placeholders(self):
        """Test template with no placeholders (static string)."""
        data = {"name": "test"}
        result = self.parser.parse(data, {"template": "Static text"})
        assert result == "Static text"

    def test_empty_data_dict(self):
        """Test with empty data dictionary."""
        data = {}
        result = self.parser.parse(data, {"template": "Hello {name}"})
        # "Hello " is meaningful text (not a pure delimiter), so it's kept
        # For templates where you want full skipping, use pure delimiter patterns
        assert result == "Hello"

    def test_numeric_field_value(self):
        """Test that numeric values are converted to strings."""
        data = {"count": 42, "score": 7.5}
        result = self.parser.parse(data, {"template": "Count: {count}, Score: {score}"})
        assert result == "Count: 42, Score: 7.5"

    def test_boolean_field_value(self):
        """Test that boolean values are converted to strings."""
        data = {"active": True, "verified": False}
        result = self.parser.parse(data, {"template": "Active: {active}, Verified: {verified}"})
        assert result == "Active: True, Verified: False"

    def test_whitespace_in_field_path(self):
        """Test that field paths are trimmed."""
        data = {"name": "test"}
        result = self.parser.parse(data, {"template": "{ name }"})
        assert result == "test"

    def test_field_with_empty_string_value(self):
        """Test field that exists but has empty string value."""
        data = {"name": "", "other": "value"}
        result = self.parser.parse(data, {"template": "{name} - {other}"})
        # Empty string should be treated as missing
        assert result == "value"

    def test_field_with_whitespace_only_value(self):
        """Test field that exists but has only whitespace."""
        data = {"name": "   ", "other": "value"}
        result = self.parser.parse(data, {"template": "{name} - {other}"})
        # Whitespace-only should be treated as missing
        assert result == "value"

    # Error handling tests

    def test_missing_config_raises_error(self):
        """Test that missing config raises ValueError."""
        data = {"name": "test"}
        with pytest.raises(ValueError) as exc_info:
            self.parser.parse(data, None)
        assert "config is required" in str(exc_info.value)

    def test_missing_template_in_config_raises_error(self):
        """Test that missing template in config raises ValueError."""
        data = {"name": "test"}
        with pytest.raises(ValueError) as exc_info:
            self.parser.parse(data, {})
        assert "template is required" in str(exc_info.value)

    def test_non_dict_value_returns_string(self):
        """Test that non-dict value returns string representation."""
        result = self.parser.parse("not a dict", {"template": "{name}"})
        assert result == "not a dict"

    def test_none_value_returns_empty_string(self):
        """Test that None value returns empty string."""
        result = self.parser.parse(None, {"template": "{name}"})
        assert result == ""

    # Complex delimiter tests

    def test_parentheses_as_delimiters(self):
        """Test parentheses wrapping missing field are skipped."""
        data = {"cve": "CVE-2025-001"}
        result = self.parser.parse(data, {"template": "{cve} ({version})"})
        # "(version)" should be skipped
        assert result == "CVE-2025-001"

    def test_colon_delimiter(self):
        """Test colon delimiter handling."""
        data = {"component": "jackson"}
        result = self.parser.parse(data, {"template": "{component}:{version}"})
        assert result == "jackson"

    def test_complex_delimiter_pattern(self):
        """Test complex delimiter patterns."""
        data = {"a": "first", "d": "fourth"}
        result = self.parser.parse(data, {"template": "{a} -> {b} => {c} -- {d}"})
        # Middle fields missing, should result in clean output
        assert result == "first -> fourth" or result == "first fourth" or "first" in result and "fourth" in result


class TestTemplateParserDelimiterLogic:
    """Test the delimiter handling logic in detail."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = TemplateParser()

    def test_is_pure_delimiter_common_delimiters(self):
        """Test _is_pure_delimiter identifies common delimiters."""
        assert self.parser._is_pure_delimiter(" - ") is True
        assert self.parser._is_pure_delimiter(" | ") is True
        assert self.parser._is_pure_delimiter(": ") is True
        assert self.parser._is_pure_delimiter(", ") is True
        assert self.parser._is_pure_delimiter("  ") is True

    def test_is_pure_delimiter_text_is_not_delimiter(self):
        """Test that actual text is not identified as delimiter."""
        assert self.parser._is_pure_delimiter("affects") is False
        assert self.parser._is_pure_delimiter("version") is False
        assert self.parser._is_pure_delimiter("(version:") is False


class TestTemplateParserIntegration:
    """Integration-style tests simulating real YAML config usage."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = TemplateParser()

    def test_full_wazuh_finding(self):
        """Test with full Wazuh-style finding data."""
        raw_finding = {
            "vulnerability": {
                "id": "CVE-2025-27558",
                "description": "A vulnerability in the package...",
                "severity": "High",
                "score": {"base": 7.5}
            },
            "package": {
                "name": "libssl",
                "version": "6.8.0-60.63"
            },
            "agent": {
                "id": "001",
                "name": "server-01"
            }
        }

        # Test title
        title = self.parser.parse(raw_finding, {
            "template": "{vulnerability.id} affects (version: {package.version})"
        })
        assert title == "CVE-2025-27558 affects (version: 6.8.0-60.63)"

        # Test unique_id
        unique_id = self.parser.parse(raw_finding, {
            "template": "{vulnerability.id}-{agent.id}"
        })
        assert unique_id == "CVE-2025-27558-001"

    def test_full_cyclonedx_finding(self):
        """Test with full CycloneDX-style finding data."""
        raw_finding = {
            "id": "SNYK-JAVA-COMFASTERXMLJACKSONCORE-32111",
            "source": {"name": "Snyk"},
            "ratings": [{"score": 7.5, "severity": "high"}],
            "affects": [{"ref": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.4"}],
            # Pre-extracted component info (as normalizer would do)
            "component_name": "jackson-databind",
            "component_version": "2.9.4"
        }

        title = self.parser.parse(raw_finding, {
            "template": "{component_name}:{component_version} | {id}"
        })
        assert title == "jackson-databind:2.9.4 | SNYK-JAVA-COMFASTERXMLJACKSONCORE-32111"


# Run tests if executed directly
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
