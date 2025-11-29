"""
Tests for Conditional Append feature.

This tests the append_if_present field that allows building composite
field values with optional sections based on field existence.

Use cases:
- Acunetix: Description + conditional target, fix version
- Trivy: Description + conditional fixed version info
- Wazuh: Description + conditional agent info
"""

import pytest
from pydantic import ValidationError as PydanticValidationError
from app.models.yaml_config import FieldMapping, YAMLConfig, ConditionalAppend
from app.services.normalizer import NormalizerService


# =============================================================================
# ConditionalAppend Model Tests
# =============================================================================

class TestConditionalAppendModel:
    """Test ConditionalAppend Pydantic model."""

    def test_conditional_append_valid(self):
        """Test valid ConditionalAppend configuration."""
        append = ConditionalAppend(
            source_field="target",
            prefix="\n**Target:** "
        )
        assert append.source_field == "target"
        assert append.prefix == "\n**Target:** "

    def test_conditional_append_requires_source_field(self):
        """Test that source_field is required."""
        with pytest.raises(PydanticValidationError):
            ConditionalAppend(prefix="\n**Target:** ")

    def test_conditional_append_requires_prefix(self):
        """Test that prefix is required."""
        with pytest.raises(PydanticValidationError):
            ConditionalAppend(source_field="target")

    def test_conditional_append_empty_prefix_valid(self):
        """Test that empty prefix is valid (just appends value)."""
        append = ConditionalAppend(
            source_field="target",
            prefix=""
        )
        assert append.prefix == ""


# =============================================================================
# FieldMapping with append_if_present Tests
# =============================================================================

class TestFieldMappingAppendIfPresent:
    """Test FieldMapping with append_if_present configuration."""

    def test_append_if_present_single_rule(self):
        """Test append_if_present with single rule."""
        mapping = FieldMapping(
            source_field="description",
            target_field="description",
            data_type="string",
            append_if_present=[
                {"source_field": "target", "prefix": "\n**Target:** "}
            ]
        )
        assert len(mapping.append_if_present) == 1
        assert mapping.append_if_present[0].source_field == "target"

    def test_append_if_present_multiple_rules(self):
        """Test append_if_present with multiple rules."""
        mapping = FieldMapping(
            source_field="description",
            target_field="description",
            data_type="string",
            append_if_present=[
                {"source_field": "target", "prefix": "\n**Target:** "},
                {"source_field": "fix_version", "prefix": "\n**Fixed in:** "},
                {"source_field": "cvss_score", "prefix": "\n**CVSS:** "}
            ]
        )
        assert len(mapping.append_if_present) == 3

    def test_append_if_present_with_nested_source(self):
        """Test append_if_present with nested field path."""
        mapping = FieldMapping(
            source_field="description",
            target_field="description",
            data_type="string",
            append_if_present=[
                {"source_field": "metadata.version", "prefix": "\n**Version:** "}
            ]
        )
        assert mapping.append_if_present[0].source_field == "metadata.version"


# =============================================================================
# Normalizer Conditional Append Tests
# =============================================================================

class TestNormalizerConditionalAppend:
    """Test NormalizerService handling of append_if_present."""

    @pytest.fixture
    def base_config(self):
        """Base YAML config for testing."""
        return {
            "parser_name": "TestParser",
            "parser_version": "1.0",
            "tool_name": "Test Tool",
            "tool_type": "Test_Tool_JSON",
            "file_format": "json",
            "json_root_path": "$.findings[*]",
            "field_mappings": [
                {
                    "source_field": "name",
                    "target_field": "title",
                    "data_type": "string"
                },
                {
                    "source_field": "desc",
                    "target_field": "description",
                    "data_type": "string",
                    "append_if_present": [
                        {"source_field": "target", "prefix": "\n**Target:** "},
                        {"source_field": "fix_version", "prefix": "\n**Fixed in:** "}
                    ]
                },
                {
                    "source_field": "level",
                    "target_field": "severity",
                    "data_type": "severity",
                    "severity_mapping": {
                        "high": "High",
                        "medium": "Medium",
                        "low": "Low"
                    }
                }
            ]
        }

    def test_append_single_field_present(self, base_config):
        """Test appending when one optional field is present."""
        config = YAMLConfig(**base_config)
        service = NormalizerService(config)

        scan_data = b'''{"findings": [{
            "name": "SQL Injection",
            "desc": "A SQL injection vulnerability was found",
            "target": "/api/users",
            "level": "high"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        expected = "A SQL injection vulnerability was found\n**Target:** /api/users"
        assert findings[0]["description"] == expected

    def test_append_multiple_fields_present(self, base_config):
        """Test appending when multiple optional fields are present."""
        config = YAMLConfig(**base_config)
        service = NormalizerService(config)

        scan_data = b'''{"findings": [{
            "name": "SQL Injection",
            "desc": "A SQL injection vulnerability was found",
            "target": "/api/users",
            "fix_version": "2.0.1",
            "level": "high"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        expected = "A SQL injection vulnerability was found\n**Target:** /api/users\n**Fixed in:** 2.0.1"
        assert findings[0]["description"] == expected

    def test_append_no_optional_fields_present(self, base_config):
        """Test when no optional fields are present - just base value."""
        config = YAMLConfig(**base_config)
        service = NormalizerService(config)

        scan_data = b'''{"findings": [{
            "name": "SQL Injection",
            "desc": "A SQL injection vulnerability was found",
            "level": "high"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        assert findings[0]["description"] == "A SQL injection vulnerability was found"

    def test_append_skips_null_field(self, base_config):
        """Test that null values are skipped."""
        config = YAMLConfig(**base_config)
        service = NormalizerService(config)

        scan_data = b'''{"findings": [{
            "name": "SQL Injection",
            "desc": "A SQL injection vulnerability was found",
            "target": null,
            "fix_version": "2.0.1",
            "level": "high"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        # target is null, so only fix_version appended
        expected = "A SQL injection vulnerability was found\n**Fixed in:** 2.0.1"
        assert findings[0]["description"] == expected

    def test_append_skips_empty_string(self, base_config):
        """Test that empty string values are skipped."""
        config = YAMLConfig(**base_config)
        service = NormalizerService(config)

        scan_data = b'''{"findings": [{
            "name": "SQL Injection",
            "desc": "A SQL injection vulnerability was found",
            "target": "",
            "fix_version": "2.0.1",
            "level": "high"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        # target is empty, so only fix_version appended
        expected = "A SQL injection vulnerability was found\n**Fixed in:** 2.0.1"
        assert findings[0]["description"] == expected

    def test_append_skips_whitespace_only(self, base_config):
        """Test that whitespace-only values are skipped."""
        config = YAMLConfig(**base_config)
        service = NormalizerService(config)

        scan_data = b'''{"findings": [{
            "name": "SQL Injection",
            "desc": "A SQL injection vulnerability was found",
            "target": "   ",
            "fix_version": "2.0.1",
            "level": "high"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        expected = "A SQL injection vulnerability was found\n**Fixed in:** 2.0.1"
        assert findings[0]["description"] == expected


# =============================================================================
# Advanced Conditional Append Tests
# =============================================================================

class TestConditionalAppendAdvanced:
    """Advanced conditional append test scenarios."""

    @pytest.fixture
    def advanced_config(self):
        """Config with nested fields and multiple append scenarios."""
        return {
            "parser_name": "AdvancedParser",
            "parser_version": "1.0",
            "tool_name": "Advanced Tool",
            "tool_type": "Advanced_JSON",
            "file_format": "json",
            "json_root_path": "$.vulnerabilities[*]",
            "field_mappings": [
                {
                    "source_field": "title",
                    "target_field": "title",
                    "data_type": "string"
                },
                {
                    "source_field": "summary",
                    "target_field": "description",
                    "data_type": "string",
                    "append_if_present": [
                        {"source_field": "metadata.endpoint", "prefix": "\n\n**Endpoint:** "},
                        {"source_field": "metadata.method", "prefix": "\n**Method:** "},
                        {"source_field": "fix.version", "prefix": "\n\n**Fixed in version:** "},
                        {"source_field": "references", "prefix": "\n\n**References:**\n"}
                    ]
                },
                {
                    "source_field": "severity",
                    "target_field": "severity",
                    "data_type": "severity",
                    "severity_mapping": {
                        "critical": "Critical",
                        "high": "High",
                        "medium": "Medium",
                        "low": "Low"
                    }
                }
            ]
        }

    def test_append_with_nested_fields(self, advanced_config):
        """Test appending values from nested field paths."""
        config = YAMLConfig(**advanced_config)
        service = NormalizerService(config)

        scan_data = b'''{"vulnerabilities": [{
            "title": "XSS Vulnerability",
            "summary": "Cross-site scripting detected",
            "metadata": {
                "endpoint": "/search",
                "method": "GET"
            },
            "severity": "high"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        desc = findings[0]["description"]
        assert "Cross-site scripting detected" in desc
        assert "**Endpoint:** /search" in desc
        assert "**Method:** GET" in desc

    def test_append_with_numeric_value(self):
        """Test appending numeric values (converted to string)."""
        config_dict = {
            "parser_name": "TestParser",
            "parser_version": "1.0",
            "tool_name": "Test",
            "tool_type": "Test_JSON",
            "file_format": "json",
            "json_root_path": "$.items[*]",
            "field_mappings": [
                {
                    "source_field": "name",
                    "target_field": "title",
                    "data_type": "string"
                },
                {
                    "source_field": "desc",
                    "target_field": "description",
                    "data_type": "string",
                    "append_if_present": [
                        {"source_field": "cvss_score", "prefix": "\n**CVSS Score:** "},
                        {"source_field": "port", "prefix": "\n**Port:** "}
                    ]
                },
                {
                    "source_field": "severity",
                    "target_field": "severity",
                    "data_type": "severity",
                    "severity_mapping": {"high": "High"}
                }
            ]
        }
        config = YAMLConfig(**config_dict)
        service = NormalizerService(config)

        scan_data = b'''{"items": [{
            "name": "Open Port",
            "desc": "Port is open",
            "cvss_score": 7.5,
            "port": 443,
            "severity": "high"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        desc = findings[0]["description"]
        assert "**CVSS Score:** 7.5" in desc
        assert "**Port:** 443" in desc

    def test_append_preserves_order(self):
        """Test that appends are applied in defined order."""
        config_dict = {
            "parser_name": "OrderTest",
            "parser_version": "1.0",
            "tool_name": "Order Test",
            "tool_type": "Order_JSON",
            "file_format": "json",
            "json_root_path": "$.items[*]",
            "field_mappings": [
                {
                    "source_field": "name",
                    "target_field": "title",
                    "data_type": "string"
                },
                {
                    "source_field": "base",
                    "target_field": "description",
                    "data_type": "string",
                    "append_if_present": [
                        {"source_field": "first", "prefix": "[1]"},
                        {"source_field": "second", "prefix": "[2]"},
                        {"source_field": "third", "prefix": "[3]"}
                    ]
                },
                {
                    "source_field": "severity",
                    "target_field": "severity",
                    "data_type": "severity",
                    "severity_mapping": {"high": "High"}
                }
            ]
        }
        config = YAMLConfig(**config_dict)
        service = NormalizerService(config)

        scan_data = b'''{"items": [{
            "name": "Test",
            "base": "BASE",
            "first": "A",
            "second": "B",
            "third": "C",
            "severity": "high"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        # Should be in order: BASE[1]A[2]B[3]C
        assert findings[0]["description"] == "BASE[1]A[2]B[3]C"


# =============================================================================
# Edge Cases
# =============================================================================

class TestConditionalAppendEdgeCases:
    """Edge cases for conditional append."""

    def test_append_with_empty_prefix(self):
        """Test append with empty prefix (just concatenates value)."""
        config_dict = {
            "parser_name": "EmptyPrefix",
            "parser_version": "1.0",
            "tool_name": "Test",
            "tool_type": "Test_JSON",
            "file_format": "json",
            "json_root_path": "$.items[*]",
            "field_mappings": [
                {
                    "source_field": "name",
                    "target_field": "title",
                    "data_type": "string"
                },
                {
                    "source_field": "part1",
                    "target_field": "description",
                    "data_type": "string",
                    "append_if_present": [
                        {"source_field": "part2", "prefix": ""},
                        {"source_field": "part3", "prefix": ""}
                    ]
                },
                {
                    "source_field": "severity",
                    "target_field": "severity",
                    "data_type": "severity",
                    "severity_mapping": {"high": "High"}
                }
            ]
        }
        config = YAMLConfig(**config_dict)
        service = NormalizerService(config)

        scan_data = b'''{"items": [{
            "name": "Test",
            "part1": "Hello",
            "part2": "World",
            "part3": "!",
            "severity": "high"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        assert findings[0]["description"] == "HelloWorld!"

    def test_append_zero_is_valid(self):
        """Test that 0 is appended (not treated as falsy)."""
        config_dict = {
            "parser_name": "ZeroTest",
            "parser_version": "1.0",
            "tool_name": "Test",
            "tool_type": "Test_JSON",
            "file_format": "json",
            "json_root_path": "$.items[*]",
            "field_mappings": [
                {
                    "source_field": "name",
                    "target_field": "title",
                    "data_type": "string"
                },
                {
                    "source_field": "desc",
                    "target_field": "description",
                    "data_type": "string",
                    "append_if_present": [
                        {"source_field": "count", "prefix": "\nCount: "}
                    ]
                },
                {
                    "source_field": "severity",
                    "target_field": "severity",
                    "data_type": "severity",
                    "severity_mapping": {"high": "High"}
                }
            ]
        }
        config = YAMLConfig(**config_dict)
        service = NormalizerService(config)

        scan_data = b'''{"items": [{
            "name": "Test",
            "desc": "Description",
            "count": 0,
            "severity": "high"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        assert findings[0]["description"] == "Description\nCount: 0"

    def test_append_false_boolean_is_valid(self):
        """Test that false boolean is appended."""
        config_dict = {
            "parser_name": "BoolTest",
            "parser_version": "1.0",
            "tool_name": "Test",
            "tool_type": "Test_JSON",
            "file_format": "json",
            "json_root_path": "$.items[*]",
            "field_mappings": [
                {
                    "source_field": "name",
                    "target_field": "title",
                    "data_type": "string"
                },
                {
                    "source_field": "desc",
                    "target_field": "description",
                    "data_type": "string",
                    "append_if_present": [
                        {"source_field": "exploitable", "prefix": "\nExploitable: "}
                    ]
                },
                {
                    "source_field": "severity",
                    "target_field": "severity",
                    "data_type": "severity",
                    "severity_mapping": {"high": "High"}
                }
            ]
        }
        config = YAMLConfig(**config_dict)
        service = NormalizerService(config)

        scan_data = b'''{"items": [{
            "name": "Test",
            "desc": "Description",
            "exploitable": false,
            "severity": "high"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        assert findings[0]["description"] == "Description\nExploitable: False"

    def test_no_append_if_present_returns_original(self):
        """Test that without append_if_present, value is unchanged."""
        config_dict = {
            "parser_name": "NoAppend",
            "parser_version": "1.0",
            "tool_name": "Test",
            "tool_type": "Test_JSON",
            "file_format": "json",
            "json_root_path": "$.items[*]",
            "field_mappings": [
                {
                    "source_field": "name",
                    "target_field": "title",
                    "data_type": "string"
                },
                {
                    "source_field": "desc",
                    "target_field": "description",
                    "data_type": "string"
                    # No append_if_present
                },
                {
                    "source_field": "severity",
                    "target_field": "severity",
                    "data_type": "severity",
                    "severity_mapping": {"high": "High"}
                }
            ]
        }
        config = YAMLConfig(**config_dict)
        service = NormalizerService(config)

        scan_data = b'''{"items": [{
            "name": "Test",
            "desc": "Original description",
            "extra_field": "This should not appear",
            "severity": "high"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        assert findings[0]["description"] == "Original description"
