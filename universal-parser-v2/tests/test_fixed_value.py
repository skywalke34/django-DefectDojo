"""
Tests for Fixed Value feature.

This tests the fixed_value field that allows hardcoded constant values
to be assigned to fields without extracting from source data.

Use cases:
- Ggshield: severity="High", cwe=798 (always the same for secrets detection)
- Compliance parsers: fixed mitigation text
"""

import pytest
import warnings
from pydantic import ValidationError as PydanticValidationError
from app.models.yaml_config import FieldMapping, YAMLConfig
from app.services.normalizer import NormalizerService


# =============================================================================
# FieldMapping Model Tests - fixed_value validation
# =============================================================================

class TestFieldMappingFixedValue:
    """Test FieldMapping Pydantic model with fixed_value."""

    def test_fixed_value_string(self):
        """Test fixed_value with string constant."""
        mapping = FieldMapping(
            target_field="severity",
            data_type="string",
            fixed_value="High"
        )
        assert mapping.fixed_value == "High"
        assert mapping.source_field is None
        assert mapping.source_fields is None

    def test_fixed_value_integer(self):
        """Test fixed_value with integer constant."""
        mapping = FieldMapping(
            target_field="cwe",
            data_type="integer",
            fixed_value=798
        )
        assert mapping.fixed_value == 798

    def test_fixed_value_boolean(self):
        """Test fixed_value with boolean constant."""
        mapping = FieldMapping(
            target_field="verified",
            data_type="boolean",
            fixed_value=True
        )
        assert mapping.fixed_value is True

    def test_fixed_value_does_not_require_source_field(self):
        """Test that fixed_value doesn't require source_field or source_fields."""
        # This should not raise an error
        mapping = FieldMapping(
            target_field="severity",
            data_type="string",
            fixed_value="High"
        )
        assert mapping.fixed_value == "High"

    def test_fixed_value_with_source_field_warns(self):
        """Test that providing source_field with fixed_value warns."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            mapping = FieldMapping(
                source_field="some_field",
                target_field="severity",
                data_type="string",
                fixed_value="High"
            )
            # Check that a warning was issued
            assert len(w) == 1
            assert "source_field/source_fields are ignored" in str(w[0].message)
            # fixed_value should still be set
            assert mapping.fixed_value == "High"

    def test_fixed_value_with_source_fields_warns(self):
        """Test that providing source_fields with fixed_value warns."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            mapping = FieldMapping(
                source_fields=["field1", "field2"],
                target_field="severity",
                data_type="string",
                fixed_value="High"
            )
            # Check that a warning was issued
            assert len(w) == 1
            assert "source_field/source_fields are ignored" in str(w[0].message)

    def test_fixed_value_zero_is_valid(self):
        """Test that fixed_value=0 is a valid value (not treated as falsy)."""
        mapping = FieldMapping(
            target_field="line",
            data_type="integer",
            fixed_value=0
        )
        assert mapping.fixed_value == 0

    def test_fixed_value_empty_string_is_valid(self):
        """Test that fixed_value='' is valid (explicitly set empty)."""
        mapping = FieldMapping(
            target_field="mitigation",
            data_type="string",
            fixed_value=""
        )
        assert mapping.fixed_value == ""

    def test_fixed_value_none_requires_source_field(self):
        """Test that fixed_value=None (unset) requires source_field."""
        with pytest.raises(PydanticValidationError) as exc_info:
            FieldMapping(
                target_field="severity",
                data_type="string"
                # No fixed_value, no source_field
            )
        assert "Either 'source_field' or 'source_fields' is required" in str(exc_info.value)


# =============================================================================
# Normalizer Fixed Value Tests
# =============================================================================

class TestNormalizerFixedValue:
    """Test NormalizerService handling of fixed_value."""

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
                    "data_type": "string"
                },
                {
                    "target_field": "severity",
                    "data_type": "string",
                    "fixed_value": "High"
                }
            ]
        }

    def test_fixed_value_applied_to_all_findings(self, base_config):
        """Test that fixed_value is applied to every finding."""
        config = YAMLConfig(**base_config)
        service = NormalizerService(config)

        scan_data = b'''{"findings": [
            {"name": "Finding 1", "desc": "Description 1"},
            {"name": "Finding 2", "desc": "Description 2"},
            {"name": "Finding 3", "desc": "Description 3"}
        ]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 3
        # All findings should have severity="High"
        for finding in findings:
            assert finding["severity"] == "High"

    def test_fixed_value_ignores_source_data(self, base_config):
        """Test that fixed_value ignores any value in source data."""
        config = YAMLConfig(**base_config)
        service = NormalizerService(config)

        # Source data has severity="Low" but fixed_value="High"
        scan_data = b'''{"findings": [{
            "name": "Test Finding",
            "desc": "Test description",
            "severity": "Low"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        # fixed_value should override source data
        assert findings[0]["severity"] == "High"

    def test_fixed_value_integer(self, base_config):
        """Test fixed_value with integer for CWE."""
        base_config["field_mappings"].append({
            "target_field": "cwe",
            "data_type": "integer",
            "fixed_value": 798
        })
        config = YAMLConfig(**base_config)
        service = NormalizerService(config)

        scan_data = b'''{"findings": [{
            "name": "Hardcoded Credentials",
            "desc": "Found hardcoded credentials"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        assert findings[0]["cwe"] == 798

    def test_fixed_value_boolean(self, base_config):
        """Test fixed_value with boolean."""
        base_config["field_mappings"].append({
            "target_field": "verified",
            "data_type": "boolean",
            "fixed_value": True
        })
        config = YAMLConfig(**base_config)
        service = NormalizerService(config)

        scan_data = b'''{"findings": [{
            "name": "Test Finding",
            "desc": "Test description"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        assert findings[0]["verified"] is True


# =============================================================================
# End-to-End Tests - Ggshield Style
# =============================================================================

class TestGgshieldStyleConfig:
    """Test Ggshield-style config with multiple fixed values."""

    @pytest.fixture
    def ggshield_config(self):
        """Ggshield-style config with fixed severity and CWE."""
        return {
            "parser_name": "GgshieldStyle",
            "parser_version": "1.0",
            "tool_name": "Ggshield Style",
            "tool_type": "Ggshield_JSON",
            "file_format": "json",
            "json_root_path": "$.incidents[*]",
            "field_mappings": [
                {
                    "source_field": "match",
                    "target_field": "title",
                    "data_type": "string"
                },
                {
                    "source_field": "policy",
                    "target_field": "description",
                    "data_type": "string"
                },
                {
                    # Fixed severity - secrets are always High
                    "target_field": "severity",
                    "data_type": "string",
                    "fixed_value": "High"
                },
                {
                    # Fixed CWE - Use of Hard-coded Credentials
                    "target_field": "cwe",
                    "data_type": "integer",
                    "fixed_value": 798
                },
                {
                    # Fixed mitigation text
                    "target_field": "mitigation",
                    "data_type": "string",
                    "fixed_value": "Remove the hardcoded secret and use environment variables or a secrets manager."
                }
            ]
        }

    def test_ggshield_style_all_fixed_values(self, ggshield_config):
        """Test that all fixed values are applied correctly."""
        config = YAMLConfig(**ggshield_config)
        service = NormalizerService(config)

        scan_data = b'''{"incidents": [{
            "match": "AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE",
            "policy": "AWS Secret Key detected"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        finding = findings[0]
        assert finding["title"] == "AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE"
        assert finding["description"] == "AWS Secret Key detected"
        assert finding["severity"] == "High"
        assert finding["cwe"] == 798
        assert finding["mitigation"] == "Remove the hardcoded secret and use environment variables or a secrets manager."

    def test_ggshield_style_multiple_findings(self, ggshield_config):
        """Test multiple findings all get fixed values."""
        config = YAMLConfig(**ggshield_config)
        service = NormalizerService(config)

        scan_data = b'''{"incidents": [
            {"match": "Secret 1", "policy": "Policy 1"},
            {"match": "Secret 2", "policy": "Policy 2"},
            {"match": "Secret 3", "policy": "Policy 3"}
        ]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 3
        for finding in findings:
            assert finding["severity"] == "High"
            assert finding["cwe"] == 798
            assert "Remove the hardcoded secret" in finding["mitigation"]


# =============================================================================
# Edge Cases
# =============================================================================

class TestFixedValueEdgeCases:
    """Test edge cases for fixed_value."""

    def test_fixed_value_with_inactive_mapping(self):
        """Test that inactive mappings with fixed_value are skipped."""
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
                    "data_type": "string"
                },
                {
                    "target_field": "severity",
                    "data_type": "string",
                    "fixed_value": "High"
                },
                {
                    # Inactive mapping with fixed_value
                    "target_field": "cwe",
                    "data_type": "integer",
                    "fixed_value": 123,
                    "active": False
                }
            ]
        }
        config = YAMLConfig(**config_dict)
        service = NormalizerService(config)

        scan_data = b'''{"items": [{
            "name": "Test",
            "desc": "Test desc"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        assert "cwe" not in findings[0]  # Inactive mapping skipped

    def test_mixed_fixed_and_source_mappings(self):
        """Test config with mix of fixed values and source field mappings."""
        config_dict = {
            "parser_name": "MixedParser",
            "parser_version": "1.0",
            "tool_name": "Mixed",
            "tool_type": "Mixed_JSON",
            "file_format": "json",
            "json_root_path": "$.findings[*]",
            "field_mappings": [
                # Source field mapping
                {
                    "source_field": "name",
                    "target_field": "title",
                    "data_type": "string"
                },
                # Source field mapping
                {
                    "source_field": "desc",
                    "target_field": "description",
                    "data_type": "string"
                },
                # Fixed value
                {
                    "target_field": "severity",
                    "data_type": "string",
                    "fixed_value": "Medium"
                },
                # Source field mapping (optional field)
                {
                    "source_field": "cve_id",
                    "target_field": "cve",
                    "data_type": "string"
                },
                # Fixed value
                {
                    "target_field": "static_finding",
                    "data_type": "boolean",
                    "fixed_value": True
                }
            ]
        }
        config = YAMLConfig(**config_dict)
        service = NormalizerService(config)

        scan_data = b'''{"findings": [{
            "name": "Test Finding",
            "desc": "Test description",
            "cve_id": "CVE-2021-1234"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        finding = findings[0]
        # From source fields
        assert finding["title"] == "Test Finding"
        assert finding["description"] == "Test description"
        assert finding["cve"] == "CVE-2021-1234"
        # From fixed values
        assert finding["severity"] == "Medium"
        assert finding["static_finding"] is True
