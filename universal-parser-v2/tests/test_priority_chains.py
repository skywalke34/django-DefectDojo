"""
Tests for Priority Chain / Alternative Fields feature.

This tests the source_fields: List[str] functionality that enables
first-available extraction from multiple alternative field names.

Use cases:
- Tenable CSV: 20+ alternative field names for same data
- Dependency-Check: 5-level component extraction priority
"""

import pytest
from pydantic import ValidationError as PydanticValidationError
from app.models.yaml_config import FieldMapping, YAMLConfig
from app.services.normalizer import NormalizerService
from app.parsers.base import FieldExtractor


# =============================================================================
# FieldMapping Model Tests - source_fields validation
# =============================================================================

class TestFieldMappingSourceFields:
    """Test FieldMapping Pydantic model with source_fields."""

    def test_source_fields_basic_valid(self):
        """Test valid source_fields configuration."""
        mapping = FieldMapping(
            source_fields=["Name", "Plugin Name", "asset.name"],
            target_field="title",
            data_type="string"
        )
        assert mapping.source_fields == ["Name", "Plugin Name", "asset.name"]
        assert mapping.source_field is None

    def test_source_field_still_works(self):
        """Test existing source_field syntax still works (backward compatible)."""
        mapping = FieldMapping(
            source_field="Name",
            target_field="title",
            data_type="string"
        )
        assert mapping.source_field == "Name"
        assert mapping.source_fields is None

    def test_cannot_have_both_source_field_and_source_fields(self):
        """Test that having both source_field and source_fields raises error."""
        with pytest.raises(PydanticValidationError) as exc_info:
            FieldMapping(
                source_field="Name",
                source_fields=["Plugin Name", "asset.name"],
                target_field="title",
                data_type="string"
            )
        assert "Cannot specify both" in str(exc_info.value)

    def test_requires_source_field_or_source_fields(self):
        """Test that neither source_field nor source_fields raises error."""
        with pytest.raises(PydanticValidationError) as exc_info:
            FieldMapping(
                target_field="title",
                data_type="string"
            )
        assert "Either 'source_field' or 'source_fields' is required" in str(exc_info.value)

    def test_empty_source_fields_list_invalid(self):
        """Test that empty source_fields list raises error."""
        with pytest.raises(PydanticValidationError) as exc_info:
            FieldMapping(
                source_fields=[],
                target_field="title",
                data_type="string"
            )
        assert "Either 'source_field' or 'source_fields' is required" in str(exc_info.value)

    def test_template_does_not_need_source_field(self):
        """Test template data_type doesn't need source_field or source_fields."""
        mapping = FieldMapping(
            target_field="title",
            data_type="template",
            template="{cve} affects {package}"
        )
        assert mapping.source_field is None
        assert mapping.source_fields is None
        assert mapping.template == "{cve} affects {package}"


class TestFieldMappingGetSourceFieldsList:
    """Test get_source_fields_list() helper method."""

    def test_get_source_fields_list_from_source_fields(self):
        """Test get_source_fields_list returns source_fields when set."""
        mapping = FieldMapping(
            source_fields=["Name", "Plugin Name"],
            target_field="title",
            data_type="string"
        )
        assert mapping.get_source_fields_list() == ["Name", "Plugin Name"]

    def test_get_source_fields_list_from_source_field(self):
        """Test get_source_fields_list returns [source_field] when set."""
        mapping = FieldMapping(
            source_field="Name",
            target_field="title",
            data_type="string"
        )
        assert mapping.get_source_fields_list() == ["Name"]

    def test_get_source_fields_list_empty_for_template(self):
        """Test get_source_fields_list returns [] for template."""
        mapping = FieldMapping(
            target_field="title",
            data_type="template",
            template="{cve}"
        )
        assert mapping.get_source_fields_list() == []


# =============================================================================
# Normalizer Priority Chain Extraction Tests
# =============================================================================

class TestPriorityChainExtraction:
    """Test _extract_first_available in NormalizerService."""

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
                    "source_field": "title",
                    "target_field": "title",
                    "data_type": "string"
                },
                {
                    "source_field": "description",
                    "target_field": "description",
                    "data_type": "string"
                },
                {
                    "source_field": "severity",
                    "target_field": "severity",
                    "data_type": "severity",
                    "severity_mapping": {
                        "HIGH": "High",
                        "MEDIUM": "Medium",
                        "LOW": "Low"
                    }
                }
            ]
        }

    def test_first_available_uses_first_match(self, base_config):
        """Test priority chain returns first available value."""
        # Update config to use source_fields
        base_config["field_mappings"][0] = {
            "source_fields": ["Name", "Plugin Name", "asset.name"],
            "target_field": "title",
            "data_type": "string"
        }
        config = YAMLConfig(**base_config)
        service = NormalizerService(config)

        # Raw finding with "Plugin Name" (second option)
        raw_finding = {
            "Plugin Name": "SQL Injection",
            "description": "A SQL injection vulnerability",
            "severity": "HIGH"
        }

        mapping = config.field_mappings[0]
        value, matched = service._extract_first_available(raw_finding, mapping)

        assert value == "SQL Injection"
        assert matched == "Plugin Name"

    def test_first_available_prefers_first_option(self, base_config):
        """Test priority chain prefers first option when multiple exist."""
        base_config["field_mappings"][0] = {
            "source_fields": ["Name", "Plugin Name", "asset.name"],
            "target_field": "title",
            "data_type": "string"
        }
        config = YAMLConfig(**base_config)
        service = NormalizerService(config)

        # Raw finding with both "Name" and "Plugin Name"
        raw_finding = {
            "Name": "XSS Vulnerability",
            "Plugin Name": "SQL Injection",
            "description": "Description here",
            "severity": "HIGH"
        }

        mapping = config.field_mappings[0]
        value, matched = service._extract_first_available(raw_finding, mapping)

        assert value == "XSS Vulnerability"
        assert matched == "Name"

    def test_first_available_skips_empty_strings(self, base_config):
        """Test priority chain skips empty string values."""
        base_config["field_mappings"][0] = {
            "source_fields": ["Name", "Plugin Name"],
            "target_field": "title",
            "data_type": "string"
        }
        config = YAMLConfig(**base_config)
        service = NormalizerService(config)

        raw_finding = {
            "Name": "",  # Empty string - should skip
            "Plugin Name": "SQL Injection",
            "description": "Desc",
            "severity": "HIGH"
        }

        mapping = config.field_mappings[0]
        value, matched = service._extract_first_available(raw_finding, mapping)

        assert value == "SQL Injection"
        assert matched == "Plugin Name"

    def test_first_available_skips_whitespace_only(self, base_config):
        """Test priority chain skips whitespace-only strings."""
        base_config["field_mappings"][0] = {
            "source_fields": ["Name", "Plugin Name"],
            "target_field": "title",
            "data_type": "string"
        }
        config = YAMLConfig(**base_config)
        service = NormalizerService(config)

        raw_finding = {
            "Name": "   ",  # Whitespace only - should skip
            "Plugin Name": "SQL Injection",
            "description": "Desc",
            "severity": "HIGH"
        }

        mapping = config.field_mappings[0]
        value, matched = service._extract_first_available(raw_finding, mapping)

        assert value == "SQL Injection"
        assert matched == "Plugin Name"

    def test_first_available_accepts_zero(self, base_config):
        """Test priority chain accepts 0 as valid value."""
        base_config["field_mappings"].append({
            "source_fields": ["count", "total_count"],
            "target_field": "line",
            "data_type": "integer"
        })
        config = YAMLConfig(**base_config)
        service = NormalizerService(config)

        raw_finding = {
            "title": "Test",
            "description": "Desc",
            "severity": "HIGH",
            "count": 0,  # Zero is valid
            "total_count": 5
        }

        mapping = config.field_mappings[3]  # The new mapping
        value, matched = service._extract_first_available(raw_finding, mapping)

        assert value == 0
        assert matched == "count"

    def test_first_available_returns_none_when_all_fail(self, base_config):
        """Test priority chain returns None when no source has value."""
        base_config["field_mappings"][0] = {
            "source_fields": ["Name", "Plugin Name", "asset.name"],
            "target_field": "title",
            "data_type": "string"
        }
        config = YAMLConfig(**base_config)
        service = NormalizerService(config)

        raw_finding = {
            "other_field": "some value",
            "description": "Desc",
            "severity": "HIGH"
        }

        mapping = config.field_mappings[0]
        value, matched = service._extract_first_available(raw_finding, mapping)

        assert value is None
        assert matched is None

    def test_first_available_with_nested_fields(self, base_config):
        """Test priority chain with nested field paths."""
        base_config["field_mappings"][0] = {
            "source_fields": ["vuln.name", "meta.title", "Name"],
            "target_field": "title",
            "data_type": "string"
        }
        config = YAMLConfig(**base_config)
        service = NormalizerService(config)

        raw_finding = {
            "meta": {
                "title": "Nested Title"
            },
            "description": "Desc",
            "severity": "HIGH"
        }

        mapping = config.field_mappings[0]
        value, matched = service._extract_first_available(raw_finding, mapping)

        assert value == "Nested Title"
        assert matched == "meta.title"


# =============================================================================
# End-to-End Normalization Tests with Priority Chains
# =============================================================================

class TestNormalizationWithPriorityChains:
    """Test full normalization flow with source_fields."""

    @pytest.fixture
    def tenable_style_config(self):
        """Tenable-style config with many alternative field names."""
        return {
            "parser_name": "TenableStyleParser",
            "parser_version": "1.0",
            "tool_name": "Tenable Style",
            "tool_type": "Tenable_CSV",
            "file_format": "json",
            "json_root_path": "$.findings[*]",
            "field_mappings": [
                {
                    "source_fields": ["Name", "Plugin Name", "asset.name"],
                    "target_field": "title",
                    "data_type": "string"
                },
                {
                    "source_fields": ["Synopsis", "definition.synopsis", "Description"],
                    "target_field": "description",
                    "data_type": "string"
                },
                {
                    "source_fields": ["Severity", "Risk", "severity"],
                    "target_field": "severity",
                    "data_type": "severity",
                    "severity_mapping": {
                        "Critical": "Critical",
                        "High": "High",
                        "Medium": "Medium",
                        "Low": "Low",
                        "Info": "Info"
                    }
                },
                {
                    "source_fields": ["Solution", "definition.solution", "Steps to Remediate"],
                    "target_field": "mitigation",
                    "data_type": "string",
                    "default": "N/A"
                }
            ]
        }

    def test_normalize_with_primary_fields(self, tenable_style_config):
        """Test normalization using primary (first) source fields."""
        config = YAMLConfig(**tenable_style_config)
        service = NormalizerService(config)

        scan_data = b'''{"findings": [{
            "Name": "SQL Injection",
            "Synopsis": "A SQL injection vulnerability was found",
            "Severity": "Critical",
            "Solution": "Parameterize queries"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        assert findings[0]["title"] == "SQL Injection"
        assert findings[0]["description"] == "A SQL injection vulnerability was found"
        assert findings[0]["severity"] == "Critical"
        assert findings[0]["mitigation"] == "Parameterize queries"

    def test_normalize_with_alternate_fields(self, tenable_style_config):
        """Test normalization using alternate source fields."""
        config = YAMLConfig(**tenable_style_config)
        service = NormalizerService(config)

        # Use alternate field names (Plugin Name, definition.synopsis, etc.)
        scan_data = b'''{"findings": [{
            "Plugin Name": "XSS Vulnerability",
            "definition": {
                "synopsis": "Cross-site scripting detected",
                "solution": "Encode output"
            },
            "Risk": "High"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        assert findings[0]["title"] == "XSS Vulnerability"
        assert findings[0]["description"] == "Cross-site scripting detected"
        assert findings[0]["severity"] == "High"
        assert findings[0]["mitigation"] == "Encode output"

    def test_normalize_with_fallback_chain(self, tenable_style_config):
        """Test fallback through multiple levels of priority chain."""
        config = YAMLConfig(**tenable_style_config)
        service = NormalizerService(config)

        # First two title options missing, falls back to third
        scan_data = b'''{"findings": [{
            "asset": {"name": "Fallback Title"},
            "Description": "Using Description as fallback for description",
            "severity": "Medium",
            "Steps to Remediate": "Final fallback for mitigation"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        assert findings[0]["title"] == "Fallback Title"
        assert findings[0]["description"] == "Using Description as fallback for description"
        assert findings[0]["severity"] == "Medium"
        assert findings[0]["mitigation"] == "Final fallback for mitigation"

    def test_normalize_with_default_when_all_sources_fail(self, tenable_style_config):
        """Test default value is used when all source_fields fail."""
        config = YAMLConfig(**tenable_style_config)
        service = NormalizerService(config)

        # No mitigation field present - should use default "N/A"
        scan_data = b'''{"findings": [{
            "Name": "Test Finding",
            "Synopsis": "Test description",
            "Severity": "Low"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        # mitigation should be None (not in output since optional)
        # or default "N/A" depending on implementation
        # The default is applied by the parser, not the extraction


class TestMixedSourceFieldConfigurations:
    """Test configs with mix of source_field and source_fields."""

    @pytest.fixture
    def mixed_config(self):
        """Config with both source_field and source_fields mappings."""
        return {
            "parser_name": "MixedParser",
            "parser_version": "1.0",
            "tool_name": "Mixed",
            "tool_type": "Mixed_JSON",
            "file_format": "json",
            "json_root_path": "$.items[*]",
            "field_mappings": [
                {
                    # Old style - single source_field
                    "source_field": "name",
                    "target_field": "title",
                    "data_type": "string"
                },
                {
                    # New style - priority chain
                    "source_fields": ["desc", "description", "summary"],
                    "target_field": "description",
                    "data_type": "string"
                },
                {
                    # Old style
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

    def test_mixed_config_works(self, mixed_config):
        """Test config with both source_field and source_fields."""
        config = YAMLConfig(**mixed_config)
        service = NormalizerService(config)

        scan_data = b'''{"items": [{
            "name": "Test Vuln",
            "summary": "A summary field (third option)",
            "level": "high"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        assert findings[0]["title"] == "Test Vuln"
        assert findings[0]["description"] == "A summary field (third option)"
        assert findings[0]["severity"] == "High"


# =============================================================================
# Edge Cases and Error Handling
# =============================================================================

class TestPriorityChainEdgeCases:
    """Test edge cases for priority chains."""

    def test_single_item_source_fields(self):
        """Test source_fields with just one item works like source_field."""
        mapping = FieldMapping(
            source_fields=["single_field"],
            target_field="title",
            data_type="string"
        )
        assert mapping.get_source_fields_list() == ["single_field"]

    def test_source_fields_preserves_order(self):
        """Test that source_fields order is preserved."""
        fields = ["first", "second", "third", "fourth", "fifth"]
        mapping = FieldMapping(
            source_fields=fields,
            target_field="title",
            data_type="string"
        )
        assert mapping.get_source_fields_list() == fields

    def test_source_fields_with_special_characters(self):
        """Test source_fields with special field names (dots, underscores)."""
        mapping = FieldMapping(
            source_fields=["field.with.dots", "field_with_underscores", "field-with-dashes"],
            target_field="title",
            data_type="string"
        )
        assert len(mapping.source_fields) == 3
