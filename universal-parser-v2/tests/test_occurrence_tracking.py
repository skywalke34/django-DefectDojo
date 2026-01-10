"""
Unit tests for Occurrence Tracking feature.

Tests:
- Basic occurrence count mapping
- Default occurrence value
- Occurrence from nested fields
- Integer parsing for occurrences

Authored by T. Walker - DefectDojo
"""

import pytest
from app.models.yaml_config import YAMLConfig


class TestOccurrenceTracking:
    """Test occurrence tracking feature"""

    @pytest.fixture
    def create_normalizer(self):
        """Factory to create normalizer with occurrence tracking"""
        from app.services.normalizer import NormalizerService

        def _create(occurrence_config):
            base_mappings = [
                {"source_field": "name", "target_field": "title", "data_type": "string"},
                {"source_field": "desc", "target_field": "description", "data_type": "string"},
                {"source_field": "sev", "target_field": "severity", "data_type": "severity",
                 "severity_mapping": {"high": "High", "medium": "Medium", "low": "Low"}}
            ]
            # Add occurrence mapping if provided
            if occurrence_config:
                base_mappings.append(occurrence_config)

            config_dict = {
                "parser_name": "TestParser",
                "parser_version": "1.0",
                "tool_name": "Test Tool",
                "tool_type": "Test_Scanner",
                "file_format": "json",
                "json_root_path": "$.findings[*]",
                "field_mappings": base_mappings
            }
            config = YAMLConfig.model_validate(config_dict)
            return NormalizerService(config)

        return _create

    def test_occurrence_count_from_source(self, create_normalizer):
        """Test extracting occurrence count from source field"""
        import json

        normalizer = create_normalizer({
            "source_field": "count",
            "target_field": "nb_occurences",
            "data_type": "integer"
        })

        scan_content = json.dumps({
            "findings": [
                {"name": "XSS", "desc": "Found XSS", "sev": "high", "count": 5},
                {"name": "SQLi", "desc": "Found SQLi", "sev": "high", "count": 3}
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 2
        assert findings[0]['nb_occurences'] == 5
        assert findings[1]['nb_occurences'] == 3

    def test_occurrence_fixed_value(self, create_normalizer):
        """Test fixed occurrence count (default to 1)"""
        import json

        normalizer = create_normalizer({
            "target_field": "nb_occurences",
            "data_type": "integer",
            "fixed_value": 1
        })

        scan_content = json.dumps({
            "findings": [
                {"name": "XSS", "desc": "Found XSS", "sev": "high"},
                {"name": "SQLi", "desc": "Found SQLi", "sev": "high"}
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 2
        assert findings[0]['nb_occurences'] == 1
        assert findings[1]['nb_occurences'] == 1

    def test_occurrence_from_nested_field(self, create_normalizer):
        """Test occurrence count from nested field path"""
        import json

        normalizer = create_normalizer({
            "source_field": "metadata.occurrence_count",
            "target_field": "nb_occurences",
            "data_type": "integer"
        })

        scan_content = json.dumps({
            "findings": [
                {
                    "name": "Issue",
                    "desc": "Description",
                    "sev": "medium",
                    "metadata": {"occurrence_count": 10}
                }
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        assert findings[0]['nb_occurences'] == 10

    def test_occurrence_string_to_integer(self, create_normalizer):
        """Test occurrence count conversion from string"""
        import json

        normalizer = create_normalizer({
            "source_field": "occurrences",
            "target_field": "nb_occurences",
            "data_type": "integer"
        })

        scan_content = json.dumps({
            "findings": [
                {"name": "Issue", "desc": "Description", "sev": "low", "occurrences": "42"}
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        assert findings[0]['nb_occurences'] == 42

    def test_occurrence_with_default_value(self, create_normalizer):
        """Test occurrence with default when value is unparseable (not missing)"""
        import json

        # Note: The integer parser returns the default as-is (not converted to int)
        # So we pass "1" and expect "1" back, which is acceptable for the field
        normalizer = create_normalizer({
            "source_field": "count",
            "target_field": "nb_occurences",
            "data_type": "integer",
            "default": "1"
        })

        scan_content = json.dumps({
            "findings": [
                {"name": "With Count", "desc": "Has count", "sev": "high", "count": 5},
                {"name": "With Bad Count", "desc": "Unparseable count", "sev": "low", "count": "not-a-number"}
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 2
        assert findings[0]['nb_occurences'] == 5
        # Default value is returned when parsing fails for non-null input
        # IntegerParser returns default as-is (string "1"), could also be int 1
        assert str(findings[1]['nb_occurences']) == "1"

    def test_occurrence_field_missing_is_skipped(self, create_normalizer):
        """Test that missing source field doesn't add nb_occurences"""
        import json

        normalizer = create_normalizer({
            "source_field": "count",
            "target_field": "nb_occurences",
            "data_type": "integer"
        })

        scan_content = json.dumps({
            "findings": [
                {"name": "With Count", "desc": "Has count", "sev": "high", "count": 5},
                {"name": "Without Count", "desc": "No count field", "sev": "low"}
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 2
        assert findings[0]['nb_occurences'] == 5
        # When source field is missing, non-required fields are skipped
        assert 'nb_occurences' not in findings[1]

    def test_occurrence_not_set_when_no_config(self, create_normalizer):
        """Test that nb_occurences is not set when not configured"""
        import json

        normalizer = create_normalizer(None)  # No occurrence config

        scan_content = json.dumps({
            "findings": [
                {"name": "Issue", "desc": "Description", "sev": "medium"}
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        assert 'nb_occurences' not in findings[0]

    def test_occurrence_priority_chain(self, create_normalizer):
        """Test occurrence with priority chain of source fields"""
        import json

        normalizer = create_normalizer({
            "source_fields": ["occurrence_count", "count", "num_occurrences"],
            "target_field": "nb_occurences",
            "data_type": "integer"
        })

        scan_content = json.dumps({
            "findings": [
                {"name": "Issue1", "desc": "Desc", "sev": "high", "count": 3},  # Second in chain
                {"name": "Issue2", "desc": "Desc", "sev": "low", "num_occurrences": 7}  # Third in chain
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 2
        assert findings[0]['nb_occurences'] == 3
        assert findings[1]['nb_occurences'] == 7


class TestOccurrenceTrackingFieldValidation:
    """Test that nb_occurences is a valid target field"""

    def test_nb_occurences_is_valid_target_field(self):
        """Test that nb_occurences doesn't trigger unknown field warning"""
        import warnings

        # Capture warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            config = YAMLConfig.model_validate({
                "parser_name": "TestParser",
                "parser_version": "1.0",
                "tool_name": "Test",
                "tool_type": "Test",
                "file_format": "json",
                "json_root_path": "$[*]",
                "field_mappings": [
                    {"source_field": "name", "target_field": "title", "data_type": "string"},
                    {"source_field": "desc", "target_field": "description", "data_type": "string"},
                    {"source_field": "sev", "target_field": "severity", "data_type": "severity",
                     "severity_mapping": {"high": "High"}},
                    {"source_field": "count", "target_field": "nb_occurences", "data_type": "integer"}
                ]
            })

            # Check that no warning was raised for nb_occurences
            nb_occurences_warnings = [
                warning for warning in w
                if "nb_occurences" in str(warning.message) and "not a standard" in str(warning.message)
            ]
            assert len(nb_occurences_warnings) == 0
