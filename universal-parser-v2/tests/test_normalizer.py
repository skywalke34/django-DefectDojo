"""
Unit tests for NormalizerService.

Tests the complete parsing flow:
- Loading YAML configuration
- Reading scan files
- Extracting and transforming field values
- Building normalized DefectDojo findings
- Validation
"""

import pytest
import json
from pathlib import Path

from app.services.normalizer import NormalizerService
from app.models.yaml_config import YAMLConfig
from app.utils.errors import ValidationError
from app.validators.yaml_validator import YAMLValidator


class TestNormalizerService:
    """Test NormalizerService with Acunetix sample"""

    @pytest.fixture
    def acunetix_config(self):
        """Load Acunetix YAML configuration"""
        config_path = Path(__file__).parent.parent / "configs" / "acunetix360_json.yaml"
        with open(config_path, "r") as f:
            yaml_str = f.read()

        config, _ = YAMLValidator.validate_with_checksum(yaml_str)
        return config

    @pytest.fixture
    def acunetix_scan_file(self):
        """Load Acunetix sample scan file"""
        scan_path = Path(__file__).parent / "fixtures" / "acunetix_sample.json"
        with open(scan_path, "rb") as f:
            return f.read()

    def test_initialize_normalizer(self, acunetix_config):
        """Test that normalizer initializes with valid config"""
        service = NormalizerService(acunetix_config)
        assert service.config == acunetix_config
        assert service.file_reader is not None

    def test_normalize_acunetix_sample(self, acunetix_config, acunetix_scan_file):
        """Test normalizing Acunetix sample file"""
        service = NormalizerService(acunetix_config)
        findings = service.normalize(acunetix_scan_file)

        # Should extract 1 finding
        assert len(findings) == 1

        # Verify required fields are present
        finding = findings[0]
        assert 'title' in finding
        assert 'severity' in finding
        assert 'description' in finding

        # Verify field values are correctly mapped
        assert finding['title'] == "Cookie Not Marked as HttpOnly"
        assert finding['severity'] == "Medium"
        assert "Acunetix360 identified a cookie not marked as HTTPOnly" in finding['description']

    def test_normalize_extracts_all_mapped_fields(self, acunetix_config, acunetix_scan_file):
        """Test that all configured field mappings are applied"""
        service = NormalizerService(acunetix_config)
        findings = service.normalize(acunetix_scan_file)

        finding = findings[0]

        # Check that all active field mappings were processed
        active_target_fields = {
            fm.target_field for fm in acunetix_config.field_mappings if fm.active
        }

        for field in active_target_fields:
            # Field should be present (or intentionally None for optional fields)
            if field in NormalizerService.REQUIRED_FIELDS:
                assert field in finding, f"Required field '{field}' missing"

    def test_normalize_adds_metadata(self, acunetix_config, acunetix_scan_file):
        """Test that metadata fields are added"""
        service = NormalizerService(acunetix_config)
        findings = service.normalize(acunetix_scan_file)

        finding = findings[0]

        # Should have scan_type metadata
        assert 'scan_type' in finding
        assert finding['scan_type'] == acunetix_config.tool_type

        # Should have unique_id_from_tool if deduplication fields configured
        if acunetix_config.deduplication_fields:
            assert 'unique_id_from_tool' in finding

    def test_normalize_validates_required_fields(self, acunetix_config):
        """Test that missing required fields raise ValidationError"""
        service = NormalizerService(acunetix_config)

        # Create scan data missing required fields
        incomplete_scan = json.dumps({
            "Vulnerabilities": [
                {
                    "Name": "Test",
                    # Missing Severity and Description
                }
            ]
        }).encode('utf-8')

        # Should skip finding with missing required fields
        findings = service.normalize(incomplete_scan)

        # Finding should be skipped (logged as warning)
        assert len(findings) == 0

    def test_get_stats(self, acunetix_config, acunetix_scan_file):
        """Test statistics generation"""
        service = NormalizerService(acunetix_config)
        findings = service.normalize(acunetix_scan_file)

        stats = service.get_stats(findings)

        assert stats['total_count'] == 1
        assert 'severity_breakdown' in stats
        assert stats['severity_breakdown']['Medium'] == 1

    def test_normalize_with_multiple_findings(self, acunetix_config):
        """Test normalizing multiple findings"""
        service = NormalizerService(acunetix_config)

        # Create scan with multiple findings
        multi_scan = json.dumps({
            "Vulnerabilities": [
                {
                    "Name": "XSS Vulnerability",
                    "Severity": "High",
                    "Description": "Cross-site scripting found",
                    "Classification": {"Cwe": "79"}
                },
                {
                    "Name": "SQL Injection",
                    "Severity": "Critical",
                    "Description": "SQL injection vulnerability",
                    "Classification": {"Cwe": "89"}
                },
                {
                    "Name": "Missing Header",
                    "Severity": "Low",
                    "Description": "Security header missing",
                    "Classification": {"Cwe": "16"}
                }
            ]
        }).encode('utf-8')

        findings = service.normalize(multi_scan)

        assert len(findings) == 3

        # Verify severity mapping worked correctly
        severities = [f['severity'] for f in findings]
        assert 'High' in severities
        assert 'Critical' in severities
        assert 'Low' in severities

    def test_normalize_handles_nested_fields(self, acunetix_config, acunetix_scan_file):
        """Test that nested fields are correctly extracted"""
        service = NormalizerService(acunetix_config)
        findings = service.normalize(acunetix_scan_file)

        finding = findings[0]

        # Acunetix config should extract nested CWE field
        # Classification.Cwe from raw finding
        if 'cwe' in finding:
            assert finding['cwe'] is not None

    def test_severity_parser_integration(self, acunetix_config):
        """Test that severity parser is correctly applied"""
        service = NormalizerService(acunetix_config)

        # Create findings with various severity formats
        scan = json.dumps({
            "Vulnerabilities": [
                {"Name": "Test1", "Severity": "high", "Description": "Test"},  # lowercase
                {"Name": "Test2", "Severity": "CRITICAL", "Description": "Test"},  # uppercase
                {"Name": "Test3", "Severity": "Medium", "Description": "Test"},  # mixed case
            ]
        }).encode('utf-8')

        findings = service.normalize(scan)

        # All severities should be normalized to proper case
        assert findings[0]['severity'] == "High"
        assert findings[1]['severity'] == "Critical"
        assert findings[2]['severity'] == "Medium"

    def test_inactive_field_mappings_are_skipped(self, acunetix_config):
        """Test that inactive field mappings are not processed"""
        # Modify config to mark a field as inactive
        acunetix_config.field_mappings[0].active = False
        inactive_field = acunetix_config.field_mappings[0].target_field

        service = NormalizerService(acunetix_config)

        scan = json.dumps({
            "Vulnerabilities": [
                {
                    "Name": "Test",
                    "Severity": "High",
                    "Description": "Test description"
                }
            ]
        }).encode('utf-8')

        findings = service.normalize(scan)

        # If inactive field was 'title', it should be missing
        # (unless it's a required field, which would cause validation error)
        if inactive_field not in NormalizerService.REQUIRED_FIELDS:
            assert inactive_field not in findings[0]


class TestNormalizerWithCustomConfig:
    """Test NormalizerService with custom configurations"""

    def test_custom_severity_mapping(self):
        """Test custom severity mappings"""
        config_dict = {
            "parser_name": "CustomParser",
            "parser_version": "1.0",
            "tool_name": "Custom Tool",
            "tool_type": "custom",
            "file_format": "json",
            "json_root_path": "$.findings[*]",
            "field_mappings": [
                {
                    "source_field": "title",
                    "target_field": "title",
                    "data_type": "string",
                    "active": True
                },
                {
                    "source_field": "risk_level",
                    "target_field": "severity",
                    "data_type": "severity",
                    "active": True,
                    "severity_mapping": {
                        "5": "Critical",
                        "4": "High",
                        "3": "Medium",
                        "2": "Low",
                        "1": "Info"
                    }
                },
                {
                    "source_field": "details",
                    "target_field": "description",
                    "data_type": "string",
                    "active": True
                }
            ],
            "deduplication_fields": ["title"]
        }

        config = YAMLConfig.parse_obj(config_dict)
        service = NormalizerService(config)

        scan = json.dumps({
            "findings": [
                {"title": "Test Finding", "risk_level": "5", "details": "Test details"}
            ]
        }).encode('utf-8')

        findings = service.normalize(scan)

        assert len(findings) == 1
        assert findings[0]['severity'] == "Critical"


# Run tests if executed directly
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
