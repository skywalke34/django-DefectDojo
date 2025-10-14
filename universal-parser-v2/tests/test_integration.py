"""
Integration tests for Universal Parser V2.

Tests the complete end-to-end parsing flow:
1. Load YAML configuration
2. Read scan file
3. Parse and normalize findings
4. Validate output format
"""

import pytest
from pathlib import Path

from app.validators.yaml_validator import YAMLValidator
from app.services.normalizer import NormalizerService


class TestEndToEndParsing:
    """Test complete parsing flow with Acunetix sample"""

    @pytest.fixture
    def acunetix_yaml_path(self):
        """Path to Acunetix YAML config"""
        return Path(__file__).parent.parent / "configs" / "acunetix360_json.yaml"

    @pytest.fixture
    def acunetix_scan_path(self):
        """Path to Acunetix sample scan"""
        return Path(__file__).parent / "fixtures" / "acunetix_sample.json"

    def test_complete_acunetix_parsing_flow(self, acunetix_yaml_path, acunetix_scan_path):
        """
        Test complete parsing flow from YAML to normalized findings.

        This simulates what happens when a user uploads:
        1. A YAML parser configuration
        2. A scan file to parse
        """
        # Step 1: Load and validate YAML configuration
        with open(acunetix_yaml_path, "r") as f:
            yaml_content = f.read()

        config, checksum = YAMLValidator.validate_with_checksum(yaml_content)

        assert config is not None
        assert checksum is not None
        assert config.parser_name == "Acunetix360JSON"
        assert config.file_format == "json"

        # Step 2: Initialize normalizer service
        service = NormalizerService(config)
        assert service.file_reader is not None

        # Step 3: Load scan file
        with open(acunetix_scan_path, "rb") as f:
            scan_content = f.read()

        # Step 4: Parse and normalize
        findings = service.normalize(scan_content)

        # Step 5: Verify results
        assert len(findings) == 1, "Should extract exactly 1 finding"

        finding = findings[0]

        # Verify all required fields are present
        assert "title" in finding
        assert "description" in finding
        assert "severity" in finding

        # Verify field values
        assert finding["title"] == "Cookie Not Marked as HttpOnly"
        assert finding["severity"] == "Medium"
        assert "Acunetix360 identified" in finding["description"]

        # Verify metadata fields
        assert finding["scan_type"] == "Acunetix_360_JSON"
        assert "unique_id_from_tool" in finding

        # Note: CWE field is commented out in the Acunetix config (MVP)
        # Only required fields (title, description, severity) are active

        # Step 6: Get statistics
        stats = service.get_stats(findings)
        assert stats["total_count"] == 1
        assert stats["severity_breakdown"]["Medium"] == 1

    def test_yaml_validation_catches_invalid_config(self):
        """Test that invalid YAML configurations are rejected"""
        invalid_yaml = """
parser_name: "InvalidParser"
parser_version: "1.0"
# Missing required fields: tool_name, tool_type, file_format, field_mappings
"""

        with pytest.raises(Exception):
            YAMLValidator.validate_with_checksum(invalid_yaml)

    def test_parsing_fails_gracefully_with_invalid_json(self, acunetix_yaml_path):
        """Test that invalid scan files are handled gracefully"""
        # Load valid YAML config
        with open(acunetix_yaml_path, "r") as f:
            yaml_content = f.read()

        config, _ = YAMLValidator.validate_with_checksum(yaml_content)
        service = NormalizerService(config)

        # Try to parse invalid JSON
        invalid_json = b"{this is not valid json}"

        from app.utils.errors import FileFormatError
        with pytest.raises(FileFormatError):
            service.normalize(invalid_json)

    def test_parsing_multiple_findings(self, acunetix_yaml_path):
        """Test parsing scan file with multiple findings"""
        # Load YAML config
        with open(acunetix_yaml_path, "r") as f:
            yaml_content = f.read()

        config, _ = YAMLValidator.validate_with_checksum(yaml_content)
        service = NormalizerService(config)

        # Create scan with multiple findings
        multi_finding_scan = b"""
{
  "Vulnerabilities": [
    {
      "Name": "XSS Vulnerability",
      "Severity": "High",
      "Description": "Cross-site scripting detected"
    },
    {
      "Name": "SQL Injection",
      "Severity": "Critical",
      "Description": "SQL injection vulnerability"
    },
    {
      "Name": "Information Disclosure",
      "Severity": "Low",
      "Description": "Sensitive information exposed"
    }
  ]
}
"""

        findings = service.normalize(multi_finding_scan)

        assert len(findings) == 3

        # Verify findings are properly normalized
        titles = [f["title"] for f in findings]
        assert "XSS Vulnerability" in titles
        assert "SQL Injection" in titles
        assert "Information Disclosure" in titles

        # Verify severity normalization
        severities = [f["severity"] for f in findings]
        assert "High" in severities
        assert "Critical" in severities
        assert "Low" in severities

        # Verify statistics
        stats = service.get_stats(findings)
        assert stats["total_count"] == 3
        assert stats["severity_breakdown"]["High"] == 1
        assert stats["severity_breakdown"]["Critical"] == 1
        assert stats["severity_breakdown"]["Low"] == 1


class TestYAMLConfigurationValidation:
    """Test YAML configuration validation"""

    def test_valid_minimal_config(self):
        """Test minimal valid YAML configuration"""
        minimal_yaml = """
parser_name: "MinimalParser"
parser_version: "1.0"
tool_name: "Minimal Scanner"
tool_type: "minimal"
file_format: "json"
json_root_path: "$.findings[*]"
field_mappings:
  - source_field: "title"
    target_field: "title"
    data_type: "string"
    active: true
  - source_field: "severity"
    target_field: "severity"
    data_type: "severity"
    active: true
    severity_mapping:
      "high": "High"
      "medium": "Medium"
      "low": "Low"
  - source_field: "description"
    target_field: "description"
    data_type: "string"
    active: true
"""

        config, checksum = YAMLValidator.validate_with_checksum(minimal_yaml)

        assert config.parser_name == "MinimalParser"
        assert config.file_format == "json"
        assert len(config.field_mappings) == 3
        assert checksum is not None

    def test_config_with_deduplication_fields(self):
        """Test configuration with deduplication settings"""
        yaml_with_dedup = """
parser_name: "DedupParser"
parser_version: "1.0"
tool_name: "Dedup Scanner"
tool_type: "dedup"
file_format: "json"
json_root_path: "$.results[*]"
field_mappings:
  - source_field: "name"
    target_field: "title"
    data_type: "string"
    active: true
  - source_field: "risk"
    target_field: "severity"
    data_type: "severity"
    active: true
    severity_mapping:
      "critical": "Critical"
      "high": "High"
  - source_field: "details"
    target_field: "description"
    data_type: "string"
    active: true
  - source_field: "cwe_id"
    target_field: "cwe"
    data_type: "string"
    active: true
deduplication_fields:
  - "title"
  - "cwe"
"""

        config, _ = YAMLValidator.validate_with_checksum(yaml_with_dedup)

        assert config.deduplication_fields == ["title", "cwe"]


class TestFieldMapping:
    """Test field mapping and transformation"""

    def test_nested_field_extraction(self):
        """Test extracting nested fields using dot notation"""
        from app.parsers.base import FieldExtractor

        data = {
            "vulnerability": {
                "details": {
                    "severity": "High",
                    "cwe": {
                        "id": 79,
                        "name": "XSS"
                    }
                }
            }
        }

        # Test nested extraction
        severity = FieldExtractor.extract(data, "vulnerability.details.severity")
        assert severity == "High"

        cwe_id = FieldExtractor.extract(data, "vulnerability.details.cwe.id")
        assert cwe_id == 79

    def test_severity_normalization_with_various_formats(self):
        """Test severity parser handles various input formats"""
        from app.parsers.data_types.severity_parser import SeverityParser

        parser = SeverityParser()

        # Test various formats
        assert parser.parse("high") == "High"
        assert parser.parse("HIGH") == "High"
        assert parser.parse("High") == "High"
        assert parser.parse("critical") == "Critical"
        assert parser.parse("informational") == "Info"
        assert parser.parse("1") == "Critical"
        assert parser.parse("5") == "Info"

    def test_string_parser_transformations(self):
        """Test string parser HTML stripping and normalization"""
        from app.parsers.data_types.string_parser import StringParser

        parser = StringParser()

        # Test HTML stripping
        html_text = "<p>This is <b>bold</b> text</p>"
        result = parser.parse(html_text, {"strip_html": True})
        assert result == "This is bold text"

        # Test whitespace normalization
        messy_text = "Multiple    spaces\n\nand   lines"
        result = parser.parse(messy_text, {"normalize_whitespace": True})
        assert result == "Multiple spaces and lines"


class TestErrorHandling:
    """Test error handling throughout the pipeline"""

    def test_missing_required_fields_skipped(self, tmp_path):
        """Test that findings missing required fields are skipped"""
        # Create temporary YAML config
        config_yaml = """
parser_name: "TestParser"
parser_version: "1.0"
tool_name: "Test Scanner"
tool_type: "test"
file_format: "json"
json_root_path: "$.findings[*]"
field_mappings:
  - source_field: "name"
    target_field: "title"
    data_type: "string"
    active: true
  - source_field: "severity"
    target_field: "severity"
    data_type: "severity"
    active: true
    severity_mapping:
      "high": "High"
  - source_field: "description"
    target_field: "description"
    data_type: "string"
    active: true
"""

        config, _ = YAMLValidator.validate_with_checksum(config_yaml)
        service = NormalizerService(config)

        # Scan with one valid finding and one invalid (missing severity)
        scan = b"""
{
  "findings": [
    {
      "name": "Valid Finding",
      "severity": "high",
      "description": "This is valid"
    },
    {
      "name": "Invalid Finding",
      "description": "Missing severity!"
    }
  ]
}
"""

        findings = service.normalize(scan)

        # Only the valid finding should be returned
        assert len(findings) == 1
        assert findings[0]["title"] == "Valid Finding"


# Run tests if executed directly
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
