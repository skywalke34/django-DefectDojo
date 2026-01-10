"""
Unit tests for Format Version Detection feature.

Tests:
- VersionDetection model validation
- FormatVersion model validation
- YAMLConfig with format_versions
- Version detection logic in normalizer
- Real-world scenarios (TruffleHog v2/v3)

Authored by T. Walker - DefectDojo
"""

import pytest
from pydantic import ValidationError as PydanticValidationError
from app.models.yaml_config import (
    VersionDetection, FormatVersion, FieldMapping, YAMLConfig
)


class TestVersionDetectionModel:
    """Test VersionDetection Pydantic model"""

    def test_field_exists_detection(self):
        """Test field_exists detection method"""
        detection = VersionDetection(field_exists="DetectorName")
        assert detection.field_exists == "DetectorName"
        assert detection.field_equals is None

    def test_field_equals_detection(self):
        """Test field_equals detection method"""
        detection = VersionDetection(
            field_equals={"path": "version", "value": "3.0"}
        )
        assert detection.field_equals["path"] == "version"
        assert detection.field_equals["value"] == "3.0"

    def test_field_contains_detection(self):
        """Test field_contains detection method"""
        detection = VersionDetection(
            field_contains={"path": "type", "value": "v3"}
        )
        assert detection.field_contains["path"] == "type"
        assert detection.field_contains["value"] == "v3"

    def test_field_matches_detection(self):
        """Test field_matches detection method"""
        detection = VersionDetection(
            field_matches={"path": "version", "pattern": r"\d+\.\d+"}
        )
        assert detection.field_matches["path"] == "version"
        assert detection.field_matches["pattern"] == r"\d+\.\d+"

    def test_no_detection_method_fails(self):
        """Test that missing all detection methods fails"""
        with pytest.raises(PydanticValidationError) as exc_info:
            VersionDetection()
        assert "requires at least one detection method" in str(exc_info.value).lower()


class TestFormatVersionModel:
    """Test FormatVersion Pydantic model"""

    def test_valid_format_version(self):
        """Test valid format version configuration"""
        fv = FormatVersion(
            version="v3",
            detection=VersionDetection(field_exists="DetectorName"),
            field_mappings=[
                FieldMapping(
                    source_field="DetectorName",
                    target_field="title",
                    data_type="string"
                ),
                FieldMapping(
                    source_field="Raw",
                    target_field="description",
                    data_type="string"
                ),
                FieldMapping(
                    source_field="sev",
                    target_field="severity",
                    data_type="severity",
                    severity_mapping={"high": "High", "low": "Low"}
                )
            ]
        )
        assert fv.version == "v3"
        assert len(fv.field_mappings) == 3

    def test_format_version_with_json_root_path(self):
        """Test format version with version-specific json_root_path"""
        fv = FormatVersion(
            version="v3",
            detection=VersionDetection(field_exists="results"),
            json_root_path="$.results[*]",
            field_mappings=[
                FieldMapping(
                    source_field="name",
                    target_field="title",
                    data_type="string"
                ),
                FieldMapping(
                    source_field="desc",
                    target_field="description",
                    data_type="string"
                ),
                FieldMapping(
                    source_field="sev",
                    target_field="severity",
                    data_type="severity",
                    severity_mapping={"high": "High"}
                )
            ]
        )
        assert fv.json_root_path == "$.results[*]"


class TestYAMLConfigWithFormatVersions:
    """Test YAMLConfig with format_versions"""

    @pytest.fixture
    def trufflehog_style_config(self):
        """TruffleHog-style config with v2/v3 detection"""
        return {
            "parser_name": "TruffleHog",
            "parser_version": "1.0",
            "tool_name": "TruffleHog",
            "tool_type": "TruffleHog_Scan",
            "file_format": "json",
            "json_root_path": "$.results[*]",
            "format_versions": [
                {
                    "version": "v3",
                    "detection": {"field_exists": "DetectorName"},
                    "field_mappings": [
                        {"source_field": "DetectorName", "target_field": "title", "data_type": "string"},
                        {"source_field": "Raw", "target_field": "description", "data_type": "string"},
                        {"source_field": "Severity", "target_field": "severity", "data_type": "severity",
                         "severity_mapping": {"high": "High", "medium": "Medium", "low": "Low"}}
                    ]
                },
                {
                    "version": "v2",
                    "detection": {"field_exists": "reason"},
                    "field_mappings": [
                        {"source_field": "reason", "target_field": "title", "data_type": "string"},
                        {"source_field": "stringsFound", "target_field": "description", "data_type": "string"},
                        {"target_field": "severity", "data_type": "severity",
                         "fixed_value": "High"}
                    ]
                }
            ]
        }

    def test_config_with_format_versions(self, trufflehog_style_config):
        """Test config with format_versions is valid"""
        config = YAMLConfig.model_validate(trufflehog_style_config)
        assert config.format_versions is not None
        assert len(config.format_versions) == 2
        assert config.format_versions[0].version == "v3"
        assert config.format_versions[1].version == "v2"
        assert config.field_mappings is None

    def test_config_without_mappings_or_versions_fails(self):
        """Test that config without field_mappings or format_versions fails"""
        with pytest.raises(PydanticValidationError) as exc_info:
            YAMLConfig.model_validate({
                "parser_name": "Test",
                "parser_version": "1.0",
                "tool_name": "Test",
                "tool_type": "Test",
                "file_format": "json",
                "json_root_path": "$[*]"
            })
        assert "field_mappings" in str(exc_info.value).lower() or "format_versions" in str(exc_info.value).lower()

    def test_config_with_both_mappings_and_versions_fails(self, trufflehog_style_config):
        """Test that config with both field_mappings and format_versions fails"""
        # Need complete field_mappings to get past the first validator
        trufflehog_style_config["field_mappings"] = [
            {"source_field": "test", "target_field": "title", "data_type": "string"},
            {"source_field": "desc", "target_field": "description", "data_type": "string"},
            {"source_field": "sev", "target_field": "severity", "data_type": "severity",
             "severity_mapping": {"high": "High"}}
        ]
        with pytest.raises(PydanticValidationError) as exc_info:
            YAMLConfig.model_validate(trufflehog_style_config)
        assert "cannot specify both" in str(exc_info.value).lower()

    def test_format_version_missing_required_fields_fails(self):
        """Test that format_version missing required fields fails"""
        config_dict = {
            "parser_name": "Test",
            "parser_version": "1.0",
            "tool_name": "Test",
            "tool_type": "Test",
            "file_format": "json",
            "json_root_path": "$[*]",
            "format_versions": [
                {
                    "version": "v1",
                    "detection": {"field_exists": "test"},
                    "field_mappings": [
                        {"source_field": "name", "target_field": "title", "data_type": "string"}
                        # Missing description and severity
                    ]
                }
            ]
        }
        with pytest.raises(PydanticValidationError) as exc_info:
            YAMLConfig.model_validate(config_dict)
        assert "missing required fields" in str(exc_info.value).lower()


class TestNormalizerVersionDetection:
    """Test NormalizerService format version detection"""

    @pytest.fixture
    def create_normalizer(self):
        """Factory to create normalizer with format versions"""
        from app.services.normalizer import NormalizerService

        def _create(format_versions):
            config_dict = {
                "parser_name": "TestParser",
                "parser_version": "1.0",
                "tool_name": "Test Tool",
                "tool_type": "Test_Scanner",
                "file_format": "json",
                "json_root_path": "$[*]",
                "format_versions": format_versions
            }
            config = YAMLConfig.model_validate(config_dict)
            return NormalizerService(config)

        return _create

    def test_field_exists_detection(self, create_normalizer):
        """Test version detection using field_exists"""
        import json

        normalizer = create_normalizer([
            {
                "version": "v3",
                "detection": {"field_exists": "DetectorName"},
                "field_mappings": [
                    {"source_field": "DetectorName", "target_field": "title", "data_type": "string"},
                    {"source_field": "Raw", "target_field": "description", "data_type": "string"},
                    {"fixed_value": "High", "target_field": "severity", "data_type": "string"}
                ]
            },
            {
                "version": "v2",
                "detection": {"field_exists": "reason"},
                "field_mappings": [
                    {"source_field": "reason", "target_field": "title", "data_type": "string"},
                    {"source_field": "stringsFound", "target_field": "description", "data_type": "string"},
                    {"fixed_value": "Medium", "target_field": "severity", "data_type": "string"}
                ]
            }
        ])

        # V3 format
        v3_content = json.dumps([
            {"DetectorName": "AWS Key", "Raw": "AKIA..."}
        ]).encode('utf-8')

        findings = normalizer.normalize(v3_content)
        assert len(findings) == 1
        assert findings[0]['title'] == "AWS Key"
        assert findings[0]['severity'] == "High"

    def test_field_equals_detection(self, create_normalizer):
        """Test version detection using field_equals"""
        import json

        normalizer = create_normalizer([
            {
                "version": "2.0",
                "detection": {"field_equals": {"path": "version", "value": "2.0"}},
                "field_mappings": [
                    {"source_field": "vuln_name", "target_field": "title", "data_type": "string"},
                    {"source_field": "vuln_desc", "target_field": "description", "data_type": "string"},
                    {"fixed_value": "High", "target_field": "severity", "data_type": "string"}
                ]
            },
            {
                "version": "1.0",
                "detection": {"field_equals": {"path": "version", "value": "1.0"}},
                "field_mappings": [
                    {"source_field": "name", "target_field": "title", "data_type": "string"},
                    {"source_field": "description", "target_field": "description", "data_type": "string"},
                    {"fixed_value": "Medium", "target_field": "severity", "data_type": "string"}
                ]
            }
        ])

        # Version 2.0 format
        v2_content = json.dumps([
            {"version": "2.0", "vuln_name": "XSS", "vuln_desc": "Cross-site scripting"}
        ]).encode('utf-8')

        findings = normalizer.normalize(v2_content)
        assert len(findings) == 1
        assert findings[0]['title'] == "XSS"
        assert findings[0]['severity'] == "High"

    def test_field_contains_detection(self, create_normalizer):
        """Test version detection using field_contains"""
        import json

        normalizer = create_normalizer([
            {
                "version": "enterprise",
                "detection": {"field_contains": {"path": "scanner", "value": "Enterprise"}},
                "field_mappings": [
                    {"source_field": "finding", "target_field": "title", "data_type": "string"},
                    {"source_field": "details", "target_field": "description", "data_type": "string"},
                    {"fixed_value": "Critical", "target_field": "severity", "data_type": "string"}
                ]
            },
            {
                "version": "community",
                "detection": {"field_contains": {"path": "scanner", "value": "Community"}},
                "field_mappings": [
                    {"source_field": "finding", "target_field": "title", "data_type": "string"},
                    {"source_field": "details", "target_field": "description", "data_type": "string"},
                    {"fixed_value": "Low", "target_field": "severity", "data_type": "string"}
                ]
            }
        ])

        content = json.dumps([
            {"scanner": "Scanner Enterprise v2", "finding": "SQLi", "details": "Injection found"}
        ]).encode('utf-8')

        findings = normalizer.normalize(content)
        assert len(findings) == 1
        assert findings[0]['severity'] == "Critical"

    def test_field_matches_detection(self, create_normalizer):
        """Test version detection using field_matches (regex)"""
        import json

        normalizer = create_normalizer([
            {
                "version": "semver3",
                "detection": {"field_matches": {"path": "api_version", "pattern": r"^3\.\d+\.\d+"}},
                "field_mappings": [
                    {"source_field": "issue", "target_field": "title", "data_type": "string"},
                    {"source_field": "desc", "target_field": "description", "data_type": "string"},
                    {"fixed_value": "High", "target_field": "severity", "data_type": "string"}
                ]
            },
            {
                "version": "semver2",
                "detection": {"field_matches": {"path": "api_version", "pattern": r"^2\.\d+\.\d+"}},
                "field_mappings": [
                    {"source_field": "name", "target_field": "title", "data_type": "string"},
                    {"source_field": "detail", "target_field": "description", "data_type": "string"},
                    {"fixed_value": "Medium", "target_field": "severity", "data_type": "string"}
                ]
            }
        ])

        content = json.dumps([
            {"api_version": "3.2.1", "issue": "Issue Found", "desc": "Description"}
        ]).encode('utf-8')

        findings = normalizer.normalize(content)
        assert len(findings) == 1
        assert findings[0]['title'] == "Issue Found"
        assert findings[0]['severity'] == "High"

    def test_fallback_to_first_version(self, create_normalizer):
        """Test fallback to first version when no match"""
        import json

        normalizer = create_normalizer([
            {
                "version": "v1",
                "detection": {"field_exists": "not_present_field"},
                "field_mappings": [
                    {"source_field": "name", "target_field": "title", "data_type": "string"},
                    {"source_field": "desc", "target_field": "description", "data_type": "string"},
                    {"fixed_value": "High", "target_field": "severity", "data_type": "string"}
                ]
            }
        ])

        content = json.dumps([
            {"name": "Test", "desc": "Description"}
        ]).encode('utf-8')

        # Should still work using fallback
        findings = normalizer.normalize(content)
        assert len(findings) == 1
        assert findings[0]['title'] == "Test"


class TestTruffleHogScenario:
    """Test real-world TruffleHog v2/v3 detection scenario"""

    @pytest.fixture
    def trufflehog_normalizer(self):
        """Create normalizer for TruffleHog multi-version support"""
        from app.services.normalizer import NormalizerService

        config_dict = {
            "parser_name": "TruffleHog",
            "parser_version": "1.0",
            "tool_name": "TruffleHog",
            "tool_type": "TruffleHog_Scan",
            "file_format": "json",
            "json_root_path": "$[*]",
            "format_versions": [
                {
                    "version": "v3",
                    "detection": {"field_exists": "DetectorName"},
                    "field_mappings": [
                        {"source_field": "DetectorName", "target_field": "title", "data_type": "string"},
                        {"source_field": "Raw", "target_field": "description", "data_type": "string"},
                        {
                            "target_field": "severity",
                            "data_type": "conditional_severity",
                            "conditional_severity": [
                                {"source_field": "DetectorName", "condition": "contains", "value": "AWS", "severity": "Critical"},
                            ],
                            "default_severity": "High"
                        }
                    ]
                },
                {
                    "version": "v2",
                    "detection": {"field_exists": "reason"},
                    "field_mappings": [
                        {"source_field": "reason", "target_field": "title", "data_type": "string"},
                        {
                            "target_field": "description",
                            "data_type": "template",
                            "template": "Found in file: {path}\nStrings: {stringsFound}"
                        },
                        {"fixed_value": "High", "target_field": "severity", "data_type": "string"}
                    ]
                }
            ]
        }
        config = YAMLConfig.model_validate(config_dict)
        return NormalizerService(config)

    def test_trufflehog_v3_detection(self, trufflehog_normalizer):
        """Test TruffleHog v3 format detection"""
        import json

        v3_content = json.dumps([
            {
                "DetectorName": "AWSAccessKey",
                "Raw": "AKIAIOSFODNN7EXAMPLE",
                "SourceMetadata": {"file": "config.yml"}
            }
        ]).encode('utf-8')

        findings = trufflehog_normalizer.normalize(v3_content)
        assert len(findings) == 1
        assert findings[0]['title'] == "AWSAccessKey"
        assert findings[0]['description'] == "AKIAIOSFODNN7EXAMPLE"
        assert findings[0]['severity'] == "Critical"  # AWS = Critical

    def test_trufflehog_v2_detection(self, trufflehog_normalizer):
        """Test TruffleHog v2 format detection"""
        import json

        v2_content = json.dumps([
            {
                "reason": "High Entropy",
                "stringsFound": ["secret123abc"],
                "path": "/app/config.json"
            }
        ]).encode('utf-8')

        findings = trufflehog_normalizer.normalize(v2_content)
        assert len(findings) == 1
        assert findings[0]['title'] == "High Entropy"
        assert "Found in file:" in findings[0]['description']
        assert findings[0]['severity'] == "High"

    def test_multiple_findings_same_version(self, trufflehog_normalizer):
        """Test multiple findings in same version format"""
        import json

        v3_content = json.dumps([
            {"DetectorName": "AWSAccessKey", "Raw": "AKIA..."},
            {"DetectorName": "GitHubToken", "Raw": "ghp_..."},
            {"DetectorName": "PrivateKey", "Raw": "-----BEGIN..."}
        ]).encode('utf-8')

        findings = trufflehog_normalizer.normalize(v3_content)
        assert len(findings) == 3
        assert findings[0]['title'] == "AWSAccessKey"
        assert findings[1]['title'] == "GitHubToken"
        assert findings[2]['title'] == "PrivateKey"
