"""
Unit tests for Conditional Severity feature.

Tests:
- ConditionalSeverity model validation
- Condition types (equals, contains, regex, in, starts_with, ends_with)
- First-match behavior
- Default severity fallback
- Normalizer integration
- Edge cases

Authored by T. Walker - DefectDojo
"""

import pytest
from pydantic import ValidationError as PydanticValidationError
from app.models.yaml_config import ConditionalSeverity, FieldMapping, YAMLConfig


class TestConditionalSeverityModel:
    """Test ConditionalSeverity Pydantic model"""

    def test_valid_equals_condition(self):
        """Test valid equals condition"""
        rule = ConditionalSeverity(
            source_field="detector",
            condition="equals",
            value="AWS",
            severity="Critical"
        )
        assert rule.condition == "equals"
        assert rule.value == "AWS"
        assert rule.severity == "Critical"

    def test_valid_contains_condition(self):
        """Test valid contains condition"""
        rule = ConditionalSeverity(
            source_field="detector_name",
            condition="contains",
            value="secret",
            severity="High"
        )
        assert rule.condition == "contains"
        assert rule.severity == "High"

    def test_valid_regex_condition(self):
        """Test valid regex condition"""
        rule = ConditionalSeverity(
            source_field="message",
            condition="regex",
            value=r"CVE-\d{4}-\d+",
            severity="High"
        )
        assert rule.condition == "regex"
        assert "CVE" in rule.value

    def test_valid_in_condition(self):
        """Test valid 'in' condition with list"""
        rule = ConditionalSeverity(
            source_field="category",
            condition="in",
            value=["A1", "A2", "A3"],
            severity="Critical"
        )
        assert rule.condition == "in"
        assert isinstance(rule.value, list)

    def test_valid_starts_with_condition(self):
        """Test valid starts_with condition"""
        rule = ConditionalSeverity(
            source_field="path",
            condition="starts_with",
            value="/admin",
            severity="High"
        )
        assert rule.condition == "starts_with"

    def test_valid_ends_with_condition(self):
        """Test valid ends_with condition"""
        rule = ConditionalSeverity(
            source_field="filename",
            condition="ends_with",
            value=".key",
            severity="Critical"
        )
        assert rule.condition == "ends_with"

    def test_invalid_condition_fails(self):
        """Test invalid condition type fails"""
        with pytest.raises(PydanticValidationError) as exc_info:
            ConditionalSeverity(
                source_field="test",
                condition="invalid",
                value="test",
                severity="High"
            )
        assert "condition must be one of" in str(exc_info.value).lower()

    def test_invalid_severity_fails(self):
        """Test invalid severity value fails"""
        with pytest.raises(PydanticValidationError) as exc_info:
            ConditionalSeverity(
                source_field="test",
                condition="equals",
                value="test",
                severity="InvalidSeverity"
            )
        assert "severity must be one of" in str(exc_info.value).lower()

    def test_all_valid_severities(self):
        """Test all valid severity values"""
        for severity in ["Critical", "High", "Medium", "Low", "Info"]:
            rule = ConditionalSeverity(
                source_field="test",
                condition="equals",
                value="test",
                severity=severity
            )
            assert rule.severity == severity


class TestFieldMappingWithConditionalSeverity:
    """Test FieldMapping with conditional_severity configuration"""

    def test_valid_conditional_severity_mapping(self):
        """Test valid conditional_severity field mapping"""
        mapping = FieldMapping(
            target_field="severity",
            data_type="conditional_severity",
            conditional_severity=[
                ConditionalSeverity(
                    source_field="detector",
                    condition="contains",
                    value="AWS",
                    severity="Critical"
                ),
                ConditionalSeverity(
                    source_field="detector",
                    condition="equals",
                    value="Generic",
                    severity="Medium"
                )
            ],
            default_severity="High"
        )
        assert len(mapping.conditional_severity) == 2
        assert mapping.default_severity == "High"

    def test_conditional_severity_requires_rules(self):
        """Test that conditional_severity requires rules"""
        with pytest.raises(PydanticValidationError) as exc_info:
            FieldMapping(
                target_field="severity",
                data_type="conditional_severity",
                default_severity="High"
            )
        assert "conditional_severity" in str(exc_info.value).lower()

    def test_conditional_severity_requires_default(self):
        """Test that conditional_severity requires default_severity"""
        with pytest.raises(PydanticValidationError) as exc_info:
            FieldMapping(
                target_field="severity",
                data_type="conditional_severity",
                conditional_severity=[
                    ConditionalSeverity(
                        source_field="test",
                        condition="equals",
                        value="test",
                        severity="High"
                    )
                ]
            )
        assert "default_severity" in str(exc_info.value).lower()


class TestNormalizerConditionalSeverity:
    """Test NormalizerService conditional severity processing"""

    @pytest.fixture
    def create_normalizer(self):
        """Factory to create normalizer with conditional severity config"""
        from app.services.normalizer import NormalizerService

        def _create(conditional_rules, default_severity):
            config_dict = {
                "parser_name": "TestParser",
                "parser_version": "1.0",
                "tool_name": "Test Tool",
                "tool_type": "Test_Scanner",
                "file_format": "json",
                "json_root_path": "$.findings[*]",
                "field_mappings": [
                    {"source_field": "name", "target_field": "title", "data_type": "string"},
                    {"source_field": "desc", "target_field": "description", "data_type": "string"},
                    {
                        "target_field": "severity",
                        "data_type": "conditional_severity",
                        "conditional_severity": conditional_rules,
                        "default_severity": default_severity
                    }
                ]
            }
            config = YAMLConfig.model_validate(config_dict)
            return NormalizerService(config)

        return _create

    def test_equals_condition_match(self, create_normalizer):
        """Test equals condition matching"""
        import json

        normalizer = create_normalizer(
            [{"source_field": "detector", "condition": "equals", "value": "AWS", "severity": "Critical"}],
            "Medium"
        )

        scan_content = json.dumps({
            "findings": [
                {"name": "AWS Key", "desc": "AWS credential found", "detector": "AWS"}
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        assert findings[0]['severity'] == "Critical"

    def test_equals_condition_no_match(self, create_normalizer):
        """Test equals condition not matching uses default"""
        import json

        normalizer = create_normalizer(
            [{"source_field": "detector", "condition": "equals", "value": "AWS", "severity": "Critical"}],
            "Medium"
        )

        scan_content = json.dumps({
            "findings": [
                {"name": "Generic Secret", "desc": "Secret found", "detector": "Generic"}
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        assert findings[0]['severity'] == "Medium"

    def test_contains_condition_match(self, create_normalizer):
        """Test contains condition matching"""
        import json

        normalizer = create_normalizer(
            [{"source_field": "detector_name", "condition": "contains", "value": "AWS", "severity": "Critical"}],
            "Low"
        )

        scan_content = json.dumps({
            "findings": [
                {"name": "Key", "desc": "Found key", "detector_name": "AWSAccessKey"}
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        assert findings[0]['severity'] == "Critical"

    def test_starts_with_condition_match(self, create_normalizer):
        """Test starts_with condition matching"""
        import json

        normalizer = create_normalizer(
            [{"source_field": "path", "condition": "starts_with", "value": "/admin", "severity": "High"}],
            "Low"
        )

        scan_content = json.dumps({
            "findings": [
                {"name": "Admin Access", "desc": "Admin path", "path": "/admin/users"}
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        assert findings[0]['severity'] == "High"

    def test_ends_with_condition_match(self, create_normalizer):
        """Test ends_with condition matching"""
        import json

        normalizer = create_normalizer(
            [{"source_field": "filename", "condition": "ends_with", "value": ".pem", "severity": "Critical"}],
            "Info"
        )

        scan_content = json.dumps({
            "findings": [
                {"name": "PEM Key", "desc": "Key file", "filename": "server.pem"}
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        assert findings[0]['severity'] == "Critical"

    def test_regex_condition_match(self, create_normalizer):
        """Test regex condition matching"""
        import json

        normalizer = create_normalizer(
            [{"source_field": "message", "condition": "regex", "value": r"CVE-\d{4}-\d+", "severity": "High"}],
            "Low"
        )

        scan_content = json.dumps({
            "findings": [
                {"name": "CVE Found", "desc": "Has CVE", "message": "Affected by CVE-2021-44228"}
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        assert findings[0]['severity'] == "High"

    def test_in_condition_match(self, create_normalizer):
        """Test 'in' condition matching"""
        import json

        normalizer = create_normalizer(
            [{"source_field": "owasp", "condition": "in", "value": ["A1", "A2", "A3"], "severity": "Critical"}],
            "Low"
        )

        scan_content = json.dumps({
            "findings": [
                {"name": "Injection", "desc": "SQL Injection", "owasp": "A1"}
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        assert findings[0]['severity'] == "Critical"

    def test_first_match_wins(self, create_normalizer):
        """Test that first matching rule wins"""
        import json

        normalizer = create_normalizer(
            [
                {"source_field": "detector", "condition": "equals", "value": "AWS", "severity": "Critical"},
                {"source_field": "detector", "condition": "contains", "value": "A", "severity": "High"},
                {"source_field": "detector", "condition": "equals", "value": "AWS", "severity": "Low"}
            ],
            "Info"
        )

        scan_content = json.dumps({
            "findings": [
                {"name": "AWS", "desc": "AWS credential", "detector": "AWS"}
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        assert findings[0]['severity'] == "Critical"  # First match, not Low

    def test_nested_field_path(self, create_normalizer):
        """Test conditional severity with nested field paths"""
        import json

        normalizer = create_normalizer(
            [{"source_field": "metadata.type", "condition": "equals", "value": "credential", "severity": "High"}],
            "Low"
        )

        scan_content = json.dumps({
            "findings": [
                {"name": "Secret", "desc": "Found secret", "metadata": {"type": "credential"}}
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        assert findings[0]['severity'] == "High"

    def test_missing_source_field(self, create_normalizer):
        """Test handling when source field is missing"""
        import json

        normalizer = create_normalizer(
            [{"source_field": "missing_field", "condition": "equals", "value": "test", "severity": "Critical"}],
            "Info"
        )

        scan_content = json.dumps({
            "findings": [
                {"name": "No Field", "desc": "Missing source field"}
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        assert findings[0]['severity'] == "Info"  # Default


class TestConditionalSeverityEdgeCases:
    """Test edge cases for conditional severity"""

    @pytest.fixture
    def create_normalizer(self):
        """Factory to create normalizer"""
        from app.services.normalizer import NormalizerService

        def _create(conditional_rules, default_severity):
            config_dict = {
                "parser_name": "TestParser",
                "parser_version": "1.0",
                "tool_name": "Test Tool",
                "tool_type": "Test_Scanner",
                "file_format": "json",
                "json_root_path": "$.findings[*]",
                "field_mappings": [
                    {"source_field": "name", "target_field": "title", "data_type": "string"},
                    {"source_field": "desc", "target_field": "description", "data_type": "string"},
                    {
                        "target_field": "severity",
                        "data_type": "conditional_severity",
                        "conditional_severity": conditional_rules,
                        "default_severity": default_severity
                    }
                ]
            }
            config = YAMLConfig.model_validate(config_dict)
            return NormalizerService(config)

        return _create

    def test_non_string_source_value(self, create_normalizer):
        """Test handling non-string source values (should be converted)"""
        import json

        normalizer = create_normalizer(
            [{"source_field": "severity_score", "condition": "equals", "value": "10", "severity": "Critical"}],
            "Low"
        )

        scan_content = json.dumps({
            "findings": [
                {"name": "High Score", "desc": "Score is 10", "severity_score": 10}
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        assert findings[0]['severity'] == "Critical"

    def test_case_sensitive_equals(self, create_normalizer):
        """Test that equals is case sensitive"""
        import json

        normalizer = create_normalizer(
            [{"source_field": "detector", "condition": "equals", "value": "AWS", "severity": "Critical"}],
            "Low"
        )

        scan_content = json.dumps({
            "findings": [
                {"name": "Lowercase", "desc": "Lowercase detector", "detector": "aws"}
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        assert findings[0]['severity'] == "Low"  # No match, uses default

    def test_empty_string_value(self, create_normalizer):
        """Test handling empty string values"""
        import json

        normalizer = create_normalizer(
            [{"source_field": "detector", "condition": "equals", "value": "", "severity": "Info"}],
            "Low"
        )

        scan_content = json.dumps({
            "findings": [
                {"name": "Empty", "desc": "Empty detector", "detector": ""}
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        assert findings[0]['severity'] == "Info"

    def test_multiple_findings_different_severities(self, create_normalizer):
        """Test multiple findings with different severities"""
        import json

        normalizer = create_normalizer(
            [
                {"source_field": "type", "condition": "equals", "value": "critical", "severity": "Critical"},
                {"source_field": "type", "condition": "equals", "value": "warning", "severity": "Medium"}
            ],
            "Low"
        )

        scan_content = json.dumps({
            "findings": [
                {"name": "Critical Issue", "desc": "Critical", "type": "critical"},
                {"name": "Warning Issue", "desc": "Warning", "type": "warning"},
                {"name": "Info Issue", "desc": "Info", "type": "info"}
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 3
        assert findings[0]['severity'] == "Critical"
        assert findings[1]['severity'] == "Medium"
        assert findings[2]['severity'] == "Low"  # Default

    def test_invalid_regex_pattern(self, create_normalizer):
        """Test handling invalid regex pattern"""
        import json

        normalizer = create_normalizer(
            [{"source_field": "text", "condition": "regex", "value": "[invalid", "severity": "Critical"}],
            "Low"
        )

        scan_content = json.dumps({
            "findings": [
                {"name": "Bad Regex", "desc": "Invalid pattern", "text": "test"}
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        # Should fall through to default due to invalid regex
        assert findings[0]['severity'] == "Low"


class TestConditionalSeverityRealWorld:
    """Test real-world conditional severity scenarios"""

    @pytest.fixture
    def trufflehog_normalizer(self):
        """Create normalizer mimicking TruffleHog severity logic"""
        from app.services.normalizer import NormalizerService

        config_dict = {
            "parser_name": "TruffleHog",
            "parser_version": "1.0",
            "tool_name": "TruffleHog",
            "tool_type": "TruffleHog_Scan",
            "file_format": "json",
            "json_root_path": "$.results[*]",
            "field_mappings": [
                {"source_field": "DetectorName", "target_field": "title", "data_type": "string"},
                {"source_field": "Raw", "target_field": "description", "data_type": "string"},
                {
                    "target_field": "severity",
                    "data_type": "conditional_severity",
                    "conditional_severity": [
                        {"source_field": "DetectorName", "condition": "contains", "value": "AWS", "severity": "Critical"},
                        {"source_field": "DetectorName", "condition": "contains", "value": "OAuth", "severity": "Critical"},
                        {"source_field": "DetectorName", "condition": "contains", "value": "PrivateKey", "severity": "High"},
                        {"source_field": "DetectorName", "condition": "contains", "value": "Generic", "severity": "Medium"},
                    ],
                    "default_severity": "High"
                }
            ]
        }
        config = YAMLConfig.model_validate(config_dict)
        return NormalizerService(config)

    def test_aws_credential_critical(self, trufflehog_normalizer):
        """Test AWS credentials get Critical severity"""
        import json

        scan_content = json.dumps({
            "results": [
                {"DetectorName": "AWSAccessKey", "Raw": "AKIAIOSFODNN7EXAMPLE"}
            ]
        }).encode('utf-8')

        findings = trufflehog_normalizer.normalize(scan_content)
        assert findings[0]['severity'] == "Critical"

    def test_oauth_credential_critical(self, trufflehog_normalizer):
        """Test OAuth credentials get Critical severity"""
        import json

        scan_content = json.dumps({
            "results": [
                {"DetectorName": "GitHubOAuth", "Raw": "ghp_xxxxxxxxxxxxxxxxxxxx"}
            ]
        }).encode('utf-8')

        findings = trufflehog_normalizer.normalize(scan_content)
        assert findings[0]['severity'] == "Critical"

    def test_private_key_high(self, trufflehog_normalizer):
        """Test private keys get High severity"""
        import json

        scan_content = json.dumps({
            "results": [
                {"DetectorName": "SSHPrivateKey", "Raw": "-----BEGIN RSA PRIVATE KEY-----"}
            ]
        }).encode('utf-8')

        findings = trufflehog_normalizer.normalize(scan_content)
        assert findings[0]['severity'] == "High"

    def test_generic_secret_medium(self, trufflehog_normalizer):
        """Test generic secrets get Medium severity"""
        import json

        scan_content = json.dumps({
            "results": [
                {"DetectorName": "GenericHighEntropy", "Raw": "aaaaaabbbbbbcccccc"}
            ]
        }).encode('utf-8')

        findings = trufflehog_normalizer.normalize(scan_content)
        assert findings[0]['severity'] == "Medium"

    def test_unknown_detector_default(self, trufflehog_normalizer):
        """Test unknown detector uses default severity"""
        import json

        scan_content = json.dumps({
            "results": [
                {"DetectorName": "CustomDetector", "Raw": "some_secret"}
            ]
        }).encode('utf-8')

        findings = trufflehog_normalizer.normalize(scan_content)
        assert findings[0]['severity'] == "High"  # Default
