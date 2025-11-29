"""
Tests for State Machine feature.

This tests the state_mapping field that maps a single input value
to multiple output fields - used for status/state conversion.

Use cases:
- Trivy: 8 status states → multiple boolean outputs (active, verified, is_mitigated, false_p)
- CycloneDX: Analysis state → finding status fields
- Qualys: Status conversion between systems
"""

import pytest
from pydantic import ValidationError as PydanticValidationError
from app.models.yaml_config import FieldMapping, YAMLConfig
from app.services.normalizer import NormalizerService


# =============================================================================
# FieldMapping Model Tests - state_mapping validation
# =============================================================================

class TestFieldMappingStateMachine:
    """Test FieldMapping Pydantic model with state_mapping."""

    def test_state_machine_valid(self):
        """Test valid state_machine configuration."""
        mapping = FieldMapping(
            source_field="status",
            target_field="_status",
            data_type="state_machine",
            state_mapping={
                "not_affected": {"active": False, "verified": True},
                "affected": {"active": True, "verified": True}
            }
        )
        assert mapping.data_type == "state_machine"
        assert len(mapping.state_mapping) == 2

    def test_state_machine_requires_state_mapping(self):
        """Test that state_machine requires state_mapping."""
        with pytest.raises(PydanticValidationError) as exc_info:
            FieldMapping(
                source_field="status",
                target_field="_status",
                data_type="state_machine"
                # No state_mapping provided - should raise
            )
        assert "state_mapping is required" in str(exc_info.value)

    def test_state_machine_with_default(self):
        """Test state_machine with default fallback state."""
        mapping = FieldMapping(
            source_field="status",
            target_field="_status",
            data_type="state_machine",
            state_mapping={
                "known_state": {"active": False},
                "default": {"active": True}
            }
        )
        assert "default" in mapping.state_mapping

    def test_state_mapping_values_must_be_dicts(self):
        """Test that state_mapping values must be dictionaries."""
        with pytest.raises(PydanticValidationError) as exc_info:
            FieldMapping(
                source_field="status",
                target_field="_status",
                data_type="state_machine",
                state_mapping={
                    "bad_state": "not_a_dict"  # Should be a dict
                }
            )
        # Pydantic V2 says "Input should be a valid dictionary"
        assert "valid dictionary" in str(exc_info.value)

    def test_virtual_target_field_allowed(self):
        """Test that virtual target fields (prefixed _) are allowed."""
        mapping = FieldMapping(
            source_field="status",
            target_field="_status_mapping",
            data_type="state_machine",
            state_mapping={
                "active": {"active": True}
            }
        )
        assert mapping.target_field == "_status_mapping"

    def test_state_machine_with_source_fields(self):
        """Test state_machine with priority chain source_fields."""
        mapping = FieldMapping(
            source_fields=["Status", "analysis.state", "state"],
            target_field="_status",
            data_type="state_machine",
            state_mapping={
                "affected": {"active": True}
            }
        )
        assert mapping.source_fields == ["Status", "analysis.state", "state"]


# =============================================================================
# Normalizer State Machine Tests
# =============================================================================

class TestNormalizerStateMachine:
    """Test NormalizerService handling of state_machine."""

    @pytest.fixture
    def trivy_style_config(self):
        """Trivy-style config with comprehensive state machine."""
        return {
            "parser_name": "TrivyStyleParser",
            "parser_version": "1.0",
            "tool_name": "Trivy Style",
            "tool_type": "Trivy_JSON",
            "file_format": "json",
            "json_root_path": "$.vulnerabilities[*]",
            "field_mappings": [
                {
                    "source_field": "VulnerabilityID",
                    "target_field": "title",
                    "data_type": "string"
                },
                {
                    "source_field": "Description",
                    "target_field": "description",
                    "data_type": "string"
                },
                {
                    "source_field": "Severity",
                    "target_field": "severity",
                    "data_type": "severity",
                    "severity_mapping": {
                        "CRITICAL": "Critical",
                        "HIGH": "High",
                        "MEDIUM": "Medium",
                        "LOW": "Low",
                        "UNKNOWN": "Info"
                    }
                },
                {
                    # State machine for status conversion
                    "source_field": "Status",
                    "target_field": "_status",
                    "data_type": "state_machine",
                    "state_mapping": {
                        "not_affected": {
                            "active": False,
                            "verified": True,
                            "is_mitigated": True
                        },
                        "false_positive": {
                            "false_p": True,
                            "active": False
                        },
                        "affected": {
                            "active": True,
                            "verified": True
                        },
                        "fixed": {
                            "active": True,
                            "verified": True,
                            "is_mitigated": False
                        },
                        "under_investigation": {
                            "active": True,
                            "verified": False
                        },
                        "will_not_fix": {
                            "active": True,
                            "risk_accepted": True
                        },
                        "default": {
                            "active": True,
                            "verified": False
                        }
                    }
                }
            ]
        }

    def test_state_machine_not_affected(self, trivy_style_config):
        """Test not_affected state sets multiple fields."""
        config = YAMLConfig(**trivy_style_config)
        service = NormalizerService(config)

        scan_data = b'''{"vulnerabilities": [{
            "VulnerabilityID": "CVE-2021-1234",
            "Description": "Test vulnerability",
            "Severity": "HIGH",
            "Status": "not_affected"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        assert findings[0]["active"] is False
        assert findings[0]["verified"] is True
        assert findings[0]["is_mitigated"] is True

    def test_state_machine_false_positive(self, trivy_style_config):
        """Test false_positive state."""
        config = YAMLConfig(**trivy_style_config)
        service = NormalizerService(config)

        scan_data = b'''{"vulnerabilities": [{
            "VulnerabilityID": "CVE-2021-1234",
            "Description": "Test vulnerability",
            "Severity": "HIGH",
            "Status": "false_positive"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        assert findings[0]["false_p"] is True
        assert findings[0]["active"] is False

    def test_state_machine_affected(self, trivy_style_config):
        """Test affected state."""
        config = YAMLConfig(**trivy_style_config)
        service = NormalizerService(config)

        scan_data = b'''{"vulnerabilities": [{
            "VulnerabilityID": "CVE-2021-1234",
            "Description": "Test vulnerability",
            "Severity": "HIGH",
            "Status": "affected"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        assert findings[0]["active"] is True
        assert findings[0]["verified"] is True

    def test_state_machine_uses_default(self, trivy_style_config):
        """Test unknown state falls back to default."""
        config = YAMLConfig(**trivy_style_config)
        service = NormalizerService(config)

        scan_data = b'''{"vulnerabilities": [{
            "VulnerabilityID": "CVE-2021-1234",
            "Description": "Test vulnerability",
            "Severity": "HIGH",
            "Status": "unknown_new_status"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        # Should use default: active=True, verified=False
        assert findings[0]["active"] is True
        assert findings[0]["verified"] is False

    def test_state_machine_multiple_findings(self, trivy_style_config):
        """Test state machine works correctly across multiple findings."""
        config = YAMLConfig(**trivy_style_config)
        service = NormalizerService(config)

        scan_data = b'''{"vulnerabilities": [
            {"VulnerabilityID": "CVE-1", "Description": "Desc 1", "Severity": "HIGH", "Status": "affected"},
            {"VulnerabilityID": "CVE-2", "Description": "Desc 2", "Severity": "MEDIUM", "Status": "not_affected"},
            {"VulnerabilityID": "CVE-3", "Description": "Desc 3", "Severity": "LOW", "Status": "false_positive"}
        ]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 3

        # CVE-1: affected
        assert findings[0]["active"] is True
        assert findings[0]["verified"] is True

        # CVE-2: not_affected
        assert findings[1]["active"] is False
        assert findings[1]["is_mitigated"] is True

        # CVE-3: false_positive
        assert findings[2]["false_p"] is True
        assert findings[2]["active"] is False


# =============================================================================
# State Machine Edge Cases
# =============================================================================

class TestStateMachineEdgeCases:
    """Edge cases for state machine."""

    @pytest.fixture
    def simple_config(self):
        """Simple state machine config for edge case testing."""
        return {
            "parser_name": "SimpleParser",
            "parser_version": "1.0",
            "tool_name": "Simple",
            "tool_type": "Simple_JSON",
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
                    "source_field": "level",
                    "target_field": "severity",
                    "data_type": "severity",
                    "severity_mapping": {"high": "High", "medium": "Medium", "low": "Low"}
                },
                {
                    "source_field": "state",
                    "target_field": "_state",
                    "data_type": "state_machine",
                    "state_mapping": {
                        "open": {"active": True},
                        "closed": {"active": False}
                    }
                }
            ]
        }

    def test_missing_source_field_skips_state_machine(self, simple_config):
        """Test that missing source field doesn't error, just skips."""
        config = YAMLConfig(**simple_config)
        service = NormalizerService(config)

        scan_data = b'''{"items": [{
            "name": "Test",
            "desc": "Description",
            "level": "high"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        # No state machine outputs should be set
        assert "active" not in findings[0]

    def test_null_source_value_skips_state_machine(self, simple_config):
        """Test that null source value skips state machine."""
        config = YAMLConfig(**simple_config)
        service = NormalizerService(config)

        scan_data = b'''{"items": [{
            "name": "Test",
            "desc": "Description",
            "level": "high",
            "state": null
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        assert "active" not in findings[0]

    def test_unmatched_state_no_default_logs_warning(self, simple_config):
        """Test that unmatched state with no default skips without error."""
        config = YAMLConfig(**simple_config)
        service = NormalizerService(config)

        scan_data = b'''{"items": [{
            "name": "Test",
            "desc": "Description",
            "level": "high",
            "state": "unknown_state"
        }]}'''

        # Should not raise, just log warning and skip
        findings = service.normalize(scan_data)

        assert len(findings) == 1
        # No active field since state didn't match
        assert "active" not in findings[0]

    def test_numeric_state_value_converted_to_string(self):
        """Test that numeric state values are converted to string for lookup."""
        config_dict = {
            "parser_name": "NumericState",
            "parser_version": "1.0",
            "tool_name": "Numeric",
            "tool_type": "Numeric_JSON",
            "file_format": "json",
            "json_root_path": "$.items[*]",
            "field_mappings": [
                {"source_field": "name", "target_field": "title", "data_type": "string"},
                {"source_field": "desc", "target_field": "description", "data_type": "string"},
                {"source_field": "level", "target_field": "severity", "data_type": "severity",
                 "severity_mapping": {"high": "High"}},
                {
                    "source_field": "status_code",
                    "target_field": "_status",
                    "data_type": "state_machine",
                    "state_mapping": {
                        "1": {"active": True},
                        "0": {"active": False}
                    }
                }
            ]
        }
        config = YAMLConfig(**config_dict)
        service = NormalizerService(config)

        scan_data = b'''{"items": [{
            "name": "Test",
            "desc": "Description",
            "level": "high",
            "status_code": 1
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        assert findings[0]["active"] is True

    def test_state_machine_with_priority_chain(self):
        """Test state machine with source_fields priority chain."""
        config_dict = {
            "parser_name": "PriorityState",
            "parser_version": "1.0",
            "tool_name": "Priority",
            "tool_type": "Priority_JSON",
            "file_format": "json",
            "json_root_path": "$.items[*]",
            "field_mappings": [
                {"source_field": "name", "target_field": "title", "data_type": "string"},
                {"source_field": "desc", "target_field": "description", "data_type": "string"},
                {"source_field": "level", "target_field": "severity", "data_type": "severity",
                 "severity_mapping": {"high": "High"}},
                {
                    "source_fields": ["status", "analysis.state", "state"],
                    "target_field": "_status",
                    "data_type": "state_machine",
                    "state_mapping": {
                        "active": {"active": True},
                        "inactive": {"active": False}
                    }
                }
            ]
        }
        config = YAMLConfig(**config_dict)
        service = NormalizerService(config)

        # Only analysis.state exists (second in priority)
        scan_data = b'''{"items": [{
            "name": "Test",
            "desc": "Description",
            "level": "high",
            "analysis": {"state": "inactive"}
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        assert findings[0]["active"] is False

    def test_state_machine_single_output_field(self):
        """Test state machine that outputs to single field."""
        config_dict = {
            "parser_name": "SingleOutput",
            "parser_version": "1.0",
            "tool_name": "Single",
            "tool_type": "Single_JSON",
            "file_format": "json",
            "json_root_path": "$.items[*]",
            "field_mappings": [
                {"source_field": "name", "target_field": "title", "data_type": "string"},
                {"source_field": "desc", "target_field": "description", "data_type": "string"},
                {"source_field": "level", "target_field": "severity", "data_type": "severity",
                 "severity_mapping": {"high": "High"}},
                {
                    "source_field": "status",
                    "target_field": "_verified_state",
                    "data_type": "state_machine",
                    "state_mapping": {
                        "confirmed": {"verified": True},
                        "unconfirmed": {"verified": False}
                    }
                }
            ]
        }
        config = YAMLConfig(**config_dict)
        service = NormalizerService(config)

        scan_data = b'''{"items": [{
            "name": "Test",
            "desc": "Description",
            "level": "high",
            "status": "confirmed"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        assert findings[0]["verified"] is True


# =============================================================================
# State Machine with Other Features
# =============================================================================

class TestStateMachineCombinations:
    """Test state machine combined with other features."""

    def test_state_machine_with_fixed_value(self):
        """Test state machine alongside fixed_value fields."""
        config_dict = {
            "parser_name": "CombinedParser",
            "parser_version": "1.0",
            "tool_name": "Combined",
            "tool_type": "Combined_JSON",
            "file_format": "json",
            "json_root_path": "$.items[*]",
            "field_mappings": [
                {"source_field": "name", "target_field": "title", "data_type": "string"},
                {"source_field": "desc", "target_field": "description", "data_type": "string"},
                # Fixed severity
                {"target_field": "severity", "data_type": "string", "fixed_value": "High"},
                # State machine for status
                {
                    "source_field": "status",
                    "target_field": "_status",
                    "data_type": "state_machine",
                    "state_mapping": {
                        "open": {"active": True},
                        "closed": {"active": False}
                    }
                }
            ]
        }
        config = YAMLConfig(**config_dict)
        service = NormalizerService(config)

        scan_data = b'''{"items": [{
            "name": "Test",
            "desc": "Description",
            "status": "closed"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        assert findings[0]["severity"] == "High"  # From fixed_value
        assert findings[0]["active"] is False  # From state_machine

    def test_state_machine_with_conditional_append(self):
        """Test state machine alongside append_if_present."""
        config_dict = {
            "parser_name": "AppendCombined",
            "parser_version": "1.0",
            "tool_name": "Append Combined",
            "tool_type": "Append_JSON",
            "file_format": "json",
            "json_root_path": "$.items[*]",
            "field_mappings": [
                {"source_field": "name", "target_field": "title", "data_type": "string"},
                {
                    "source_field": "base_desc",
                    "target_field": "description",
                    "data_type": "string",
                    "append_if_present": [
                        {"source_field": "extra", "prefix": "\n\n"}
                    ]
                },
                {"source_field": "level", "target_field": "severity", "data_type": "severity",
                 "severity_mapping": {"high": "High"}},
                {
                    "source_field": "status",
                    "target_field": "_status",
                    "data_type": "state_machine",
                    "state_mapping": {
                        "verified": {"verified": True, "active": True}
                    }
                }
            ]
        }
        config = YAMLConfig(**config_dict)
        service = NormalizerService(config)

        scan_data = b'''{"items": [{
            "name": "Test",
            "base_desc": "Base description",
            "extra": "Additional info",
            "level": "high",
            "status": "verified"
        }]}'''

        findings = service.normalize(scan_data)

        assert len(findings) == 1
        assert "Base description\n\nAdditional info" == findings[0]["description"]
        assert findings[0]["verified"] is True
        assert findings[0]["active"] is True
