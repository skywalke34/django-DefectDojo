"""
Parser Configuration Tests for Universal Parser V2.

Tests the YAML parser configurations for real security tools:
- Nuclei
- TruffleHog
- Trivy
- Bandit
- Semgrep

Authored by T. Walker - DefectDojo
"""

import pytest
import os
import yaml

from app.validators.yaml_validator import YAMLValidator
from app.services.normalizer import NormalizerService
from app.models.yaml_config import YAMLConfig


@pytest.fixture
def configs_path():
    """Get path to configs directory."""
    return os.path.join(os.path.dirname(__file__), "..", "configs")


@pytest.fixture
def fixtures_path():
    """Get path to fixtures directory."""
    return os.path.join(os.path.dirname(__file__), "fixtures")


def load_config(configs_path: str, config_name: str) -> YAMLConfig:
    """Load and validate a YAML config file."""
    config_path = os.path.join(configs_path, config_name)
    with open(config_path, "r") as f:
        yaml_content = f.read()
    config, _ = YAMLValidator.validate_with_checksum(yaml_content)
    return config


def load_fixture(fixtures_path: str, fixture_name: str) -> bytes:
    """Load a fixture file as bytes."""
    fixture_path = os.path.join(fixtures_path, fixture_name)
    with open(fixture_path, "rb") as f:
        return f.read()


class TestNucleiConfig:
    """Tests for Nuclei JSON parser configuration."""

    def test_config_validates(self, configs_path):
        """Test that nuclei config passes validation."""
        config = load_config(configs_path, "nuclei_json.yaml")
        assert config.parser_name == "NucleiJSON"
        assert config.tool_type == "Nuclei Scan"
        assert config.file_format == "json"

    def test_parse_nuclei_sample(self, configs_path, fixtures_path):
        """Test parsing sample Nuclei output."""
        config = load_config(configs_path, "nuclei_json.yaml")
        scan_content = load_fixture(fixtures_path, "sample_nuclei.json")

        normalizer = NormalizerService(config)
        findings = normalizer.normalize(scan_content)

        assert len(findings) == 2

        # Check first finding (Log4j RCE)
        log4j = findings[0]
        assert log4j["title"] == "Apache Log4j RCE"
        assert log4j["severity"] == "Critical"
        assert "Log4j2" in log4j["description"]

        # Check CVSS was extracted
        assert "cvssv3" in log4j
        assert log4j["cvssv3_score"] == 10.0

        # Check second finding (Admin Panel)
        admin = findings[1]
        assert admin["title"] == "Admin Panel Detected"
        assert admin["severity"] == "Info"


class TestBanditConfig:
    """Tests for Bandit JSON parser configuration."""

    def test_config_validates(self, configs_path):
        """Test that bandit config passes validation."""
        config = load_config(configs_path, "bandit_json.yaml")
        assert config.parser_name == "BanditJSON"
        assert config.tool_type == "Bandit Scan"

    def test_parse_bandit_sample(self, configs_path, fixtures_path):
        """Test parsing sample Bandit output."""
        config = load_config(configs_path, "bandit_json.yaml")
        scan_content = load_fixture(fixtures_path, "sample_bandit.json")

        normalizer = NormalizerService(config)
        findings = normalizer.normalize(scan_content)

        assert len(findings) == 3

        # Check high severity finding
        high_finding = next(f for f in findings if f["severity"] == "High")
        assert "hardcoded" in high_finding["title"].lower() or "password" in high_finding["title"].lower()
        assert high_finding["file_path"] == "app/config.py"
        assert high_finding["line"] == 42

        # Check medium severity finding
        medium_finding = next(f for f in findings if f["severity"] == "Medium")
        assert "exec" in medium_finding["title"].lower()

        # Check static finding flags
        for finding in findings:
            assert finding.get("static_finding") is True
            assert finding.get("dynamic_finding") is False


class TestSemgrepConfig:
    """Tests for Semgrep JSON parser configuration."""

    def test_config_validates(self, configs_path):
        """Test that semgrep config passes validation."""
        config = load_config(configs_path, "semgrep_json.yaml")
        assert config.parser_name == "SemgrepJSON"
        assert config.tool_type == "Semgrep JSON Report"

    def test_parse_semgrep_sample(self, configs_path, fixtures_path):
        """Test parsing sample Semgrep output."""
        config = load_config(configs_path, "semgrep_json.yaml")
        scan_content = load_fixture(fixtures_path, "sample_semgrep.json")

        normalizer = NormalizerService(config)
        findings = normalizer.normalize(scan_content)

        assert len(findings) == 2

        # Check exec finding (ERROR = High)
        exec_finding = next(f for f in findings if "exec" in f["title"])
        assert exec_finding["severity"] == "High"
        assert exec_finding["file_path"] == "app/utils.py"
        assert exec_finding["line"] == 15

        # Check password finding (WARNING = Medium)
        password_finding = next(f for f in findings if "password" in f["title"])
        assert password_finding["severity"] == "Medium"


class TestTrivyConfig:
    """Tests for Trivy JSON parser configuration."""

    def test_config_validates(self, configs_path):
        """Test that trivy config passes validation."""
        config = load_config(configs_path, "trivy_json.yaml")
        assert config.parser_name == "TrivyJSON"
        assert config.tool_type == "Trivy Scan"

    def test_parse_trivy_sample(self, configs_path, fixtures_path):
        """Test parsing sample Trivy output."""
        config = load_config(configs_path, "trivy_json.yaml")
        scan_content = load_fixture(fixtures_path, "sample_trivy.json")

        normalizer = NormalizerService(config)
        findings = normalizer.normalize(scan_content)

        assert len(findings) == 2

        # Check Log4j finding
        log4j = next(f for f in findings if "CVE-2021-44228" in f["title"])
        assert log4j["severity"] == "Critical"
        assert log4j["component_name"] == "log4j"
        assert log4j["component_version"] == "2.14.1"
        assert "2.17.0" in log4j.get("mitigation", "")

        # Check Spring finding
        spring = next(f for f in findings if "CVE-2022-22965" in f["title"])
        assert spring["severity"] == "High"
        assert spring["component_name"] == "spring-framework"


class TestTruffleHogConfig:
    """Tests for TruffleHog JSON parser configuration."""

    def test_config_validates(self, configs_path):
        """Test that trufflehog config passes validation."""
        config = load_config(configs_path, "trufflehog_json.yaml")
        assert config.parser_name == "TruffleHogJSON"
        assert config.tool_type == "TruffleHog Scan"

    def test_config_has_version_detection(self, configs_path):
        """Test that config has version detection for v2/v3."""
        config = load_config(configs_path, "trufflehog_json.yaml")
        assert config.format_versions is not None
        assert len(config.format_versions) == 2

        versions = [fv.version for fv in config.format_versions]
        assert "v3" in versions
        assert "v2" in versions


class TestAllConfigsValidate:
    """Tests that all config files in configs/ directory are valid."""

    def test_all_configs_validate(self, configs_path):
        """Test that all YAML configs pass validation."""
        config_files = [
            "nuclei_json.yaml",
            "trufflehog_json.yaml",
            "trivy_json.yaml",
            "bandit_json.yaml",
            "semgrep_json.yaml",
            "acunetix360_json.yaml",
        ]

        for config_file in config_files:
            config_path = os.path.join(configs_path, config_file)
            if os.path.exists(config_path):
                with open(config_path, "r") as f:
                    yaml_content = f.read()

                # Should not raise
                config, checksum = YAMLValidator.validate_with_checksum(yaml_content)
                assert config.parser_name is not None
                assert checksum is not None


class TestConfigRequiredFields:
    """Tests that configs have required DefectDojo fields mapped."""

    @pytest.fixture
    def all_configs(self, configs_path):
        """Load all config files."""
        configs = {}
        config_files = [
            "nuclei_json.yaml",
            "trufflehog_json.yaml",
            "trivy_json.yaml",
            "bandit_json.yaml",
            "semgrep_json.yaml",
        ]
        for config_file in config_files:
            config_path = os.path.join(configs_path, config_file)
            if os.path.exists(config_path):
                configs[config_file] = load_config(configs_path, config_file)
        return configs

    def test_configs_have_title_mapping(self, all_configs):
        """Test that all configs map a title field."""
        for name, config in all_configs.items():
            mappings = config.get_active_field_mappings()
            target_fields = [m.target_field for m in mappings]

            # Either direct title or via format_versions
            has_title = "title" in target_fields
            if config.format_versions:
                for fv in config.format_versions:
                    fv_targets = [m.target_field for m in fv.field_mappings]
                    if "title" in fv_targets:
                        has_title = True

            assert has_title, f"{name} missing title mapping"

    def test_configs_have_severity_mapping(self, all_configs):
        """Test that all configs map a severity field."""
        for name, config in all_configs.items():
            mappings = config.get_active_field_mappings()
            target_fields = [m.target_field for m in mappings]

            has_severity = "severity" in target_fields
            if config.format_versions:
                for fv in config.format_versions:
                    fv_targets = [m.target_field for m in fv.field_mappings]
                    if "severity" in fv_targets:
                        has_severity = True

            assert has_severity, f"{name} missing severity mapping"

    def test_configs_have_description_mapping(self, all_configs):
        """Test that all configs map a description field."""
        for name, config in all_configs.items():
            mappings = config.get_active_field_mappings()
            target_fields = [m.target_field for m in mappings]

            has_description = "description" in target_fields
            if config.format_versions:
                for fv in config.format_versions:
                    fv_targets = [m.target_field for m in fv.field_mappings]
                    if "description" in fv_targets:
                        has_description = True

            assert has_description, f"{name} missing description mapping"
