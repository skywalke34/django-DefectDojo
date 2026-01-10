"""
End-to-End API Tests for Universal Parser V2.

Tests the FastAPI endpoints:
- GET /health
- POST /api/validate-yaml
- POST /api/parse
- POST /api/import (with mocked DefectDojo)

Authored by T. Walker - DefectDojo
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch, MagicMock
import json
import os

from app.main import app


@pytest.fixture
def client():
    """Create test client for FastAPI app."""
    return TestClient(app)


@pytest.fixture
def sample_yaml_config():
    """Return a minimal valid YAML config for testing."""
    return """
parser_name: "TestParser"
parser_version: "1.0"
tool_name: "Test Tool"
tool_type: "Test_Scanner"
file_format: "json"
json_root_path: "$.findings[*]"
field_mappings:
  - source_field: "name"
    target_field: "title"
    data_type: "string"
  - source_field: "desc"
    target_field: "description"
    data_type: "string"
  - source_field: "sev"
    target_field: "severity"
    data_type: "severity"
    severity_mapping:
      high: "High"
      medium: "Medium"
      low: "Low"
deduplication_fields:
  - "title"
"""


@pytest.fixture
def sample_scan_data():
    """Return sample scan data for testing."""
    return {
        "findings": [
            {
                "name": "SQL Injection",
                "desc": "SQL injection vulnerability found",
                "sev": "high"
            },
            {
                "name": "XSS",
                "desc": "Cross-site scripting found",
                "sev": "medium"
            }
        ]
    }


class TestHealthEndpoint:
    """Tests for the /health endpoint."""

    def test_health_check_returns_healthy(self, client):
        """Test that health check returns healthy status."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "universal-parser-v2"
        assert "version" in data


class TestValidateYamlEndpoint:
    """Tests for the /api/validate-yaml endpoint."""

    def test_validate_valid_yaml(self, client, sample_yaml_config):
        """Test validation of a valid YAML config."""
        response = client.post(
            "/api/validate-yaml",
            files={"yaml_file": ("test.yaml", sample_yaml_config, "text/yaml")}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "valid"
        assert data["config"]["parser_name"] == "TestParser"
        assert data["config"]["tool_type"] == "Test_Scanner"
        assert "yaml_checksum" in data["config"]

    def test_validate_invalid_yaml_syntax(self, client):
        """Test validation rejects invalid YAML syntax."""
        invalid_yaml = "invalid: yaml: syntax:"
        response = client.post(
            "/api/validate-yaml",
            files={"yaml_file": ("test.yaml", invalid_yaml, "text/yaml")}
        )
        assert response.status_code == 400

    def test_validate_missing_required_fields(self, client):
        """Test validation rejects YAML missing required fields."""
        incomplete_yaml = """
parser_name: "Test"
parser_version: "1.0"
"""
        response = client.post(
            "/api/validate-yaml",
            files={"yaml_file": ("test.yaml", incomplete_yaml, "text/yaml")}
        )
        assert response.status_code == 400


class TestParseEndpoint:
    """Tests for the /api/parse endpoint."""

    def test_parse_json_scan(self, client, sample_yaml_config, sample_scan_data):
        """Test parsing a JSON scan file."""
        scan_content = json.dumps(sample_scan_data)

        response = client.post(
            "/api/parse",
            files={
                "scan_file": ("scan.json", scan_content, "application/json"),
                "yaml_file": ("config.yaml", sample_yaml_config, "text/yaml")
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["statistics"]["total_findings"] == 2
        assert len(data["findings"]) == 2

        # Check first finding
        finding = data["findings"][0]
        assert finding["title"] == "SQL Injection"
        assert finding["severity"] == "High"

    def test_parse_with_limit(self, client, sample_yaml_config, sample_scan_data):
        """Test parsing with limit parameter."""
        scan_content = json.dumps(sample_scan_data)

        response = client.post(
            "/api/parse",
            files={
                "scan_file": ("scan.json", scan_content, "application/json"),
                "yaml_file": ("config.yaml", sample_yaml_config, "text/yaml")
            },
            data={"limit": 1}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["statistics"]["total_findings"] == 2
        assert data["statistics"]["returned_findings"] == 1
        assert data["statistics"]["limited"] is True
        assert len(data["findings"]) == 1

    def test_parse_empty_findings(self, client, sample_yaml_config):
        """Test parsing scan with no findings returns error.

        Note: The JSON reader treats empty arrays as "no matches found"
        to catch misconfigured JSONPaths. This is by design - a scan
        with no vulnerabilities should ideally use a different indicator.
        """
        scan_content = json.dumps({"findings": []})

        response = client.post(
            "/api/parse",
            files={
                "scan_file": ("scan.json", scan_content, "application/json"),
                "yaml_file": ("config.yaml", sample_yaml_config, "text/yaml")
            }
        )

        # Empty findings array is treated as error (no matches found)
        assert response.status_code == 500

    def test_parse_invalid_json(self, client, sample_yaml_config):
        """Test parsing invalid JSON scan file."""
        response = client.post(
            "/api/parse",
            files={
                "scan_file": ("scan.json", "not valid json", "application/json"),
                "yaml_file": ("config.yaml", sample_yaml_config, "text/yaml")
            }
        )

        assert response.status_code == 500  # Internal error from JSON parse failure


class TestImportEndpoint:
    """Tests for the /api/import endpoint."""

    def test_import_requires_test_id_or_product(self, client, sample_yaml_config, sample_scan_data):
        """Test that import requires test_id or product_name+engagement_name."""
        scan_content = json.dumps(sample_scan_data)

        response = client.post(
            "/api/import",
            files={
                "scan_file": ("scan.json", scan_content, "application/json"),
                "yaml_file": ("config.yaml", sample_yaml_config, "text/yaml")
            },
            data={
                "defectdojo_url": "http://localhost:8080",
                "defectdojo_api_token": "test-token"
                # Missing test_id AND product_name/engagement_name
            }
        )

        assert response.status_code == 400
        data = response.json()
        assert "test_id" in data["detail"]["message"]

    @patch("app.main.DefectDojoClient")
    def test_import_with_test_id(self, mock_client_class, client, sample_yaml_config, sample_scan_data):
        """Test import with existing test_id."""
        # Setup mock
        mock_client = AsyncMock()
        mock_client.universal_parser_v2_reimport = AsyncMock(return_value={
            "test_import_finding_action": {
                "created": 2,
                "updated": 0,
                "closed": 0,
                "reactivated": 0,
                "untouched": 0
            }
        })
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_class.return_value = mock_client

        scan_content = json.dumps(sample_scan_data)

        response = client.post(
            "/api/import",
            files={
                "scan_file": ("scan.json", scan_content, "application/json"),
                "yaml_file": ("config.yaml", sample_yaml_config, "text/yaml")
            },
            data={
                "defectdojo_url": "http://localhost:8080",
                "defectdojo_api_token": "test-token",
                "test_id": 123
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["results"]["findings_parsed"] == 2
        assert data["results"]["findings_created"] == 2
        assert data["defectdojo"]["test_id"] == 123

    @patch("app.main.DefectDojoClient")
    def test_import_with_auto_create(self, mock_client_class, client, sample_yaml_config, sample_scan_data):
        """Test import with auto-create product/engagement/test."""
        # Setup mock
        mock_client = AsyncMock()
        mock_client.find_or_create_product = AsyncMock(return_value={"id": 1, "name": "Test Product"})
        mock_client.find_or_create_engagement = AsyncMock(return_value={"id": 10, "name": "Test Engagement"})
        mock_client.find_or_create_test = AsyncMock(return_value={"id": 100, "title": "Test Scan"})
        mock_client.universal_parser_v2_reimport = AsyncMock(return_value={
            "test_import_finding_action": {
                "created": 2,
                "updated": 0,
                "closed": 0,
                "reactivated": 0,
                "untouched": 0
            }
        })
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_class.return_value = mock_client

        scan_content = json.dumps(sample_scan_data)

        response = client.post(
            "/api/import",
            files={
                "scan_file": ("scan.json", scan_content, "application/json"),
                "yaml_file": ("config.yaml", sample_yaml_config, "text/yaml")
            },
            data={
                "defectdojo_url": "http://localhost:8080",
                "defectdojo_api_token": "test-token",
                "product_name": "Test Product",
                "engagement_name": "Test Engagement"
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["defectdojo"]["test_id"] == 100

        # Verify auto-create methods were called
        mock_client.find_or_create_product.assert_called_once()
        mock_client.find_or_create_engagement.assert_called_once()
        mock_client.find_or_create_test.assert_called_once()


class TestParseWithRealFixtures:
    """Tests using real fixture files."""

    @pytest.fixture
    def fixtures_path(self):
        """Get path to fixtures directory."""
        return os.path.join(os.path.dirname(__file__), "fixtures")

    @pytest.fixture
    def configs_path(self):
        """Get path to configs directory."""
        return os.path.join(os.path.dirname(__file__), "..", "configs")

    def test_parse_acunetix_sample(self, client, fixtures_path, configs_path):
        """Test parsing sample Acunetix scan with real config."""
        scan_path = os.path.join(fixtures_path, "sample_acunetix.json")
        config_path = os.path.join(configs_path, "acunetix360_json.yaml")

        # Skip if files don't exist
        if not os.path.exists(scan_path) or not os.path.exists(config_path):
            pytest.skip("Fixture files not found")

        with open(scan_path, "r") as scan_file, open(config_path, "r") as config_file:
            response = client.post(
                "/api/parse",
                files={
                    "scan_file": ("scan.json", scan_file.read(), "application/json"),
                    "yaml_file": ("config.yaml", config_file.read(), "text/yaml")
                }
            )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["statistics"]["total_findings"] == 3

        # Check findings
        findings = data["findings"]
        titles = [f["title"] for f in findings]
        assert "SQL Injection" in titles
        assert "Cross-Site Scripting (XSS)" in titles

        # Check CVSS was extracted
        sql_finding = next(f for f in findings if f["title"] == "SQL Injection")
        assert sql_finding["severity"] == "Critical"
        assert "cvssv3" in sql_finding
        assert sql_finding["cvssv3_score"] == 10.0


class TestErrorHandling:
    """Tests for error handling scenarios."""

    def test_missing_yaml_file(self, client, sample_scan_data):
        """Test error when YAML file is missing."""
        scan_content = json.dumps(sample_scan_data)

        response = client.post(
            "/api/parse",
            files={
                "scan_file": ("scan.json", scan_content, "application/json")
            }
        )

        assert response.status_code == 422  # Unprocessable Entity

    def test_missing_scan_file(self, client, sample_yaml_config):
        """Test error when scan file is missing."""
        response = client.post(
            "/api/parse",
            files={
                "yaml_file": ("config.yaml", sample_yaml_config, "text/yaml")
            }
        )

        assert response.status_code == 422  # Unprocessable Entity


class TestImportOptions:
    """Tests for import endpoint options."""

    @patch("app.main.DefectDojoClient")
    def test_import_with_scan_date(self, mock_client_class, client, sample_yaml_config, sample_scan_data):
        """Test import with custom scan_date."""
        mock_client = AsyncMock()
        mock_client.universal_parser_v2_reimport = AsyncMock(return_value={
            "test_import_finding_action": {"created": 2}
        })
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_class.return_value = mock_client

        scan_content = json.dumps(sample_scan_data)

        response = client.post(
            "/api/import",
            files={
                "scan_file": ("scan.json", scan_content, "application/json"),
                "yaml_file": ("config.yaml", sample_yaml_config, "text/yaml")
            },
            data={
                "defectdojo_url": "http://localhost:8080",
                "defectdojo_api_token": "test-token",
                "test_id": 123,
                "scan_date": "2024-01-15"
            }
        )

        assert response.status_code == 200

        # Verify scan_date was passed to client
        call_kwargs = mock_client.universal_parser_v2_reimport.call_args[1]
        assert call_kwargs["scan_date"] == "2024-01-15"

    @patch("app.main.DefectDojoClient")
    def test_import_with_options(self, mock_client_class, client, sample_yaml_config, sample_scan_data):
        """Test import with close_old_findings and verified options."""
        mock_client = AsyncMock()
        mock_client.universal_parser_v2_reimport = AsyncMock(return_value={
            "test_import_finding_action": {"created": 2}
        })
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_class.return_value = mock_client

        scan_content = json.dumps(sample_scan_data)

        response = client.post(
            "/api/import",
            files={
                "scan_file": ("scan.json", scan_content, "application/json"),
                "yaml_file": ("config.yaml", sample_yaml_config, "text/yaml")
            },
            data={
                "defectdojo_url": "http://localhost:8080",
                "defectdojo_api_token": "test-token",
                "test_id": 123,
                "close_old_findings": False,
                "verified": True,
                "active": False,
                "version": "1.2.3"
            }
        )

        assert response.status_code == 200

        # Verify options were passed to client
        call_kwargs = mock_client.universal_parser_v2_reimport.call_args[1]
        assert call_kwargs["close_old_findings"] is False
        assert call_kwargs["verified"] is True
        assert call_kwargs["active"] is False
        assert call_kwargs["version"] == "1.2.3"
