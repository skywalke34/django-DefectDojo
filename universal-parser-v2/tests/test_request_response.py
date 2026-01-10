"""
Unit tests for Request/Response pair handling.

Tests:
- RequestResponseMapping model validation
- Separate field mode (request_field + response_field)
- Combined field mode
- Array field mode
- Normalizer integration
- Edge cases and error handling

Authored by T. Walker - DefectDojo
"""

import pytest
from pydantic import ValidationError as PydanticValidationError
from app.models.yaml_config import RequestResponseMapping, YAMLConfig


class TestRequestResponseMappingModel:
    """Test RequestResponseMapping Pydantic model"""

    def test_separate_fields_mode_valid(self):
        """Test valid separate fields configuration"""
        mapping = RequestResponseMapping(
            request_field="raw_request",
            response_field="raw_response"
        )
        assert mapping.request_field == "raw_request"
        assert mapping.response_field == "raw_response"
        assert mapping.combined_field is None
        assert mapping.array_field is None

    def test_combined_field_mode_valid(self):
        """Test valid combined field configuration"""
        mapping = RequestResponseMapping(
            combined_field="http_exchange",
            request_key="req",
            response_key="resp"
        )
        assert mapping.combined_field == "http_exchange"
        assert mapping.request_key == "req"
        assert mapping.response_key == "resp"

    def test_array_field_mode_valid(self):
        """Test valid array field configuration"""
        mapping = RequestResponseMapping(
            array_field="http_messages",
            request_key="request",
            response_key="response"
        )
        assert mapping.array_field == "http_messages"
        assert mapping.request_key == "request"
        assert mapping.response_key == "response"

    def test_default_keys(self):
        """Test default request/response keys"""
        mapping = RequestResponseMapping(
            combined_field="data"
        )
        assert mapping.request_key == "request"
        assert mapping.response_key == "response"

    def test_no_mode_configured_fails(self):
        """Test that missing all fields fails validation"""
        with pytest.raises(PydanticValidationError) as exc_info:
            RequestResponseMapping()
        assert "requires one of" in str(exc_info.value).lower()

    def test_multiple_modes_fails(self):
        """Test that multiple modes fail validation"""
        with pytest.raises(PydanticValidationError) as exc_info:
            RequestResponseMapping(
                request_field="req",
                response_field="resp",
                combined_field="data"
            )
        assert "only one mode" in str(exc_info.value).lower()

    def test_separate_mode_missing_response_fails(self):
        """Test that separate mode requires both fields"""
        with pytest.raises(PydanticValidationError) as exc_info:
            RequestResponseMapping(
                request_field="request"
            )
        assert "both request_field and response_field" in str(exc_info.value).lower()

    def test_separate_mode_missing_request_fails(self):
        """Test that separate mode requires both fields"""
        with pytest.raises(PydanticValidationError) as exc_info:
            RequestResponseMapping(
                response_field="response"
            )
        assert "both request_field and response_field" in str(exc_info.value).lower()


class TestYAMLConfigWithRequestResponse:
    """Test YAMLConfig with request_response_mapping"""

    @pytest.fixture
    def base_config(self):
        """Base configuration dict"""
        return {
            "parser_name": "TestParser",
            "parser_version": "1.0",
            "tool_name": "Test Tool",
            "tool_type": "Test_Scanner",
            "file_format": "json",
            "json_root_path": "$.findings[*]",
            "field_mappings": [
                {"source_field": "name", "target_field": "title", "data_type": "string"},
                {"source_field": "desc", "target_field": "description", "data_type": "string"},
                {"source_field": "sev", "target_field": "severity", "data_type": "severity",
                 "severity_mapping": {"high": "High", "low": "Low"}},
            ]
        }

    def test_config_with_separate_req_resp(self, base_config):
        """Test config with separate request/response fields"""
        base_config["request_response_mapping"] = {
            "request_field": "http.request",
            "response_field": "http.response"
        }
        config = YAMLConfig.model_validate(base_config)
        assert config.request_response_mapping is not None
        assert config.request_response_mapping.request_field == "http.request"
        assert config.request_response_mapping.response_field == "http.response"

    def test_config_with_combined_req_resp(self, base_config):
        """Test config with combined request/response field"""
        base_config["request_response_mapping"] = {
            "combined_field": "http_exchange",
            "request_key": "req",
            "response_key": "resp"
        }
        config = YAMLConfig.model_validate(base_config)
        assert config.request_response_mapping.combined_field == "http_exchange"

    def test_config_with_array_req_resp(self, base_config):
        """Test config with array request/response field"""
        base_config["request_response_mapping"] = {
            "array_field": "http_messages"
        }
        config = YAMLConfig.model_validate(base_config)
        assert config.request_response_mapping.array_field == "http_messages"

    def test_config_without_req_resp(self, base_config):
        """Test config without request_response_mapping"""
        config = YAMLConfig.model_validate(base_config)
        assert config.request_response_mapping is None


class TestNormalizerRequestResponse:
    """Test NormalizerService request/response processing"""

    @pytest.fixture
    def create_normalizer(self):
        """Factory to create normalizer with custom config"""
        from app.services.normalizer import NormalizerService

        def _create(req_resp_config=None):
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
                    {"source_field": "sev", "target_field": "severity", "data_type": "severity",
                     "severity_mapping": {"high": "High", "low": "Low", "medium": "Medium"}},
                ]
            }
            if req_resp_config:
                config_dict["request_response_mapping"] = req_resp_config

            config = YAMLConfig.model_validate(config_dict)
            return NormalizerService(config)

        return _create

    def test_separate_fields_extraction(self, create_normalizer):
        """Test extraction from separate request/response fields"""
        import json

        normalizer = create_normalizer({
            "request_field": "request_data",
            "response_field": "response_data"
        })

        scan_content = json.dumps({
            "findings": [
                {
                    "name": "XSS Vulnerability",
                    "desc": "Cross-site scripting found",
                    "sev": "high",
                    "request_data": "GET /api/users HTTP/1.1\nHost: example.com",
                    "response_data": "HTTP/1.1 200 OK\n\n<script>alert(1)</script>"
                }
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        assert 'unsaved_req_resp' in findings[0]
        assert len(findings[0]['unsaved_req_resp']) == 1
        assert findings[0]['unsaved_req_resp'][0]['req'] == "GET /api/users HTTP/1.1\nHost: example.com"
        assert "<script>" in findings[0]['unsaved_req_resp'][0]['resp']

    def test_combined_field_extraction(self, create_normalizer):
        """Test extraction from combined field"""
        import json

        normalizer = create_normalizer({
            "combined_field": "http_exchange",
            "request_key": "req",
            "response_key": "resp"
        })

        scan_content = json.dumps({
            "findings": [
                {
                    "name": "SQL Injection",
                    "desc": "SQL injection found",
                    "sev": "high",
                    "http_exchange": {
                        "req": "POST /login HTTP/1.1\n\nuser=admin'--",
                        "resp": "HTTP/1.1 500 Internal Server Error"
                    }
                }
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        assert 'unsaved_req_resp' in findings[0]
        assert len(findings[0]['unsaved_req_resp']) == 1
        assert "admin'--" in findings[0]['unsaved_req_resp'][0]['req']
        assert "500" in findings[0]['unsaved_req_resp'][0]['resp']

    def test_array_field_extraction(self, create_normalizer):
        """Test extraction from array of request/response pairs"""
        import json

        normalizer = create_normalizer({
            "array_field": "http_messages",
            "request_key": "request",
            "response_key": "response"
        })

        scan_content = json.dumps({
            "findings": [
                {
                    "name": "Multiple Requests",
                    "desc": "Issue found across multiple requests",
                    "sev": "medium",
                    "http_messages": [
                        {
                            "request": "GET /page1 HTTP/1.1",
                            "response": "HTTP/1.1 200 OK"
                        },
                        {
                            "request": "GET /page2 HTTP/1.1",
                            "response": "HTTP/1.1 200 OK"
                        },
                        {
                            "request": "POST /page3 HTTP/1.1",
                            "response": "HTTP/1.1 302 Found"
                        }
                    ]
                }
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        assert 'unsaved_req_resp' in findings[0]
        assert len(findings[0]['unsaved_req_resp']) == 3
        assert findings[0]['unsaved_req_resp'][0]['req'] == "GET /page1 HTTP/1.1"
        assert findings[0]['unsaved_req_resp'][2]['req'] == "POST /page3 HTTP/1.1"

    def test_nested_field_path_extraction(self, create_normalizer):
        """Test extraction with nested field paths"""
        import json

        normalizer = create_normalizer({
            "request_field": "http.data.request",
            "response_field": "http.data.response"
        })

        scan_content = json.dumps({
            "findings": [
                {
                    "name": "Nested Data",
                    "desc": "Found in nested structure",
                    "sev": "low",
                    "http": {
                        "data": {
                            "request": "GET /nested HTTP/1.1",
                            "response": "HTTP/1.1 200 OK"
                        }
                    }
                }
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        assert 'unsaved_req_resp' in findings[0]
        assert findings[0]['unsaved_req_resp'][0]['req'] == "GET /nested HTTP/1.1"

    def test_missing_request_response_data(self, create_normalizer):
        """Test handling when request/response data is missing"""
        import json

        normalizer = create_normalizer({
            "request_field": "request_data",
            "response_field": "response_data"
        })

        scan_content = json.dumps({
            "findings": [
                {
                    "name": "No HTTP Data",
                    "desc": "Finding without HTTP data",
                    "sev": "low"
                }
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        # unsaved_req_resp should not be present if no data
        assert 'unsaved_req_resp' not in findings[0] or len(findings[0].get('unsaved_req_resp', [])) == 0

    def test_partial_request_response_data(self, create_normalizer):
        """Test handling when only request is present"""
        import json

        normalizer = create_normalizer({
            "request_field": "request_data",
            "response_field": "response_data"
        })

        scan_content = json.dumps({
            "findings": [
                {
                    "name": "Only Request",
                    "desc": "Finding with only request",
                    "sev": "low",
                    "request_data": "GET /partial HTTP/1.1"
                }
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        assert 'unsaved_req_resp' in findings[0]
        assert findings[0]['unsaved_req_resp'][0]['req'] == "GET /partial HTTP/1.1"
        assert findings[0]['unsaved_req_resp'][0]['resp'] == ""

    def test_no_req_resp_config(self, create_normalizer):
        """Test that findings work without request_response_mapping"""
        import json

        normalizer = create_normalizer(None)  # No req/resp config

        scan_content = json.dumps({
            "findings": [
                {
                    "name": "Simple Finding",
                    "desc": "No HTTP data needed",
                    "sev": "medium"
                }
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        assert 'unsaved_req_resp' not in findings[0]

    def test_empty_array_field(self, create_normalizer):
        """Test handling empty array field"""
        import json

        normalizer = create_normalizer({
            "array_field": "http_messages"
        })

        scan_content = json.dumps({
            "findings": [
                {
                    "name": "Empty Array",
                    "desc": "Finding with empty array",
                    "sev": "low",
                    "http_messages": []
                }
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        # unsaved_req_resp should not be present for empty array
        assert 'unsaved_req_resp' not in findings[0] or len(findings[0].get('unsaved_req_resp', [])) == 0


class TestRequestResponseEdgeCases:
    """Test edge cases for request/response handling"""

    @pytest.fixture
    def create_normalizer(self):
        """Factory to create normalizer"""
        from app.services.normalizer import NormalizerService

        def _create(req_resp_config):
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
                    {"source_field": "sev", "target_field": "severity", "data_type": "severity",
                     "severity_mapping": {"high": "High", "low": "Low"}},
                ],
                "request_response_mapping": req_resp_config
            }
            config = YAMLConfig.model_validate(config_dict)
            return NormalizerService(config)

        return _create

    def test_non_string_request_data(self, create_normalizer):
        """Test handling non-string request data (should be converted)"""
        import json

        normalizer = create_normalizer({
            "request_field": "request",
            "response_field": "response"
        })

        scan_content = json.dumps({
            "findings": [
                {
                    "name": "Numeric Data",
                    "desc": "Data with numeric values",
                    "sev": "low",
                    "request": 12345,
                    "response": {"status": 200}
                }
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        assert 'unsaved_req_resp' in findings[0]
        assert findings[0]['unsaved_req_resp'][0]['req'] == "12345"
        assert "status" in findings[0]['unsaved_req_resp'][0]['resp']

    def test_combined_field_wrong_type(self, create_normalizer):
        """Test handling when combined field is not a dict"""
        import json

        normalizer = create_normalizer({
            "combined_field": "http_exchange"
        })

        scan_content = json.dumps({
            "findings": [
                {
                    "name": "Wrong Type",
                    "desc": "Combined field is a string",
                    "sev": "low",
                    "http_exchange": "not a dict"
                }
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        # Should not crash, just skip the extraction
        assert 'unsaved_req_resp' not in findings[0] or len(findings[0].get('unsaved_req_resp', [])) == 0

    def test_array_field_non_dict_items(self, create_normalizer):
        """Test handling when array field contains non-dict items"""
        import json

        normalizer = create_normalizer({
            "array_field": "http_messages"
        })

        scan_content = json.dumps({
            "findings": [
                {
                    "name": "Mixed Array",
                    "desc": "Array with mixed types",
                    "sev": "low",
                    "http_messages": [
                        "string item",
                        {"request": "valid", "response": "valid"},
                        123,
                        {"request": "another", "response": "pair"}
                    ]
                }
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        assert 'unsaved_req_resp' in findings[0]
        # Should only extract the valid dict items
        assert len(findings[0]['unsaved_req_resp']) == 2

    def test_large_request_response_data(self, create_normalizer):
        """Test handling large request/response data"""
        import json

        normalizer = create_normalizer({
            "request_field": "request",
            "response_field": "response"
        })

        large_request = "GET /api HTTP/1.1\n" + "X-Header: " + "A" * 10000
        large_response = "HTTP/1.1 200 OK\n\n" + "B" * 10000

        scan_content = json.dumps({
            "findings": [
                {
                    "name": "Large Data",
                    "desc": "Large request/response",
                    "sev": "low",
                    "request": large_request,
                    "response": large_response
                }
            ]
        }).encode('utf-8')

        findings = normalizer.normalize(scan_content)
        assert len(findings) == 1
        assert 'unsaved_req_resp' in findings[0]
        assert len(findings[0]['unsaved_req_resp'][0]['req']) > 10000
        assert len(findings[0]['unsaved_req_resp'][0]['resp']) > 10000
