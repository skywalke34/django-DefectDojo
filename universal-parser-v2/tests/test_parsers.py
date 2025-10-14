"""
Unit tests for Universal Parser V2 parsers.

Tests:
- JSON file reader
- String parser
- Severity parser
- Field extractor
"""

import pytest
import json
from pathlib import Path

# Import parsers
from app.parsers.file_formats.json_reader import JSONReader
from app.parsers.data_types.string_parser import StringParser
from app.parsers.data_types.severity_parser import SeverityParser
from app.parsers.base import FieldExtractor
from app.utils.errors import FileFormatError, SeverityMappingError


class TestFieldExtractor:
    """Test FieldExtractor utility class"""

    def test_simple_field_extraction(self):
        """Test extracting simple top-level fields"""
        data = {"name": "XSS", "severity": "High"}
        assert FieldExtractor.extract(data, "name") == "XSS"
        assert FieldExtractor.extract(data, "severity") == "High"

    def test_nested_field_extraction(self):
        """Test extracting nested fields with dot notation"""
        data = {
            "vulnerability": {
                "Classification": {
                    "Cwe": "79",
                    "Cvss": {"BaseScore": {"Value": "7.5"}}
                }
            }
        }
        assert FieldExtractor.extract(data, "vulnerability.Classification.Cwe") == "79"
        assert FieldExtractor.extract(data, "vulnerability.Classification.Cvss.BaseScore.Value") == "7.5"

    def test_missing_field_returns_default(self):
        """Test that missing fields return default value"""
        data = {"name": "XSS"}
        assert FieldExtractor.extract(data, "missing") is None
        assert FieldExtractor.extract(data, "missing", default="N/A") == "N/A"

    def test_extract_all(self):
        """Test extracting multiple fields at once"""
        data = {"title": "XSS", "severity": "High", "cwe": 79}
        paths = ["title", "severity", "cwe"]
        result = FieldExtractor.extract_all(data, paths)
        assert result == {"title": "XSS", "severity": "High", "cwe": 79}


class TestStringParser:
    """Test StringParser"""

    def test_simple_string_parse(self):
        """Test basic string conversion"""
        parser = StringParser()
        assert parser.parse("Hello World") == "Hello World"
        assert parser.parse(123) == "123"
        assert parser.parse(True) == "True"

    def test_default_value_for_none(self):
        """Test that None uses default value"""
        parser = StringParser()
        assert parser.parse(None, {"default": "Unknown"}) == "Unknown"
        assert parser.parse("", {"default": "Empty"}) == "Empty"

    def test_whitespace_trimming(self):
        """Test that whitespace is trimmed"""
        parser = StringParser()
        assert parser.parse("  padded  ") == "padded"

    def test_html_stripping(self):
        """Test HTML tag removal"""
        parser = StringParser()
        result = parser.parse("<p>Test <b>content</b></p>", {"strip_html": True})
        assert result == "Test content"

    def test_whitespace_normalization(self):
        """Test whitespace normalization"""
        parser = StringParser()
        result = parser.parse("Multiple    spaces\n\nand   lines", {"normalize_whitespace": True})
        assert result == "Multiple spaces and lines"

    def test_truncate(self):
        """Test text truncation"""
        long_text = "This is a very long text that needs truncation"
        result = StringParser.truncate(long_text, 20)
        assert len(result) == 20
        assert result.endswith("...")


class TestSeverityParser:
    """Test SeverityParser"""

    def test_exact_mapping_match(self):
        """Test exact severity mapping"""
        parser = SeverityParser()
        config = {"severity_mapping": {"high": "High", "medium": "Medium"}}
        assert parser.parse("high", config) == "High"
        assert parser.parse("medium", config) == "Medium"

    def test_case_insensitive_mapping(self):
        """Test case-insensitive matching"""
        parser = SeverityParser()
        config = {"severity_mapping": {"high": "High"}}
        assert parser.parse("HIGH", config) == "High"
        assert parser.parse("High", config) == "High"
        assert parser.parse("HiGh", config) == "High"

    def test_default_mappings(self):
        """Test built-in default mappings"""
        parser = SeverityParser()
        assert parser.parse("CRITICAL") == "Critical"
        assert parser.parse("high") == "High"
        assert parser.parse("Medium") == "Medium"
        assert parser.parse("low") == "Low"
        assert parser.parse("info") == "Info"
        assert parser.parse("informational") == "Info"

    def test_numeric_mappings(self):
        """Test numeric severity mappings"""
        parser = SeverityParser()
        assert parser.parse("1") == "Critical"
        assert parser.parse("2") == "High"
        assert parser.parse("3") == "Medium"
        assert parser.parse("4") == "Low"
        assert parser.parse("5") == "Info"

    def test_unmapped_value_raises_error(self):
        """Test that unmapped values raise SeverityMappingError"""
        parser = SeverityParser()
        config = {"severity_mapping": {"high": "High"}}

        with pytest.raises(SeverityMappingError) as exc_info:
            parser.parse("unknown", config)

        assert "unknown" in str(exc_info.value)

    def test_validate_severity(self):
        """Test severity validation"""
        assert SeverityParser.validate_severity("Critical")
        assert SeverityParser.validate_severity("High")
        assert not SeverityParser.validate_severity("invalid")

    def test_severity_weights(self):
        """Test severity weight calculation for sorting"""
        assert SeverityParser.get_severity_weight("Critical") < SeverityParser.get_severity_weight("High")
        assert SeverityParser.get_severity_weight("High") < SeverityParser.get_severity_weight("Medium")
        assert SeverityParser.get_severity_weight("Medium") < SeverityParser.get_severity_weight("Low")
        assert SeverityParser.get_severity_weight("Low") < SeverityParser.get_severity_weight("Info")


class TestJSONReader:
    """Test JSONReader"""

    def test_read_simple_json(self):
        """Test reading simple JSON array"""
        reader = JSONReader()
        json_data = b'{"Vulnerabilities": [{"Name": "XSS", "Severity": "High"}]}'
        config = {"json_root_path": "$.Vulnerabilities[*]"}

        findings = reader.read(json_data, config)
        assert len(findings) == 1
        assert findings[0]["Name"] == "XSS"
        assert findings[0]["Severity"] == "High"

    def test_read_acunetix_sample(self):
        """Test reading actual Acunetix sample file"""
        reader = JSONReader()
        fixture_path = Path(__file__).parent / "fixtures" / "acunetix_sample.json"

        with open(fixture_path, "rb") as f:
            json_data = f.read()

        config = {"json_root_path": "$.Vulnerabilities[*]"}
        findings = reader.read(json_data, config)

        # Acunetix sample has 1 finding
        assert len(findings) == 1
        assert "Name" in findings[0]
        assert "Severity" in findings[0]
        assert findings[0]["Name"] == "Cookie Not Marked as HttpOnly"
        assert findings[0]["Severity"] == "Medium"

    def test_invalid_json_raises_error(self):
        """Test that invalid JSON raises FileFormatError"""
        reader = JSONReader()
        invalid_json = b'{invalid json}'

        with pytest.raises(FileFormatError) as exc_info:
            reader.read(invalid_json, {})

        assert "Invalid JSON format" in str(exc_info.value)

    def test_invalid_jsonpath_raises_error(self):
        """Test that invalid JSONPath raises error"""
        reader = JSONReader()
        json_data = b'{"data": []}'
        config = {"json_root_path": "$.NonExistent[*]"}

        with pytest.raises(FileFormatError) as exc_info:
            reader.read(json_data, config)

        assert "No findings found" in str(exc_info.value)

    def test_validate_json_syntax(self):
        """Test JSON syntax validation"""
        valid, error = JSONReader.validate_json_syntax('{"valid": true}')
        assert valid
        assert error == ""

        valid, error = JSONReader.validate_json_syntax('{invalid}')
        assert not valid
        assert "Line" in error


# Run tests if executed directly
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
