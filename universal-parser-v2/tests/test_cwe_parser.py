"""
Unit tests for CWEParser.

Tests:
- Standard CWE format parsing (CWE-89)
- Various CWE formats (CWE89, CWE 89)
- URL-based CWE extraction
- Array handling (multiple CWEs)
- Dict handling (cwe-id fields)
- Edge cases and validation
- Utility methods
"""

import pytest
from app.parsers.data_types.cwe_parser import CWEParser


class TestCWEParserBasics:
    """Test basic CWE parsing"""

    def test_standard_format(self):
        """Test parsing standard CWE-XX format"""
        parser = CWEParser()
        assert parser.parse("CWE-89") == 89

    def test_no_hyphen_format(self):
        """Test parsing CWE without hyphen"""
        parser = CWEParser()
        assert parser.parse("CWE89") == 89

    def test_space_format(self):
        """Test parsing CWE with space"""
        parser = CWEParser()
        assert parser.parse("CWE 89") == 89

    def test_lowercase_format(self):
        """Test parsing lowercase cwe"""
        parser = CWEParser()
        assert parser.parse("cwe-79") == 79

    def test_just_number(self):
        """Test parsing just the number"""
        parser = CWEParser()
        assert parser.parse("89") == 89

    def test_integer_input(self):
        """Test parsing integer directly"""
        parser = CWEParser()
        assert parser.parse(89) == 89

    def test_with_text_prefix(self):
        """Test parsing CWE embedded in text"""
        parser = CWEParser()
        assert parser.parse("Weakness: CWE-89 SQL Injection") == 89


class TestCWEParserURLs:
    """Test CWE URL parsing"""

    def test_mitre_url(self):
        """Test parsing MITRE CWE URL"""
        parser = CWEParser()
        url = "https://cwe.mitre.org/data/definitions/89.html"
        assert parser.parse(url) == 89

    def test_mitre_url_https(self):
        """Test parsing HTTPS MITRE URL"""
        parser = CWEParser()
        url = "https://cwe.mitre.org/data/definitions/79.html"
        assert parser.parse(url) == 79

    def test_url_in_text(self):
        """Test extracting CWE from text with URL"""
        parser = CWEParser()
        text = "See https://cwe.mitre.org/data/definitions/89.html for details"
        assert parser.parse(text) == 89


class TestCWEParserArrays:
    """Test array/list handling"""

    def test_array_takes_first(self):
        """Test that array returns first valid CWE"""
        parser = CWEParser()
        result = parser.parse(["CWE-89", "CWE-79", "CWE-22"])
        assert result == 89

    def test_array_with_invalid_first(self):
        """Test array with invalid first element"""
        parser = CWEParser()
        result = parser.parse(["invalid", "CWE-79", "CWE-22"])
        assert result == 79

    def test_array_all_invalid(self):
        """Test array with all invalid elements"""
        parser = CWEParser()
        result = parser.parse(["invalid", "not-a-cwe", ""])
        assert result is None

    def test_array_with_integers(self):
        """Test array with integer CWE numbers"""
        parser = CWEParser()
        result = parser.parse([89, 79, 22])
        assert result == 89

    def test_array_mixed_formats(self):
        """Test array with mixed formats"""
        parser = CWEParser()
        result = parser.parse(["not-valid", 79, "CWE-22"])
        assert result == 79

    def test_empty_array(self):
        """Test empty array"""
        parser = CWEParser()
        result = parser.parse([])
        assert result is None


class TestCWEParserDicts:
    """Test dictionary handling"""

    def test_dict_with_cwe_id(self):
        """Test dict with cwe-id key"""
        parser = CWEParser()
        result = parser.parse({"cwe-id": "CWE-89"})
        assert result == 89

    def test_dict_with_cwe_id_underscore(self):
        """Test dict with cwe_id key"""
        parser = CWEParser()
        result = parser.parse({"cwe_id": "89"})
        assert result == 89

    def test_dict_with_cwe_key(self):
        """Test dict with cwe key"""
        parser = CWEParser()
        result = parser.parse({"cwe": "CWE-79"})
        assert result == 79

    def test_dict_array_of_dicts(self):
        """Test array of dicts with CWE"""
        parser = CWEParser()
        result = parser.parse([{"cwe-id": "CWE-89"}, {"cwe-id": "CWE-79"}])
        assert result == 89

    def test_dict_with_no_cwe_key(self):
        """Test dict without recognized CWE key"""
        parser = CWEParser()
        result = parser.parse({"some_field": "CWE-89"})
        assert result == 89  # Should find it in values

    def test_dict_empty(self):
        """Test empty dict"""
        parser = CWEParser()
        result = parser.parse({})
        assert result is None


class TestCWEParserValidation:
    """Test CWE validation"""

    def test_valid_cwe_range(self):
        """Test CWE in valid range"""
        parser = CWEParser()
        assert parser.parse("CWE-1") == 1
        assert parser.parse("CWE-9999") == 9999

    def test_cwe_above_max(self):
        """Test CWE above maximum"""
        parser = CWEParser()
        result = parser.parse("CWE-99999")
        assert result is None

    def test_cwe_zero(self):
        """Test CWE-0 (invalid)"""
        parser = CWEParser()
        result = parser.parse("CWE-0")
        assert result is None

    def test_custom_range(self):
        """Test custom min/max CWE range"""
        parser = CWEParser()
        result = parser.parse("CWE-100", {"min_cwe": 50, "max_cwe": 200})
        assert result == 100

    def test_custom_range_out_of_bounds(self):
        """Test value outside custom range"""
        parser = CWEParser()
        result = parser.parse("CWE-300", {"min_cwe": 50, "max_cwe": 200})
        assert result is None


class TestCWEParserConfiguration:
    """Test configuration options"""

    def test_default_value(self):
        """Test default value for invalid input"""
        parser = CWEParser()
        result = parser.parse("invalid", {"default": 0})
        assert result == 0

    def test_default_for_none(self):
        """Test default value for None"""
        parser = CWEParser()
        result = parser.parse(None, {"default": 79})
        assert result == 79

    def test_return_formatted(self):
        """Test returning formatted CWE string"""
        parser = CWEParser()
        result = parser.parse("89", {"return_formatted": True})
        assert result == "CWE-89"

    def test_return_formatted_from_url(self):
        """Test formatted return from URL input"""
        parser = CWEParser()
        url = "https://cwe.mitre.org/data/definitions/79.html"
        result = parser.parse(url, {"return_formatted": True})
        assert result == "CWE-79"


class TestCWEParserEdgeCases:
    """Test edge cases"""

    def test_none_input(self):
        """Test None input"""
        parser = CWEParser()
        assert parser.parse(None) is None

    def test_empty_string(self):
        """Test empty string"""
        parser = CWEParser()
        assert parser.parse("") is None

    def test_whitespace_only(self):
        """Test whitespace-only input"""
        parser = CWEParser()
        assert parser.parse("   ") is None

    def test_whitespace_around_cwe(self):
        """Test whitespace around CWE"""
        parser = CWEParser()
        assert parser.parse("  CWE-89  ") == 89

    def test_cwe_with_leading_zeros(self):
        """Test CWE with leading zeros"""
        parser = CWEParser()
        assert parser.parse("CWE-089") == 89

    def test_float_input(self):
        """Test float input"""
        parser = CWEParser()
        assert parser.parse(89.5) == 89

    def test_negative_number(self):
        """Test negative number"""
        parser = CWEParser()
        result = parser.parse("-89")
        assert result is None

    def test_very_large_number(self):
        """Test very large number"""
        parser = CWEParser()
        result = parser.parse("CWE-999999999")
        assert result is None

    def test_non_numeric_string(self):
        """Test non-numeric string"""
        parser = CWEParser()
        result = parser.parse("not-a-cwe")
        assert result is None


class TestCWEParserSecurityScannerFormats:
    """Test with realistic security scanner formats"""

    def test_nuclei_format(self):
        """Test Nuclei-style CWE format"""
        parser = CWEParser()
        # Nuclei uses array of CWE strings
        assert parser.parse(["cwe-89"]) == 89

    def test_semgrep_format(self):
        """Test Semgrep-style CWE format"""
        parser = CWEParser()
        # Semgrep uses cwe field with array
        data = {"cwe": ["CWE-89: SQL Injection"]}
        result = parser.parse(data["cwe"])
        assert result == 89

    def test_bandit_format(self):
        """Test Bandit-style CWE format"""
        parser = CWEParser()
        # Bandit uses CWE in issue_cwe field
        assert parser.parse({"issue_cwe": "CWE-78"}) == 78

    def test_arachni_format(self):
        """Test Arachni-style CWE format"""
        parser = CWEParser()
        # Arachni uses cwe-id in classification
        data = {"classification": {"cwe-id": ["CWE-79"]}}
        result = parser.parse(data["classification"]["cwe-id"])
        assert result == 79

    def test_owasp_zap_format(self):
        """Test OWASP ZAP-style CWE format"""
        parser = CWEParser()
        # ZAP uses cweid as integer
        assert parser.parse({"cweid": 89}) == 89


class TestCWEParserUtilityMethods:
    """Test utility methods"""

    def test_format_cwe(self):
        """Test format_cwe static method"""
        assert CWEParser.format_cwe(89) == "CWE-89"
        assert CWEParser.format_cwe(1) == "CWE-1"
        assert CWEParser.format_cwe(9999) == "CWE-9999"

    def test_get_cwe_url(self):
        """Test get_cwe_url static method"""
        url = CWEParser.get_cwe_url(89)
        assert url == "https://cwe.mitre.org/data/definitions/89.html"

    def test_is_valid_cwe_number_true(self):
        """Test is_valid_cwe_number for valid CWEs"""
        assert CWEParser.is_valid_cwe_number(1) is True
        assert CWEParser.is_valid_cwe_number(89) is True
        assert CWEParser.is_valid_cwe_number(9999) is True

    def test_is_valid_cwe_number_false(self):
        """Test is_valid_cwe_number for invalid CWEs"""
        assert CWEParser.is_valid_cwe_number(0) is False
        assert CWEParser.is_valid_cwe_number(-1) is False
        assert CWEParser.is_valid_cwe_number(10000) is False

    def test_extract_multiple_cwes(self):
        """Test extract_multiple_cwes"""
        text = "This has CWE-89, CWE-79, and also CWE-22 issues"
        cwes = CWEParser.extract_multiple_cwes(text)
        assert 89 in cwes
        assert 79 in cwes
        assert 22 in cwes
        assert len(cwes) == 3

    def test_extract_multiple_cwes_deduped(self):
        """Test extract_multiple_cwes removes duplicates"""
        text = "CWE-89 and again CWE-89 and CWE-79"
        cwes = CWEParser.extract_multiple_cwes(text)
        assert cwes.count(89) == 1  # Should only appear once
        assert 79 in cwes

    def test_extract_multiple_cwes_empty(self):
        """Test extract_multiple_cwes with no CWEs"""
        text = "No CWE numbers here"
        cwes = CWEParser.extract_multiple_cwes(text)
        assert cwes == []

    def test_extract_multiple_cwes_none(self):
        """Test extract_multiple_cwes with None"""
        cwes = CWEParser.extract_multiple_cwes(None)
        assert cwes == []


class TestCWEParserIntegration:
    """Integration tests with registry"""

    def test_parser_in_registry(self):
        """Test parser is registered correctly"""
        from app.parsers.data_types import get_parser
        parser = get_parser('cwe')
        assert isinstance(parser, CWEParser)

    def test_parser_via_registry(self):
        """Test using parser via registry"""
        from app.parsers.data_types import get_parser
        parser = get_parser('cwe')
        result = parser.parse("CWE-89")
        assert result == 89
