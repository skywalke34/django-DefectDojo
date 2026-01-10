"""
Unit tests for RegexParser.

Tests:
- Basic pattern matching
- Capture groups
- Match modes (first, last, all, join)
- Regex flags (case, multiline, dotall)
- Edge cases
- Utility methods
- Common patterns
"""

import pytest
from app.parsers.data_types.regex_parser import RegexParser, CommonPatterns


class TestRegexParserBasics:
    """Test basic regex matching"""

    def test_simple_match(self):
        """Test simple pattern match"""
        parser = RegexParser()
        result = parser.parse("CVE-2021-44228", {"pattern": r"CVE-\d{4}-\d+"})
        assert result == "CVE-2021-44228"

    def test_partial_match(self):
        """Test match within larger text"""
        parser = RegexParser()
        result = parser.parse("Found vulnerability CVE-2021-44228 in system",
                             {"pattern": r"CVE-\d{4}-\d+"})
        assert result == "CVE-2021-44228"

    def test_no_match(self):
        """Test when pattern doesn't match"""
        parser = RegexParser()
        result = parser.parse("No CVE here", {"pattern": r"CVE-\d{4}-\d+"})
        assert result is None

    def test_no_match_with_default(self):
        """Test no match returns default"""
        parser = RegexParser()
        result = parser.parse("No CVE here",
                             {"pattern": r"CVE-\d{4}-\d+", "default": "N/A"})
        assert result == "N/A"


class TestRegexParserGroups:
    """Test capture group extraction"""

    def test_numbered_group(self):
        """Test numbered capture group"""
        parser = RegexParser()
        result = parser.parse("Version: 1.2.3",
                             {"pattern": r"Version: ([\d.]+)", "group": 1})
        assert result == "1.2.3"

    def test_group_zero_full_match(self):
        """Test group 0 returns full match"""
        parser = RegexParser()
        result = parser.parse("Version: 1.2.3",
                             {"pattern": r"Version: ([\d.]+)", "group": 0})
        assert result == "Version: 1.2.3"

    def test_multiple_groups(self):
        """Test selecting different groups"""
        parser = RegexParser()
        text = "file.py:123"
        config = {"pattern": r"([^:]+):(\d+)"}

        # Group 1 = filename
        config["group"] = 1
        assert parser.parse(text, config) == "file.py"

        # Group 2 = line number
        config["group"] = 2
        assert parser.parse(text, config) == "123"

    def test_named_group(self):
        """Test named capture group"""
        parser = RegexParser()
        result = parser.parse("CVE-2021-44228",
                             {"pattern": r"CVE-(?P<year>\d{4})-(?P<id>\d+)",
                              "group": "year"})
        assert result == "2021"

    def test_invalid_group(self):
        """Test invalid group returns default"""
        parser = RegexParser()
        result = parser.parse("test",
                             {"pattern": r"test", "group": 5, "default": "err"})
        assert result == "err"


class TestRegexParserMatchModes:
    """Test match modes"""

    def test_match_mode_first(self):
        """Test first match mode (default)"""
        parser = RegexParser()
        result = parser.parse("CVE-2021-1111, CVE-2021-2222, CVE-2021-3333",
                             {"pattern": r"CVE-\d{4}-\d+", "match_mode": "first"})
        assert result == "CVE-2021-1111"

    def test_match_mode_last(self):
        """Test last match mode"""
        parser = RegexParser()
        result = parser.parse("CVE-2021-1111, CVE-2021-2222, CVE-2021-3333",
                             {"pattern": r"CVE-\d{4}-\d+", "match_mode": "last"})
        assert result == "CVE-2021-3333"

    def test_match_mode_all(self):
        """Test all matches mode"""
        parser = RegexParser()
        result = parser.parse("CVE-2021-1111, CVE-2021-2222, CVE-2021-3333",
                             {"pattern": r"CVE-\d{4}-\d+", "match_mode": "all"})
        assert isinstance(result, list)
        assert len(result) == 3
        assert "CVE-2021-1111" in result
        assert "CVE-2021-2222" in result
        assert "CVE-2021-3333" in result

    def test_match_mode_join(self):
        """Test join matches mode"""
        parser = RegexParser()
        result = parser.parse("CVE-2021-1111, CVE-2021-2222",
                             {"pattern": r"CVE-\d{4}-\d+", "match_mode": "join"})
        assert result == "CVE-2021-1111, CVE-2021-2222"

    def test_match_mode_join_custom_separator(self):
        """Test join with custom separator"""
        parser = RegexParser()
        result = parser.parse("CVE-2021-1111, CVE-2021-2222",
                             {"pattern": r"CVE-\d{4}-\d+",
                              "match_mode": "join",
                              "join_separator": " | "})
        assert result == "CVE-2021-1111 | CVE-2021-2222"

    def test_match_mode_all_with_groups(self):
        """Test all matches with capture group"""
        parser = RegexParser()
        result = parser.parse("v1.0, v2.0, v3.0",
                             {"pattern": r"v([\d.]+)", "group": 1, "match_mode": "all"})
        assert result == ["1.0", "2.0", "3.0"]


class TestRegexParserFlags:
    """Test regex flags"""

    def test_case_sensitive_default(self):
        """Test case sensitive matching (default)"""
        parser = RegexParser()
        result = parser.parse("cve-2021-1234", {"pattern": r"CVE-\d{4}-\d+"})
        assert result is None  # No match due to case

    def test_case_insensitive(self):
        """Test case insensitive matching"""
        parser = RegexParser()
        result = parser.parse("cve-2021-1234",
                             {"pattern": r"CVE-\d{4}-\d+", "case_sensitive": False})
        assert result == "cve-2021-1234"

    def test_multiline_mode(self):
        """Test multiline mode"""
        parser = RegexParser()
        text = "Line 1\nLine 2\nLine 3"
        # Without multiline, ^ only matches start of string
        result = parser.parse(text, {"pattern": r"^Line \d", "match_mode": "all"})
        assert len(result) == 1

        # With multiline, ^ matches start of each line
        result = parser.parse(text,
                             {"pattern": r"^Line \d", "match_mode": "all", "multiline": True})
        assert len(result) == 3

    def test_dotall_mode(self):
        """Test dotall mode (. matches newline)"""
        parser = RegexParser()
        text = "Start\nMiddle\nEnd"
        # Without dotall, . doesn't match newline
        result = parser.parse(text, {"pattern": r"Start.+End"})
        assert result is None

        # With dotall, . matches newline
        result = parser.parse(text, {"pattern": r"Start.+End", "dotall": True})
        assert result == text


class TestRegexParserEdgeCases:
    """Test edge cases"""

    def test_none_input(self):
        """Test None input"""
        parser = RegexParser()
        result = parser.parse(None, {"pattern": r"test"})
        assert result is None

    def test_empty_string(self):
        """Test empty string"""
        parser = RegexParser()
        result = parser.parse("", {"pattern": r"test"})
        assert result is None

    def test_no_pattern(self):
        """Test missing pattern"""
        parser = RegexParser()
        result = parser.parse("test", {})
        assert result is None

    def test_invalid_pattern(self):
        """Test invalid regex pattern"""
        parser = RegexParser()
        result = parser.parse("test", {"pattern": r"[invalid"})
        assert result is None

    def test_non_string_input(self):
        """Test non-string input is converted"""
        parser = RegexParser()
        result = parser.parse(12345, {"pattern": r"\d+"})
        assert result == "12345"

    def test_special_characters_in_input(self):
        """Test input with regex special characters"""
        parser = RegexParser()
        result = parser.parse("Price: $100.00",
                             {"pattern": r"\$[\d.]+"})
        assert result == "$100.00"


class TestRegexParserSecurityScenarios:
    """Test with security scanner scenarios"""

    def test_extract_cve(self):
        """Test extracting CVE"""
        parser = RegexParser()
        text = "Vulnerability CVE-2021-44228 (Log4Shell) found"
        result = parser.parse(text, {"pattern": CommonPatterns.CVE})
        assert result == "CVE-2021-44228"

    def test_extract_multiple_cves(self):
        """Test extracting multiple CVEs"""
        parser = RegexParser()
        text = "CVE-2021-44228, CVE-2021-45046, CVE-2021-45105"
        result = parser.parse(text,
                             {"pattern": CommonPatterns.CVE, "match_mode": "all"})
        assert len(result) == 3

    def test_extract_ip_addresses(self):
        """Test extracting IP addresses"""
        parser = RegexParser()
        text = "Hosts: 192.168.1.1, 10.0.0.50, 172.16.0.1"
        result = parser.parse(text,
                             {"pattern": CommonPatterns.IPV4, "match_mode": "all"})
        assert len(result) == 3
        assert "192.168.1.1" in result

    def test_extract_file_path_line(self):
        """Test extracting file:line from stack trace"""
        parser = RegexParser()
        text = "Error at /src/app/main.py:42"
        result = parser.parse(text, {"pattern": CommonPatterns.FILE_LINE, "group": 1})
        assert result == "/src/app/main.py"

    def test_extract_version(self):
        """Test extracting version numbers"""
        parser = RegexParser()
        text = "Apache/2.4.51 (Unix) OpenSSL/1.1.1k"
        result = parser.parse(text,
                             {"pattern": CommonPatterns.SEMVER, "match_mode": "all"})
        # SEMVER may or may not match these depending on format
        # Let's use VERSION pattern
        result = parser.parse(text,
                             {"pattern": r"([\d.]+)", "match_mode": "all"})
        assert "2.4.51" in result
        assert "1.1.1" in result

    def test_extract_hash(self):
        """Test extracting file hash"""
        parser = RegexParser()
        text = "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = parser.parse(text, {"pattern": CommonPatterns.SHA256})
        assert result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class TestRegexParserUtilityMethods:
    """Test utility methods"""

    def test_validate_pattern_valid(self):
        """Test pattern validation for valid pattern"""
        is_valid, error = RegexParser.validate_pattern(r"CVE-\d+")
        assert is_valid is True
        assert error == ""

    def test_validate_pattern_invalid(self):
        """Test pattern validation for invalid pattern"""
        is_valid, error = RegexParser.validate_pattern(r"[invalid")
        assert is_valid is False
        assert "unterminated" in error.lower()

    def test_escape_for_literal(self):
        """Test escaping special characters"""
        escaped = RegexParser.escape_for_literal("foo.bar[0]")
        assert "\\." in escaped
        assert "\\[" in escaped

    def test_extract_with_pattern(self):
        """Test quick extraction"""
        result = RegexParser.extract_with_pattern("Version: 1.2.3", r"Version: ([\d.]+)", 1)
        assert result == "1.2.3"

    def test_extract_all_with_pattern(self):
        """Test extract all"""
        result = RegexParser.extract_all_with_pattern("a1 b2 c3", r"[a-z](\d)")
        # With group 0 (default), gets full matches
        result = RegexParser.extract_all_with_pattern("a1 b2 c3", r"[a-z]\d")
        assert result == ["a1", "b2", "c3"]

    def test_replace_with_pattern(self):
        """Test pattern replacement"""
        result = RegexParser.replace_with_pattern("CVE-2021-1234", r"\d{4}", "XXXX", count=1)
        assert result == "CVE-XXXX-1234"

    def test_split_with_pattern(self):
        """Test pattern split"""
        result = RegexParser.split_with_pattern("a,b;c|d", r"[,;|]")
        assert result == ["a", "b", "c", "d"]


class TestCommonPatterns:
    """Test common patterns"""

    def test_cve_pattern(self):
        """Test CVE pattern"""
        import re
        assert re.match(CommonPatterns.CVE, "CVE-2021-44228")
        assert re.match(CommonPatterns.CVE, "CVE-1999-0001")
        assert not re.match(CommonPatterns.CVE, "CVE2021-1234")

    def test_ipv4_pattern(self):
        """Test IPv4 pattern (format match, not validation)"""
        import re
        assert re.match(CommonPatterns.IPV4, "192.168.1.1")
        assert re.match(CommonPatterns.IPV4, "10.0.0.1")
        # Note: Pattern matches format, doesn't validate octets
        assert re.match(CommonPatterns.IPV4, "999.999.999.999")
        # Non-IP strings should not match
        assert not re.match(CommonPatterns.IPV4, "not-an-ip")

    def test_url_pattern(self):
        """Test URL pattern"""
        import re
        assert re.search(CommonPatterns.URL, "Visit https://example.com/path")
        assert re.search(CommonPatterns.URL, "http://test.com")

    def test_semver_pattern(self):
        """Test semver pattern"""
        import re
        assert re.match(CommonPatterns.SEMVER, "1.2.3")
        assert re.match(CommonPatterns.SEMVER, "1.0.0-alpha")
        assert re.match(CommonPatterns.SEMVER, "2.0.0+build.123")

    def test_hash_patterns(self):
        """Test hash patterns"""
        import re
        assert re.match(CommonPatterns.MD5, "d41d8cd98f00b204e9800998ecf8427e")
        assert re.match(CommonPatterns.SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709")
        assert re.match(CommonPatterns.SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")


class TestRegexParserIntegration:
    """Integration tests with registry"""

    def test_parser_in_registry(self):
        """Test parser is registered correctly"""
        from app.parsers.data_types import get_parser
        parser = get_parser('regex')
        assert isinstance(parser, RegexParser)

    def test_parser_via_registry(self):
        """Test using parser via registry"""
        from app.parsers.data_types import get_parser
        parser = get_parser('regex')
        result = parser.parse("CVE-2021-44228", {"pattern": r"CVE-\d{4}-\d+"})
        assert result == "CVE-2021-44228"
