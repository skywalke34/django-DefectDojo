"""
Unit tests for CSVReader.

Tests:
- Basic CSV parsing
- Header handling
- Delimiter detection and configuration
- Skip rows functionality
- Column index access
- Quote character handling
- Encoding handling
- Error handling
- Qualys-style CSV parsing
"""

import pytest
from app.parsers.file_formats.csv_reader import CSVReader
from app.utils.errors import FileFormatError


class TestCSVReaderBasics:
    """Test basic CSV reading functionality"""

    def test_simple_csv_parsing(self):
        """Test parsing simple CSV with headers"""
        csv_bytes = b"id,severity,title\nCVE-2021-1234,High,SQL Injection\nCVE-2021-5678,Medium,XSS"

        reader = CSVReader()
        config = {"csv_has_header": True}
        findings = reader.read(csv_bytes, config)

        assert len(findings) == 2
        assert findings[0]["id"] == "CVE-2021-1234"
        assert findings[0]["severity"] == "High"
        assert findings[0]["title"] == "SQL Injection"
        assert findings[1]["id"] == "CVE-2021-5678"

    def test_csv_without_header(self):
        """Test parsing CSV without headers using column indices"""
        csv_bytes = b"CVE-2021-1234,High,SQL Injection\nCVE-2021-5678,Medium,XSS"

        reader = CSVReader()
        config = {"csv_has_header": False}
        findings = reader.read(csv_bytes, config)

        assert len(findings) == 2
        assert findings[0]["_col_0"] == "CVE-2021-1234"
        assert findings[0]["_col_1"] == "High"
        assert findings[0]["_col_2"] == "SQL Injection"

    def test_indexed_access_with_headers(self):
        """Test that indexed access (_col_N) works even with headers"""
        csv_bytes = b"id,severity,title\nCVE-2021-1234,High,SQL Injection"

        reader = CSVReader()
        config = {"csv_has_header": True}
        findings = reader.read(csv_bytes, config)

        assert len(findings) == 1
        # Both named and indexed access should work
        assert findings[0]["id"] == "CVE-2021-1234"
        assert findings[0]["_col_0"] == "CVE-2021-1234"
        assert findings[0]["severity"] == "High"
        assert findings[0]["_col_1"] == "High"


class TestCSVReaderDelimiters:
    """Test delimiter handling"""

    def test_comma_delimiter(self):
        """Test parsing with comma delimiter"""
        csv_bytes = b"id,severity\nCVE-2021-1234,High"

        reader = CSVReader()
        config = {"csv_delimiter": ",", "csv_has_header": True}
        findings = reader.read(csv_bytes, config)

        assert len(findings) == 1
        assert findings[0]["id"] == "CVE-2021-1234"

    def test_tab_delimiter(self):
        """Test parsing with tab delimiter"""
        csv_bytes = b"id\tseverity\tname\nCVE-2021-1234\tHigh\tSQL Injection"

        reader = CSVReader()
        config = {"csv_delimiter": "\t", "csv_has_header": True}
        findings = reader.read(csv_bytes, config)

        assert len(findings) == 1
        assert findings[0]["id"] == "CVE-2021-1234"
        assert findings[0]["severity"] == "High"
        assert findings[0]["name"] == "SQL Injection"

    def test_semicolon_delimiter(self):
        """Test parsing with semicolon delimiter"""
        csv_bytes = b"id;severity;title\nCVE-2021-1234;High;SQL Injection"

        reader = CSVReader()
        config = {"csv_delimiter": ";", "csv_has_header": True}
        findings = reader.read(csv_bytes, config)

        assert len(findings) == 1
        assert findings[0]["id"] == "CVE-2021-1234"

    def test_pipe_delimiter(self):
        """Test parsing with pipe delimiter"""
        csv_bytes = b"id|severity|title\nCVE-2021-1234|High|SQL Injection"

        reader = CSVReader()
        config = {"csv_delimiter": "|", "csv_has_header": True}
        findings = reader.read(csv_bytes, config)

        assert len(findings) == 1
        assert findings[0]["id"] == "CVE-2021-1234"

    def test_auto_detect_comma(self):
        """Test auto-detection of comma delimiter"""
        csv_bytes = b"id,severity,title\nCVE-2021-1234,High,SQL Injection"

        reader = CSVReader()
        config = {"csv_has_header": True}  # No delimiter specified
        findings = reader.read(csv_bytes, config)

        assert len(findings) == 1
        assert findings[0]["id"] == "CVE-2021-1234"

    def test_auto_detect_tab(self):
        """Test auto-detection of tab delimiter"""
        csv_bytes = b"id\tseverity\ttitle\nCVE-2021-1234\tHigh\tSQL Injection"

        reader = CSVReader()
        config = {"csv_has_header": True}  # No delimiter specified
        findings = reader.read(csv_bytes, config)

        assert len(findings) == 1
        assert findings[0]["id"] == "CVE-2021-1234"


class TestCSVReaderSkipRows:
    """Test skip rows functionality"""

    def test_skip_header_rows(self):
        """Test skipping header rows before actual data"""
        csv_bytes = b"""Qualys Scan Report
Generated: 2021-01-01
---
id,severity,title
CVE-2021-1234,High,SQL Injection"""

        reader = CSVReader()
        config = {"csv_skip_rows": 3, "csv_has_header": True}
        findings = reader.read(csv_bytes, config)

        assert len(findings) == 1
        assert findings[0]["id"] == "CVE-2021-1234"

    def test_skip_multiple_rows(self):
        """Test skipping multiple report header rows"""
        csv_bytes = b"""Report Title
Export Date: 2021-01-01
Scanner Version: 1.0
Account: TestAccount
---
id,severity
CVE-2021-1234,High
CVE-2021-5678,Medium"""

        reader = CSVReader()
        config = {"csv_skip_rows": 5, "csv_has_header": True}
        findings = reader.read(csv_bytes, config)

        assert len(findings) == 2
        assert findings[0]["id"] == "CVE-2021-1234"

    def test_skip_rows_error_when_exceeds_lines(self):
        """Test error when skip_rows exceeds total lines"""
        csv_bytes = b"id,severity\nCVE-2021-1234,High"

        reader = CSVReader()
        config = {"csv_skip_rows": 10, "csv_has_header": True}

        with pytest.raises(FileFormatError) as exc_info:
            reader.read(csv_bytes, config)

        assert "exceeds total lines" in str(exc_info.value)


class TestCSVReaderQuoting:
    """Test quote character handling"""

    def test_quoted_fields_with_delimiter(self):
        """Test fields containing delimiter inside quotes"""
        csv_bytes = b'id,description\nCVE-2021-1234,"Contains, comma inside"'

        reader = CSVReader()
        config = {"csv_has_header": True}
        findings = reader.read(csv_bytes, config)

        assert len(findings) == 1
        assert findings[0]["description"] == "Contains, comma inside"

    def test_quoted_fields_with_newline(self):
        """Test fields containing newline inside quotes"""
        csv_bytes = b'id,description\nCVE-2021-1234,"Line 1\nLine 2"'

        reader = CSVReader()
        config = {"csv_has_header": True}
        findings = reader.read(csv_bytes, config)

        assert len(findings) == 1
        assert "Line 1" in findings[0]["description"]
        assert "Line 2" in findings[0]["description"]

    def test_escaped_quotes(self):
        """Test escaped quote characters"""
        csv_bytes = b'id,description\nCVE-2021-1234,"Contains ""quoted"" text"'

        reader = CSVReader()
        config = {"csv_has_header": True}
        findings = reader.read(csv_bytes, config)

        assert len(findings) == 1
        assert 'quoted' in findings[0]["description"]

    def test_custom_quote_char(self):
        """Test custom quote character"""
        csv_bytes = b"id,description\nCVE-2021-1234,'Contains, comma'"

        reader = CSVReader()
        config = {"csv_has_header": True, "csv_quote_char": "'"}
        findings = reader.read(csv_bytes, config)

        assert len(findings) == 1
        assert findings[0]["description"] == "Contains, comma"


class TestCSVReaderEncoding:
    """Test encoding handling"""

    def test_utf8_encoding(self):
        """Test UTF-8 encoded content"""
        csv_bytes = "id,description\nCVE-2021-1234,Vulnérabilité critique".encode('utf-8')

        reader = CSVReader()
        config = {"csv_has_header": True, "file_encoding": "utf-8"}
        findings = reader.read(csv_bytes, config)

        assert len(findings) == 1
        assert "Vulnérabilité" in findings[0]["description"]

    def test_utf8_with_bom(self):
        """Test UTF-8 with BOM encoding"""
        csv_bytes = b'\xef\xbb\xbfid,description\nCVE-2021-1234,Test'

        reader = CSVReader()
        config = {"csv_has_header": True}
        findings = reader.read(csv_bytes, config)

        assert len(findings) == 1

    def test_latin1_fallback(self):
        """Test fallback to latin-1 encoding"""
        # Create content that's valid latin-1 but not UTF-8
        csv_bytes = "id,description\nCVE-2021-1234,Café résumé".encode('latin-1')

        reader = CSVReader()
        config = {"csv_has_header": True}
        findings = reader.read(csv_bytes, config)

        assert len(findings) == 1


class TestCSVReaderEdgeCases:
    """Test edge cases"""

    def test_empty_cells(self):
        """Test handling of empty cells"""
        csv_bytes = b"id,severity,description\nCVE-2021-1234,High,\nCVE-2021-5678,,Missing severity"

        reader = CSVReader()
        config = {"csv_has_header": True}
        findings = reader.read(csv_bytes, config)

        assert len(findings) == 2
        assert findings[0]["description"] == ""
        assert findings[1]["severity"] == ""

    def test_empty_rows_skipped(self):
        """Test that empty rows are skipped"""
        csv_bytes = b"id,severity\nCVE-2021-1234,High\n\n\nCVE-2021-5678,Medium"

        reader = CSVReader()
        config = {"csv_has_header": True}
        findings = reader.read(csv_bytes, config)

        # Empty rows should be skipped
        assert len(findings) == 2

    def test_whitespace_trimming(self):
        """Test that whitespace is trimmed from values"""
        csv_bytes = b"id,severity\n  CVE-2021-1234  ,  High  "

        reader = CSVReader()
        config = {"csv_has_header": True}
        findings = reader.read(csv_bytes, config)

        assert len(findings) == 1
        assert findings[0]["id"] == "CVE-2021-1234"
        assert findings[0]["severity"] == "High"

    def test_row_with_fewer_columns(self):
        """Test row with fewer columns than header"""
        csv_bytes = b"id,severity,title\nCVE-2021-1234,High"

        reader = CSVReader()
        config = {"csv_has_header": True}
        findings = reader.read(csv_bytes, config)

        assert len(findings) == 1
        assert findings[0]["id"] == "CVE-2021-1234"
        assert findings[0]["title"] == ""  # Missing column gets empty string

    def test_row_number_tracking(self):
        """Test that row numbers are tracked"""
        csv_bytes = b"id,severity\nCVE-2021-1234,High\nCVE-2021-5678,Medium"

        reader = CSVReader()
        config = {"csv_has_header": True}
        findings = reader.read(csv_bytes, config)

        assert findings[0]["_row_number"] == 2  # Row 1 is header
        assert findings[1]["_row_number"] == 3

    def test_empty_header_column(self):
        """Test handling of empty column header"""
        csv_bytes = b"id,,title\nCVE-2021-1234,High,SQL Injection"

        reader = CSVReader()
        config = {"csv_has_header": True}
        findings = reader.read(csv_bytes, config)

        assert len(findings) == 1
        assert findings[0]["id"] == "CVE-2021-1234"
        # Empty header becomes _col_N
        assert findings[0]["_col_1"] == "High"


class TestCSVReaderErrors:
    """Test error handling"""

    def test_empty_file(self):
        """Test handling of empty CSV file"""
        csv_bytes = b""

        reader = CSVReader()
        config = {"csv_has_header": True}

        with pytest.raises(FileFormatError) as exc_info:
            reader.read(csv_bytes, config)

        assert "No data rows" in str(exc_info.value)

    def test_header_only_file(self):
        """Test handling of CSV with only header"""
        csv_bytes = b"id,severity,title"

        reader = CSVReader()
        config = {"csv_has_header": True}

        with pytest.raises(FileFormatError) as exc_info:
            reader.read(csv_bytes, config)

        assert "No data rows" in str(exc_info.value)


class TestCSVReaderValidation:
    """Test CSV syntax validation"""

    def test_validate_valid_csv(self):
        """Test validation of valid CSV"""
        csv_bytes = b"a,b,c\n1,2,3"

        is_valid, error = CSVReader.validate_csv_syntax(csv_bytes)

        assert is_valid is True
        assert error == ""

    def test_validate_empty_csv(self):
        """Test validation of empty CSV"""
        csv_bytes = b""

        is_valid, error = CSVReader.validate_csv_syntax(csv_bytes)

        assert is_valid is False
        assert "empty" in error.lower()


class TestCSVReaderColumnNames:
    """Test column name extraction"""

    def test_get_column_names(self):
        """Test extracting column names from CSV"""
        csv_bytes = b"id,severity,title,description\nCVE-2021-1234,High,XSS,Details"

        reader = CSVReader()
        config = {"csv_has_header": True}
        columns = reader.get_column_names(csv_bytes, config)

        assert columns == ["id", "severity", "title", "description"]

    def test_get_column_names_with_skip_rows(self):
        """Test extracting column names with skip rows"""
        csv_bytes = b"Report Header\n---\nid,severity,title\nCVE-2021-1234,High,XSS"

        reader = CSVReader()
        config = {"csv_skip_rows": 2}
        columns = reader.get_column_names(csv_bytes, config)

        assert columns == ["id", "severity", "title"]


class TestCSVReaderQualysStyle:
    """Test Qualys-style CSV parsing (realistic example)"""

    def test_qualys_csv_format(self):
        """Test parsing Qualys-style CSV export"""
        csv_bytes = b"""Qualys Cloud Platform
Vulnerability Management
Export Date: 2021-06-15

IP,DNS,NetBIOS,QID,Title,Vuln Status,Severity,Port,First Detected,Last Detected,CVE ID,CVSS3 Base
192.168.1.1,server1.example.com,SERVER1,105971,OpenSSL Multiple Vulnerabilities,Active,4,443,2021-01-01T00:00:00Z,2021-06-15T00:00:00Z,CVE-2021-3449,7.5
192.168.1.2,server2.example.com,SERVER2,105972,Apache Vulnerability,Active,5,80,2021-02-01T00:00:00Z,2021-06-15T00:00:00Z,CVE-2021-41773,9.8"""

        reader = CSVReader()
        config = {
            "csv_skip_rows": 4,  # Skip report header
            "csv_has_header": True,
            "csv_delimiter": ","
        }
        findings = reader.read(csv_bytes, config)

        assert len(findings) == 2

        # First finding
        assert findings[0]["IP"] == "192.168.1.1"
        assert findings[0]["DNS"] == "server1.example.com"
        assert findings[0]["QID"] == "105971"
        assert findings[0]["Title"] == "OpenSSL Multiple Vulnerabilities"
        assert findings[0]["Severity"] == "4"
        assert findings[0]["CVE ID"] == "CVE-2021-3449"
        assert findings[0]["CVSS3 Base"] == "7.5"

        # Second finding
        assert findings[1]["IP"] == "192.168.1.2"
        assert findings[1]["QID"] == "105972"
        assert findings[1]["Severity"] == "5"
