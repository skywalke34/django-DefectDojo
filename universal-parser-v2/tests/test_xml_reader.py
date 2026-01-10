"""
Unit tests for XMLReader.

Tests:
- Basic XML parsing
- XPath extraction
- Namespace handling
- Attribute extraction
- Nested element extraction
- Error handling
- CycloneDX-style XML parsing
"""

import pytest
from app.parsers.file_formats.xml_reader import XMLReader
from app.utils.errors import FileFormatError


class TestXMLReaderBasics:
    """Test basic XML reading functionality"""

    def test_simple_xml_parsing(self):
        """Test parsing simple XML without namespaces"""
        xml_bytes = b'''<?xml version="1.0"?>
        <report>
            <vulnerability>
                <id>CVE-2021-1234</id>
                <severity>High</severity>
                <title>SQL Injection</title>
            </vulnerability>
        </report>'''

        reader = XMLReader()
        config = {"xml_finding_xpath": "//vulnerability"}
        findings = reader.read(xml_bytes, config)

        assert len(findings) == 1
        assert findings[0]["id"] == "CVE-2021-1234"
        assert findings[0]["severity"] == "High"
        assert findings[0]["title"] == "SQL Injection"

    def test_multiple_findings(self):
        """Test parsing XML with multiple findings"""
        xml_bytes = b'''<?xml version="1.0"?>
        <report>
            <vulnerabilities>
                <vulnerability>
                    <id>CVE-2021-1234</id>
                    <severity>High</severity>
                </vulnerability>
                <vulnerability>
                    <id>CVE-2021-5678</id>
                    <severity>Medium</severity>
                </vulnerability>
                <vulnerability>
                    <id>CVE-2021-9999</id>
                    <severity>Low</severity>
                </vulnerability>
            </vulnerabilities>
        </report>'''

        reader = XMLReader()
        config = {"xml_finding_xpath": "//vulnerability"}
        findings = reader.read(xml_bytes, config)

        assert len(findings) == 3
        assert findings[0]["id"] == "CVE-2021-1234"
        assert findings[1]["id"] == "CVE-2021-5678"
        assert findings[2]["id"] == "CVE-2021-9999"

    def test_nested_elements(self):
        """Test parsing XML with nested elements"""
        xml_bytes = b'''<?xml version="1.0"?>
        <report>
            <vulnerability>
                <id>CVE-2021-1234</id>
                <classification>
                    <cwe>89</cwe>
                    <cvss>
                        <score>7.5</score>
                        <vector>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N</vector>
                    </cvss>
                </classification>
            </vulnerability>
        </report>'''

        reader = XMLReader()
        config = {"xml_finding_xpath": "//vulnerability"}
        findings = reader.read(xml_bytes, config)

        assert len(findings) == 1
        assert findings[0]["id"] == "CVE-2021-1234"
        assert findings[0]["classification"]["cwe"] == "89"
        assert findings[0]["classification"]["cvss"]["score"] == "7.5"


class TestXMLReaderAttributes:
    """Test XML attribute extraction"""

    def test_attribute_extraction(self):
        """Test extracting attributes from elements"""
        xml_bytes = b'''<?xml version="1.0"?>
        <report>
            <vulnerability id="VULN-001" severity="High">
                <title>Cross-Site Scripting</title>
            </vulnerability>
        </report>'''

        reader = XMLReader()
        config = {"xml_finding_xpath": "//vulnerability"}
        findings = reader.read(xml_bytes, config)

        assert len(findings) == 1
        assert findings[0]["@id"] == "VULN-001"
        assert findings[0]["@severity"] == "High"
        assert findings[0]["title"] == "Cross-Site Scripting"

    def test_mixed_attributes_and_elements(self):
        """Test parsing elements with both attributes and child elements"""
        xml_bytes = b'''<?xml version="1.0"?>
        <report>
            <vulnerability bom-ref="pkg:npm/lodash@4.17.15">
                <id>CVE-2020-8203</id>
                <source name="NVD">
                    <url>https://nvd.nist.gov/vuln/detail/CVE-2020-8203</url>
                </source>
            </vulnerability>
        </report>'''

        reader = XMLReader()
        config = {"xml_finding_xpath": "//vulnerability"}
        findings = reader.read(xml_bytes, config)

        assert len(findings) == 1
        assert findings[0]["@bom-ref"] == "pkg:npm/lodash@4.17.15"
        assert findings[0]["id"] == "CVE-2020-8203"
        assert findings[0]["source"]["@name"] == "NVD"


class TestXMLReaderNamespaces:
    """Test XML namespace handling"""

    def test_default_namespace(self):
        """Test parsing XML with default namespace"""
        xml_bytes = b'''<?xml version="1.0"?>
        <bom xmlns="http://cyclonedx.org/schema/bom/1.4">
            <vulnerability>
                <id>CVE-2021-1234</id>
            </vulnerability>
        </bom>'''

        reader = XMLReader()
        config = {
            "xml_finding_xpath": "//ns:vulnerability",
            "xml_namespaces": {"ns": "http://cyclonedx.org/schema/bom/1.4"}
        }
        findings = reader.read(xml_bytes, config)

        assert len(findings) == 1
        assert findings[0]["id"] == "CVE-2021-1234"

    def test_prefixed_namespace(self):
        """Test parsing XML with prefixed namespace"""
        xml_bytes = b'''<?xml version="1.0"?>
        <bom xmlns:cdx="http://cyclonedx.org/schema/bom/1.4">
            <cdx:vulnerabilities>
                <cdx:vulnerability>
                    <cdx:id>CVE-2021-1234</cdx:id>
                </cdx:vulnerability>
            </cdx:vulnerabilities>
        </bom>'''

        reader = XMLReader()
        config = {
            "xml_finding_xpath": "//cdx:vulnerability",
            "xml_namespaces": {"cdx": "http://cyclonedx.org/schema/bom/1.4"}
        }
        findings = reader.read(xml_bytes, config)

        assert len(findings) == 1
        assert findings[0]["id"] == "CVE-2021-1234"

    def test_auto_namespace_detection(self):
        """Test automatic namespace detection from root element"""
        xml_bytes = b'''<?xml version="1.0"?>
        <bom xmlns="http://cyclonedx.org/schema/bom/1.4">
            <vulnerabilities>
                <vulnerability>
                    <id>CVE-2021-1234</id>
                </vulnerability>
            </vulnerabilities>
        </bom>'''

        reader = XMLReader()
        # Without explicit namespaces, should try to auto-detect
        config = {"xml_finding_xpath": "//ns:vulnerability"}
        findings = reader.read(xml_bytes, config)

        assert len(findings) == 1


class TestXMLReaderCycloneDX:
    """Test CycloneDX-style XML parsing"""

    def test_cyclonedx_vulnerability(self):
        """Test parsing CycloneDX vulnerability format"""
        xml_bytes = b'''<?xml version="1.0"?>
        <bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1">
            <vulnerabilities>
                <vulnerability ref="CVE-2021-44228">
                    <id>CVE-2021-44228</id>
                    <source name="NVD">
                        <url>https://nvd.nist.gov</url>
                    </source>
                    <ratings>
                        <rating>
                            <source name="NVD"/>
                            <score>10.0</score>
                            <severity>critical</severity>
                            <method>CVSSv3</method>
                            <vector>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H</vector>
                        </rating>
                    </ratings>
                    <cwes>
                        <cwe>502</cwe>
                    </cwes>
                    <description>Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.</description>
                    <recommendation>Upgrade to Log4j 2.17.0 or later.</recommendation>
                </vulnerability>
            </vulnerabilities>
        </bom>'''

        reader = XMLReader()
        config = {
            "xml_finding_xpath": "//ns:vulnerability",
            "xml_namespaces": {"ns": "http://cyclonedx.org/schema/bom/1.4"}
        }
        findings = reader.read(xml_bytes, config)

        assert len(findings) == 1
        vuln = findings[0]
        assert vuln["@ref"] == "CVE-2021-44228"
        assert vuln["id"] == "CVE-2021-44228"
        assert vuln["ratings"]["rating"]["score"] == "10.0"
        assert vuln["ratings"]["rating"]["severity"] == "critical"
        assert vuln["cwes"]["cwe"] == "502"

    def test_cyclonedx_with_affects(self):
        """Test parsing CycloneDX with affects section"""
        xml_bytes = b'''<?xml version="1.0"?>
        <bom xmlns="http://cyclonedx.org/schema/bom/1.4">
            <vulnerabilities>
                <vulnerability>
                    <id>CVE-2021-44228</id>
                    <affects>
                        <target>
                            <ref>pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1</ref>
                        </target>
                    </affects>
                </vulnerability>
            </vulnerabilities>
        </bom>'''

        reader = XMLReader()
        config = {
            "xml_finding_xpath": "//ns:vulnerability",
            "xml_namespaces": {"ns": "http://cyclonedx.org/schema/bom/1.4"}
        }
        findings = reader.read(xml_bytes, config)

        assert len(findings) == 1
        assert findings[0]["affects"]["target"]["ref"] == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"


class TestXMLReaderXPath:
    """Test various XPath expression patterns"""

    def test_absolute_xpath(self):
        """Test absolute XPath expression"""
        xml_bytes = b'''<?xml version="1.0"?>
        <report>
            <results>
                <vulnerabilities>
                    <vulnerability>
                        <id>CVE-2021-1234</id>
                    </vulnerability>
                </vulnerabilities>
            </results>
        </report>'''

        reader = XMLReader()
        config = {"xml_finding_xpath": "/report/results/vulnerabilities/vulnerability"}
        findings = reader.read(xml_bytes, config)

        assert len(findings) == 1
        assert findings[0]["id"] == "CVE-2021-1234"

    def test_descendant_xpath(self):
        """Test descendant XPath expression"""
        xml_bytes = b'''<?xml version="1.0"?>
        <deep>
            <nested>
                <structure>
                    <vulnerability>
                        <id>CVE-2021-1234</id>
                    </vulnerability>
                </structure>
            </nested>
        </deep>'''

        reader = XMLReader()
        config = {"xml_finding_xpath": "//vulnerability"}
        findings = reader.read(xml_bytes, config)

        assert len(findings) == 1
        assert findings[0]["id"] == "CVE-2021-1234"

    def test_predicate_xpath(self):
        """Test XPath with predicate"""
        xml_bytes = b'''<?xml version="1.0"?>
        <report>
            <vulnerability severity="High">
                <id>CVE-2021-1111</id>
            </vulnerability>
            <vulnerability severity="Low">
                <id>CVE-2021-2222</id>
            </vulnerability>
            <vulnerability severity="High">
                <id>CVE-2021-3333</id>
            </vulnerability>
        </report>'''

        reader = XMLReader()
        config = {"xml_finding_xpath": "//vulnerability[@severity='High']"}
        findings = reader.read(xml_bytes, config)

        assert len(findings) == 2
        assert findings[0]["id"] == "CVE-2021-1111"
        assert findings[1]["id"] == "CVE-2021-3333"


class TestXMLReaderErrors:
    """Test XML reader error handling"""

    def test_invalid_xml_syntax(self):
        """Test handling of invalid XML syntax"""
        xml_bytes = b'<invalid>unclosed tag'

        reader = XMLReader()
        config = {"xml_finding_xpath": "//vulnerability"}

        with pytest.raises(FileFormatError) as exc_info:
            reader.read(xml_bytes, config)

        assert "Invalid XML format" in str(exc_info.value)

    def test_missing_xpath_config(self):
        """Test handling of missing xpath configuration"""
        xml_bytes = b'<root><item>test</item></root>'

        reader = XMLReader()
        config = {}  # Missing xml_finding_xpath

        with pytest.raises(FileFormatError) as exc_info:
            reader.read(xml_bytes, config)

        assert "xml_finding_xpath is required" in str(exc_info.value)

    def test_invalid_xpath_expression(self):
        """Test handling of invalid XPath expression"""
        xml_bytes = b'<root><item>test</item></root>'

        reader = XMLReader()
        config = {"xml_finding_xpath": "[[[invalid xpath"}

        with pytest.raises(FileFormatError) as exc_info:
            reader.read(xml_bytes, config)

        assert "Invalid XPath expression" in str(exc_info.value)

    def test_no_findings_found(self):
        """Test handling when no findings match XPath"""
        xml_bytes = b'<root><other>content</other></root>'

        reader = XMLReader()
        config = {"xml_finding_xpath": "//vulnerability"}

        with pytest.raises(FileFormatError) as exc_info:
            reader.read(xml_bytes, config)

        assert "No findings found" in str(exc_info.value)


class TestXMLReaderValidation:
    """Test XML syntax validation"""

    def test_validate_valid_xml(self):
        """Test validation of valid XML"""
        xml_bytes = b'<root><item>test</item></root>'

        is_valid, error = XMLReader.validate_xml_syntax(xml_bytes)

        assert is_valid is True
        assert error == ""

    def test_validate_invalid_xml(self):
        """Test validation of invalid XML"""
        xml_bytes = b'<root><item>unclosed'

        is_valid, error = XMLReader.validate_xml_syntax(xml_bytes)

        assert is_valid is False
        assert "Line" in error or len(error) > 0


class TestXMLReaderEdgeCases:
    """Test edge cases and special scenarios"""

    def test_empty_elements(self):
        """Test handling of empty elements"""
        xml_bytes = b'''<?xml version="1.0"?>
        <report>
            <vulnerability>
                <id>CVE-2021-1234</id>
                <description/>
                <solution></solution>
            </vulnerability>
        </report>'''

        reader = XMLReader()
        config = {"xml_finding_xpath": "//vulnerability"}
        findings = reader.read(xml_bytes, config)

        assert len(findings) == 1
        assert findings[0]["id"] == "CVE-2021-1234"

    def test_cdata_content(self):
        """Test handling of CDATA sections"""
        xml_bytes = b'''<?xml version="1.0"?>
        <report>
            <vulnerability>
                <id>CVE-2021-1234</id>
                <description><![CDATA[This is <b>HTML</b> content]]></description>
            </vulnerability>
        </report>'''

        reader = XMLReader()
        config = {"xml_finding_xpath": "//vulnerability"}
        findings = reader.read(xml_bytes, config)

        assert len(findings) == 1
        assert "HTML" in findings[0]["description"]

    def test_multiple_same_child_elements(self):
        """Test handling of multiple child elements with same name"""
        xml_bytes = b'''<?xml version="1.0"?>
        <report>
            <vulnerability>
                <id>CVE-2021-1234</id>
                <cwe>79</cwe>
                <cwe>89</cwe>
                <cwe>502</cwe>
            </vulnerability>
        </report>'''

        reader = XMLReader()
        config = {"xml_finding_xpath": "//vulnerability"}
        findings = reader.read(xml_bytes, config)

        assert len(findings) == 1
        # Multiple CWEs should be converted to a list
        cwes = findings[0]["cwe"]
        assert isinstance(cwes, list)
        assert len(cwes) == 3

    def test_special_characters_in_content(self):
        """Test handling of special XML characters in content"""
        xml_bytes = b'''<?xml version="1.0"?>
        <report>
            <vulnerability>
                <id>CVE-2021-1234</id>
                <description>SQL: SELECT * FROM users WHERE name=&apos;admin&apos; &amp;&amp; 1=1</description>
            </vulnerability>
        </report>'''

        reader = XMLReader()
        config = {"xml_finding_xpath": "//vulnerability"}
        findings = reader.read(xml_bytes, config)

        assert len(findings) == 1
        assert "admin" in findings[0]["description"]
        assert "&&" in findings[0]["description"]

    def test_utf8_encoding(self):
        """Test handling of UTF-8 encoded content"""
        xml_bytes = '''<?xml version="1.0" encoding="UTF-8"?>
        <report>
            <vulnerability>
                <id>CVE-2021-1234</id>
                <description>Vulnérabilité critique avec des caractères spéciaux: é, ñ, ü</description>
            </vulnerability>
        </report>'''.encode('utf-8')

        reader = XMLReader()
        config = {"xml_finding_xpath": "//vulnerability"}
        findings = reader.read(xml_bytes, config)

        assert len(findings) == 1
        assert "Vulnérabilité" in findings[0]["description"]
        assert "ñ" in findings[0]["description"]


class TestXMLReaderFieldExtraction:
    """Test field extraction helper method"""

    def test_extract_text_field(self):
        """Test extracting text content using XPath"""
        xml_bytes = b'''<?xml version="1.0"?>
        <vulnerability>
            <id>CVE-2021-1234</id>
            <nested><deep><value>found</value></deep></nested>
        </vulnerability>'''

        from lxml import etree
        root = etree.fromstring(xml_bytes)

        reader = XMLReader()

        # Test simple extraction
        result = reader.extract_field(root, "id/text()")
        assert result == "CVE-2021-1234"

        # Test nested extraction
        result = reader.extract_field(root, "nested/deep/value/text()")
        assert result == "found"

    def test_extract_attribute_field(self):
        """Test extracting attribute using XPath"""
        xml_bytes = b'''<?xml version="1.0"?>
        <vulnerability severity="High" cwe="79">
            <id>CVE-2021-1234</id>
        </vulnerability>'''

        from lxml import etree
        root = etree.fromstring(xml_bytes)

        reader = XMLReader()

        result = reader.extract_field(root, "@severity")
        assert result == "High"

        result = reader.extract_field(root, "@cwe")
        assert result == "79"
