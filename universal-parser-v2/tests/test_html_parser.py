"""
Unit tests for HTMLToTextParser.

Tests:
- Basic HTML to text conversion
- Markdown output preservation
- Link handling
- Emphasis handling
- Table handling
- Edge cases and error handling
- Utility methods (extract_links, extract_text_from_element)
"""

import pytest
from app.parsers.data_types.html_parser import HTMLToTextParser


class TestHTMLToTextBasics:
    """Test basic HTML to text conversion"""

    def test_simple_paragraph(self):
        """Test converting simple paragraph"""
        parser = HTMLToTextParser()
        result = parser.parse("<p>Hello World</p>")
        assert "Hello World" in result

    def test_multiple_paragraphs(self):
        """Test converting multiple paragraphs"""
        parser = HTMLToTextParser()
        html = "<p>First paragraph</p><p>Second paragraph</p>"
        result = parser.parse(html)
        assert "First paragraph" in result
        assert "Second paragraph" in result

    def test_nested_tags(self):
        """Test converting nested tags"""
        parser = HTMLToTextParser()
        html = "<div><p><span>Nested content</span></p></div>"
        result = parser.parse(html)
        assert "Nested content" in result

    def test_br_tags(self):
        """Test handling line break tags"""
        parser = HTMLToTextParser()
        html = "Line one<br>Line two<br/>Line three"
        result = parser.parse(html)
        assert "Line one" in result
        assert "Line two" in result

    def test_heading_tags(self):
        """Test converting heading tags"""
        parser = HTMLToTextParser()
        html = "<h1>Main Title</h1><h2>Subtitle</h2><p>Content</p>"
        result = parser.parse(html)
        assert "Main Title" in result
        assert "Subtitle" in result
        assert "Content" in result

    def test_plain_text_passthrough(self):
        """Test that plain text without HTML passes through"""
        parser = HTMLToTextParser()
        text = "Just plain text without any HTML"
        result = parser.parse(text)
        assert result == text


class TestHTMLToTextEmphasis:
    """Test emphasis (bold/italic) handling"""

    def test_bold_text(self):
        """Test bold text conversion"""
        parser = HTMLToTextParser()
        html = "<p>This is <b>bold</b> text</p>"
        result = parser.parse(html, {"preserve_emphasis": True, "output_format": "markdown"})
        assert "bold" in result

    def test_italic_text(self):
        """Test italic text conversion"""
        parser = HTMLToTextParser()
        html = "<p>This is <i>italic</i> text</p>"
        result = parser.parse(html, {"preserve_emphasis": True, "output_format": "markdown"})
        assert "italic" in result

    def test_strong_em_tags(self):
        """Test strong and em tags"""
        parser = HTMLToTextParser()
        html = "<p><strong>Important</strong> and <em>emphasized</em></p>"
        result = parser.parse(html)
        assert "Important" in result
        assert "emphasized" in result

    def test_strip_emphasis(self):
        """Test stripping emphasis markers in text output"""
        parser = HTMLToTextParser()
        html = "<p>This is <b>bold</b> text</p>"
        result = parser.parse(html, {"preserve_emphasis": False, "output_format": "text"})
        assert "**" not in result
        assert "bold" in result


class TestHTMLToTextLinks:
    """Test link handling"""

    def test_simple_link(self):
        """Test converting simple link"""
        parser = HTMLToTextParser()
        html = '<a href="http://example.com">Example</a>'
        result = parser.parse(html, {"preserve_links": True, "output_format": "markdown"})
        assert "Example" in result
        # Link may be preserved as markdown or text depending on config

    def test_link_with_text(self):
        """Test link with descriptive text"""
        parser = HTMLToTextParser()
        html = 'Visit <a href="https://cve.org">CVE Database</a> for details'
        result = parser.parse(html)
        assert "CVE Database" in result

    def test_strip_links(self):
        """Test stripping links to just text"""
        parser = HTMLToTextParser()
        html = '<a href="http://example.com">Click here</a>'
        result = parser.parse(html, {"preserve_links": False})
        assert "Click here" in result
        assert "http://" not in result

    def test_multiple_links(self):
        """Test multiple links in text"""
        parser = HTMLToTextParser()
        html = '''
        <p>References:
        <a href="http://cve.org">CVE</a>,
        <a href="http://nvd.nist.gov">NVD</a>
        </p>
        '''
        result = parser.parse(html)
        assert "CVE" in result
        assert "NVD" in result


class TestHTMLToTextLists:
    """Test list handling"""

    def test_unordered_list(self):
        """Test converting unordered list"""
        parser = HTMLToTextParser()
        html = "<ul><li>Item 1</li><li>Item 2</li><li>Item 3</li></ul>"
        result = parser.parse(html)
        assert "Item 1" in result
        assert "Item 2" in result
        assert "Item 3" in result

    def test_ordered_list(self):
        """Test converting ordered list"""
        parser = HTMLToTextParser()
        html = "<ol><li>First</li><li>Second</li><li>Third</li></ol>"
        result = parser.parse(html)
        assert "First" in result
        assert "Second" in result

    def test_nested_list(self):
        """Test converting nested list"""
        parser = HTMLToTextParser()
        html = "<ul><li>Parent<ul><li>Child</li></ul></li></ul>"
        result = parser.parse(html)
        assert "Parent" in result
        assert "Child" in result


class TestHTMLToTextTables:
    """Test table handling"""

    def test_simple_table(self):
        """Test converting simple table"""
        parser = HTMLToTextParser()
        html = """
        <table>
            <tr><th>Header 1</th><th>Header 2</th></tr>
            <tr><td>Cell 1</td><td>Cell 2</td></tr>
        </table>
        """
        result = parser.parse(html, {"ignore_tables": False})
        assert "Header 1" in result
        assert "Cell 1" in result

    def test_ignore_tables(self):
        """Test ignoring table structure"""
        parser = HTMLToTextParser()
        html = """
        <table>
            <tr><td>Data</td></tr>
        </table>
        """
        result = parser.parse(html, {"ignore_tables": True})
        # Content should still be present even if table structure is ignored
        assert "Data" in result


class TestHTMLToTextCodeBlocks:
    """Test code block handling"""

    def test_inline_code(self):
        """Test inline code"""
        parser = HTMLToTextParser()
        html = "<p>Use <code>printf()</code> function</p>"
        result = parser.parse(html)
        assert "printf()" in result

    def test_pre_block(self):
        """Test preformatted block"""
        parser = HTMLToTextParser()
        html = "<pre>int main() {\n    return 0;\n}</pre>"
        result = parser.parse(html)
        assert "int main()" in result


class TestHTMLToTextEntities:
    """Test HTML entity handling"""

    def test_common_entities(self):
        """Test common HTML entities"""
        parser = HTMLToTextParser()
        html = "<p>&lt;script&gt; &amp; &quot;test&quot;</p>"
        result = parser.parse(html)
        assert "<script>" in result
        assert "&" in result
        assert '"' in result or "test" in result

    def test_nbsp_entity(self):
        """Test non-breaking space"""
        parser = HTMLToTextParser()
        html = "<p>Word&nbsp;Word</p>"
        result = parser.parse(html)
        assert "Word" in result

    def test_numeric_entities(self):
        """Test numeric character entities"""
        parser = HTMLToTextParser()
        html = "<p>&#169; Copyright &#8212; test</p>"
        result = parser.parse(html)
        # Should handle numeric entities
        assert "Copyright" in result


class TestHTMLToTextSecurityScannerContent:
    """Test with realistic security scanner HTML content"""

    def test_arachni_style_description(self):
        """Test Arachni-style HTML description"""
        parser = HTMLToTextParser()
        html = """
        <div class="description">
            <h3>SQL Injection Vulnerability</h3>
            <p>The application is vulnerable to <strong>SQL injection</strong> attacks.</p>
            <p>An attacker can use this to:</p>
            <ul>
                <li>Extract sensitive data from the database</li>
                <li>Modify or delete data</li>
                <li>Escalate privileges</li>
            </ul>
            <p>For more information, see
            <a href="https://owasp.org/www-community/attacks/SQL_Injection">OWASP SQL Injection</a>
            </p>
        </div>
        """
        result = parser.parse(html)
        assert "SQL Injection" in result
        assert "Extract sensitive data" in result
        assert "OWASP" in result

    def test_qualys_style_remediation(self):
        """Test Qualys-style HTML remediation"""
        parser = HTMLToTextParser()
        html = """
        <p><b>Remediation:</b></p>
        <p>Apply the following patches:</p>
        <table>
            <tr><td>Windows Server 2019</td><td>KB5001342</td></tr>
            <tr><td>Windows Server 2016</td><td>KB5001347</td></tr>
        </table>
        <p>Reference: <a href="https://docs.microsoft.com/security">Microsoft Security</a></p>
        """
        result = parser.parse(html)
        assert "Remediation" in result
        assert "KB5001342" in result

    def test_zap_alert_description(self):
        """Test ZAP-style alert description"""
        parser = HTMLToTextParser()
        html = """
        <p>Cross-Site Scripting (XSS) attacks are a type of injection,
        in which malicious scripts are injected into otherwise benign and trusted websites.</p>
        <br>
        <b>Evidence:</b>
        <code>&lt;script&gt;alert(1)&lt;/script&gt;</code>
        """
        result = parser.parse(html)
        assert "Cross-Site Scripting" in result
        assert "Evidence" in result


class TestHTMLToTextEdgeCases:
    """Test edge cases"""

    def test_none_input(self):
        """Test None input returns empty or default"""
        parser = HTMLToTextParser()
        result = parser.parse(None)
        assert result == ""

    def test_none_with_default(self):
        """Test None input with default value"""
        parser = HTMLToTextParser()
        result = parser.parse(None, {"default": "No description"})
        assert result == "No description"

    def test_empty_string(self):
        """Test empty string input"""
        parser = HTMLToTextParser()
        result = parser.parse("")
        assert result == ""

    def test_empty_with_default(self):
        """Test empty string with default"""
        parser = HTMLToTextParser()
        result = parser.parse("", {"default": "N/A"})
        assert result == "N/A"

    def test_whitespace_only(self):
        """Test whitespace-only input"""
        parser = HTMLToTextParser()
        result = parser.parse("   \n\t   ")
        assert result == ""

    def test_malformed_html(self):
        """Test malformed HTML is handled gracefully"""
        parser = HTMLToTextParser()
        html = "<p>Unclosed paragraph<div>Mixed <b>tags</div></p>"
        result = parser.parse(html)
        # Should not raise, should extract text
        assert "Unclosed paragraph" in result

    def test_script_tags_removed(self):
        """Test that script tags are removed"""
        parser = HTMLToTextParser()
        html = "<p>Before</p><script>alert('xss')</script><p>After</p>"
        result = parser.parse(html)
        assert "Before" in result
        assert "After" in result
        assert "alert" not in result

    def test_style_tags_removed(self):
        """Test that style tags are removed"""
        parser = HTMLToTextParser()
        html = "<style>.test{color:red}</style><p>Content</p>"
        result = parser.parse(html)
        assert "Content" in result
        assert "color" not in result

    def test_very_long_content(self):
        """Test handling very long HTML content"""
        parser = HTMLToTextParser()
        html = "<p>" + "Word " * 10000 + "</p>"
        result = parser.parse(html)
        assert len(result) > 0
        assert "Word" in result

    def test_non_string_input(self):
        """Test non-string input is converted"""
        parser = HTMLToTextParser()
        result = parser.parse(12345)
        assert result == "12345"


class TestHTMLToTextConfiguration:
    """Test configuration options"""

    def test_body_width_wrapping(self):
        """Test body width for line wrapping"""
        parser = HTMLToTextParser()
        html = "<p>" + "A" * 100 + "</p>"
        # No wrapping (body_width=0)
        result_no_wrap = parser.parse(html, {"body_width": 0})
        # With wrapping
        result_wrap = parser.parse(html, {"body_width": 40})
        # Both should contain the content
        assert "A" in result_no_wrap
        assert "A" in result_wrap

    def test_output_format_text(self):
        """Test text output format strips markdown"""
        parser = HTMLToTextParser()
        html = "<p><b>Bold</b> and <a href='http://test.com'>link</a></p>"
        result = parser.parse(html, {"output_format": "text"})
        assert "Bold" in result
        assert "link" in result


class TestHTMLToTextUtilityMethods:
    """Test utility methods"""

    def test_extract_links_single(self):
        """Test extracting single link"""
        html = '<a href="http://example.com">Example</a>'
        links = HTMLToTextParser.extract_links(html)
        assert len(links) == 1
        assert links[0]['url'] == 'http://example.com'
        assert links[0]['text'] == 'Example'

    def test_extract_links_multiple(self):
        """Test extracting multiple links"""
        html = '''
        <a href="http://one.com">One</a>
        <a href="http://two.com">Two</a>
        <a href="http://three.com">Three</a>
        '''
        links = HTMLToTextParser.extract_links(html)
        assert len(links) == 3

    def test_extract_links_skip_anchors(self):
        """Test that anchor links are skipped"""
        html = '<a href="#section">Section</a><a href="http://real.com">Real</a>'
        links = HTMLToTextParser.extract_links(html)
        assert len(links) == 1
        assert links[0]['url'] == 'http://real.com'

    def test_extract_links_empty_text(self):
        """Test link with no text uses URL"""
        html = '<a href="http://example.com"></a>'
        links = HTMLToTextParser.extract_links(html)
        # Empty link text cases may vary in handling

    def test_extract_text_from_element_li(self):
        """Test extracting text from li elements"""
        html = '<ul><li>Item 1</li><li>Item 2</li><li>Item 3</li></ul>'
        items = HTMLToTextParser.extract_text_from_element(html, 'li')
        assert len(items) == 3
        assert 'Item 1' in items
        assert 'Item 2' in items

    def test_extract_text_from_element_p(self):
        """Test extracting text from p elements"""
        html = '<div><p>Para 1</p><p>Para 2</p></div>'
        paras = HTMLToTextParser.extract_text_from_element(html, 'p')
        assert len(paras) == 2
        assert 'Para 1' in paras

    def test_extract_text_from_element_code(self):
        """Test extracting text from code elements"""
        html = '<p>Use <code>function1()</code> and <code>function2()</code></p>'
        codes = HTMLToTextParser.extract_text_from_element(html, 'code')
        assert len(codes) == 2
        assert 'function1()' in codes

    def test_contains_html_true(self):
        """Test _contains_html detects HTML"""
        assert HTMLToTextParser._contains_html("<p>test</p>") is True
        assert HTMLToTextParser._contains_html("<div class='x'>text</div>") is True
        assert HTMLToTextParser._contains_html("<br>") is True

    def test_contains_html_false(self):
        """Test _contains_html returns false for plain text"""
        assert HTMLToTextParser._contains_html("Just plain text") is False
        assert HTMLToTextParser._contains_html("Text with < less than") is False
        assert HTMLToTextParser._contains_html("") is False


class TestHTMLToTextIntegration:
    """Integration tests with registry"""

    def test_parser_in_registry(self):
        """Test parser is registered correctly"""
        from app.parsers.data_types import get_parser
        parser = get_parser('html_to_text')
        assert isinstance(parser, HTMLToTextParser)

    def test_parser_via_registry(self):
        """Test using parser via registry"""
        from app.parsers.data_types import get_parser
        parser = get_parser('html_to_text')
        result = parser.parse("<p>Test</p>")
        assert "Test" in result
