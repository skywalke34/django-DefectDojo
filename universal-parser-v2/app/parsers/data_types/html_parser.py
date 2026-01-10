"""
HTML to Text data type parser.

Converts HTML content to plain text or markdown format.
Used by parsers for tools like Arachni, Qualys, ZAP, Burp
that output HTML-formatted descriptions and recommendations.
"""

import logging
import re
from typing import Any

import html2text

from app.parsers.base import DataTypeParser

logger = logging.getLogger(__name__)


class HTMLToTextParser(DataTypeParser):
    """
    Parser that converts HTML to plain text or markdown.

    Configuration options:
        - preserve_links: Keep links as markdown links (default: True)
        - preserve_emphasis: Keep bold/italic as markdown (default: True)
        - body_width: Line width for wrapping (default: 0 = no wrapping)
        - ignore_images: Skip image tags (default: True)
        - ignore_tables: Skip table formatting (default: False)
        - output_format: 'text' or 'markdown' (default: 'text')
        - default: Value to return if input is None/empty

    Example YAML config:
        - source_field: "Description"
          target_field: "description"
          data_type: "html_to_text"
          preserve_links: true
          output_format: "text"
    """

    def __init__(self):
        """Initialize HTML to text converter with default settings."""
        self._converter = None

    def _get_converter(self, config: dict) -> html2text.HTML2Text:
        """
        Create configured HTML2Text converter instance.

        Args:
            config: Configuration dictionary

        Returns:
            Configured HTML2Text instance
        """
        h = html2text.HTML2Text()

        # Link handling
        h.ignore_links = not config.get('preserve_links', True)

        # Emphasis handling (bold/italic)
        h.ignore_emphasis = not config.get('preserve_emphasis', True)

        # Line width (0 = no wrapping)
        h.body_width = config.get('body_width', 0)

        # Image handling
        h.ignore_images = config.get('ignore_images', True)

        # Table handling
        h.ignore_tables = config.get('ignore_tables', False)

        # Skip internal links (anchors)
        h.skip_internal_links = True

        # Don't escape special markdown characters by default
        h.escape_snob = False

        return h

    def parse(self, value: Any, config: dict = None) -> str:
        """
        Convert HTML content to plain text or markdown.

        Args:
            value: HTML string to convert
            config: Optional configuration with:
                - preserve_links: Keep links as [text](url) (default: True)
                - preserve_emphasis: Keep **bold** and *italic* (default: True)
                - body_width: Line wrap width, 0=none (default: 0)
                - ignore_images: Skip image tags (default: True)
                - ignore_tables: Skip table formatting (default: False)
                - output_format: 'text' or 'markdown' (default: 'text')
                - default: Value if input is None/empty

        Returns:
            Converted text string

        Examples:
            >>> parser = HTMLToTextParser()
            >>> parser.parse("<p>Hello <b>World</b></p>")
            'Hello **World**'
            >>> parser.parse("<a href='http://example.com'>Link</a>")
            '[Link](http://example.com)'
            >>> parser.parse("<p>Test</p>", {"preserve_emphasis": False})
            'Test'
        """
        config = config or {}

        # Handle None or empty values
        if value is None or value == "":
            default = config.get('default')
            return default if default is not None else ""

        # Convert to string if needed
        if not isinstance(value, str):
            value = str(value)

        # Quick check: if no HTML tags, just clean up whitespace
        if not self._contains_html(value):
            return self._clean_text(value, config)

        # Create converter with config
        converter = self._get_converter(config)

        # Convert HTML to text/markdown
        try:
            result = converter.handle(value)
        except Exception as e:
            logger.warning(f"HTML conversion failed, falling back to simple strip: {e}")
            result = self._simple_strip_html(value)

        # Post-process based on output format
        output_format = config.get('output_format', 'text')
        if output_format == 'text':
            result = self._strip_markdown(result, config)

        # Clean up whitespace
        result = self._clean_text(result, config)

        # Apply default if result is empty
        if not result:
            default = config.get('default')
            return default if default is not None else ""

        return result

    @staticmethod
    def _contains_html(text: str) -> bool:
        """
        Check if text contains HTML tags.

        Args:
            text: Text to check

        Returns:
            True if HTML tags found
        """
        # Look for common HTML patterns
        return bool(re.search(r'<[a-zA-Z][^>]*>', text))

    @staticmethod
    def _clean_text(text: str, config: dict) -> str:
        """
        Clean up whitespace in converted text.

        Args:
            text: Text to clean
            config: Configuration dict

        Returns:
            Cleaned text
        """
        # Remove excess blank lines (more than 2 consecutive)
        text = re.sub(r'\n{3,}', '\n\n', text)

        # Strip leading/trailing whitespace from each line
        lines = [line.strip() for line in text.split('\n')]
        text = '\n'.join(lines)

        # Strip overall leading/trailing whitespace
        text = text.strip()

        return text

    @staticmethod
    def _strip_markdown(text: str, config: dict) -> str:
        """
        Remove markdown formatting from text for plain text output.

        Args:
            text: Text potentially containing markdown
            config: Configuration dict

        Returns:
            Plain text without markdown
        """
        # Only strip if not preserving these elements
        if not config.get('preserve_links', True):
            # Links are already stripped by html2text when ignore_links=True
            pass
        else:
            # Convert markdown links [text](url) to just text
            text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)

        if not config.get('preserve_emphasis', True):
            # Emphasis already stripped by html2text when ignore_emphasis=True
            pass
        else:
            # Remove ** and * emphasis markers
            text = re.sub(r'\*\*([^*]+)\*\*', r'\1', text)
            text = re.sub(r'\*([^*]+)\*', r'\1', text)
            text = re.sub(r'__([^_]+)__', r'\1', text)
            text = re.sub(r'_([^_]+)_', r'\1', text)

        # Remove heading markers
        text = re.sub(r'^#+\s*', '', text, flags=re.MULTILINE)

        # Remove horizontal rules
        text = re.sub(r'^[\-*_]{3,}\s*$', '', text, flags=re.MULTILINE)

        return text

    @staticmethod
    def _simple_strip_html(text: str) -> str:
        """
        Simple fallback HTML stripping if html2text fails.

        Args:
            text: HTML text

        Returns:
            Text with HTML tags removed
        """
        # Remove script and style content
        text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.IGNORECASE | re.DOTALL)
        text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.IGNORECASE | re.DOTALL)

        # Remove HTML tags
        text = re.sub(r'<[^>]+>', ' ', text)

        # Decode common HTML entities
        entities = {
            '&nbsp;': ' ',
            '&lt;': '<',
            '&gt;': '>',
            '&amp;': '&',
            '&quot;': '"',
            '&#39;': "'",
            '&apos;': "'",
            '&mdash;': '—',
            '&ndash;': '–',
            '&hellip;': '...',
            '&bull;': '•',
            '&copy;': '©',
            '&reg;': '®',
            '&trade;': '™',
        }
        for entity, char in entities.items():
            text = text.replace(entity, char)

        # Handle numeric entities
        text = re.sub(r'&#(\d+);', lambda m: chr(int(m.group(1))), text)
        text = re.sub(r'&#x([0-9a-fA-F]+);', lambda m: chr(int(m.group(1), 16)), text)

        # Collapse whitespace
        text = re.sub(r'\s+', ' ', text)

        return text.strip()

    @staticmethod
    def extract_links(html: str) -> list[dict]:
        """
        Extract all links from HTML content.

        Useful for building reference lists from HTML descriptions.

        Args:
            html: HTML string to extract links from

        Returns:
            List of dicts with 'text' and 'url' keys

        Example:
            >>> HTMLToTextParser.extract_links('<a href="http://cve.org">CVE</a>')
            [{'text': 'CVE', 'url': 'http://cve.org'}]
        """
        links = []
        pattern = r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]*)</a>'
        for match in re.finditer(pattern, html, re.IGNORECASE):
            url, text = match.groups()
            if url and not url.startswith('#'):  # Skip anchor links
                links.append({
                    'text': text.strip() or url,
                    'url': url
                })
        return links

    @staticmethod
    def extract_text_from_element(html: str, tag: str) -> list[str]:
        """
        Extract text content from specific HTML elements.

        Args:
            html: HTML string
            tag: Tag name to extract (e.g., 'li', 'p', 'code')

        Returns:
            List of text contents from matching elements

        Example:
            >>> HTMLToTextParser.extract_text_from_element('<ul><li>Item 1</li><li>Item 2</li></ul>', 'li')
            ['Item 1', 'Item 2']
        """
        pattern = rf'<{tag}[^>]*>([^<]*)</{tag}>'
        matches = re.findall(pattern, html, re.IGNORECASE)
        return [m.strip() for m in matches if m.strip()]
