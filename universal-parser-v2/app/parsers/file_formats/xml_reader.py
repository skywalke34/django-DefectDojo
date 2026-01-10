"""
XML file format reader.

Parses XML files and extracts findings using XPath expressions.
Supports XML namespaces for formats like CycloneDX.
"""

import logging
from typing import Any, Optional
from lxml import etree

from app.parsers.base import FileFormatReader
from app.utils.errors import FileFormatError

logger = logging.getLogger(__name__)


class XMLReader(FileFormatReader):
    """
    Reads and parses XML scan files.

    Supports:
    - XPath expressions for finding extraction
    - XML namespace handling
    - Attribute extraction (@attr syntax)
    - Nested element extraction
    - Text content extraction
    """

    def read(self, file_content: bytes, config: dict) -> list[dict]:
        """
        Read XML file and extract findings array.

        Args:
            file_content: Raw XML file content as bytes
            config: Configuration dict with:
                - xml_finding_xpath: XPath to finding elements
                - xml_namespaces: Optional dict of namespace prefixes to URIs

        Returns:
            List of finding dictionaries

        Raises:
            FileFormatError: If XML is invalid or findings cannot be extracted

        Example:
            >>> config = {
            ...     "xml_finding_xpath": "//vulnerability",
            ...     "xml_namespaces": {"bom": "http://cyclonedx.org/schema/bom/1.4"}
            ... }
            >>> xml_bytes = b'<bom><vulnerability><id>CVE-2021-1234</id></vulnerability></bom>'
            >>> reader = XMLReader()
            >>> findings = reader.read(xml_bytes, config)
            >>> len(findings) > 0
            True
        """
        # Parse XML
        try:
            root = etree.fromstring(file_content)
        except etree.XMLSyntaxError as e:
            raise FileFormatError(
                f"Invalid XML format: {str(e)}\n"
                f"Line {e.lineno if hasattr(e, 'lineno') else 'unknown'}"
            )

        # Get XPath expression from config
        xpath_expr = config.get('xml_finding_xpath')
        if not xpath_expr:
            raise FileFormatError(
                "xml_finding_xpath is required for XML format. "
                "Example: '//vulnerability' or '//bom:vulnerability'"
            )

        # Get namespace mappings
        namespaces = config.get('xml_namespaces', {})

        # If no namespaces provided, try to detect from root element
        if not namespaces:
            namespaces = self._detect_namespaces(root)

        # Extract findings using XPath
        try:
            elements = root.xpath(xpath_expr, namespaces=namespaces)
        except etree.XPathError as e:
            raise FileFormatError(
                f"Invalid XPath expression '{xpath_expr}': {str(e)}"
            )

        if not elements:
            # Try without namespace if no results
            if namespaces:
                logger.warning(
                    f"No findings found with namespaces. "
                    f"Trying without namespace prefixes..."
                )
                try:
                    elements = root.xpath(xpath_expr)
                except etree.XPathError:
                    pass

            if not elements:
                raise FileFormatError(
                    f"No findings found using XPath: {xpath_expr}\n"
                    f"Namespaces: {namespaces}\n"
                    f"Make sure the XPath points to the vulnerability elements in your XML file."
                )

        # Convert XML elements to dictionaries
        findings = []
        for element in elements:
            finding_dict = self._element_to_dict(element, namespaces)
            findings.append(finding_dict)

        logger.info(f"Extracted {len(findings)} findings from XML file")
        return findings

    def _detect_namespaces(self, root: etree._Element) -> dict:
        """
        Detect namespace mappings from root element.

        Args:
            root: Root XML element

        Returns:
            Dictionary of namespace prefix to URI mappings
        """
        namespaces = {}

        # Get default namespace if present
        if root.nsmap:
            for prefix, uri in root.nsmap.items():
                if prefix is None:
                    # Default namespace - assign a prefix for XPath use
                    namespaces['ns'] = uri
                else:
                    namespaces[prefix] = uri

        return namespaces

    def _element_to_dict(
        self,
        element: etree._Element,
        namespaces: dict,
        depth: int = 0,
        max_depth: int = 10
    ) -> dict:
        """
        Convert XML element to nested dictionary.

        Args:
            element: XML element to convert
            namespaces: Namespace mappings for element name cleaning
            depth: Current recursion depth
            max_depth: Maximum recursion depth to prevent infinite loops

        Returns:
            Dictionary representation of element

        Note:
            - Element attributes are prefixed with '@'
            - Text content is stored as the key without prefix
            - Child elements are nested dictionaries
        """
        if depth > max_depth:
            return {"_truncated": True, "_text": self._get_text(element)}

        result = {}

        # Get element tag name (without namespace prefix)
        tag = self._clean_tag(element.tag)

        # Add attributes with @ prefix
        for attr_name, attr_value in element.attrib.items():
            clean_attr = self._clean_tag(attr_name)
            result[f"@{clean_attr}"] = attr_value

        # Check for child elements
        children = list(element)

        if children:
            # Process child elements
            for child in children:
                child_tag = self._clean_tag(child.tag)
                child_dict = self._element_to_dict(
                    child, namespaces, depth + 1, max_depth
                )

                # Handle multiple children with same tag name
                if child_tag in result:
                    # Convert to list if not already
                    if not isinstance(result[child_tag], list):
                        result[child_tag] = [result[child_tag]]
                    result[child_tag].append(child_dict)
                else:
                    result[child_tag] = child_dict

            # Also capture any text content mixed with children
            if element.text and element.text.strip():
                result['_text'] = element.text.strip()

        else:
            # Leaf element - get text content
            text = self._get_text(element)
            if text:
                # For simple elements, return just the text if no attributes
                if not result:
                    return text
                result['_text'] = text

        return result if result else ""

    def _get_text(self, element: etree._Element) -> str:
        """
        Get text content of element, including tail text.

        Args:
            element: XML element

        Returns:
            Combined text content, stripped of whitespace
        """
        # Get direct text content
        text = element.text or ""

        # Get all descendant text (for mixed content)
        all_text = ''.join(element.itertext())

        return all_text.strip() if all_text else text.strip()

    def _clean_tag(self, tag: str) -> str:
        """
        Remove namespace prefix from tag name.

        Args:
            tag: XML tag potentially with namespace (e.g., '{http://...}tagname')

        Returns:
            Clean tag name without namespace

        Example:
            >>> reader = XMLReader()
            >>> reader._clean_tag('{http://cyclonedx.org/schema/bom/1.4}vulnerability')
            'vulnerability'
        """
        if tag.startswith('{'):
            # Remove namespace URI in curly braces
            return tag.split('}', 1)[1]
        return tag

    def extract_field(
        self,
        element: etree._Element,
        xpath: str,
        namespaces: dict = None
    ) -> Optional[str]:
        """
        Extract a single field value using XPath.

        Args:
            element: Parent XML element
            xpath: XPath expression relative to element
            namespaces: Namespace mappings

        Returns:
            Extracted value or None

        Example:
            >>> # For element <vuln><id>CVE-2021-1234</id></vuln>
            >>> reader.extract_field(element, 'id/text()')
            'CVE-2021-1234'
        """
        try:
            results = element.xpath(xpath, namespaces=namespaces or {})
            if results:
                if isinstance(results[0], etree._Element):
                    return self._get_text(results[0])
                return str(results[0])
        except etree.XPathError as e:
            logger.warning(f"XPath extraction failed for '{xpath}': {e}")

        return None

    @staticmethod
    def validate_xml_syntax(xml_bytes: bytes) -> tuple[bool, str]:
        """
        Validate XML syntax.

        Args:
            xml_bytes: XML content as bytes

        Returns:
            Tuple of (is_valid, error_message)

        Example:
            >>> valid, error = XMLReader.validate_xml_syntax(b'<valid/>')
            >>> valid
            True
            >>> valid, error = XMLReader.validate_xml_syntax(b'<invalid')
            >>> valid
            False
        """
        try:
            etree.fromstring(xml_bytes)
            return True, ""
        except etree.XMLSyntaxError as e:
            return False, f"Line {getattr(e, 'lineno', 'unknown')}: {str(e)}"
