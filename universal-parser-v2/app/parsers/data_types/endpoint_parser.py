"""
Endpoint data type parser.

Parses URLs into DefectDojo Endpoint-compatible dictionaries.
Used by web scanners like Nuclei, ZAP, Arachni, Burp.

DefectDojo Endpoint fields:
- protocol: http, https, ftp, etc.
- host: hostname or IP address
- port: port number (integer)
- path: URL path
- query: query string (without ?)
- fragment: URL fragment (without #)
"""

import logging
import re
from typing import Any
from urllib.parse import urlparse, parse_qs, unquote

from app.parsers.base import DataTypeParser

logger = logging.getLogger(__name__)


class EndpointParser(DataTypeParser):
    """
    Parser that converts URLs to DefectDojo Endpoint dictionaries.

    Configuration options:
        - add_protocol_if_missing: Protocol to add if URL lacks one (e.g., 'https')
        - default_port: Default port if not specified (None = no port)
        - include_query: Whether to include query string (default: True)
        - include_fragment: Whether to include URL fragment (default: False)
        - extract_path: Whether to include path (default: True)
        - default: Value to return if URL parsing fails

    Example YAML config:
        - source_field: "matched"
          target_field: "unsaved_endpoints"
          data_type: "endpoint"
          add_protocol_if_missing: "https"

    Output format (DefectDojo Endpoint):
        {
            "protocol": "https",
            "host": "example.com",
            "port": 443,
            "path": "/api/v1",
            "query": "id=123"
        }
    """

    # Common default ports by protocol
    DEFAULT_PORTS = {
        'http': 80,
        'https': 443,
        'ftp': 21,
        'ssh': 22,
        'ws': 80,
        'wss': 443,
    }

    def parse(self, value: Any, config: dict = None) -> dict | list[dict] | None:
        """
        Parse URL(s) into Endpoint dictionary/dictionaries.

        Args:
            value: URL string or list of URLs
            config: Optional configuration with:
                - add_protocol_if_missing: Protocol to add (e.g., 'https')
                - default_port: Default port if none specified
                - include_query: Include query string (default: True)
                - include_fragment: Include fragment (default: False)
                - extract_path: Include path (default: True)
                - return_list: Always return a list (default: False)
                - default: Value if parsing fails

        Returns:
            Endpoint dict, list of Endpoint dicts, or None

        Examples:
            >>> parser = EndpointParser()
            >>> parser.parse("https://example.com:8080/path?q=1")
            {'protocol': 'https', 'host': 'example.com', 'port': 8080, 'path': '/path', 'query': 'q=1'}
            >>> parser.parse("example.com", {"add_protocol_if_missing": "https"})
            {'protocol': 'https', 'host': 'example.com'}
        """
        config = config or {}

        # Handle None or empty values
        if value is None or value == "":
            return config.get('default')

        # Handle list of URLs
        if isinstance(value, list):
            endpoints = []
            for url in value:
                ep = self._parse_single_url(url, config)
                if ep:
                    endpoints.append(ep)
            return endpoints if endpoints else config.get('default')

        # Handle single URL
        endpoint = self._parse_single_url(value, config)

        if endpoint:
            if config.get('return_list', False):
                return [endpoint]
            return endpoint

        return config.get('default')

    def _parse_single_url(self, url: Any, config: dict) -> dict | None:
        """
        Parse a single URL into an Endpoint dictionary.

        Args:
            url: URL string to parse
            config: Configuration dictionary

        Returns:
            Endpoint dictionary or None if parsing fails
        """
        if url is None or url == "":
            return None

        # Convert to string
        if not isinstance(url, str):
            url = str(url)

        url = url.strip()
        if not url:
            return None

        # Add protocol if missing
        original_url = url
        url = self._normalize_url(url, config)

        try:
            parsed = urlparse(url)
        except Exception as e:
            logger.warning(f"Failed to parse URL '{original_url}': {e}")
            return None

        # Build endpoint dictionary
        endpoint = {}

        # Protocol
        if parsed.scheme:
            endpoint['protocol'] = parsed.scheme.lower()

        # Host
        host = parsed.hostname
        if host:
            # Validate the host
            if not self._is_valid_host(host):
                logger.warning(f"Invalid host '{host}' in URL: {original_url}")
                return None
            endpoint['host'] = host.lower()
        else:
            # Try to extract host from path for protocol-less URLs
            host = self._extract_host_from_path(parsed.path)
            if host:
                endpoint['host'] = host.lower()
            else:
                logger.warning(f"No host found in URL: {original_url}")
                return None

        # Port
        try:
            port = parsed.port
        except ValueError:
            # Invalid port format (e.g., "not:a:valid:url:format")
            logger.warning(f"Invalid port in URL: {original_url}")
            return None

        if port:
            endpoint['port'] = port
        else:
            # Check for default port config or use protocol default
            default_port = config.get('default_port')
            if default_port:
                endpoint['port'] = int(default_port)
            elif config.get('use_default_ports', False) and parsed.scheme:
                protocol_default = self.DEFAULT_PORTS.get(parsed.scheme.lower())
                if protocol_default:
                    endpoint['port'] = protocol_default

        # Path
        if config.get('extract_path', True) and parsed.path:
            path = parsed.path
            # Don't include path if it's just the host (from protocol-less URL)
            if path and path != '/' and path != endpoint.get('host', ''):
                endpoint['path'] = unquote(path)

        # Query string
        if config.get('include_query', True) and parsed.query:
            endpoint['query'] = parsed.query

        # Fragment
        if config.get('include_fragment', False) and parsed.fragment:
            endpoint['fragment'] = parsed.fragment

        return endpoint if endpoint.get('host') else None

    def _normalize_url(self, url: str, config: dict) -> str:
        """
        Normalize URL by adding protocol if needed.

        Args:
            url: URL string
            config: Configuration dict

        Returns:
            Normalized URL string
        """
        # Check if URL already has a scheme
        if '://' in url:
            return url

        # Handle protocol-relative URLs (//example.com)
        if url.startswith('//'):
            protocol = config.get('add_protocol_if_missing', 'https')
            return f"{protocol}:{url}"

        # Add protocol if configured
        add_protocol = config.get('add_protocol_if_missing')
        if add_protocol:
            return f"{add_protocol}://{url}"

        # Return with // prefix for urlparse to work
        return f"//{url}"

    def _extract_host_from_path(self, path: str) -> str | None:
        """
        Extract hostname from path when URL has no scheme.

        Args:
            path: Path string that might contain host

        Returns:
            Hostname or None
        """
        if not path:
            return None

        # Remove leading slashes
        path = path.lstrip('/')

        # Split on / to get potential host
        parts = path.split('/')
        if parts:
            potential_host = parts[0]
            # Remove port if present
            if ':' in potential_host:
                potential_host = potential_host.split(':')[0]
            # Validate it looks like a host
            if self._is_valid_host(potential_host):
                return potential_host

        return None

    @staticmethod
    def _is_valid_host(host: str) -> bool:
        """
        Check if string is a valid hostname or IP address.

        Args:
            host: String to validate

        Returns:
            True if valid host
        """
        if not host:
            return False

        # Reject pure numeric strings (not valid hostnames)
        if host.isdigit():
            return False

        # Check for IP address (v4)
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, host):
            # Validate octets are 0-255
            octets = host.split('.')
            if all(0 <= int(o) <= 255 for o in octets):
                return True
            return False

        # Check for valid hostname
        # Must contain at least one dot or be 'localhost'
        if host == 'localhost':
            return True

        # Hostname pattern: alphanumeric with dots and hyphens
        # Must contain at least one letter (not pure numeric)
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$'
        if re.match(hostname_pattern, host):
            # Must have at least one letter or a dot (TLD)
            if '.' in host or any(c.isalpha() for c in host):
                return True

        return False

    @staticmethod
    def parse_host_port(value: str) -> tuple[str | None, int | None]:
        """
        Parse host:port string into components.

        Args:
            value: String like "example.com:8080" or "192.168.1.1:443"

        Returns:
            Tuple of (host, port) where port may be None

        Example:
            >>> EndpointParser.parse_host_port("example.com:8080")
            ('example.com', 8080)
            >>> EndpointParser.parse_host_port("example.com")
            ('example.com', None)
        """
        if not value:
            return None, None

        value = value.strip()

        # Handle IPv6 addresses [::1]:8080
        if value.startswith('['):
            bracket_end = value.find(']')
            if bracket_end > 0:
                host = value[1:bracket_end]
                if len(value) > bracket_end + 2 and value[bracket_end + 1] == ':':
                    try:
                        port = int(value[bracket_end + 2:])
                        return host, port
                    except ValueError:
                        pass
                return host, None

        # Handle host:port
        if ':' in value:
            parts = value.rsplit(':', 1)
            try:
                port = int(parts[1])
                return parts[0], port
            except ValueError:
                # Not a valid port, might be IPv6 without brackets
                return value, None

        return value, None

    @staticmethod
    def build_url(endpoint: dict) -> str:
        """
        Build URL string from Endpoint dictionary.

        Args:
            endpoint: Endpoint dictionary with protocol, host, port, path, query

        Returns:
            URL string

        Example:
            >>> EndpointParser.build_url({'protocol': 'https', 'host': 'example.com', 'port': 8080, 'path': '/api'})
            'https://example.com:8080/api'
        """
        if not endpoint or not endpoint.get('host'):
            return ""

        parts = []

        # Protocol
        protocol = endpoint.get('protocol', 'https')
        parts.append(f"{protocol}://")

        # Host
        parts.append(endpoint['host'])

        # Port (only if non-default)
        port = endpoint.get('port')
        if port:
            default_ports = EndpointParser.DEFAULT_PORTS
            if port != default_ports.get(protocol):
                parts.append(f":{port}")

        # Path
        path = endpoint.get('path', '')
        if path:
            if not path.startswith('/'):
                path = '/' + path
            parts.append(path)

        # Query
        query = endpoint.get('query')
        if query:
            parts.append(f"?{query}")

        # Fragment
        fragment = endpoint.get('fragment')
        if fragment:
            parts.append(f"#{fragment}")

        return ''.join(parts)

    @staticmethod
    def extract_ip_addresses(text: str) -> list[str]:
        """
        Extract IP addresses from text.

        Args:
            text: Text potentially containing IP addresses

        Returns:
            List of extracted IP addresses

        Example:
            >>> EndpointParser.extract_ip_addresses("Found at 192.168.1.1 and 10.0.0.1")
            ['192.168.1.1', '10.0.0.1']
        """
        if not text:
            return []

        # IPv4 pattern
        ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        return re.findall(ipv4_pattern, text)

    @staticmethod
    def extract_urls(text: str) -> list[str]:
        """
        Extract URLs from text.

        Args:
            text: Text potentially containing URLs

        Returns:
            List of extracted URLs

        Example:
            >>> EndpointParser.extract_urls("Visit https://example.com and http://test.com/path")
            ['https://example.com', 'http://test.com/path']
        """
        if not text:
            return []

        # URL pattern (simple but effective)
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
        urls = re.findall(url_pattern, text)

        # Clean up trailing punctuation
        cleaned = []
        for url in urls:
            # Remove trailing punctuation that's likely not part of URL
            url = re.sub(r'[.,;:!?)>\]]+$', '', url)
            if url:
                cleaned.append(url)

        return cleaned
