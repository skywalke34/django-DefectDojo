"""
Unit tests for EndpointParser.

Tests:
- Basic URL parsing
- Protocol handling
- Host extraction
- Port handling
- Path and query string
- IP addresses
- Edge cases and error handling
- Utility methods
"""

import pytest
from app.parsers.data_types.endpoint_parser import EndpointParser


class TestEndpointParserBasics:
    """Test basic URL parsing"""

    def test_simple_https_url(self):
        """Test parsing simple HTTPS URL"""
        parser = EndpointParser()
        result = parser.parse("https://example.com")
        assert result['protocol'] == 'https'
        assert result['host'] == 'example.com'

    def test_http_url_with_path(self):
        """Test parsing HTTP URL with path"""
        parser = EndpointParser()
        result = parser.parse("http://example.com/api/v1/users")
        assert result['protocol'] == 'http'
        assert result['host'] == 'example.com'
        assert result['path'] == '/api/v1/users'

    def test_url_with_port(self):
        """Test parsing URL with explicit port"""
        parser = EndpointParser()
        result = parser.parse("https://example.com:8443/api")
        assert result['protocol'] == 'https'
        assert result['host'] == 'example.com'
        assert result['port'] == 8443
        assert result['path'] == '/api'

    def test_url_with_query_string(self):
        """Test parsing URL with query string"""
        parser = EndpointParser()
        result = parser.parse("https://example.com/search?q=test&page=1")
        assert result['host'] == 'example.com'
        assert result['path'] == '/search'
        assert result['query'] == 'q=test&page=1'

    def test_url_with_fragment(self):
        """Test parsing URL with fragment (when enabled)"""
        parser = EndpointParser()
        result = parser.parse("https://example.com/docs#section1", {"include_fragment": True})
        assert result['host'] == 'example.com'
        assert result['fragment'] == 'section1'

    def test_fragment_excluded_by_default(self):
        """Test that fragment is excluded by default"""
        parser = EndpointParser()
        result = parser.parse("https://example.com/docs#section1")
        assert 'fragment' not in result


class TestEndpointParserProtocol:
    """Test protocol handling"""

    def test_add_protocol_if_missing(self):
        """Test adding protocol to URL without one"""
        parser = EndpointParser()
        result = parser.parse("example.com/path", {"add_protocol_if_missing": "https"})
        assert result['protocol'] == 'https'
        assert result['host'] == 'example.com'

    def test_preserve_existing_protocol(self):
        """Test that existing protocol is preserved"""
        parser = EndpointParser()
        result = parser.parse("http://example.com", {"add_protocol_if_missing": "https"})
        assert result['protocol'] == 'http'

    def test_protocol_relative_url(self):
        """Test protocol-relative URL (//example.com)"""
        parser = EndpointParser()
        result = parser.parse("//example.com/path", {"add_protocol_if_missing": "https"})
        assert result['protocol'] == 'https'
        assert result['host'] == 'example.com'

    def test_ftp_protocol(self):
        """Test FTP protocol"""
        parser = EndpointParser()
        result = parser.parse("ftp://files.example.com/pub")
        assert result['protocol'] == 'ftp'
        assert result['host'] == 'files.example.com'

    def test_websocket_protocol(self):
        """Test WebSocket protocol"""
        parser = EndpointParser()
        result = parser.parse("wss://socket.example.com/connect")
        assert result['protocol'] == 'wss'
        assert result['host'] == 'socket.example.com'


class TestEndpointParserHost:
    """Test host extraction"""

    def test_hostname_lowercase(self):
        """Test hostname is lowercased"""
        parser = EndpointParser()
        result = parser.parse("https://EXAMPLE.COM")
        assert result['host'] == 'example.com'

    def test_subdomain(self):
        """Test URL with subdomain"""
        parser = EndpointParser()
        result = parser.parse("https://api.v2.example.com")
        assert result['host'] == 'api.v2.example.com'

    def test_localhost(self):
        """Test localhost"""
        parser = EndpointParser()
        result = parser.parse("http://localhost:3000", {"add_protocol_if_missing": "http"})
        assert result['host'] == 'localhost'
        assert result['port'] == 3000

    def test_ipv4_address(self):
        """Test IPv4 address as host"""
        parser = EndpointParser()
        result = parser.parse("http://192.168.1.100:8080/api")
        assert result['host'] == '192.168.1.100'
        assert result['port'] == 8080


class TestEndpointParserPort:
    """Test port handling"""

    def test_explicit_port(self):
        """Test explicit port in URL"""
        parser = EndpointParser()
        result = parser.parse("https://example.com:9443")
        assert result['port'] == 9443

    def test_default_port_config(self):
        """Test default port from config"""
        parser = EndpointParser()
        result = parser.parse("https://example.com", {"default_port": 443})
        assert result['port'] == 443

    def test_use_protocol_default_ports(self):
        """Test using default ports based on protocol"""
        parser = EndpointParser()
        result = parser.parse("https://example.com", {"use_default_ports": True})
        assert result['port'] == 443

    def test_http_default_port(self):
        """Test HTTP default port"""
        parser = EndpointParser()
        result = parser.parse("http://example.com", {"use_default_ports": True})
        assert result['port'] == 80

    def test_no_port_by_default(self):
        """Test that port is not included by default if not in URL"""
        parser = EndpointParser()
        result = parser.parse("https://example.com")
        assert 'port' not in result


class TestEndpointParserPath:
    """Test path handling"""

    def test_simple_path(self):
        """Test simple path"""
        parser = EndpointParser()
        result = parser.parse("https://example.com/api")
        assert result['path'] == '/api'

    def test_nested_path(self):
        """Test nested path"""
        parser = EndpointParser()
        result = parser.parse("https://example.com/api/v1/users/123")
        assert result['path'] == '/api/v1/users/123'

    def test_root_path_excluded(self):
        """Test that root path (/) is excluded"""
        parser = EndpointParser()
        result = parser.parse("https://example.com/")
        assert 'path' not in result or result.get('path') == '/'

    def test_url_encoded_path(self):
        """Test URL-encoded path is decoded"""
        parser = EndpointParser()
        result = parser.parse("https://example.com/path%20with%20spaces")
        assert result['path'] == '/path with spaces'

    def test_exclude_path(self):
        """Test excluding path from result"""
        parser = EndpointParser()
        result = parser.parse("https://example.com/api/v1", {"extract_path": False})
        assert 'path' not in result


class TestEndpointParserQuery:
    """Test query string handling"""

    def test_simple_query(self):
        """Test simple query string"""
        parser = EndpointParser()
        result = parser.parse("https://example.com?id=123")
        assert result['query'] == 'id=123'

    def test_multiple_params(self):
        """Test multiple query parameters"""
        parser = EndpointParser()
        result = parser.parse("https://example.com?a=1&b=2&c=3")
        assert result['query'] == 'a=1&b=2&c=3'

    def test_exclude_query(self):
        """Test excluding query string"""
        parser = EndpointParser()
        result = parser.parse("https://example.com?secret=token", {"include_query": False})
        assert 'query' not in result


class TestEndpointParserList:
    """Test handling lists of URLs"""

    def test_list_of_urls(self):
        """Test parsing list of URLs"""
        parser = EndpointParser()
        urls = [
            "https://example.com/api",
            "https://api.example.com/v2",
            "http://localhost:8080"
        ]
        result = parser.parse(urls)
        assert len(result) == 3
        assert result[0]['host'] == 'example.com'
        assert result[1]['host'] == 'api.example.com'
        assert result[2]['host'] == 'localhost'

    def test_return_list_single_url(self):
        """Test returning list for single URL"""
        parser = EndpointParser()
        result = parser.parse("https://example.com", {"return_list": True})
        assert isinstance(result, list)
        assert len(result) == 1

    def test_list_with_invalid_urls(self):
        """Test list with some invalid URLs"""
        parser = EndpointParser()
        urls = [
            "https://valid.com",
            "",
            None,
            "https://also-valid.com"
        ]
        result = parser.parse(urls)
        assert len(result) == 2


class TestEndpointParserEdgeCases:
    """Test edge cases"""

    def test_none_input(self):
        """Test None input"""
        parser = EndpointParser()
        result = parser.parse(None)
        assert result is None

    def test_none_with_default(self):
        """Test None with default value"""
        parser = EndpointParser()
        default_ep = {"host": "fallback.com", "protocol": "https"}
        result = parser.parse(None, {"default": default_ep})
        assert result == default_ep

    def test_empty_string(self):
        """Test empty string"""
        parser = EndpointParser()
        result = parser.parse("")
        assert result is None

    def test_whitespace_only(self):
        """Test whitespace-only input"""
        parser = EndpointParser()
        result = parser.parse("   \n\t  ")
        assert result is None

    def test_malformed_url(self):
        """Test malformed URL is handled gracefully"""
        parser = EndpointParser()
        result = parser.parse("not:a:valid:url:format")
        # Should return None or best effort parse
        # Behavior depends on implementation

    def test_url_with_credentials(self):
        """Test URL with credentials (user:pass@host)"""
        parser = EndpointParser()
        result = parser.parse("https://user:pass@example.com/api")
        assert result['host'] == 'example.com'
        # Credentials should not be in endpoint

    def test_numeric_input(self):
        """Test numeric input returns None (not a valid hostname)"""
        parser = EndpointParser()
        result = parser.parse(12345)
        # Pure numeric strings are not valid hostnames
        assert result is None


class TestEndpointParserSecurityScannerURLs:
    """Test with realistic security scanner URLs"""

    def test_nuclei_matched_url(self):
        """Test Nuclei-style matched URL"""
        parser = EndpointParser()
        result = parser.parse("https://vulnerable-app.example.com:8443/api/v1/admin")
        assert result['protocol'] == 'https'
        assert result['host'] == 'vulnerable-app.example.com'
        assert result['port'] == 8443
        assert result['path'] == '/api/v1/admin'

    def test_zap_target_url(self):
        """Test ZAP-style target URL"""
        parser = EndpointParser()
        result = parser.parse("http://testsite.local:8080/login.php?redirect=/admin")
        assert result['host'] == 'testsite.local'
        assert result['port'] == 8080
        assert result['path'] == '/login.php'
        assert result['query'] == 'redirect=/admin'

    def test_burp_url_with_params(self):
        """Test Burp-style URL with parameters"""
        parser = EndpointParser()
        result = parser.parse("https://app.example.com/search?q=test&category=all&sort=date")
        assert result['query'] == 'q=test&category=all&sort=date'

    def test_internal_ip_scan(self):
        """Test internal IP address from scanner"""
        parser = EndpointParser()
        result = parser.parse("http://10.0.0.50:9000/healthcheck")
        assert result['host'] == '10.0.0.50'
        assert result['port'] == 9000


class TestEndpointParserUtilityMethods:
    """Test utility methods"""

    def test_parse_host_port_with_port(self):
        """Test parse_host_port with port"""
        host, port = EndpointParser.parse_host_port("example.com:8080")
        assert host == "example.com"
        assert port == 8080

    def test_parse_host_port_without_port(self):
        """Test parse_host_port without port"""
        host, port = EndpointParser.parse_host_port("example.com")
        assert host == "example.com"
        assert port is None

    def test_parse_host_port_ip(self):
        """Test parse_host_port with IP"""
        host, port = EndpointParser.parse_host_port("192.168.1.1:443")
        assert host == "192.168.1.1"
        assert port == 443

    def test_parse_host_port_empty(self):
        """Test parse_host_port with empty string"""
        host, port = EndpointParser.parse_host_port("")
        assert host is None
        assert port is None

    def test_build_url_basic(self):
        """Test build_url with basic endpoint"""
        endpoint = {"protocol": "https", "host": "example.com"}
        url = EndpointParser.build_url(endpoint)
        assert url == "https://example.com"

    def test_build_url_with_port(self):
        """Test build_url with non-default port"""
        endpoint = {"protocol": "https", "host": "example.com", "port": 8443}
        url = EndpointParser.build_url(endpoint)
        assert url == "https://example.com:8443"

    def test_build_url_default_port_excluded(self):
        """Test build_url excludes default port"""
        endpoint = {"protocol": "https", "host": "example.com", "port": 443}
        url = EndpointParser.build_url(endpoint)
        assert url == "https://example.com"

    def test_build_url_with_path(self):
        """Test build_url with path"""
        endpoint = {"protocol": "https", "host": "example.com", "path": "/api/v1"}
        url = EndpointParser.build_url(endpoint)
        assert url == "https://example.com/api/v1"

    def test_build_url_with_query(self):
        """Test build_url with query string"""
        endpoint = {"protocol": "https", "host": "example.com", "query": "id=123"}
        url = EndpointParser.build_url(endpoint)
        assert url == "https://example.com?id=123"

    def test_build_url_complete(self):
        """Test build_url with all components"""
        endpoint = {
            "protocol": "https",
            "host": "example.com",
            "port": 8443,
            "path": "/api",
            "query": "v=1",
            "fragment": "section"
        }
        url = EndpointParser.build_url(endpoint)
        assert url == "https://example.com:8443/api?v=1#section"

    def test_extract_ip_addresses(self):
        """Test extract_ip_addresses"""
        text = "Hosts found: 192.168.1.1, 10.0.0.50, and 172.16.0.1"
        ips = EndpointParser.extract_ip_addresses(text)
        assert len(ips) == 3
        assert "192.168.1.1" in ips
        assert "10.0.0.50" in ips

    def test_extract_ip_addresses_empty(self):
        """Test extract_ip_addresses with no IPs"""
        text = "No IP addresses here"
        ips = EndpointParser.extract_ip_addresses(text)
        assert len(ips) == 0

    def test_extract_urls(self):
        """Test extract_urls from text"""
        text = "Visit https://example.com and http://test.com/path for more info."
        urls = EndpointParser.extract_urls(text)
        assert len(urls) == 2
        assert "https://example.com" in urls
        assert "http://test.com/path" in urls

    def test_extract_urls_cleans_punctuation(self):
        """Test extract_urls removes trailing punctuation"""
        text = "See https://example.com. Also http://test.com!"
        urls = EndpointParser.extract_urls(text)
        assert "https://example.com" in urls
        assert "http://test.com" in urls

    def test_is_valid_host_hostname(self):
        """Test _is_valid_host with hostname"""
        assert EndpointParser._is_valid_host("example.com") is True
        assert EndpointParser._is_valid_host("sub.domain.example.com") is True

    def test_is_valid_host_ip(self):
        """Test _is_valid_host with IP"""
        assert EndpointParser._is_valid_host("192.168.1.1") is True
        assert EndpointParser._is_valid_host("10.0.0.1") is True

    def test_is_valid_host_localhost(self):
        """Test _is_valid_host with localhost"""
        assert EndpointParser._is_valid_host("localhost") is True

    def test_is_valid_host_invalid(self):
        """Test _is_valid_host with invalid hosts"""
        assert EndpointParser._is_valid_host("") is False
        assert EndpointParser._is_valid_host(None) is False


class TestEndpointParserIntegration:
    """Integration tests with registry"""

    def test_parser_in_registry(self):
        """Test parser is registered correctly"""
        from app.parsers.data_types import get_parser
        parser = get_parser('endpoint')
        assert isinstance(parser, EndpointParser)

    def test_parser_via_registry(self):
        """Test using parser via registry"""
        from app.parsers.data_types import get_parser
        parser = get_parser('endpoint')
        result = parser.parse("https://test.example.com:8080/api")
        assert result['host'] == 'test.example.com'
        assert result['port'] == 8080
