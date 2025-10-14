"""
Unit tests for DefectDojoClient.

Tests client initialization and basic functionality.
For now these are basic tests - integration tests with real API will come later.
"""

import pytest
from app.clients.defectdojo_client import DefectDojoClient


class TestDefectDojoClient:
    """Test DefectDojoClient initialization and configuration"""

    def test_client_initialization(self):
        """Test that client initializes with required parameters"""
        client = DefectDojoClient(
            base_url="https://defectdojo.example.com",
            api_token="test-token-123"
        )

        assert client.base_url == "https://defectdojo.example.com"
        assert client.api_token == "test-token-123"
        assert client.timeout == 300  # default
        assert client.verify_ssl is True  # default

    def test_client_initialization_with_custom_params(self):
        """Test client initialization with custom parameters"""
        client = DefectDojoClient(
            base_url="https://defectdojo.example.com/",  # trailing slash
            api_token="custom-token",
            timeout=600,
            verify_ssl=False
        )

        assert client.base_url == "https://defectdojo.example.com"  # trailing slash removed
        assert client.timeout == 600
        assert client.verify_ssl is False

    def test_get_headers(self):
        """Test that headers are correctly formatted"""
        client = DefectDojoClient(
            base_url="https://defectdojo.example.com",
            api_token="test-token-123"
        )

        headers = client._get_headers()

        assert headers["Authorization"] == "Token test-token-123"
        assert headers["Content-Type"] == "application/json"
        assert headers["Accept"] == "application/json"

    @pytest.mark.asyncio
    async def test_client_context_manager(self):
        """Test that client works as async context manager"""
        async with DefectDojoClient(
            base_url="https://defectdojo.example.com",
            api_token="test-token"
        ) as client:
            assert client is not None
            assert client.client is not None

        # Client should be closed after context manager exits
        # (we can't easily test this without making actual requests)


# Run tests if executed directly
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
