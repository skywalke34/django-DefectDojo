"""
DefectDojo API Client.

Handles communication with DefectDojo's REST API for importing/reimporting findings.
"""

import logging
from typing import Any, Optional
import httpx

from app.utils.errors import DefectDojoAPIError

logger = logging.getLogger(__name__)


class DefectDojoClient:
    """
    Client for interacting with DefectDojo API.

    This client handles:
    - Authentication (API token)
    - Reimport-scan endpoint calls
    - Error handling and retries
    - Response validation

    Example:
        >>> client = DefectDojo Client(
        ...     base_url="https://defectdojo.example.com",
        ...     api_token="your-api-token"
        ... )
        >>> result = await client.reimport_scan(
        ...     test_id=123,
        ...     findings=[...],
        ...     scan_date="2024-01-01"
        ... )
        >>> result['test_import_finding_action']['processed']
        5
    """

    def __init__(
        self,
        base_url: str,
        api_token: str,
        timeout: int = 300,
        verify_ssl: bool = True
    ):
        """
        Initialize DefectDojo API client.

        Args:
            base_url: DefectDojo base URL (e.g., "https://defectdojo.example.com")
            api_token: API authentication token
            timeout: Request timeout in seconds (default: 300)
            verify_ssl: Whether to verify SSL certificates (default: True)
        """
        self.base_url = base_url.rstrip('/')
        self.api_token = api_token
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        # Create HTTP client
        self.client = httpx.AsyncClient(
            timeout=timeout,
            verify=verify_ssl,
            headers=self._get_headers()
        )

    def _get_headers(self) -> dict[str, str]:
        """
        Get HTTP headers for API requests.

        Returns:
            Dictionary of HTTP headers including authentication
        """
        return {
            "Authorization": f"Token {self.api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    async def universal_parser_v2_reimport(
        self,
        test_id: int,
        findings: list[dict[str, Any]],
        scan_date: str,
        minimum_severity: Optional[str] = None,
        active: bool = True,
        verified: bool = False,
        close_old_findings: bool = True,
        do_not_reactivate: bool = False,
        push_to_jira: bool = False,
        version: Optional[str] = None,
        tags: Optional[list[str]] = None,
        **kwargs
    ) -> dict[str, Any]:
        """
        Reimport pre-normalized findings using Universal Parser V2 endpoint.

        This method calls the `/api/v2/universal-parser-v2/reimport-scan/` endpoint
        which is specifically designed for Universal Parser V2. Unlike the standard
        reimport endpoint, this accepts pre-normalized finding dictionaries directly.

        The Universal Parser V2 endpoint handles:
        - Pre-normalized findings (no file parsing needed)
        - Deduplication using DefectDojo's existing logic
        - Updating existing findings
        - Creating new findings
        - Closing findings not in current scan
        - Reactivating previously closed findings

        Args:
            test_id: DefectDojo Test ID to reimport into
            findings: List of normalized finding dictionaries from microservice
            scan_date: Scan date in YYYY-MM-DD format
            minimum_severity: Minimum severity to import (optional)
            active: Mark new findings as active (default: True)
            verified: Mark new findings as verified (default: False)
            close_old_findings: Close findings not in scan (default: True)
            do_not_reactivate: Don't reactivate closed findings (default: False)
            push_to_jira: Push findings to JIRA if configured (default: False)
            version: Version string for the test (optional)
            tags: Tags to apply to findings (optional)
            **kwargs: Additional parameters

        Returns:
            API response dictionary with import statistics

        Raises:
            DefectDojoAPIError: If API call fails

        Example:
            >>> result = await client.universal_parser_v2_reimport(
            ...     test_id=123,
            ...     findings=[
            ...         {
            ...             "title": "XSS Vulnerability",
            ...             "severity": "High",
            ...             "description": "Cross-site scripting found",
            ...             "unique_id_from_tool": "acunetix-xss-001",
            ...             "cwe": 79,
            ...             "cvssv3_score": 6.1
            ...         }
            ...     ],
            ...     scan_date="2024-01-15",
            ...     version="1.2.3",
            ...     tags=["automated", "nightly"]
            ... )
            >>> result['test_import_finding_action']
            {
                'created': 1,
                'closed': 0,
                'reactivated': 0,
                'updated': 0,
                'untouched': 0
            }
        """
        # Build request payload
        payload = {
            "test": test_id,
            "findings": findings,
            "scan_date": scan_date,
            "active": active,
            "verified": verified,
            "close_old_findings": close_old_findings,
            "do_not_reactivate": do_not_reactivate,
            "push_to_jira": push_to_jira,
        }

        # Add optional parameters
        if minimum_severity:
            payload["minimum_severity"] = minimum_severity

        if version:
            payload["version"] = version

        if tags:
            payload["tags"] = tags

        # Add any additional kwargs
        payload.update(kwargs)

        # Make API request to Universal Parser V2 endpoint
        url = f"{self.base_url}/api/v2/universal-parser-v2/reimport-scan/"
        logger.info(
            f"Universal Parser V2: Reimporting {len(findings)} findings to test {test_id}"
        )

        try:
            response = await self.client.post(url, json=payload)

            # Check for errors
            if response.status_code not in (200, 201):
                error_message = self._extract_error_message(response)
                raise DefectDojoAPIError(
                    status_code=response.status_code,
                    message=error_message
                )

            result = response.json()
            logger.info(
                f"Universal Parser V2 reimport successful: "
                f"{result.get('test_import_finding_action', {})}"
            )
            return result

        except httpx.HTTPError as e:
            logger.error(f"HTTP error during Universal Parser V2 reimport: {str(e)}")
            raise DefectDojoAPIError(
                status_code=0,
                message=f"HTTP request failed: {str(e)}"
            )

    async def reimport_scan(
        self,
        test_id: int,
        findings: list[dict[str, Any]],
        scan_date: str,
        scan_type: Optional[str] = None,
        minimum_severity: Optional[str] = None,
        active: bool = True,
        verified: bool = False,
        close_old_findings: bool = True,
        push_to_jira: bool = False,
        **kwargs
    ) -> dict[str, Any]:
        """
        Reimport scan findings into DefectDojo (legacy endpoint).

        DEPRECATED: Use universal_parser_v2_reimport() instead for Universal Parser V2.

        This method calls the `/api/v2/reimport-scan/` endpoint which handles:
        - Deduplication using hash_code and unique_id_from_tool
        - Updating existing findings
        - Creating new findings
        - Closing findings not in current scan

        Args:
            test_id: DefectDojo Test ID to reimport into
            findings: List of normalized finding dictionaries
            scan_date: Scan date in YYYY-MM-DD format
            scan_type: Scanner type name (optional)
            minimum_severity: Minimum severity to import (optional)
            active: Mark findings as active (default: True)
            verified: Mark findings as verified (default: False)
            close_old_findings: Close findings not in scan (default: True)
            push_to_jira: Push findings to JIRA if configured (default: False)
            **kwargs: Additional parameters

        Returns:
            API response dictionary with import statistics

        Raises:
            DefectDojoAPIError: If API call fails

        Example:
            >>> result = await client.reimport_scan(
            ...     test_id=123,
            ...     findings=[
            ...         {
            ...             "title": "XSS Vulnerability",
            ...             "severity": "High",
            ...             "description": "Cross-site scripting found",
            ...             "unique_id_from_tool": "acunetix-xss-001"
            ...         }
            ...     ],
            ...     scan_date="2024-01-15",
            ...     scan_type="Acunetix 360"
            ... )
            >>> result['test_import_finding_action']
            {
                'created': 1,
                'closed': 0,
                'reactivated': 0,
                'updated': 0,
                'untouched': 0,
                'processed': 1
            }
        """
        # Build request payload
        payload = {
            "test": test_id,
            "findings": findings,
            "scan_date": scan_date,
            "active": active,
            "verified": verified,
            "close_old_findings": close_old_findings,
            "push_to_jira": push_to_jira,
        }

        # Add optional parameters
        if scan_type:
            payload["scan_type"] = scan_type

        if minimum_severity:
            payload["minimum_severity"] = minimum_severity

        # Add any additional kwargs
        payload.update(kwargs)

        # Make API request
        url = f"{self.base_url}/api/v2/reimport-scan/"
        logger.info(f"Reimporting {len(findings)} findings to test {test_id}")

        try:
            response = await self.client.post(url, json=payload)

            # Check for errors
            if response.status_code not in (200, 201):
                error_message = self._extract_error_message(response)
                raise DefectDojoAPIError(
                    status_code=response.status_code,
                    message=error_message
                )

            result = response.json()
            logger.info(
                f"Reimport successful: {result.get('test_import_finding_action', {})}"
            )
            return result

        except httpx.HTTPError as e:
            logger.error(f"HTTP error during reimport: {str(e)}")
            raise DefectDojoAPIError(
                status_code=0,
                message=f"HTTP request failed: {str(e)}"
            )

    def _extract_error_message(self, response: httpx.Response) -> str:
        """
        Extract error message from API response.

        Args:
            response: HTTP response object

        Returns:
            Error message string
        """
        try:
            error_data = response.json()
            if isinstance(error_data, dict):
                # Try common error fields
                for field in ['detail', 'message', 'error', 'errors']:
                    if field in error_data:
                        return str(error_data[field])
            return str(error_data)
        except Exception:
            return response.text or f"HTTP {response.status_code}"

    async def get_test(self, test_id: int) -> dict[str, Any]:
        """
        Get test details from DefectDojo.

        Args:
            test_id: DefectDojo Test ID

        Returns:
            Test details dictionary

        Raises:
            DefectDojoAPIError: If API call fails
        """
        url = f"{self.base_url}/api/v2/tests/{test_id}/"
        logger.debug(f"Fetching test {test_id}")

        try:
            response = await self.client.get(url)

            if response.status_code != 200:
                error_message = self._extract_error_message(response)
                raise DefectDojoAPIError(
                    status_code=response.status_code,
                    message=error_message
                )

            return response.json()

        except httpx.HTTPError as e:
            logger.error(f"HTTP error fetching test: {str(e)}")
            raise DefectDojoAPIError(
                status_code=0,
                message=f"HTTP request failed: {str(e)}"
            )

    async def get_engagement(self, engagement_id: int) -> dict[str, Any]:
        """
        Get engagement details from DefectDojo.

        Args:
            engagement_id: DefectDojo Engagement ID

        Returns:
            Engagement details dictionary

        Raises:
            DefectDojoAPIError: If API call fails
        """
        url = f"{self.base_url}/api/v2/engagements/{engagement_id}/"
        logger.debug(f"Fetching engagement {engagement_id}")

        try:
            response = await self.client.get(url)

            if response.status_code != 200:
                error_message = self._extract_error_message(response)
                raise DefectDojoAPIError(
                    status_code=response.status_code,
                    message=error_message
                )

            return response.json()

        except httpx.HTTPError as e:
            logger.error(f"HTTP error fetching engagement: {str(e)}")
            raise DefectDojoAPIError(
                status_code=0,
                message=f"HTTP request failed: {str(e)}"
            )

    async def close(self):
        """Close the HTTP client connection."""
        await self.client.aclose()

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
