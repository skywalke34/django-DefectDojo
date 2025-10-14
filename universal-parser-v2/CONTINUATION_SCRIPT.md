# Universal Parser V2 - Continuation Script (Days 4-10)

**Status:** Days 1-3 complete (microservice foundation) ✅
**Next:** Integrate with DefectDojo and complete PoC

---

## Overview

You now have a working microservice that:
- ✅ Validates YAML parser configurations
- ✅ Parses scan files (JSON format)
- ✅ Normalizes findings to DefectDojo format
- ✅ Has 47 passing tests

**Days 4-10** will integrate this with DefectDojo by creating a new API endpoint.

---

## Day 4: Create New DefectDojo API Endpoint

### Goal
Create `/api/v2/universal-parser-v2/reimport-scan/` endpoint in DefectDojo.

### Task 4.1: Create Serializers

**File:** `dojo/api_v2/serializers.py`

Add serializers for the new endpoint:

```python
class UniversalParserV2FindingSerializer(serializers.Serializer):
    """
    Serializer for normalized findings from Universal Parser V2.

    This accepts the output format from the microservice's NormalizerService.
    """
    # Required fields
    title = serializers.CharField(required=True)
    description = serializers.CharField(required=True)
    severity = serializers.ChoiceField(
        choices=['Info', 'Low', 'Medium', 'High', 'Critical'],
        required=True
    )

    # Optional fields
    date = serializers.DateField(required=False, allow_null=True)
    cwe = serializers.IntegerField(required=False, allow_null=True)
    cvssv3 = serializers.CharField(required=False, allow_null=True)
    cvssv3_score = serializers.FloatField(required=False, allow_null=True)
    mitigation = serializers.CharField(required=False, allow_null=True)
    impact = serializers.CharField(required=False, allow_null=True)
    references = serializers.CharField(required=False, allow_null=True)

    # Metadata fields from microservice
    scan_type = serializers.CharField(required=False, allow_null=True)
    unique_id_from_tool = serializers.CharField(required=False, allow_null=True)

    # DefectDojo-specific
    active = serializers.BooleanField(default=True)
    verified = serializers.BooleanField(default=False)
    false_p = serializers.BooleanField(default=False)
    duplicate = serializers.BooleanField(default=False)


class UniversalParserV2ReimportScanSerializer(serializers.Serializer):
    """
    Serializer for Universal Parser V2 reimport-scan endpoint.

    This is similar to ReImportScanSerializer but tailored for the
    microservice's normalized finding format.
    """
    # Test to reimport into
    test = serializers.PrimaryKeyRelatedField(
        queryset=Test.objects.all(),
        required=True
    )

    # Findings from microservice (already normalized)
    findings = UniversalParserV2FindingSerializer(many=True, required=True)

    # Reimport settings
    scan_date = serializers.DateField(required=True)
    scan_type = serializers.CharField(required=False, allow_null=True)
    minimum_severity = serializers.ChoiceField(
        choices=['Info', 'Low', 'Medium', 'High', 'Critical'],
        required=False,
        default='Info'
    )

    # Deduplication settings
    close_old_findings = serializers.BooleanField(default=True)

    # Status settings
    active = serializers.BooleanField(default=True)
    verified = serializers.BooleanField(default=False)

    # Integration settings
    push_to_jira = serializers.BooleanField(default=False)
```

### Task 4.2: Create API View

**File:** `dojo/api_v2/views.py`

Add the new view class:

```python
class UniversalParserV2ReImportScanView(mixins.CreateModelMixin, viewsets.GenericViewSet):
    """
    API endpoint for Universal Parser V2 reimport-scan.

    This endpoint receives normalized findings from the Universal Parser V2
    microservice and processes them using DefectDojo's reimport logic.

    POST /api/v2/universal-parser-v2/reimport-scan/

    Request body:
    {
        "test": 123,  // Test ID
        "findings": [  // Normalized findings from microservice
            {
                "title": "XSS Vulnerability",
                "severity": "High",
                "description": "Cross-site scripting found",
                "unique_id_from_tool": "acunetix-xss-001",
                "scan_type": "Acunetix_360_JSON"
            }
        ],
        "scan_date": "2024-01-15",
        "close_old_findings": true
    }

    Response:
    {
        "test": 123,
        "test_import_finding_action": {
            "created": 1,
            "closed": 0,
            "reactivated": 0,
            "updated": 0,
            "untouched": 0,
            "processed": 1
        }
    }
    """
    serializer_class = UniversalParserV2ReimportScanSerializer
    permission_classes = (IsAuthenticated, permissions.UserHasConfigurationPermissionStaff)
    parser_classes = [JSONParser]

    @extend_schema(
        request=UniversalParserV2ReimportScanSerializer,
        responses={201: serializers.TestSerializer},
        summary="Reimport normalized findings from Universal Parser V2"
    )
    def create(self, request):
        """
        Process reimport request from Universal Parser V2 microservice.

        The microservice has already:
        1. Validated the YAML parser configuration
        2. Parsed the scan file
        3. Normalized findings to DefectDojo format
        4. Validated required fields

        This endpoint:
        1. Deserializes the normalized findings
        2. Applies reimport logic (deduplication, closing old findings)
        3. Returns import statistics
        """
        # Validate request
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Extract data
        test = serializer.validated_data['test']
        findings_data = serializer.validated_data['findings']
        scan_date = serializer.validated_data['scan_date']
        close_old_findings = serializer.validated_data.get('close_old_findings', True)

        # Check permissions
        if not request.user.has_perm('dojo.add_test'):
            return Response(
                {'error': 'You do not have permission to import findings'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Import findings using reimport logic
        try:
            test_import = self._reimport_findings(
                test=test,
                findings_data=findings_data,
                scan_date=scan_date,
                close_old_findings=close_old_findings,
                user=request.user
            )

            # Return statistics
            return Response(
                {
                    'test': test.id,
                    'test_import_finding_action': {
                        'created': test_import.created_findings,
                        'closed': test_import.closed_findings,
                        'reactivated': test_import.reactivated_findings,
                        'updated': test_import.updated_findings,
                        'untouched': test_import.untouched_findings,
                        'processed': test_import.total_processed
                    }
                },
                status=status.HTTP_201_CREATED
            )

        except Exception as e:
            logger.exception(f"Error during Universal Parser V2 reimport: {str(e)}")
            return Response(
                {'error': f'Import failed: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )

    def _reimport_findings(self, test, findings_data, scan_date, close_old_findings, user):
        """
        Internal method to process reimport using DefectDojo's logic.

        This will be implemented in Day 5 using the DefaultReImporter.
        """
        # Import will be implemented using UniversalParserV2ReImporter
        from dojo.tools.universal_parser_v2.reimporter import UniversalParserV2ReImporter

        reimporter = UniversalParserV2ReImporter()
        return reimporter.reimport_findings(
            test=test,
            findings_data=findings_data,
            scan_date=scan_date,
            close_old_findings=close_old_findings,
            user=user
        )
```

### Task 4.3: Add URL Routing

**File:** `dojo/api_v2/urls.py`

Add the new endpoint to the router:

```python
# Add to the router registration section
router.register(
    r'universal-parser-v2/reimport-scan',
    UniversalParserV2ReImportScanView,
    basename='universal-parser-v2-reimport-scan'
)
```

---

## Day 5: Create UniversalParserV2ReImporter Class

### Goal
Create reimporter class that inherits from DefaultReImporter.

### Task 5.1: Create Reimporter Class

**File:** `dojo/tools/universal_parser_v2/__init__.py`

```python
"""Universal Parser V2 integration for DefectDojo."""

__all__ = ['UniversalParserV2ReImporter']
```

**File:** `dojo/tools/universal_parser_v2/reimporter.py`

```python
"""
Universal Parser V2 ReImporter.

This reimporter handles findings from the Universal Parser V2 microservice.
The microservice has already normalized the findings, so this class primarily
focuses on applying DefectDojo's deduplication and reimport logic.
"""

import logging
from datetime import datetime
from typing import List, Dict, Any

from dojo.models import Finding, Test
from dojo.tools.default_reimporter import DefaultReImporter

logger = logging.getLogger(__name__)


class UniversalParserV2ReImporter(DefaultReImporter):
    """
    ReImporter for Universal Parser V2.

    Inherits from DefaultReImporter to leverage existing deduplication logic.
    Findings arrive pre-normalized from the microservice.
    """

    def reimport_findings(
        self,
        test: Test,
        findings_data: List[Dict[str, Any]],
        scan_date: datetime.date,
        close_old_findings: bool = True,
        user = None
    ):
        """
        Reimport normalized findings from Universal Parser V2.

        Args:
            test: DefectDojo Test instance
            findings_data: List of normalized finding dictionaries
            scan_date: Date of the scan
            close_old_findings: Whether to close findings not in current scan
            user: User performing the import

        Returns:
            TestImport object with statistics
        """
        logger.info(
            f"Starting Universal Parser V2 reimport for test {test.id}: "
            f"{len(findings_data)} findings"
        )

        # Convert normalized findings to Finding objects
        findings = self._create_finding_objects(
            test=test,
            findings_data=findings_data,
            scan_date=scan_date
        )

        # Use parent class reimport logic
        test_import = self.process_findings(
            test=test,
            findings=findings,
            scan_date=scan_date,
            close_old_findings=close_old_findings,
            service=None,  # No service field for now
            user=user
        )

        logger.info(
            f"Universal Parser V2 reimport complete: "
            f"created={test_import.created_findings}, "
            f"updated={test_import.updated_findings}, "
            f"closed={test_import.closed_findings}"
        )

        return test_import

    def _create_finding_objects(
        self,
        test: Test,
        findings_data: List[Dict[str, Any]],
        scan_date: datetime.date
    ) -> List[Finding]:
        """
        Convert normalized finding dictionaries to Finding objects.

        Args:
            test: DefectDojo Test instance
            findings_data: List of normalized finding dictionaries
            scan_date: Date of the scan

        Returns:
            List of Finding objects (not yet saved to database)
        """
        findings = []

        for data in findings_data:
            finding = Finding(
                test=test,
                date=scan_date,

                # Required fields (already validated by microservice)
                title=data['title'],
                description=data['description'],
                severity=data['severity'],

                # Optional fields
                cwe=data.get('cwe'),
                cvssv3=data.get('cvssv3'),
                cvssv3_score=data.get('cvssv3_score'),
                mitigation=data.get('mitigation'),
                impact=data.get('impact'),
                references=data.get('references'),

                # Deduplication
                unique_id_from_tool=data.get('unique_id_from_tool'),

                # Status
                active=data.get('active', True),
                verified=data.get('verified', False),
                false_p=data.get('false_p', False),

                # Static/Dynamic
                static_finding=data.get('static_finding', False),
                dynamic_finding=data.get('dynamic_finding', True),
            )

            findings.append(finding)

        return findings
```

### Task 5.2: Create Unit Tests

**File:** `dojo/unittests/tools/test_universal_parser_v2_reimporter.py`

```python
"""Unit tests for Universal Parser V2 ReImporter."""

from django.test import TestCase
from dojo.models import Test, Engagement, Product, Finding
from dojo.tools.universal_parser_v2.reimporter import UniversalParserV2ReImporter
from datetime import date


class TestUniversalParserV2ReImporter(TestCase):
    """Test UniversalParserV2ReImporter class."""

    def setUp(self):
        """Set up test data."""
        self.product = Product.objects.create(name="Test Product")
        self.engagement = Engagement.objects.create(
            product=self.product,
            name="Test Engagement",
            target_start=date.today(),
            target_end=date.today()
        )
        self.test = Test.objects.create(
            engagement=self.engagement,
            test_type_id=1,  # Generic test type
            target_start=date.today(),
            target_end=date.today()
        )
        self.reimporter = UniversalParserV2ReImporter()

    def test_reimport_creates_new_findings(self):
        """Test that reimport creates new findings."""
        findings_data = [
            {
                'title': 'XSS Vulnerability',
                'description': 'Cross-site scripting found',
                'severity': 'High',
                'unique_id_from_tool': 'xss-001'
            },
            {
                'title': 'SQL Injection',
                'description': 'SQL injection vulnerability',
                'severity': 'Critical',
                'unique_id_from_tool': 'sql-001'
            }
        ]

        test_import = self.reimporter.reimport_findings(
            test=self.test,
            findings_data=findings_data,
            scan_date=date.today()
        )

        self.assertEqual(test_import.created_findings, 2)
        self.assertEqual(Finding.objects.filter(test=self.test).count(), 2)

    def test_reimport_updates_existing_findings(self):
        """Test that reimport updates existing findings."""
        # Create initial finding
        Finding.objects.create(
            test=self.test,
            title='XSS Vulnerability',
            description='Old description',
            severity='Medium',
            unique_id_from_tool='xss-001'
        )

        # Reimport with updated description
        findings_data = [
            {
                'title': 'XSS Vulnerability',
                'description': 'Updated description',
                'severity': 'High',
                'unique_id_from_tool': 'xss-001'
            }
        ]

        test_import = self.reimporter.reimport_findings(
            test=self.test,
            findings_data=findings_data,
            scan_date=date.today()
        )

        self.assertEqual(test_import.updated_findings, 1)

        # Verify update
        finding = Finding.objects.get(test=self.test, unique_id_from_tool='xss-001')
        self.assertEqual(finding.description, 'Updated description')
        self.assertEqual(finding.severity, 'High')
```

---

## Day 6: Complete DefectDojo API Client in Microservice

### Goal
Update the microservice to use the new DefectDojo endpoint.

### Task 6.1: Update DefectDojoClient

**File:** `universal-parser-v2/app/clients/defectdojo_client.py`

Add method to use the new endpoint:

```python
async def universal_parser_v2_reimport(
    self,
    test_id: int,
    findings: list[dict[str, Any]],
    scan_date: str,
    close_old_findings: bool = True
) -> dict[str, Any]:
    """
    Reimport findings using Universal Parser V2 endpoint.

    This uses the new /api/v2/universal-parser-v2/reimport-scan/ endpoint
    which expects pre-normalized findings.

    Args:
        test_id: DefectDojo Test ID
        findings: List of normalized finding dictionaries
        scan_date: Scan date in YYYY-MM-DD format
        close_old_findings: Whether to close old findings

    Returns:
        API response with import statistics
    """
    payload = {
        "test": test_id,
        "findings": findings,
        "scan_date": scan_date,
        "close_old_findings": close_old_findings
    }

    url = f"{self.base_url}/api/v2/universal-parser-v2/reimport-scan/"
    logger.info(f"Importing {len(findings)} findings to test {test_id} via Universal Parser V2")

    try:
        response = await self.client.post(url, json=payload)

        if response.status_code not in (200, 201):
            error_message = self._extract_error_message(response)
            raise DefectDojoAPIError(
                status_code=response.status_code,
                message=error_message
            )

        result = response.json()
        logger.info(f"Import successful: {result.get('test_import_finding_action', {})}")
        return result

    except httpx.HTTPError as e:
        logger.error(f"HTTP error during import: {str(e)}")
        raise DefectDojoAPIError(
            status_code=0,
            message=f"HTTP request failed: {str(e)}"
        )
```

---

## Day 7: Docker Setup

### Goal
Create Docker configuration for the microservice.

### Task 7.1: Create Dockerfile

**File:** `universal-parser-v2/Dockerfile`

```dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/
COPY configs/ ./configs/

# Expose port
EXPOSE 8000

# Run application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Task 7.2: Create docker-compose.yml

**File:** `universal-parser-v2/docker-compose.yml`

```yaml
version: '3.8'

services:
  universal-parser-v2:
    build: .
    container_name: universal-parser-v2
    ports:
      - "8001:8000"
    environment:
      - DEFECTDOJO_URL=http://defectdojo:8080
      - DEFECTDOJO_API_TOKEN=${DD_API_TOKEN}
    volumes:
      - ./configs:/app/configs
      - ./app:/app/app
    networks:
      - defectdojo-network

networks:
  defectdojo-network:
    external: true
```

### Task 7.3: Update Main DefectDojo docker-compose

**File:** `docker-compose.yml` (in DefectDojo root)

Add the microservice to the existing docker-compose:

```yaml
services:
  # ... existing services ...

  universal-parser-v2:
    build: ./universal-parser-v2
    container_name: universal-parser-v2
    ports:
      - "8001:8000"
    environment:
      - DEFECTDOJO_URL=http://nginx:8080
      - DEFECTDOJO_API_TOKEN=${DD_ADMIN_API_TOKEN}
    depends_on:
      - nginx
    networks:
      - defectdojo
```

---

## Day 8: End-to-End Testing

### Goal
Test the complete flow from microservice to DefectDojo.

### Task 8.1: Create E2E Test Script

**File:** `universal-parser-v2/tests/test_e2e.sh`

```bash
#!/bin/bash
# End-to-end test for Universal Parser V2

set -e

echo "=== Universal Parser V2 E2E Test ==="

# Configuration
MICROSERVICE_URL="http://localhost:8001"
DEFECTDOJO_URL="http://localhost:8080"
DD_API_TOKEN="${DD_ADMIN_API_TOKEN}"

# Test 1: Health check
echo "1. Testing microservice health..."
curl -f "${MICROSERVICE_URL}/health" || exit 1
echo "✓ Microservice is healthy"

# Test 2: Validate YAML
echo "2. Validating YAML configuration..."
curl -f -X POST "${MICROSERVICE_URL}/api/validate-yaml" \
  -F "yaml_file=@configs/acunetix360_json.yaml" || exit 1
echo "✓ YAML validation passed"

# Test 3: Create test in DefectDojo
echo "3. Creating test in DefectDojo..."
TEST_ID=$(curl -s -X POST "${DEFECTDOJO_URL}/api/v2/tests/" \
  -H "Authorization: Token ${DD_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"engagement":1,"test_type":1,"target_start":"2024-01-01","target_end":"2024-01-01"}' \
  | jq -r '.id')
echo "✓ Created test ${TEST_ID}"

# Test 4: Import via microservice
echo "4. Importing scan via microservice..."
# This would call the microservice endpoint which then calls DefectDojo
# Implementation depends on final microservice API design

echo "✓ All tests passed!"
```

### Task 8.2: Test Deduplication

Create test that verifies:
1. First import creates findings
2. Second import updates existing findings (doesn't duplicate)
3. Third import closes findings not in scan

---

## Day 9: Error Scenario Testing

### Goal
Test all error scenarios and edge cases.

### Test Scenarios

1. **Invalid YAML Configuration**
   - Missing required fields
   - Invalid severity mappings
   - Invalid JSONPath expressions

2. **Invalid Scan Files**
   - Malformed JSON
   - Missing required data
   - Empty findings array

3. **DefectDojo API Errors**
   - Invalid API token
   - Invalid test ID
   - Permission errors
   - Network errors

4. **Data Validation Errors**
   - Missing required finding fields
   - Invalid severity values
   - Malformed data types

5. **Large File Handling**
   - Large scan files (>10MB)
   - Many findings (>1000)
   - Performance testing

---

## Day 10: Documentation and Polish

### Goal
Complete documentation and finalize PoC.

### Task 10.1: Update README

**File:** `universal-parser-v2/README.md`

Add sections:
- Installation instructions
- Configuration guide
- API documentation
- Examples
- Troubleshooting

### Task 10.2: Create User Guide

**File:** `universal-parser-v2/docs/USER_GUIDE.md`

Include:
- How to write YAML parser configs
- Field mapping examples
- Severity mapping guide
- Testing parsers
- Deploying to production

### Task 10.3: Create Developer Guide

**File:** `universal-parser-v2/docs/DEVELOPER_GUIDE.md`

Include:
- Architecture overview
- Adding new file format readers
- Adding new data type parsers
- Contributing guidelines

### Task 10.4: Final Testing Checklist

- [ ] All unit tests passing
- [ ] All integration tests passing
- [ ] E2E tests passing
- [ ] Docker build successful
- [ ] DefectDojo integration working
- [ ] Deduplication verified
- [ ] Error handling tested
- [ ] Documentation complete
- [ ] Code formatted (ruff)
- [ ] Ready for review

---

## Quick Command Reference

```bash
# Run microservice tests
cd universal-parser-v2
source venv/bin/activate
python -m pytest tests/ -v

# Run DefectDojo tests
cd ..
./run-unittest.sh --test-case unittests.tools.test_universal_parser_v2_reimporter

# Start microservice
cd universal-parser-v2
uvicorn app.main:app --reload --port 8001

# Start DefectDojo with microservice
docker/setEnv.sh dev
docker compose up

# Check microservice logs
docker compose logs -f universal-parser-v2
```

---

## Notes

- Keep the microservice stateless
- Use DefectDojo's existing deduplication logic
- Follow DefectDojo's code style (PEP8, ruff)
- Write tests for all new code
- Document all public APIs
- Consider security (API tokens, input validation)

---

## Success Criteria

The PoC is complete when:
1. ✅ Microservice can parse Acunetix scans using YAML config
2. ✅ Findings are normalized to DefectDojo format
3. ✅ New API endpoint receives normalized findings
4. ✅ Deduplication works correctly
5. ✅ All tests passing (unit, integration, e2e)
6. ✅ Docker setup working
7. ✅ Documentation complete
8. ✅ Ready for stakeholder demo

---

**Estimated Time:** 7 days (Days 4-10)
**Status:** Ready to begin Day 4
**Last Updated:** 2024-01-14
**Author:** T. Walker - DefectDojo
