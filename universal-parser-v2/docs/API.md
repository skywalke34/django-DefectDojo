# Universal Parser V2 - API Documentation

**Version**: 0.1.0 (PoC)
**Last Updated**: October 14, 2025

## Overview

Universal Parser V2 consists of two API surfaces:

1. **Microservice API** (FastAPI) - Accepts scan files and YAML configs, performs parsing and normalization
2. **DefectDojo API** (Django REST Framework) - Receives normalized findings and handles deduplication/import

This document describes both APIs and how they work together.

---

## Table of Contents

- [Microservice API](#microservice-api)
  - [Health Check](#health-check)
  - [Validate YAML](#validate-yaml)
  - [Import Scan](#import-scan)
- [DefectDojo API](#defectdojo-api)
  - [Universal Parser V2 Reimport](#universal-parser-v2-reimport)
- [Authentication](#authentication)
- [Error Handling](#error-handling)
- [Complete Examples](#complete-examples)

---

## Microservice API

The microservice runs on FastAPI and provides endpoints for scan file processing.

**Base URL**: `http://localhost:8000` (default)
**API Documentation**:
- Swagger UI: `http://localhost:8000/api/docs`
- ReDoc: `http://localhost:8000/api/redoc`

### Health Check

Check if the microservice is running and healthy.

**Endpoint**: `GET /health`

**Authentication**: None

**Response**:
```json
{
  "status": "healthy",
  "service": "universal-parser-v2",
  "version": "0.1.0"
}
```

**Example**:
```bash
curl http://localhost:8000/health
```

**Status Codes**:
- `200 OK` - Service is healthy

---

### Validate YAML

Validate a YAML parser configuration without processing a scan file.

**Endpoint**: `POST /api/validate-yaml`

**Authentication**: None

**Request**:
- **Content-Type**: `multipart/form-data`
- **Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `yaml_file` | File | Yes | YAML configuration file to validate |

**Response**:
```json
{
  "status": "valid",
  "message": "YAML configuration is valid",
  "config": {
    "parser_name": "Acunetix360JSONParser",
    "parser_version": "1.0.0",
    "tool_name": "Acunetix 360",
    "tool_type": "DAST",
    "file_format": "json",
    "active_field_mappings": 15,
    "deduplication_fields": ["title", "file_path", "line"],
    "yaml_checksum": "sha256:abc123..."
  }
}
```

**Error Response** (400 Bad Request):
```json
{
  "detail": {
    "error": "YAML Validation Error",
    "message": "YAML configuration is invalid",
    "validation_errors": [
      {
        "field": "field_mappings.0.data_type",
        "error": "Input should be 'string', 'integer', 'float', ..."
      }
    ]
  }
}
```

**Example**:
```bash
curl -X POST http://localhost:8000/api/validate-yaml \
  -F "yaml_file=@configs/acunetix360_json.yaml"
```

**Status Codes**:
- `200 OK` - YAML is valid
- `400 Bad Request` - YAML validation failed
- `500 Internal Server Error` - Server error

---

### Import Scan

Import a scan file into DefectDojo using YAML configuration.

This is the main endpoint that orchestrates:
1. YAML validation
2. Scan file parsing
3. Finding normalization
4. DefectDojo API call

**Endpoint**: `POST /api/import`

**Authentication**: None (but requires valid DefectDojo credentials)

**Request**:
- **Content-Type**: `multipart/form-data`
- **Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `scan_file` | File | Yes | Security scan report file (JSON/XML/CSV) |
| `yaml_file` | File | Yes | YAML parser configuration file |
| `defectdojo_url` | String | Yes | DefectDojo instance URL (e.g., `http://localhost:8080`) |
| `defectdojo_api_token` | String | Yes | DefectDojo API authentication token |
| `test_id` | Integer | No* | Existing Test ID for reimport |
| `product_name` | String | No* | Product name (for auto-create) |
| `engagement_name` | String | No* | Engagement name (for auto-create) |
| `test_title` | String | No | Test title (for auto-create) |

*Either `test_id` OR both `product_name` and `engagement_name` must be provided.

**Response**:
```json
{
  "status": "success",
  "message": "Import completed successfully",
  "config": {
    "parser_name": "Acunetix360JSONParser",
    "parser_version": "1.0.0",
    "tool_type": "DAST",
    "yaml_checksum": "sha256:abc123..."
  },
  "scan_file": {
    "filename": "acunetix_scan.json",
    "size_bytes": 125340
  },
  "defectdojo": {
    "url": "http://localhost:8080",
    "test_id": 123
  },
  "results": {
    "findings_parsed": 15,
    "findings_created": 10,
    "findings_updated": 3,
    "findings_closed": 2
  }
}
```

**Error Response** (400 Bad Request):
```json
{
  "detail": {
    "error": "Invalid Request",
    "message": "Either 'test_id' or both 'product_name' and 'engagement_name' must be provided",
    "type": "validation_error"
  }
}
```

**Example (Reimport to existing test)**:
```bash
curl -X POST http://localhost:8000/api/import \
  -F "scan_file=@acunetix_scan.json" \
  -F "yaml_file=@configs/acunetix360_json.yaml" \
  -F "defectdojo_url=http://localhost:8080" \
  -F "defectdojo_api_token=your_api_token_here" \
  -F "test_id=123"
```

**Example (Auto-create test)**:
```bash
curl -X POST http://localhost:8000/api/import \
  -F "scan_file=@acunetix_scan.json" \
  -F "yaml_file=@configs/acunetix360_json.yaml" \
  -F "defectdojo_url=http://localhost:8080" \
  -F "defectdojo_api_token=your_api_token_here" \
  -F "product_name=MyWebApp" \
  -F "engagement_name=Q1 2025 Testing" \
  -F "test_title=Acunetix Scan - January 15"
```

**Status Codes**:
- `200 OK` - Import successful
- `400 Bad Request` - Invalid request parameters or YAML validation failed
- `401 Unauthorized` - Invalid DefectDojo API token
- `404 Not Found` - Test, Product, or Engagement not found
- `500 Internal Server Error` - Server error

---

## DefectDojo API

DefectDojo provides a dedicated endpoint for Universal Parser V2 that accepts pre-normalized findings.

**Base URL**: `http://localhost:8080` (default DefectDojo)
**API Documentation**: `http://localhost:8080/api/v2/doc/`

### Universal Parser V2 Reimport

Reimport pre-normalized findings into DefectDojo with deduplication.

**Endpoint**: `POST /api/v2/universal-parser-v2/reimport-scan/`

**Authentication**: Token-based (see [Authentication](#authentication))

**Location in Codebase**:
- View: `dojo/api_v2/views.py:2638`
- Serializer: `dojo/api_v2/serializers.py:3154`
- Reimporter: `dojo/tools/universal_parser_v2/reimporter.py`
- URL Config: `dojo/urls.py:164`

**Request**:
- **Content-Type**: `application/json`
- **Body**:

```json
{
  "test": 123,
  "findings": [
    {
      "title": "SQL Injection in Login Form",
      "description": "SQL injection vulnerability found in the login form parameter 'username'",
      "severity": "Critical",
      "cwe": 89,
      "cvssv3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "cvssv3_score": 9.8,
      "mitigation": "Use parameterized queries instead of string concatenation",
      "impact": "Attacker could gain unauthorized access to the database",
      "references": "https://owasp.org/www-project-top-ten/",
      "file_path": "login.php",
      "line": 42,
      "unique_id_from_tool": "acunetix-sqli-001",
      "active": true,
      "verified": false
    }
  ],
  "scan_date": "2025-01-15",
  "close_old_findings": true,
  "do_not_reactivate": false,
  "minimum_severity": "Info",
  "active": true,
  "verified": false,
  "push_to_jira": false,
  "version": "1.2.3",
  "tags": ["automated", "nightly"]
}
```

**Request Parameters**:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `test` | Integer | Yes | - | DefectDojo Test ID to reimport into |
| `findings` | Array | Yes | - | List of normalized finding objects |
| `scan_date` | String | Yes | - | Scan date (YYYY-MM-DD format) |
| `scan_type` | String | No | null | Scanner type (optional) |
| `close_old_findings` | Boolean | No | true | Close findings not in this scan |
| `do_not_reactivate` | Boolean | No | false | Don't reactivate closed findings |
| `minimum_severity` | String | No | "Info" | Minimum severity to import |
| `active` | Boolean | No | true | Mark imported findings as active |
| `verified` | Boolean | No | false | Mark imported findings as verified |
| `push_to_jira` | Boolean | No | false | Push findings to JIRA if configured |
| `version` | String | No | null | Version string for the test |
| `tags` | Array | No | [] | Tags to apply to findings |

**Finding Object Fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `title` | String | Yes | Finding title |
| `description` | String | Yes | Finding description |
| `severity` | String | Yes | Severity (Info, Low, Medium, High, Critical) |
| `date` | String | No | Date found (YYYY-MM-DD) |
| `cwe` | Integer | No | CWE ID (e.g., 89 for SQL Injection) |
| `cvssv3` | String | No | CVSS v3 vector string |
| `cvssv3_score` | Float | No | CVSS v3 score (0.0-10.0) |
| `cvssv4` | String | No | CVSS v4 vector string |
| `cvssv4_score` | Float | No | CVSS v4 score (0.0-10.0) |
| `mitigation` | String | No | Mitigation recommendations |
| `impact` | String | No | Impact description |
| `references` | String | No | References/links |
| `file_path` | String | No | File path where vulnerability found |
| `line` | Integer | No | Line number |
| `component_name` | String | No | Component/library name |
| `component_version` | String | No | Component/library version |
| `unique_id_from_tool` | String | No | Unique ID from scanner (for deduplication) |
| `active` | Boolean | No | Finding is active |
| `verified` | Boolean | No | Finding is verified |
| `false_p` | Boolean | No | Finding is false positive |
| `duplicate` | Boolean | No | Finding is duplicate |
| `out_of_scope` | Boolean | No | Finding is out of scope |
| `static_finding` | Boolean | No | Finding from SAST tool |
| `dynamic_finding` | Boolean | No | Finding from DAST tool |

**Response**:
```json
{
  "test": 123,
  "test_import_finding_action": {
    "created": 1,
    "closed": 0,
    "reactivated": 0,
    "updated": 0,
    "untouched": 0,
    "processed": 1
  },
  "scan_date": "2025-01-15",
  "version": "1.2.3",
  "tags": ["automated", "nightly"],
  "statistics": {
    "total_findings_in_scan": 1,
    "findings_after_severity_filter": 1,
    "new_findings": 1,
    "closed_findings": 0,
    "reactivated_findings": 0,
    "updated_findings": 0
  }
}
```

**Error Response** (400 Bad Request):
```json
{
  "test": [
    "This field is required."
  ]
}
```

**Error Response** (403 Forbidden):
```json
{
  "detail": "You do not have permission to perform this action."
}
```

**Example**:
```bash
curl -X POST http://localhost:8080/api/v2/universal-parser-v2/reimport-scan/ \
  -H "Authorization: Token your_api_token_here" \
  -H "Content-Type: application/json" \
  -d '{
    "test": 123,
    "findings": [
      {
        "title": "XSS Vulnerability",
        "description": "Cross-site scripting found",
        "severity": "High",
        "cwe": 79,
        "unique_id_from_tool": "xss-001"
      }
    ],
    "scan_date": "2025-01-15",
    "close_old_findings": true
  }'
```

**Status Codes**:
- `200 OK` - Reimport successful
- `201 Created` - Reimport successful (alternative success code)
- `400 Bad Request` - Invalid request data
- `401 Unauthorized` - Missing or invalid authentication token
- `403 Forbidden` - User doesn't have permission to import into this test
- `404 Not Found` - Test not found
- `500 Internal Server Error` - Server error

---

## Authentication

### Microservice API

The microservice API endpoints (`/health`, `/api/validate-yaml`, `/api/import`) do **not require authentication**.

However, the `/api/import` endpoint requires valid DefectDojo credentials passed as form parameters:
- `defectdojo_url`: DefectDojo instance URL
- `defectdojo_api_token`: Your DefectDojo API token

### DefectDojo API

The DefectDojo endpoint (`/api/v2/universal-parser-v2/reimport-scan/`) requires **token-based authentication**.

**Getting Your API Token**:

1. Log into DefectDojo web interface
2. Navigate to your user profile (top-right corner)
3. Click "API Key" or "API Token"
4. Copy your token

**Using the Token**:

Include the token in the `Authorization` header:

```
Authorization: Token your_api_token_here
```

**Example**:
```bash
curl -X POST http://localhost:8080/api/v2/universal-parser-v2/reimport-scan/ \
  -H "Authorization: Token abc123def456ghi789" \
  -H "Content-Type: application/json" \
  -d '{"test": 123, "findings": [...], "scan_date": "2025-01-15"}'
```

**Testing Your Token**:
```bash
# Check if your token is valid
curl -H "Authorization: Token your_token" http://localhost:8080/api/v2/users/
```

---

## Error Handling

### Error Response Format

All APIs return errors in a consistent JSON format:

**Microservice Errors**:
```json
{
  "detail": {
    "error": "Error Type",
    "message": "Human-readable error message",
    "type": "error_category"
  }
}
```

**DefectDojo Errors**:
```json
{
  "field_name": [
    "Error message for this field"
  ]
}
```

or

```json
{
  "detail": "Error message"
}
```

### Common Error Codes

| Status Code | Meaning | Common Causes |
|-------------|---------|---------------|
| 400 | Bad Request | Invalid parameters, YAML validation failed, missing required fields |
| 401 | Unauthorized | Missing or invalid API token |
| 403 | Forbidden | User doesn't have permission for requested action |
| 404 | Not Found | Test/Product/Engagement doesn't exist |
| 500 | Internal Server Error | Server error, database error, unexpected exception |

### Error Handling Examples

**YAML Validation Error**:
```json
{
  "detail": {
    "error": "YAML Validation Error",
    "message": "YAML configuration is invalid",
    "validation_errors": [
      {
        "field": "field_mappings.0.data_type",
        "error": "Input should be 'string', 'integer', 'float', 'boolean', 'date', 'severity', 'cve', 'cwe'"
      }
    ]
  }
}
```

**Missing Required Field**:
```json
{
  "detail": {
    "error": "Invalid Request",
    "message": "Either 'test_id' or both 'product_name' and 'engagement_name' must be provided",
    "type": "validation_error"
  }
}
```

**Authentication Error**:
```json
{
  "detail": "Invalid token."
}
```

**Permission Error**:
```json
{
  "detail": "You do not have permission to perform this action."
}
```

---

## Complete Examples

### Example 1: Validate YAML Configuration

```bash
# Validate your YAML config before importing
curl -X POST http://localhost:8000/api/validate-yaml \
  -F "yaml_file=@configs/acunetix360_json.yaml"
```

**Response**:
```json
{
  "status": "valid",
  "message": "YAML configuration is valid",
  "config": {
    "parser_name": "Acunetix360JSONParser",
    "parser_version": "1.0.0",
    "tool_name": "Acunetix 360",
    "tool_type": "DAST",
    "file_format": "json",
    "active_field_mappings": 15,
    "deduplication_fields": ["title", "file_path", "line"],
    "yaml_checksum": "sha256:7f9a8b..."
  }
}
```

---

### Example 2: Import Scan (Simple)

```bash
# Import scan file into existing test
curl -X POST http://localhost:8000/api/import \
  -F "scan_file=@acunetix_scan.json" \
  -F "yaml_file=@configs/acunetix360_json.yaml" \
  -F "defectdojo_url=http://localhost:8080" \
  -F "defectdojo_api_token=abc123def456" \
  -F "test_id=123"
```

---

### Example 3: Direct DefectDojo API Call

```bash
# Call DefectDojo endpoint directly with pre-normalized findings
curl -X POST http://localhost:8080/api/v2/universal-parser-v2/reimport-scan/ \
  -H "Authorization: Token abc123def456" \
  -H "Content-Type: application/json" \
  -d '{
    "test": 123,
    "findings": [
      {
        "title": "SQL Injection in Login Form",
        "description": "SQL injection vulnerability found in username parameter",
        "severity": "Critical",
        "cwe": 89,
        "cvssv3_score": 9.8,
        "file_path": "login.php",
        "line": 42,
        "unique_id_from_tool": "acunetix-sqli-001"
      },
      {
        "title": "XSS in Search Field",
        "description": "Cross-site scripting in search parameter",
        "severity": "High",
        "cwe": 79,
        "cvssv3_score": 6.1,
        "file_path": "search.php",
        "line": 18,
        "unique_id_from_tool": "acunetix-xss-002"
      }
    ],
    "scan_date": "2025-01-15",
    "close_old_findings": true,
    "version": "1.2.3",
    "tags": ["automated", "nightly"]
  }'
```

**Response**:
```json
{
  "test": 123,
  "test_import_finding_action": {
    "created": 2,
    "closed": 0,
    "reactivated": 0,
    "updated": 0,
    "untouched": 0,
    "processed": 2
  },
  "scan_date": "2025-01-15",
  "version": "1.2.3",
  "tags": ["automated", "nightly"]
}
```

---

### Example 4: Python Client Usage

```python
import httpx
from app.clients.defectdojo_client import DefectDojoClient

# Using the DefectDojo client from microservice
async def import_findings():
    async with DefectDojoClient(
        base_url="http://localhost:8080",
        api_token="your_api_token"
    ) as client:
        # Prepare normalized findings
        findings = [
            {
                "title": "SQL Injection",
                "description": "SQL injection found",
                "severity": "Critical",
                "cwe": 89,
                "unique_id_from_tool": "sqli-001"
            }
        ]

        # Call Universal Parser V2 endpoint
        result = await client.universal_parser_v2_reimport(
            test_id=123,
            findings=findings,
            scan_date="2025-01-15",
            close_old_findings=True,
            version="1.2.3",
            tags=["automated", "nightly"]
        )

        print(f"Created: {result['test_import_finding_action']['created']}")
        print(f"Closed: {result['test_import_finding_action']['closed']}")

# Run
import asyncio
asyncio.run(import_findings())
```

---

### Example 5: Error Handling in Python

```python
from app.clients.defectdojo_client import DefectDojoClient
from app.utils.errors import DefectDojoAPIError

async def safe_import():
    try:
        async with DefectDojoClient(
            base_url="http://localhost:8080",
            api_token="your_token"
        ) as client:
            result = await client.universal_parser_v2_reimport(
                test_id=123,
                findings=[...],
                scan_date="2025-01-15"
            )
            return result

    except DefectDojoAPIError as e:
        if e.status_code == 401:
            print("Authentication failed - check your API token")
        elif e.status_code == 403:
            print("Permission denied - you can't import to this test")
        elif e.status_code == 404:
            print("Test not found")
        else:
            print(f"API error: {e.message}")

    except Exception as e:
        print(f"Unexpected error: {str(e)}")
```

---

## API Design Decisions

### Why Two APIs?

**Microservice API** (FastAPI):
- ✅ Easy to add new file format parsers
- ✅ No DefectDojo deployment needed to test YAML configs
- ✅ Can be scaled independently
- ✅ Can be deployed closer to scan tools

**DefectDojo API** (Django REST Framework):
- ✅ Integrates with existing deduplication logic
- ✅ Reuses finding creation code
- ✅ Respects user permissions
- ✅ Integrates with JIRA, notifications, etc.

### Why Not Use Standard reimport-scan Endpoint?

The standard `/api/v2/reimport-scan/` endpoint expects:
- Raw scan files
- Parser class registered in DefectDojo
- Parser to be in `dojo/tools/` directory

Universal Parser V2 is different:
- ✅ Pre-normalized findings (no file parsing needed)
- ✅ Parser defined in YAML (no Python code)
- ✅ Parsers live outside DefectDojo
- ✅ Can support any tool without modifying DefectDojo code

---

## Support

- **Issues**: GitHub Issues (DefectDojo repository)
- **Documentation**: See `docs/` directory
- **Community**: DefectDojo Slack/Discord

---

**Status**: PoC (Proof of Concept) - Day 7 Complete ✅
**Branch**: `upV2-Poc`
**Author**: T. Walker - DefectDojo
**Created**: October 2025
