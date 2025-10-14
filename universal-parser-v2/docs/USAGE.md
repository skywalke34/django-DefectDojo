# Universal Parser V2 - Usage Guide

**Version**: 0.1.0 (PoC)
**Last Updated**: October 14, 2025

## Overview

This guide provides practical examples of using Universal Parser V2 to create parsers for security tools using YAML configuration files.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Creating Your First Parser](#creating-your-first-parser)
- [Common Use Cases](#common-use-cases)
- [Testing Parsers](#testing-parsers)
- [Integration Patterns](#integration-patterns)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

### 5-Minute Tutorial

**Prerequisites**: Microservice and DefectDojo running (see [DEPLOYMENT.md](DEPLOYMENT.md))

**Step 1**: Create a simple YAML parser config

Save as `configs/myscan_json.yaml`:

```yaml
parser_name: "MyScanParser"
parser_version: "1.0.0"
tool_name: "MyScan Tool"
tool_type: "SAST"
description: "Parser for MyScan tool JSON output"
author: "Your Name"

file_format: "json"
json_root_path: "$.results[*]"

field_mappings:
  - source_field: "issue_title"
    target_field: "title"
    data_type: "string"
    active: true

  - source_field: "issue_description"
    target_field: "description"
    data_type: "string"
    active: true

  - source_field: "risk_level"
    target_field: "severity"
    data_type: "severity"
    active: true
    severity_mapping:
      "CRITICAL": "Critical"
      "HIGH": "High"
      "MEDIUM": "Medium"
      "LOW": "Low"
      "INFO": "Info"

deduplication_fields:
  - "title"
  - "file_path"
```

**Step 2**: Test your YAML config

```bash
curl -X POST http://localhost:8000/api/validate-yaml \
  -F "yaml_file=@configs/myscan_json.yaml"
```

**Step 3**: Create a test in DefectDojo

Via web UI: Products → [Your Product] → Engagements → [Your Engagement] → Add Test
Note the Test ID (e.g., 123)

**Step 4**: Import your scan

```bash
curl -X POST http://localhost:8000/api/import \
  -F "scan_file=@myscan_results.json" \
  -F "yaml_file=@configs/myscan_json.yaml" \
  -F "defectdojo_url=http://localhost:8080" \
  -F "defectdojo_api_token=YOUR_TOKEN" \
  -F "test_id=123"
```

**Done!** Your findings are now in DefectDojo.

---

## Creating Your First Parser

### Example 1: Simple JSON Parser

**Scenario**: Parse a JSON file with this structure:

```json
{
  "vulnerabilities": [
    {
      "name": "SQL Injection",
      "details": "SQL injection in login form",
      "severity": "HIGH",
      "cwe": 89,
      "file": "login.php",
      "line": 42
    }
  ]
}
```

**YAML Configuration** (`configs/mytool_json.yaml`):

```yaml
parser_name: "MyToolParser"
parser_version: "1.0.0"
tool_name: "MyTool"
tool_type: "SAST"
description: "Parser for MyTool JSON output"
author: "Security Team"

# File format: json, xml, or csv
file_format: "json"

# JSONPath to the array of findings
json_root_path: "$.vulnerabilities[*]"

# Field mappings
field_mappings:
  # Required: title
  - source_field: "name"
    target_field: "title"
    data_type: "string"
    active: true

  # Required: description
  - source_field: "details"
    target_field: "description"
    data_type: "string"
    active: true

  # Required: severity
  - source_field: "severity"
    target_field: "severity"
    data_type: "severity"
    active: true
    severity_mapping:
      "CRITICAL": "Critical"
      "HIGH": "High"
      "MEDIUM": "Medium"
      "LOW": "Low"
      "INFO": "Info"

  # Optional fields
  - source_field: "cwe"
    target_field: "cwe"
    data_type: "integer"
    active: true

  - source_field: "file"
    target_field: "file_path"
    data_type: "string"
    active: true

  - source_field: "line"
    target_field: "line"
    data_type: "integer"
    active: true

# Fields to use for deduplication
deduplication_fields:
  - "title"
  - "file_path"
  - "line"
```

**Import**:

```bash
curl -X POST http://localhost:8000/api/import \
  -F "scan_file=@mytool_results.json" \
  -F "yaml_file=@configs/mytool_json.yaml" \
  -F "defectdojo_url=http://localhost:8080" \
  -F "defectdojo_api_token=YOUR_TOKEN" \
  -F "test_id=123"
```

---

### Example 2: XML Parser

**Scenario**: Parse XML scan results:

```xml
<report>
  <findings>
    <finding>
      <title>XSS Vulnerability</title>
      <description>Cross-site scripting found</description>
      <severity>High</severity>
      <cwe>79</cwe>
    </finding>
  </findings>
</report>
```

**YAML Configuration** (`configs/mytool_xml.yaml`):

```yaml
parser_name: "MyToolXMLParser"
parser_version: "1.0.0"
tool_name: "MyTool"
tool_type: "DAST"
description: "Parser for MyTool XML output"
author: "Security Team"

file_format: "xml"

# XPath to finding elements
xml_finding_xpath: "//findings/finding"

field_mappings:
  - source_field: "title"
    target_field: "title"
    data_type: "string"
    active: true

  - source_field: "description"
    target_field: "description"
    data_type: "string"
    active: true

  - source_field: "severity"
    target_field: "severity"
    data_type: "severity"
    active: true
    severity_mapping:
      "Critical": "Critical"
      "High": "High"
      "Medium": "Medium"
      "Low": "Low"
      "Informational": "Info"

  - source_field: "cwe"
    target_field: "cwe"
    data_type: "integer"
    active: true

deduplication_fields:
  - "title"
  - "cwe"
```

---

### Example 3: CSV Parser

**Scenario**: Parse CSV scan file:

```csv
Title,Description,Severity,CWE,FilePath,Line
SQL Injection,SQL injection in form,High,89,login.php,42
XSS,Cross-site scripting,Medium,79,search.php,18
```

**YAML Configuration** (`configs/mytool_csv.yaml`):

```yaml
parser_name: "MyToolCSVParser"
parser_version: "1.0.0"
tool_name: "MyTool"
tool_type: "SAST"
description: "Parser for MyTool CSV output"
author: "Security Team"

file_format: "csv"

# CSV configuration
csv_has_header: true
csv_delimiter: ","

field_mappings:
  - source_field: "Title"
    target_field: "title"
    data_type: "string"
    active: true

  - source_field: "Description"
    target_field: "description"
    data_type: "string"
    active: true

  - source_field: "Severity"
    target_field: "severity"
    data_type: "severity"
    active: true
    severity_mapping:
      "High": "High"
      "Medium": "Medium"
      "Low": "Low"

  - source_field: "CWE"
    target_field: "cwe"
    data_type: "integer"
    active: true

  - source_field: "FilePath"
    target_field: "file_path"
    data_type: "string"
    active: true

  - source_field: "Line"
    target_field: "line"
    data_type: "integer"
    active: true

deduplication_fields:
  - "title"
  - "file_path"
  - "line"
```

---

## Common Use Cases

### Use Case 1: Adding CVSS Scores

Include CVSS information in findings:

```yaml
field_mappings:
  - source_field: "cvss_vector"
    target_field: "cvssv3"
    data_type: "string"
    active: true

  - source_field: "cvss_score"
    target_field: "cvssv3_score"
    data_type: "float"
    active: true
```

Example JSON:
```json
{
  "name": "SQL Injection",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "cvss_score": 9.8
}
```

---

### Use Case 2: Mapping Multiple Severity Formats

Handle different severity naming conventions:

```yaml
field_mappings:
  - source_field: "risk"
    target_field: "severity"
    data_type: "severity"
    active: true
    severity_mapping:
      "CRITICAL": "Critical"
      "HIGH": "High"
      "MEDIUM": "Medium"
      "LOW": "Low"
      "INFO": "Info"
      # Handle variations
      "5": "Critical"
      "4": "High"
      "3": "Medium"
      "2": "Low"
      "1": "Info"
      # Handle lowercase
      "critical": "Critical"
      "high": "High"
```

---

### Use Case 3: Extracting CVE/CWE IDs

Parse CVE and CWE identifiers:

```yaml
field_mappings:
  - source_field: "cve_id"
    target_field: "cve"
    data_type: "cve"
    active: true

  - source_field: "cwe_id"
    target_field: "cwe"
    data_type: "cwe"
    active: true
```

The parsers will extract:
- CVE: `"CVE-2021-12345"` → `"CVE-2021-12345"`
- CWE: `"CWE-89"` or `"89"` → `89` (integer)

---

### Use Case 4: Nested JSON Fields

Access nested fields using JSONPath:

**JSON Structure**:
```json
{
  "results": [
    {
      "vulnerability": {
        "title": "XSS",
        "details": {
          "description": "Cross-site scripting",
          "severity": "High"
        }
      }
    }
  ]
}
```

**YAML Configuration**:
```yaml
json_root_path: "$.results[*]"

field_mappings:
  - source_field: "vulnerability.title"
    target_field: "title"
    data_type: "string"
    active: true

  - source_field: "vulnerability.details.description"
    target_field: "description"
    data_type: "string"
    active: true

  - source_field: "vulnerability.details.severity"
    target_field: "severity"
    data_type: "severity"
    active: true
```

---

### Use Case 5: Default Values

Provide default values for missing fields:

```yaml
field_mappings:
  - source_field: "severity"
    target_field: "severity"
    data_type: "severity"
    active: true
    default_value: "Medium"

  - source_field: "verified"
    target_field: "verified"
    data_type: "boolean"
    active: true
    default_value: false
```

---

### Use Case 6: Component/Dependency Scanning

For SCA (Software Composition Analysis) tools:

```yaml
field_mappings:
  - source_field: "component_name"
    target_field: "component_name"
    data_type: "string"
    active: true

  - source_field: "component_version"
    target_field: "component_version"
    data_type: "string"
    active: true

  - source_field: "vulnerability_name"
    target_field: "title"
    data_type: "string"
    active: true
```

---

## Testing Parsers

### Step 1: Validate YAML Syntax

```bash
# Test YAML is valid
python -c "import yaml; yaml.safe_load(open('configs/myparser.yaml'))"
```

### Step 2: Validate with API

```bash
curl -X POST http://localhost:8000/api/validate-yaml \
  -F "yaml_file=@configs/myparser.yaml"
```

Expected response:
```json
{
  "status": "valid",
  "message": "YAML configuration is valid",
  "config": {
    "parser_name": "MyParser",
    "active_field_mappings": 8,
    "deduplication_fields": ["title", "file_path"]
  }
}
```

### Step 3: Test with Sample Scan

Create a small sample scan file for testing:

**test_scan.json**:
```json
{
  "results": [
    {
      "title": "Test Finding",
      "description": "Test description",
      "severity": "High"
    }
  ]
}
```

Import to test environment:

```bash
curl -X POST http://localhost:8000/api/import \
  -F "scan_file=@test_scan.json" \
  -F "yaml_file=@configs/myparser.yaml" \
  -F "defectdojo_url=http://localhost:8080" \
  -F "defectdojo_api_token=YOUR_TOKEN" \
  -F "test_id=999"  # Use a test ID for testing
```

### Step 4: Verify in DefectDojo

1. Open DefectDojo web UI
2. Navigate to the test
3. Verify findings are created correctly
4. Check all fields are populated

---

## Integration Patterns

### Pattern 1: CI/CD Integration

**GitHub Actions Example**:

`.github/workflows/security-scan.yml`:

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run Security Scanner
        run: |
          docker run --rm \
            -v $PWD:/src \
            mytool/scanner:latest \
            scan /src -o scan-results.json

      - name: Import to DefectDojo
        run: |
          curl -X POST https://parser.example.com/api/import \
            -F "scan_file=@scan-results.json" \
            -F "yaml_file=@.defectdojo/mytool.yaml" \
            -F "defectdojo_url=${{ secrets.DEFECTDOJO_URL }}" \
            -F "defectdojo_api_token=${{ secrets.DEFECTDOJO_TOKEN }}" \
            -F "test_id=${{ secrets.DEFECTDOJO_TEST_ID }}"
```

---

### Pattern 2: Jenkins Integration

**Jenkinsfile**:

```groovy
pipeline {
    agent any

    environment {
        DEFECTDOJO_URL = credentials('defectdojo-url')
        DEFECTDOJO_TOKEN = credentials('defectdojo-token')
    }

    stages {
        stage('Security Scan') {
            steps {
                sh 'mytool scan . -o scan-results.json'
            }
        }

        stage('Import to DefectDojo') {
            steps {
                sh '''
                    curl -X POST https://parser.example.com/api/import \
                      -F "scan_file=@scan-results.json" \
                      -F "yaml_file=@configs/mytool.yaml" \
                      -F "defectdojo_url=${DEFECTDOJO_URL}" \
                      -F "defectdojo_api_token=${DEFECTDOJO_TOKEN}" \
                      -F "product_name=${JOB_NAME}" \
                      -F "engagement_name=Build ${BUILD_NUMBER}" \
                      -F "test_title=Security Scan"
                '''
            }
        }
    }
}
```

---

### Pattern 3: Python Script Integration

**scan_and_import.py**:

```python
#!/usr/bin/env python3
"""
Run security scan and import results to DefectDojo.
"""

import subprocess
import sys
import httpx
import asyncio
from pathlib import Path

DEFECTDOJO_URL = "http://localhost:8080"
DEFECTDOJO_TOKEN = "your_token_here"
PARSER_URL = "http://localhost:8000"

async def main():
    # Step 1: Run security scan
    print("Running security scan...")
    subprocess.run([
        "mytool", "scan", ".",
        "-o", "scan-results.json"
    ], check=True)

    # Step 2: Import to DefectDojo
    print("Importing to DefectDojo...")
    async with httpx.AsyncClient(timeout=300) as client:
        files = {
            "scan_file": open("scan-results.json", "rb"),
            "yaml_file": open("configs/mytool.yaml", "rb"),
        }
        data = {
            "defectdojo_url": DEFECTDOJO_URL,
            "defectdojo_api_token": DEFECTDOJO_TOKEN,
            "test_id": "123",
        }

        response = await client.post(
            f"{PARSER_URL}/api/import",
            files=files,
            data=data
        )

        if response.status_code == 200:
            result = response.json()
            print(f"✅ Import successful!")
            print(f"Created: {result['results']['findings_created']}")
            print(f"Updated: {result['results']['findings_updated']}")
        else:
            print(f"❌ Import failed: {response.text}")
            sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
```

Run with:
```bash
python scan_and_import.py
```

---

### Pattern 4: Scheduled Scans (Cron)

**scan.sh**:

```bash
#!/bin/bash
set -e

# Configuration
SCAN_OUTPUT="scan-$(date +%Y%m%d-%H%M%S).json"
YAML_CONFIG="/opt/configs/mytool.yaml"
PARSER_URL="http://localhost:8000"
DEFECTDOJO_URL="http://localhost:8080"
DEFECTDOJO_TOKEN="your_token_here"
TEST_ID="123"

# Run scan
echo "Running security scan..."
mytool scan /var/www/html -o "$SCAN_OUTPUT"

# Import to DefectDojo
echo "Importing to DefectDojo..."
curl -X POST "${PARSER_URL}/api/import" \
  -F "scan_file=@${SCAN_OUTPUT}" \
  -F "yaml_file=@${YAML_CONFIG}" \
  -F "defectdojo_url=${DEFECTDOJO_URL}" \
  -F "defectdojo_api_token=${DEFECTDOJO_TOKEN}" \
  -F "test_id=${TEST_ID}"

# Cleanup
rm "$SCAN_OUTPUT"
echo "Done!"
```

**Cron entry** (`crontab -e`):
```cron
# Run daily at 2 AM
0 2 * * * /opt/scripts/scan.sh >> /var/log/scan.log 2>&1
```

---

## Best Practices

### 1. Version Your Parser Configs

```yaml
parser_name: "MyToolParser"
parser_version: "1.2.0"  # Increment when making changes
```

Keep configs in version control:
```bash
git add configs/mytool.yaml
git commit -m "feat: Update mytool parser to v1.2.0 - add CVSS support"
```

### 2. Use Descriptive Parser Names

❌ Bad:
```yaml
parser_name: "Parser1"
tool_name: "Tool"
```

✅ Good:
```yaml
parser_name: "Acunetix360JSONParser"
tool_name: "Acunetix 360"
tool_type: "DAST"
```

### 3. Document Your Severity Mappings

```yaml
# Severity mapping notes:
# - Tool uses 1-5 scale (5=Critical)
# - "Informational" maps to "Info"
# - "Urgent" is not used by tool
severity_mapping:
  "5": "Critical"
  "4": "High"
  "3": "Medium"
  "2": "Low"
  "1": "Info"
```

### 4. Test with Real Scan Files

Always test with actual scan output, not just minimal examples.

```bash
# Get a real scan file from your tool
mytool scan /path/to/app -o real_scan.json

# Test import
curl -X POST http://localhost:8000/api/import \
  -F "scan_file=@real_scan.json" \
  -F "yaml_file=@configs/mytool.yaml" \
  ...
```

### 5. Choose Deduplication Fields Carefully

Include fields that uniquely identify a finding:

✅ Good:
```yaml
deduplication_fields:
  - "title"
  - "file_path"
  - "line"
  - "cwe"
```

❌ Bad (too generic):
```yaml
deduplication_fields:
  - "severity"  # Many findings have same severity
```

### 6. Handle Missing Fields Gracefully

Use `required: false` and `default_value`:

```yaml
field_mappings:
  - source_field: "cvss_score"
    target_field: "cvssv3_score"
    data_type: "float"
    active: true
    required: false
    default_value: null
```

### 7. Validate Before Deploying

```bash
# Always validate before using in production
curl -X POST http://localhost:8000/api/validate-yaml \
  -F "yaml_file=@configs/mytool.yaml"
```

---

## Troubleshooting

### Problem: YAML validation fails

**Error**: "Input should be 'string', 'integer'..."

**Solution**: Check `data_type` field matches allowed types:
- `string`
- `integer`
- `float`
- `boolean`
- `date`
- `severity`
- `cve`
- `cwe`

---

### Problem: No findings imported

**Possible Causes**:
1. JSONPath/XPath doesn't match scan structure
2. Required fields missing
3. Severity mapping incorrect

**Debug**:
```bash
# Check YAML validation
curl -X POST http://localhost:8000/api/validate-yaml \
  -F "yaml_file=@configs/mytool.yaml"

# Enable debug logging
LOG_LEVEL=debug uvicorn app.main:app --reload
```

---

### Problem: Findings not deduplicated

**Solution**: Ensure `unique_id_from_tool` is set or use good deduplication fields:

```yaml
field_mappings:
  - source_field: "id"
    target_field: "unique_id_from_tool"
    data_type: "string"
    active: true

deduplication_fields:
  - "title"
  - "file_path"
  - "line"
```

---

### Problem: Severity not recognized

**Error**: Findings imported but severity is wrong

**Solution**: Check severity mapping covers all values in scan:

```bash
# Extract all severity values from scan
jq '.results[].severity' scan.json | sort -u

# Add all values to severity_mapping
```

---

## Additional Resources

- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System design details
- **[API.md](API.md)** - Complete API reference
- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Deployment instructions
- **Sample Configs**: See `configs/` directory

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
