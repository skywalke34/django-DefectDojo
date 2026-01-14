# Universal Parser V2 - Continuation File

**Date**: January 12, 2026
**Session**: Phase 8 Complete - Project Feature Complete
**Author**: T. Walker - DefectDojo
**Branch**: `upV2-1.2-priority-chains`

---

## Project Status: FEATURE COMPLETE

Universal Parser V2 is now fully functional with:
- Complete API integration
- Docker deployment
- 5 production-ready parser configurations
- 578 passing tests

---

## Completed Phases Summary

| Phase | Description | Tests Added |
|-------|-------------|-------------|
| Phase 4 | File Format Readers (XML, CSV) | ~50 |
| Phase 5 | Data Type Parsers (CVSS, CWE, etc.) | ~70 |
| Phase 6 | Advanced Features (version detection, conditional severity) | 84 |
| Phase 7 | API Integration & Docker | 16 |
| Phase 8 | Parser Configuration Library | 14 |

**Total Tests**: 578 passing

---

## Commit History

```
f32518c8d7 feat: Phase 8 - Add parser configurations for major security tools
bcd05ddfe3 feat: Phase 7 - Complete API integration and Docker deployment
96195953df feat: Phase 6 - Add advanced features for complex parser patterns
12568a850f feat: Add Phase 5 data type parsers for security scanner fields
152ed91ceb feat: Add CSVReader with delimiter detection and column mapping support
8a64f603a7 feat: Add XMLReader with XPath and namespace support for XML parsing
8b40ee255d feat: Add CVSS extractor with multi-source priority and vector reconstruction
```

---

## Architecture Overview

### Directory Structure
```
universal-parser-v2/
├── app/
│   ├── main.py                 # FastAPI application
│   ├── clients/
│   │   └── defectdojo_client.py  # DefectDojo API client
│   ├── models/
│   │   └── yaml_config.py      # Pydantic models for YAML validation
│   ├── parsers/
│   │   ├── base.py             # FieldExtractor base class
│   │   ├── data_types/         # Data type parsers
│   │   └── file_formats/       # JSON, XML, CSV readers
│   ├── services/
│   │   └── normalizer.py       # Main normalization service
│   ├── validators/
│   │   └── yaml_validator.py   # YAML validation
│   └── utils/
│       └── errors.py           # Custom exceptions
├── configs/                    # YAML parser configurations
│   ├── acunetix360_json.yaml
│   ├── bandit_json.yaml
│   ├── cyclonedx_xml.yaml
│   ├── nuclei_json.yaml
│   ├── qualys_csv.yaml
│   ├── semgrep_json.yaml
│   ├── trivy_json.yaml
│   └── trufflehog_json.yaml
├── tests/
│   ├── fixtures/               # Sample scan files
│   ├── test_api_endpoints.py   # API integration tests
│   ├── test_parser_configs.py  # Parser config validation tests
│   └── ... (many more test files)
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | HTML upload form |
| `/health` | GET | Health check |
| `/api/docs` | GET | Swagger UI |
| `/api/validate-yaml` | POST | Validate YAML config |
| `/api/parse` | POST | Parse scan, return findings |
| `/api/import` | POST | Full import to DefectDojo |

### Supported Data Types
- `string`, `integer`, `float`, `boolean`, `date`, `array`
- `severity` (with mapping)
- `template` (string interpolation)
- `cvss_extractor` (multi-source CVSS)
- `html_to_text`, `hash`, `endpoint`, `cwe`, `regex`
- `conditional_severity` (dynamic severity rules)
- `state_machine` (complex field extraction)

### Advanced Features
- **Format Version Detection**: Auto-detect TruffleHog v2/v3, etc.
- **Conditional Severity**: Dynamic severity based on field values
- **Request/Response Mapping**: HTTP req/resp for DAST tools
- **Priority Chains**: Try multiple source fields in order
- **Hash Generation**: SHA256/MD5 for deduplication

---

## Parser Configurations

### Production Ready (Phase 8)

| Parser | File | Key Features |
|--------|------|--------------|
| Nuclei | `nuclei_json.yaml` | CVSS, CWE, req/resp, SHA256 dedup |
| TruffleHog | `trufflehog_json.yaml` | v2/v3 detection, conditional severity |
| Trivy | `trivy_json.yaml` | Multi-source CVSS, component tracking |
| Bandit | `bandit_json.yaml` | Code snippets, test IDs |
| Semgrep | `semgrep_json.yaml` | SAST/SCA formats, fingerprint dedup |

### Example Configs (Earlier Phases)
- `acunetix360_json.yaml` - DAST scanner
- `cyclonedx_xml.yaml` - SBOM format
- `qualys_csv.yaml` - CSV format example

---

## Key Files Reference

### Models (`app/models/yaml_config.py`)
- `YAMLConfig` - Main config model
- `FieldMapping` - Field mapping with data types
- `FormatVersion` - Version-specific mappings
- `ConditionalSeverity` - Dynamic severity rules
- `RequestResponseMapping` - HTTP req/resp extraction
- `CVSSSource`, `CVSSExtractor` - CVSS extraction config

### Normalizer (`app/services/normalizer.py`)
- `NormalizerService` - Main orchestration class
- `_detect_format_version()` - Version auto-detection
- `_process_conditional_severity()` - Dynamic severity
- `_process_request_response()` - HTTP mapping

### DefectDojo Client (`app/clients/defectdojo_client.py`)
- `universal_parser_v2_reimport()` - Main import method
- `find_or_create_product()` - Auto-create product
- `find_or_create_engagement()` - Auto-create engagement
- `find_or_create_test()` - Auto-create test

---

## Commands Reference

### Development
```bash
cd /Users/tracywalker/Development/DEV_defectdojo/django-DefectDojo/universal-parser-v2
source venv/bin/activate

# Run all tests
python -m pytest tests/ -v --tb=short

# Run specific test file
python -m pytest tests/test_parser_configs.py -v

# Start local server
uvicorn app.main:app --reload --port 8500

# Test health endpoint
curl http://localhost:8500/health
```

### Docker
```bash
# Build and start
docker compose up -d

# View logs
docker compose logs -f

# Development mode (hot-reload)
docker compose --profile dev up universal-parser-v2-dev

# Stop
docker compose down
```

### API Usage
```bash
# Parse a scan (returns findings JSON)
curl -X POST http://localhost:8500/api/parse \
  -F "scan_file=@scan.json" \
  -F "yaml_file=@configs/nuclei_json.yaml"

# Import to DefectDojo
curl -X POST http://localhost:8500/api/import \
  -F "scan_file=@scan.json" \
  -F "yaml_file=@configs/nuclei_json.yaml" \
  -F "defectdojo_url=http://localhost:8080" \
  -F "defectdojo_api_token=your-token" \
  -F "product_name=My Product" \
  -F "engagement_name=Security Scan"
```

---

## Potential Next Steps

### Additional Parsers
- OWASP ZAP (JSON)
- Checkov (JSON)
- Snyk (JSON)
- SonarQube (JSON)
- Dependency-Check (XML)

### Enhancements
- JSONL (newline-delimited JSON) native support
- XML namespace handling improvements
- Performance optimization for large scans
- Parser config hot-reload

### Integration
- DefectDojo-side API endpoint for Universal Parser V2
- CI/CD pipeline examples
- Kubernetes deployment manifests

---

## Test Counts by Category

| Test File | Count |
|-----------|-------|
| test_yaml_validator.py | ~40 |
| test_normalizer.py | ~50 |
| test_field_extractor.py | ~30 |
| test_json_reader.py | ~25 |
| test_xml_reader.py | ~20 |
| test_csv_reader.py | ~20 |
| test_cvss_extractor.py | ~40 |
| test_conditional_severity.py | 32 |
| test_format_version.py | 19 |
| test_request_response.py | 24 |
| test_occurrence_tracking.py | 9 |
| test_api_endpoints.py | 16 |
| test_parser_configs.py | 14 |
| Others | ~239 |
| **Total** | **578** |

---

## Configuration Model Summary

```yaml
# Minimal valid config
parser_name: "ToolParser"
parser_version: "1.0"
tool_name: "Tool Name"
tool_type: "Tool_Type"
file_format: "json"  # json, xml, csv
json_root_path: "$.findings[*]"
field_mappings:
  - source_field: "name"
    target_field: "title"
    data_type: "string"
  - source_field: "desc"
    target_field: "description"
    data_type: "string"
  - source_field: "sev"
    target_field: "severity"
    data_type: "severity"
    severity_mapping:
      high: "High"
      medium: "Medium"
      low: "Low"
deduplication_fields:
  - "title"
```

---

## Key Decisions Made

1. **Port 8500** - Avoids conflict with DefectDojo (8080)
2. **Multi-stage Docker** - Smaller production image
3. **Non-root user** - Security best practice
4. **Empty array = error** - Catches misconfigured JSONPaths
5. **Hash data type** - SHA256/MD5 for unique_id generation
6. **Version detection first-match** - Predictable behavior

---

*Authored by T. Walker - DefectDojo*
*Universal Parser V2 - Feature Complete*
