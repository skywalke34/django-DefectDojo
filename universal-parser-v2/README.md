# Universal Parser V2 - Microservice

**Parser-as-Code for DefectDojo Security Tool Imports**

## Overview

Universal Parser V2 is a FastAPI microservice that allows you to import security scan reports from any tool into DefectDojo using declarative YAML configuration files instead of writing Python parsers.

### Key Features

- 📝 **Parser-as-Code**: Define parsers using simple YAML files
- 🔄 **Format Agnostic**: Supports JSON, XML, CSV scan formats
- ✅ **Pre-flight Validation**: Catch errors before import
- 🎯 **Pluggable Parsers**: Data type parsers for strings, severities, dates, etc.
- 🔗 **DefectDojo Integration**: Seamless API integration with existing reimport logic

## Project Status

**⚠️ Proof of Concept (PoC) - Day 1 Complete**

- ✅ FastAPI microservice skeleton
- ✅ YAML schema validation (Pydantic)
- ✅ File upload endpoints
- ✅ HTML upload form UI
- ✅ Sample Acunetix YAML config
- 🚧 JSON parsing (Day 2)
- 🚧 Data type parsers (Day 2)
- 🚧 DefectDojo API integration (Day 6)

## Quick Start

### Prerequisites

- Python 3.11 or higher
- pip
- (Optional) Docker for containerized deployment

### Installation

1. Clone the repository and navigate to the microservice directory:

```bash
cd /Users/tracywalker/Development/DEV_defectdojo/universal-parser-v2-microservice
```

2. Create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Run the microservice:

```bash
python -m app.main
```

Or using uvicorn directly:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

5. Open your browser and navigate to:

```
http://localhost:8000
```

## Usage

### Method 1: Web Interface

1. Open `http://localhost:8000` in your browser
2. Upload your security scan file (e.g., `acunetix_scan.json`)
3. Upload the corresponding YAML configuration (e.g., `configs/acunetix360_json.yaml`)
4. Enter your DefectDojo URL and API token
5. Provide either:
   - **Test ID** (for reimporting into existing test)
   - **Product Name + Engagement Name** (for creating new test)
6. Click "Import Scan"

### Method 2: API (curl)

Validate YAML configuration:

```bash
curl -X POST http://localhost:8000/api/validate-yaml \
  -F "yaml_file=@configs/acunetix360_json.yaml"
```

Import scan:

```bash
curl -X POST http://localhost:8000/api/import \
  -F "scan_file=@path/to/acunetix_scan.json" \
  -F "yaml_file=@configs/acunetix360_json.yaml" \
  -F "defectdojo_url=http://localhost:8080" \
  -F "defectdojo_api_token=YOUR_TOKEN_HERE" \
  -F "test_id=123"
```

### Method 3: Python SDK (Future)

```python
from universal_parser_v2 import UniversalParser

parser = UniversalParser(
    yaml_config="configs/acunetix360_json.yaml",
    defectdojo_url="http://localhost:8080",
    defectdojo_token="YOUR_TOKEN"
)

result = parser.import_scan(
    scan_file="acunetix_scan.json",
    test_id=123
)

print(f"Created {result.findings_created} findings")
print(f"Updated {result.findings_updated} findings")
```

## YAML Configuration

### Sample Configuration

See `configs/acunetix360_json.yaml` for a complete example.

### Configuration Structure

```yaml
# Metadata
parser_name: "Acunetix360JSON"
parser_version: "1.0"
tool_name: "Acunetix 360"
tool_type: "Acunetix_360_JSON"

# File Format
file_format: "json"
json_root_path: "$.Vulnerabilities[*]"

# Field Mappings
field_mappings:
  - source_field: "Name"
    target_field: "title"
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

# Deduplication
deduplication_fields:
  - "title"
```

### Required Fields

Every YAML configuration must include:

- **title** mapping (required)
- **description** mapping (required)
- **severity** mapping with normalization table (required)

### Supported Data Types

- `string`: Direct string mapping
- `severity`: Severity normalization (requires mapping table)
- `date`: Date parsing (future)
- `integer`: Integer conversion (future)
- `boolean`: Boolean conversion (future)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    USER UPLOADS FILES                       │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│               FASTAPI MAIN.PY                               │
│  - File upload endpoint                                     │
│  - YAML validation                                          │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│            YAML VALIDATOR (Pydantic)                        │
│  - Schema validation                                        │
│  - Field mapping verification                               │
│  - Checksum computation                                     │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│         FILE FORMAT READER (TODO: Day 2)                    │
│  - JSON parser (jsonpath-ng)                                │
│  - XML parser (future)                                      │
│  - CSV parser (future)                                      │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│              NORMALIZER SERVICE (TODO: Day 3)               │
│  - Field extraction                                         │
│  - Data type transformation                                 │
│  - Finding validation                                       │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│           DEFECTDOJO API CLIENT (TODO: Day 6)               │
│  - POST to /api/v2/universal-v2-reimport-scan/              │
│  - Authentication                                           │
│  - Error handling                                           │
└─────────────────────────────────────────────────────────────┘
```

## Development

### Running Tests

```bash
pytest tests/ -v
```

### Code Style

This project uses:
- **Ruff** for linting
- **Black** for code formatting
- **Type hints** for better IDE support

### Project Structure

```
universal-parser-v2-microservice/
├── app/
│   ├── main.py                    # FastAPI application
│   ├── models/
│   │   └── yaml_config.py         # Pydantic YAML schema
│   ├── parsers/
│   │   ├── data_types/            # String, severity, date parsers
│   │   └── file_formats/          # JSON, XML, CSV readers
│   ├── validators/
│   │   └── yaml_validator.py      # YAML validation logic
│   ├── services/
│   │   ├── normalizer.py          # Finding normalization
│   │   └── defectdojo_client.py   # API client
│   ├── utils/
│   │   ├── checksum.py            # YAML checksum
│   │   └── errors.py              # Custom exceptions
│   └── templates/
│       └── index.html             # Upload form
├── configs/
│   └── acunetix360_json.yaml      # Sample config
├── tests/
│   └── fixtures/                  # Test data
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## Roadmap

### Week 1: Core Implementation

- [x] **Day 1**: Project setup, YAML validation, FastAPI skeleton ✅
- [ ] **Day 2**: JSON parser + data type parsers (string, severity)
- [ ] **Day 3**: Normalizer service + integration tests

### Week 2: DefectDojo Integration

- [ ] **Day 4**: DefectDojo API endpoint (serializers, view)
- [ ] **Day 5**: UniversalV2ReImporter class
- [ ] **Day 6**: DefectDojo API client in microservice
- [ ] **Day 7**: Docker setup + end-to-end testing

### Week 3: Testing & Polish

- [ ] **Day 8**: Reimport + deduplication testing
- [ ] **Day 9**: Error scenario testing
- [ ] **Day 10**: Documentation + demo

## API Documentation

Once the microservice is running, visit:

- **Swagger UI**: http://localhost:8000/api/docs
- **ReDoc**: http://localhost:8000/api/redoc

## Troubleshooting

### Common Issues

**Issue**: YAML validation fails with "Invalid YAML syntax"
- **Solution**: Check your YAML indentation. Use spaces, not tabs.

**Issue**: "Required fields not mapped" error
- **Solution**: Ensure your YAML has active mappings for `title`, `description`, and `severity`.

**Issue**: "Severity value not found in mapping"
- **Solution**: Add all severity values from your scan file to the `severity_mapping` dictionary.

**Issue**: Import fails with authentication error
- **Solution**: Verify your DefectDojo API token is correct and has import permissions.

## Contributing

This is a Proof of Concept for DefectDojo. Contributions welcome!

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-parser`)
3. Add your YAML configuration to `configs/`
4. Test thoroughly
5. Submit a pull request

## License

BSD-3-Clause (same as DefectDojo)

## Contact

- **DefectDojo**: https://www.defectdojo.com
- **GitHub Issues**: https://github.com/DefectDojo/django-DefectDojo/issues

---

**Status**: 🚧 Proof of Concept - Day 1 Complete (YAML Validation Working!)

**Next Steps**: Implement JSON parser and data type transformers (Day 2)
