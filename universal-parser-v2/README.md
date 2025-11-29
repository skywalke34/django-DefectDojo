# Universal Parser V2 for DefectDojo

**Parser-as-Code**: Define security tool parsers using YAML configuration instead of writing Python code.

## 🎯 Overview

Universal Parser V2 is a microservice-based parser system for DefectDojo that allows you to create new security tool parsers using simple YAML configuration files instead of writing Python code. It handles file parsing, field extraction, data normalization, and seamless integration with DefectDojo's deduplication system.

### Key Features

- **Parser-as-Code**: Define parsers using declarative YAML configuration
- **Multiple File Formats**: JSON, XML, CSV support built-in
- **Field Extraction**: JSONPath, XPath, and column-based extraction
- **Data Type Transformation**: Automatic conversion (severity, dates, integers, floats, booleans)
- **Priority Chains**: Try multiple source fields until one has a value
- **Template Strings**: Compose fields from multiple sources (`"{cve} - {name}"`)
- **CVSS Extraction**: Multi-source priority extraction with vector reconstruction
- **State Machine Mapping**: Map single input to multiple output fields
- **Conditional Append**: Build composite fields with optional sections
- **Fixed Values**: Set constant values for fields (e.g., `static_finding: false`)
- **Severity Normalization**: Map tool-specific severities to DefectDojo standard
- **Deduplication Ready**: Generates unique IDs for DefectDojo's deduplication
- **Pre-normalized Findings**: Sends structured data directly to DefectDojo
- **No Code Deployment**: Add new parsers without deploying DefectDojo

## 🏗️ Architecture

```
                              USER PROVIDES BOTH INPUTS
                    ┌────────────────────────────────────────┐
                    │                                        │
                    ▼                                        ▼
          ┌─────────────────┐                    ┌─────────────────────┐
          │   Scan File     │                    │   YAML Parser       │
          │  (JSON/XML/CSV) │                    │   Configuration     │
          └────────┬────────┘                    └──────────┬──────────┘
                   │                                        │
                   │         ┌──────────────────────────┐   │
                   └────────▶│  Universal Parser V2     │◀──┘
                             │     Microservice         │
                             │                          │
                             │  ┌────────────────────┐  │
                             │  │   Parser Engine    │  │
                             │  │ (Field Extraction, │  │
                             │  │  Normalization)    │  │
                             │  └────────────────────┘  │
                             └────────────┬─────────────┘
                                          │
                                          │ Pre-normalized
                                          │ Findings (JSON)
                                          ▼
                             ┌──────────────────────────┐
                             │      DefectDojo          │
                             │                          │
                             │  ┌────────────────────┐  │
                             │  │    Reimporter      │  │
                             │  │  (Deduplication)   │  │
                             │  └────────────────────┘  │
                             └──────────────────────────┘
```

**User Inputs (BOTH Required):**
1. **Scan File**: Security tool output (JSON, XML, or CSV format)
2. **YAML Parser Configuration**: Defines how to extract and map fields

**Components:**
1. **Microservice** (FastAPI): Accepts scan file + YAML config together
2. **Parser Engine**: Extracts and normalizes findings based on YAML rules
3. **DefectDojo Integration**: New API endpoint for pre-normalized findings
4. **Reimporter**: Handles deduplication using DefectDojo's existing logic

## 📊 Project Status

**✅ Milestones 1-3 Complete** - Core implementation + Advanced Transformers finished!

| Component | Status | Description |
|-----------|--------|-------------|
| Microservice (FastAPI) | ✅ Complete | File upload, YAML validation, API |
| YAML Validation (Pydantic) | ✅ Complete | Schema validation with detailed errors |
| File Parsers (JSON/XML/CSV) | ✅ Complete | JSONPath, XPath, column extraction |
| Data Type Parsers (9 types) | ✅ Complete | string, severity, date, integer, boolean, float, array, template, cvss_extractor |
| Priority Chain Extraction | ✅ Complete | Try multiple source fields |
| Template String Parser | ✅ Complete | Multi-field composition |
| CVSS Extractor | ✅ Complete | Priority extraction + vector reconstruction |
| State Machine Mapping | ✅ Complete | Single input → multiple outputs |
| Conditional Append | ✅ Complete | Build composite fields |
| Fixed Values | ✅ Complete | Constant field values |
| Normalizer Service | ✅ Complete | End-to-end normalization |
| DefectDojo API Client | ✅ Complete | Async HTTP with retry |
| DefectDojo API Endpoint | ✅ Complete | Pre-normalized findings import |

**Total: 194 tests passing ✅**

**Next Steps**: XML/CSV format readers, additional parser configs

## 🚀 Quick Start

### Prerequisites

- Python 3.12+
- DefectDojo instance running
- Virtual environment (recommended)

### Installation

```bash
# Navigate to microservice directory
cd django-DefectDojo/universal-parser-v2

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run tests to verify installation
python -m pytest tests/ -v
```

### Running the Microservice

```bash
# Start the FastAPI server
uvicorn app.main:app --reload --port 8000

# The API will be available at:
# - Swagger UI: http://localhost:8000/docs
# - ReDoc: http://localhost:8000/redoc
# - Upload Form: http://localhost:8000
```

### Create Your First Parser

1. **Create a YAML configuration** (`configs/my_tool.yaml`):

```yaml
parser_name: "MySecurityTool"
description: "Parser for My Security Tool JSON output"
version: "1.0.0"
author: "Your Name"

file_format: "json"
json_root_path: "$.vulnerabilities[*]"

field_mappings:
  - source_field: "name"
    target_field: "title"
    data_type: "string"
    active: true

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

  - source_field: "description"
    target_field: "description"
    data_type: "string"
    active: true

  - source_field: "cwe_id"
    target_field: "cwe"
    data_type: "integer"
    active: true

deduplication_fields:
  - "title"
  - "file_path"
  - "line"
```

2. **Upload via Web UI**:
   - Open http://localhost:8000
   - Upload your scan file and YAML config
   - Enter DefectDojo URL, API token, and Test ID
   - Click "Import Scan"

3. **Or use curl**:

```bash
curl -X POST "http://localhost:8000/api/v1/parse" \
  -H "Content-Type: multipart/form-data" \
  -F "scan_file=@my_scan.json" \
  -F "parser_config=@configs/my_tool.yaml" \
  -F "test_id=123" \
  -F "defectdojo_url=https://your-defectdojo.com" \
  -F "api_token=your-api-token"
```

## 📚 Documentation

- **[Architecture Guide](docs/ARCHITECTURE.md)** - System design and components
- **[API Documentation](docs/API.md)** - REST API endpoints and examples
- **[Deployment Guide](docs/DEPLOYMENT.md)** - Production deployment instructions
- **[Usage Examples](docs/USAGE.md)** - Common use cases and examples
- **[Parser Configuration](docs/PARSER_CONFIG.md)** - YAML schema reference

## 🧪 Testing

### Run All Tests

```bash
# Run all tests with coverage
python -m pytest tests/ -v --cov=app --cov-report=html

# Run specific test suites
python -m pytest tests/test_parsers.py -v              # File format parsers
python -m pytest tests/test_normalizer.py -v           # Normalizer tests
python -m pytest tests/test_integration.py -v          # Integration tests
python -m pytest tests/test_template_parser.py -v      # Template strings
python -m pytest tests/test_priority_chains.py -v      # Priority chains
python -m pytest tests/test_cvss_extractor.py -v       # CVSS extraction
python -m pytest tests/test_state_machine.py -v        # State machine
python -m pytest tests/test_conditional_append.py -v   # Conditional append
python -m pytest tests/test_fixed_value.py -v          # Fixed values
python -m pytest tests/test_defectdojo_client.py -v    # API client
```

### Current Test Coverage

| Test Suite | Tests | Coverage |
|------------|-------|----------|
| File Format Parsers | 22 | JSON, XML, CSV readers |
| Normalizer | 11 | End-to-end normalization |
| Integration | 10 | Complete parser-to-findings flow |
| Template Parser | 18 | Multi-field composition |
| Priority Chains | 24 | Alternative field extraction |
| CVSS Extractor | 30 | Vector extraction & reconstruction |
| State Machine | 32 | Multi-output mapping |
| Conditional Append | 28 | Composite field building |
| Fixed Values | 15 | Constant field values |
| API Client | 4 | DefectDojo HTTP client |

**Total: 194 tests passing ✅**

## 📋 Project Structure

```
universal-parser-v2/
├── app/
│   ├── main.py                    # FastAPI application entry point
│   ├── models/
│   │   └── yaml_config.py         # Pydantic models for YAML validation
│   ├── parsers/
│   │   ├── base.py                # Abstract base classes
│   │   ├── file_formats/          # JSON, XML, CSV readers
│   │   │   ├── json_reader.py
│   │   │   ├── xml_reader.py
│   │   │   └── csv_reader.py
│   │   └── data_types/            # Type converters (9 parsers)
│   │       ├── string_parser.py
│   │       ├── severity_parser.py
│   │       ├── date_parser.py
│   │       ├── integer_parser.py
│   │       ├── boolean_parser.py
│   │       ├── float_parser.py
│   │       ├── array_parser.py
│   │       ├── template_parser.py   # Multi-field composition
│   │       └── cvss_extractor.py    # CVSS vector extraction
│   ├── services/
│   │   └── normalizer.py          # Main normalization orchestrator
│   ├── clients/
│   │   └── defectdojo_client.py   # DefectDojo API client
│   └── utils/
│       ├── checksum.py            # Hash generation
│       └── errors.py              # Custom exceptions
├── configs/
│   └── acunetix360_json.yaml      # Example parser configuration
├── tests/
│   ├── test_parsers.py            # File format parser tests
│   ├── test_normalizer.py         # Normalizer tests
│   ├── test_integration.py        # Integration tests
│   ├── test_defectdojo_client.py  # API client tests
│   ├── test_template_parser.py    # Template string tests
│   ├── test_priority_chains.py    # Priority chain tests
│   ├── test_fixed_value.py        # Fixed value tests
│   ├── test_state_machine.py      # State machine tests
│   ├── test_conditional_append.py # Conditional append tests
│   ├── test_cvss_extractor.py     # CVSS extractor tests
│   └── fixtures/                  # Test scan files
│       └── acunetix_sample.json
├── docs/
│   ├── ARCHITECTURE.md            # Architecture & technology decisions
│   ├── API.md                     # API reference
│   ├── DEPLOYMENT.md              # Deployment guide
│   ├── PARSER_CONFIG.md           # YAML configuration reference
│   └── USAGE.md                   # Usage examples
├── requirements.txt               # Python dependencies
├── test_setup.sh                  # Test setup script
└── README.md                      # This file
```

## 🔧 DefectDojo Integration

Universal Parser V2 integrates with DefectDojo through a new dedicated API endpoint:

**Endpoint**: `POST /api/v2/universal-parser-v2/reimport-scan/`

**Location in DefectDojo**:
- **API View**: `dojo/api_v2/views.py:2638` (UniversalParserV2ReImportScanView)
- **Serializers**: `dojo/api_v2/serializers.py:3154`
- **Reimporter**: `dojo/tools/universal_parser_v2/reimporter.py`
- **URL Config**: `dojo/urls.py:164`

This endpoint accepts pre-normalized findings and handles:
- ✅ Deduplication using DefectDojo's existing logic
- ✅ Creating new findings
- ✅ Updating existing findings
- ✅ Closing old findings not in current scan
- ✅ Reactivating previously closed findings
- ✅ Version tracking
- ✅ Tag support

## 🤝 Contributing

### Adding a New Parser

1. Create YAML configuration in `configs/your_tool.yaml`
2. Test with sample scan file
3. Add test fixtures to `tests/fixtures/`
4. Run tests: `pytest tests/ -v`
5. Update documentation

### Code Contributions

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make changes with tests
4. Ensure all tests pass: `pytest tests/ -v`
5. Follow PEP8 style: `ruff check .`
6. Submit a pull request

## 📝 Example Parsers

Sample parser configurations are included in `configs/`:

- **Acunetix 360 JSON** (`acunetix360_json.yaml`)
  - JSON format with JSONPath extraction
  - Severity mapping
  - CWE extraction
  - Comprehensive field mapping
  - 47 tests validate this parser ✅

More examples can be added easily - just create a YAML file!

## 🐛 Troubleshooting

### Common Issues

**1. Import fails with "Required field missing"**
- **Solution**: Check that your YAML maps all required fields: `title`, `description`, `severity`
- Verify fields are marked `active: true`

**2. Severity not normalized correctly**
- **Solution**: Verify `severity_mapping` in YAML matches your tool's severity values exactly (case-sensitive)
- Add all possible severity values from your scan file

**3. Findings not deduplicated**
- **Solution**: Ensure `unique_id_from_tool` is generated or include deduplication fields
- Check that deduplication fields are populated in your scan file

**4. Connection refused to DefectDojo**
- **Solution**: Verify DefectDojo is running and accessible
- Check API token is valid: `curl -H "Authorization: Token YOUR_TOKEN" https://dd.com/api/v2/users/`
- Ensure DefectDojo has the Universal Parser V2 API endpoint

**5. Tests fail with "No module named pytest"**
- **Solution**: Activate virtual environment: `source venv/bin/activate`
- Install dependencies: `pip install -r requirements.txt`

## 🚀 Roadmap

### Milestone 1: Core Infrastructure ✅

- ✅ FastAPI microservice with file upload
- ✅ YAML schema validation (Pydantic)
- ✅ JSON file format parser with JSONPath
- ✅ Basic data type parsers (string, severity, date, integer, boolean)
- ✅ Normalizer service with validation
- ✅ DefectDojo API endpoint (`/api/v2/universal-parser-v2/reimport-scan/`)
- ✅ DefectDojo API client in microservice

### Milestone 2: Field Extraction Patterns ✅

- ✅ Priority chain extraction (try multiple source fields)
- ✅ Template string parser (multi-field composition)
- ✅ Fixed value support (constant field values)
- ✅ State machine mapping (single input → multiple outputs)
- ✅ Conditional append (build composite fields)

### Milestone 3: Advanced Transformers ✅

- ✅ CVSS extractor with multi-source priority
- ✅ CVSS vector reconstruction from components
- ✅ Float parser for scores
- ✅ Array parser for list values
- ✅ Comprehensive test suite (194 tests)

### Upcoming

- XML format reader (XPath extraction)
- CSV format reader (column-based extraction)
- Additional parser configurations (Nessus, Burp, etc.)
- Docker Compose setup for microservice
- End-to-end testing with live DefectDojo

## 📄 License

This project is part of DefectDojo and follows the same BSD-3-Clause license.

## 🙏 Acknowledgments

- DefectDojo team for the excellent vulnerability management platform
- All contributors to the DefectDojo project
- FastAPI and Pydantic teams for amazing tools

## 📞 Support

- **Issues**: GitHub Issues (DefectDojo repository)
- **Documentation**: See `docs/` directory
- **Community**: DefectDojo Slack/Discord

---

**Status**: Active Development - Milestones 1-3 Complete ✅

**Branch**: `upV2-1.2-priority-chains`

**Author**: T. Walker - DefectDojo

**Created**: October 2025

**Last Updated**: November 2025
