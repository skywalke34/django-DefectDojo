# Universal Parser V2 - Architecture Documentation

## Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Component Details](#component-details)
4. [Data Flow](#data-flow)
5. [Integration with DefectDojo](#integration-with-defectdojo)
6. [Design Decisions](#design-decisions)
7. [Security Considerations](#security-considerations)
8. [Performance Considerations](#performance-considerations)

## Overview

Universal Parser V2 is a microservice-based parser system that decouples security tool parser logic from DefectDojo's core codebase. It uses a "Parser-as-Code" approach where parsers are defined using YAML configuration files instead of Python code.

### Key Principles

- **Separation of Concerns**: Parser logic separated from DefectDojo core
- **Declarative Configuration**: YAML-based parser definitions
- **Pluggable Architecture**: Easy to add new file formats and data types
- **Pre-normalization**: Findings normalized before reaching DefectDojo
- **Deduplication Integration**: Leverages DefectDojo's existing deduplication logic

## System Architecture

### High-Level Architecture

```
┌───────────────────────────────────────────────────────────────────────────┐
│                              CLIENT                                        │
│  (curl, Web Browser, CI/CD Pipeline, Security Tool)                      │
└────────────────────────────┬──────────────────────────────────────────────┘
                             │
                             │ HTTP POST (scan file + YAML config)
                             ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                    UNIVERSAL PARSER V2 MICROSERVICE                        │
│                           (FastAPI)                                        │
│                                                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                        API Layer                                     │ │
│  │  - File Upload Endpoints                                            │ │
│  │  - YAML Validation                                                  │ │
│  │  - Request/Response Handling                                        │ │
│  └─────────────────┬───────────────────────────────────────────────────┘ │
│                    │                                                       │
│  ┌─────────────────▼───────────────────────────────────────────────────┐ │
│  │                      Parser Engine                                   │ │
│  │  ┌────────────────┐  ┌──────────────┐  ┌──────────────────────┐   │ │
│  │  │ File Format    │  │ Field        │  │  Data Type           │   │ │
│  │  │ Readers        │─▶│ Extractor    │─▶│  Parsers             │   │ │
│  │  │ (JSON/XML/CSV) │  │ (JSONPath)   │  │  (severity, date)    │   │ │
│  │  └────────────────┘  └──────────────┘  └──────────────────────┘   │ │
│  └─────────────────┬───────────────────────────────────────────────────┘ │
│                    │                                                       │
│  ┌─────────────────▼───────────────────────────────────────────────────┐ │
│  │                  Normalizer Service                                  │ │
│  │  - Finding Validation                                               │ │
│  │  - Required Fields Check                                            │ │
│  │  - unique_id_from_tool Generation                                   │ │
│  └─────────────────┬───────────────────────────────────────────────────┘ │
│                    │                                                       │
│  ┌─────────────────▼───────────────────────────────────────────────────┐ │
│  │                DefectDojo API Client                                 │ │
│  │  - HTTP Client (httpx)                                              │ │
│  │  - Authentication                                                   │ │
│  │  - Error Handling                                                   │ │
│  └─────────────────┬───────────────────────────────────────────────────┘ │
└────────────────────┼───────────────────────────────────────────────────────┘
                     │
                     │ HTTP POST /api/v2/universal-parser-v2/reimport-scan/
                     ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                            DEFECTDOJO                                      │
│                                                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │          UniversalParserV2ReImportScanView (DRF View)               │ │
│  │  - Request Validation (Serializers)                                 │ │
│  │  - Authentication/Permissions                                       │ │
│  └─────────────────┬───────────────────────────────────────────────────┘ │
│                    │                                                       │
│  ┌─────────────────▼───────────────────────────────────────────────────┐ │
│  │           UniversalParserV2ReImporter                                │ │
│  │  - Finding Object Creation                                          │ │
│  │  - Deduplication Logic                                              │ │
│  │  - Close Old Findings                                               │ │
│  │  - Reactivation Logic                                               │ │
│  └─────────────────┬───────────────────────────────────────────────────┘ │
│                    │                                                       │
│  ┌─────────────────▼───────────────────────────────────────────────────┐ │
│  │                    Django ORM / Database                             │ │
│  │  - Finding Models                                                   │ │
│  │  - Test/Engagement Models                                           │ │
│  │  - Test_Import (Statistics)                                         │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────────┘
```

### Technology Stack

**Microservice:**
- **Framework**: FastAPI 0.115.6
- **Validation**: Pydantic 2.x
- **HTTP Client**: httpx (async)
- **File Parsing**:
  - JSON: jsonpath-ng
  - XML: lxml
  - CSV: built-in csv module
- **Testing**: pytest, pytest-cov

**DefectDojo Integration:**
- **Framework**: Django 5.1.12
- **API**: Django REST Framework 3.15.2
- **Database**: PostgreSQL (via Django ORM)

## Component Details

### 1. FastAPI Application (`app/main.py`)

**Purpose**: HTTP server that accepts scan files and YAML configurations

**Endpoints**:
- `POST /api/v1/parse` - Main parsing endpoint
- `POST /api/v1/validate-yaml` - YAML validation endpoint
- `GET /` - Web UI for file upload
- `GET /docs` - Swagger UI
- `GET /redoc` - ReDoc API documentation

**Responsibilities**:
- HTTP request handling
- File upload management
- YAML configuration validation
- Error handling and response formatting

### 2. YAML Configuration Model (`app/models/yaml_config.py`)

**Purpose**: Pydantic models for validating YAML parser configurations

**Models**:
```python
class ParserYAMLConfig(BaseModel):
    parser_name: str
    description: str
    version: str
    author: Optional[str]
    file_format: Literal["json", "xml", "csv"]
    json_root_path: Optional[str]
    xml_root_path: Optional[str]
    field_mappings: List[FieldMapping]
    deduplication_fields: Optional[List[str]]
```

**Validation Rules**:
- Required fields: `title`, `description`, `severity` must be mapped
- Severity must have a mapping table
- File format must match specified type
- JSONPath required for JSON format

### 3. File Format Readers (`app/parsers/file_formats/`)

**Purpose**: Read and parse different scan file formats

**Implementations**:

#### JSONReader
- Uses `jsonpath-ng` for field extraction
- Supports nested object traversal
- Returns list of raw finding dictionaries

#### XMLReader
- Uses `lxml` for XML parsing
- Supports XPath expressions
- Handles namespaces

#### CSVReader
- Uses built-in `csv` module
- Column-based field mapping
- Header row detection

**Interface**:
```python
class FileFormatReader(ABC):
    @abstractmethod
    def read(self, file_content: bytes, config: dict) -> List[dict]:
        """Read file and return list of raw findings"""
        pass
```

### 4. Data Type Parsers (`app/parsers/data_types/`)

**Purpose**: Transform raw values to DefectDojo-compatible formats

**Implementations**:

#### SeverityParser
- Normalizes severity values to: Critical, High, Medium, Low, Info
- Supports custom mapping tables
- Handles numeric and string inputs

#### DateParser
- Converts various date formats to YYYY-MM-DD
- Handles ISO 8601, Unix timestamps, custom formats

#### CVEParser
- Extracts CVE identifiers (CVE-YYYY-NNNNN)
- Validates format

#### CWEParser
- Extracts CWE numbers
- Validates against CWE database

#### IntegerParser
- Safe integer conversion
- Handles null/empty values

#### BooleanParser
- Converts string/numeric to boolean
- Handles common formats (true/false, yes/no, 1/0)

**Interface**:
```python
class DataTypeParser(ABC):
    @abstractmethod
    def parse(self, value: Any, config: dict = None) -> Any:
        """Parse value to target type"""
        pass
```

### 5. Normalizer Service (`app/services/normalizer.py`)

**Purpose**: Orchestrate complete parsing pipeline

**Process**:
1. Read scan file using appropriate FileFormatReader
2. Extract fields based on YAML configuration
3. Apply DataTypeParser transformations
4. Validate required fields present
5. Generate `unique_id_from_tool` if needed
6. Add metadata (scan_type, parser_name)

**Validation**:
- Required fields: title, description, severity
- Data type validation
- Empty value handling

### 6. DefectDojo API Client (`app/clients/defectdojo_client.py`)

**Purpose**: Communicate with DefectDojo API

**Methods**:
- `universal_parser_v2_reimport()` - Send normalized findings
- `get_test()` - Fetch test details
- `get_engagement()` - Fetch engagement details

**Features**:
- Async HTTP client (httpx)
- Token-based authentication
- Automatic error handling
- Retry logic
- SSL verification

### 7. DefectDojo API Endpoint (`dojo/api_v2/views.py`)

**Class**: `UniversalParserV2ReImportScanView`

**Purpose**: Receive pre-normalized findings from microservice

**Request Format**:
```json
{
  "test": 123,
  "findings": [
    {
      "title": "SQL Injection",
      "description": "...",
      "severity": "Critical",
      "cwe": 89,
      ...
    }
  ],
  "scan_date": "2025-10-14",
  "close_old_findings": true,
  "active": true,
  "verified": false
}
```

**Serializers** (`dojo/api_v2/serializers.py`):
- `UniversalParserV2FindingSerializer` - Validates individual findings
- `UniversalParserV2ReimportScanSerializer` - Validates request

**Response Format**:
```json
{
  "test": 123,
  "test_import_finding_action": {
    "created": 5,
    "closed": 2,
    "reactivated": 1,
    "updated": 0,
    "untouched": 3
  }
}
```

### 8. UniversalV2ReImporter (`dojo/tools/universal_parser_v2/reimporter.py`)

**Purpose**: Convert normalized dicts to Finding objects and handle deduplication

**Key Methods**:

#### `reimport_findings()`
Main entry point - orchestrates the entire reimport process

#### `_create_finding_objects()`
Converts normalized dictionaries to Django Finding model instances

**Process**:
1. Create `DefaultReImporter` instance
2. Convert findings dicts to Finding objects
3. Call `process_findings()` for deduplication
4. Close old findings not in current scan
5. Update timestamps
6. Create Test_Import record
7. Send notifications
8. Return statistics

**Deduplication**:
- Uses DefectDojo's existing `process_findings()` logic
- Matches on `hash_code` and `unique_id_from_tool`
- Handles reactivation of previously closed findings

## Data Flow

### Complete Import Flow

```
1. User uploads scan file + YAML config
   │
   ▼
2. FastAPI validates YAML schema
   │
   ▼
3. File FormatReader extracts raw findings
   │
   ▼
4. For each field mapping in YAML:
   │  Extract value from raw finding
   │  Apply DataTypeParser transformation
   │  Add to normalized finding dict
   │
   ▼
5. NormalizerService validates:
   │  - Required fields present
   │  - Field types correct
   │  - Generates unique_id_from_tool
   │
   ▼
6. DefectDojoClient sends normalized findings to:
   │  POST /api/v2/universal-parser-v2/reimport-scan/
   │
   ▼
7. UniversalParserV2ReImportScanView:
   │  - Validates request (serializers)
   │  - Checks permissions
   │  - Calls UniversalV2ReImporter
   │
   ▼
8. UniversalV2ReImporter:
   │  - Converts dicts to Finding objects
   │  - Calls process_findings() (deduplication)
   │  - Closes old findings
   │  - Saves to database
   │
   ▼
9. Response returned with statistics:
   {created: 5, closed: 2, reactivated: 1}
```

### Field Mapping Example

**Scan File** (Acunetix JSON):
```json
{
  "Vulnerabilities": [
    {
      "Name": "SQL Injection",
      "Severity": 3,
      "Description": "SQL injection found...",
      "Classification": {
        "Cwe": 89
      }
    }
  ]
}
```

**YAML Configuration**:
```yaml
json_root_path: "$.Vulnerabilities[*]"
field_mappings:
  - source_field: "Name"
    target_field: "title"
    data_type: "string"

  - source_field: "Severity"
    target_field: "severity"
    data_type: "severity"
    severity_mapping:
      "3": "Critical"

  - source_field: "Classification.Cwe"
    target_field: "cwe"
    data_type: "integer"
```

**Normalized Finding**:
```python
{
    "title": "SQL Injection",
    "description": "SQL injection found...",
    "severity": "Critical",  # Mapped from 3
    "cwe": 89,
    "unique_id_from_tool": "acunetix-abc123",
    "scan_type": "Acunetix360JSON"
}
```

## Integration with DefectDojo

### API Endpoint Design

**Why a new endpoint?**
- Standard `/api/v2/reimport-scan/` expects a file upload
- Universal Parser V2 sends pre-normalized JSON data
- Different serializer validation requirements
- Specialized reimporter logic

### Deduplication Strategy

**Leverages existing DefectDojo logic**:
1. `hash_code` - Computed from finding fields
2. `unique_id_from_tool` - Generated by microservice
3. `process_findings()` - Matches existing findings
4. Updates vs Creates - Based on match results

**Benefits**:
- No duplicate deduplication logic
- Consistent with other parsers
- Reuses tested code paths

### Database Schema

**No schema changes required!**

Universal Parser V2 uses existing models:
- `Finding` - Vulnerability records
- `Test` - Test container
- `Test_Import` - Import statistics
- `Engagement` - Engagement container

## Design Decisions

### 1. Microservice vs Monolith

**Decision**: Separate microservice

**Rationale**:
- ✅ Deploy parsers without DefectDojo restart
- ✅ Scale independently
- ✅ Different technology stack (FastAPI vs Django)
- ✅ Easier testing in isolation
- ❌ Additional complexity (deployment, networking)

### 2. YAML vs Other Formats

**Decision**: YAML configuration files

**Rationale**:
- ✅ Human-readable
- ✅ Comment support
- ✅ Wide tool support
- ✅ Easier version control
- ❌ Indentation-sensitive

### 3. Pre-normalization vs File Upload

**Decision**: Normalize in microservice, send JSON to DefectDojo

**Rationale**:
- ✅ Decouple parsing from DefectDojo
- ✅ Easier to test normalization
- ✅ Reusable for other integrations
- ✅ Validation happens early
- ❌ Can't use DefectDojo's file storage

### 4. New Endpoint vs Existing

**Decision**: Create new `/api/v2/universal-parser-v2/reimport-scan/`

**Rationale**:
- ✅ Different input format (JSON vs multipart/form-data)
- ✅ Different serializer requirements
- ✅ Specialized reimporter logic
- ✅ Easier to maintain separately
- ❌ More code to maintain

## Security Considerations

### 1. Input Validation

**YAML Configuration**:
- Pydantic schema validation
- Required field enforcement
- File format verification
- JSONPath/XPath injection prevention

**Scan Files**:
- File size limits
- Format validation
- Content-type verification
- Malicious payload detection

### 2. Authentication & Authorization

**Microservice**:
- Currently no auth (internal service)
- TODO: Add API key authentication
- TODO: Rate limiting

**DefectDojo API**:
- Token-based authentication
- Permission checks (user must have reimport permission)
- Test/Engagement access validation

### 3. Data Sanitization

**Finding Data**:
- HTML escaping in descriptions
- XSS prevention in references
- SQL injection prevention (ORM)
- Path traversal prevention (file_path field)

### 4. Network Security

**Recommendations**:
- Run microservice in private network
- Use HTTPS for DefectDojo communication
- SSL certificate verification
- Network segmentation

## Performance Considerations

### 1. Scalability

**Microservice**:
- Async FastAPI (handles concurrent requests)
- Stateless (can run multiple instances)
- Horizontal scaling with load balancer
- Worker pool for CPU-intensive parsing

**DefectDojo**:
- Database indexes on Finding fields
- Bulk inserts for multiple findings
- Query optimization in reimporter

### 2. Resource Usage

**Memory**:
- File size limits (default: 100MB)
- Streaming for large files
- Garbage collection between requests

**CPU**:
- JSONPath parsing (can be slow)
- XML parsing (memory intensive)
- Severity normalization (string operations)

### 3. Optimization Opportunities

**Current**:
- Single-threaded parsing
- Sequential field extraction
- No caching

**Future**:
- Parallel field extraction
- Caching parsed YAML configs
- Connection pooling for DefectDojo API
- Redis for distributed caching

### 4. Benchmarks

**Test Environment**: MacBook Pro M1, 32GB RAM

**Acunetix JSON (100 findings)**:
- Parse + Normalize: ~200ms
- Send to DefectDojo: ~500ms
- DefectDojo Reimport: ~1.5s
- **Total: ~2.2s**

**Large Scan (1000 findings)**:
- Parse + Normalize: ~1.8s
- Send to DefectDojo: ~2.5s
- DefectDojo Reimport: ~12s
- **Total: ~16.3s**

## Future Enhancements

### Short Term
- [ ] Add authentication to microservice
- [ ] Implement caching for YAML configs
- [ ] Add more data type parsers (URL, IP, etc.)
- [ ] Support for more file formats (SARIF, CycloneDX)

### Long Term
- [ ] Async processing with Celery
- [ ] Web UI for YAML editor with autocomplete
- [ ] Parser marketplace/registry
- [ ] GraphQL API support
- [ ] Real-time progress updates (WebSockets)

---

**Author**: T. Walker - DefectDojo
**Created**: October 2025
**Last Updated**: October 2025
