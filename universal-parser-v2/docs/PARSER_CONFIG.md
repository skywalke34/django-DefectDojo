# Universal Parser V2 - Parser Configuration Reference

**Version**: 0.1.0 (PoC)
**Last Updated**: October 14, 2025

## Overview

This document provides a complete reference for the YAML parser configuration schema used by Universal Parser V2.

Parser configurations are YAML files that define how to extract findings from security tool scan files and map them to DefectDojo's Finding model.

---

## Table of Contents

- [Complete Schema](#complete-schema)
- [Configuration Sections](#configuration-sections)
  - [Metadata](#metadata)
  - [File Format](#file-format)
  - [Field Mappings](#field-mappings)
  - [Deduplication](#deduplication)
- [Data Types](#data-types)
- [Target Fields](#target-fields)
- [Validation Rules](#validation-rules)
- [Examples](#examples)

---

## Complete Schema

Here's the complete YAML schema with all available fields:

```yaml
# ===== METADATA =====
parser_name: string          # REQUIRED: Unique parser identifier
parser_version: string       # REQUIRED: Parser version (e.g., "1.0.0")
tool_name: string           # REQUIRED: Human-readable tool name
tool_type: string           # REQUIRED: DefectDojo scan_type identifier

# ===== FILE FORMAT =====
file_format: string         # REQUIRED: "json", "xml", or "csv"
file_encoding: string       # OPTIONAL: Default "utf-8"

# Format-specific (choose based on file_format)
json_root_path: string      # REQUIRED for JSON: JSONPath to findings array
xml_finding_xpath: string   # REQUIRED for XML: XPath to finding elements
csv_delimiter: string       # OPTIONAL for CSV: Default ","
csv_has_header: boolean     # OPTIONAL for CSV: Default true
csv_skip_rows: integer      # OPTIONAL for CSV: Rows to skip before header

# ===== FIELD MAPPINGS =====
field_mappings:             # REQUIRED: List of field mappings
  # Source field options (use ONE of source_field OR source_fields)
  - source_field: string    # Single field path in scan file
    source_fields: [string] # OR: Priority list of fields (first non-null wins)

    target_field: string    # REQUIRED: DefectDojo Finding field
    data_type: string       # REQUIRED: Data type parser to use
    active: boolean         # OPTIONAL: Default true

    # Data type-specific options
    severity_mapping:       # REQUIRED for data_type: "severity"
      "SOURCE_VALUE": "Target"

    date_format: string     # OPTIONAL for data_type: "date"
    default: string         # OPTIONAL: Default value if field missing
    template: string        # REQUIRED for data_type: "template"

# ===== DEDUPLICATION =====
deduplication_fields:       # OPTIONAL: List of fields for deduplication
  - string                  # Field names from target_field
```

---

## Configuration Sections

### Metadata

Parser metadata identifies your parser and the tool it supports.

#### `parser_name` (Required)

Unique identifier for your parser. Use CamelCase with tool name and format.

**Type**: String
**Required**: Yes

**Examples**:
```yaml
parser_name: "Acunetix360JSONParser"
parser_name: "BurpSuiteXMLParser"
parser_name: "CheckmarxSASTCSVParser"
```

**Best Practices**:
- Include tool name
- Include file format
- Use CamelCase
- Make it descriptive and unique

---

#### `parser_version` (Required)

Version of your parser configuration. Use semantic versioning.

**Type**: String
**Required**: Yes

**Format**: `"MAJOR.MINOR.PATCH"`

**Examples**:
```yaml
parser_version: "1.0.0"  # Initial release
parser_version: "1.1.0"  # Added new field mappings
parser_version: "2.0.0"  # Breaking change in structure
```

**When to Increment**:
- **Major**: Breaking changes (different deduplication strategy, removed fields)
- **Minor**: New features (added field mappings, new data types)
- **Patch**: Bug fixes (corrected severity mapping)

---

#### `tool_name` (Required)

Human-readable name of the security tool.

**Type**: String
**Required**: Yes

**Examples**:
```yaml
tool_name: "Acunetix 360"
tool_name: "Burp Suite Professional"
tool_name: "Checkmarx SAST"
tool_name: "OWASP ZAP"
```

---

#### `tool_type` (Required)

DefectDojo scan type identifier. This should match the type of security testing performed.

**Type**: String
**Required**: Yes

**Common Values**:
- `SAST` - Static Application Security Testing
- `DAST` - Dynamic Application Security Testing
- `SCA` - Software Composition Analysis
- `IAST` - Interactive Application Security Testing
- `Container` - Container security scanning
- `IaC` - Infrastructure as Code scanning

**Examples**:
```yaml
tool_type: "DAST"
tool_type: "SAST"
tool_type: "SCA"
tool_type: "Acunetix_360_JSON"  # Can be tool-specific
```

---

### File Format

Configuration for the scan file format and encoding.

#### `file_format` (Required)

Type of scan file to parse.

**Type**: String
**Required**: Yes
**Allowed Values**: `json`, `xml`, `csv`

**Examples**:
```yaml
file_format: "json"
file_format: "xml"
file_format: "csv"
```

---

#### `file_encoding` (Optional)

Character encoding of the scan file.

**Type**: String
**Required**: No
**Default**: `"utf-8"`

**Examples**:
```yaml
file_encoding: "utf-8"
file_encoding: "utf-16"
file_encoding: "iso-8859-1"
```

---

#### JSON Format Options

##### `json_root_path` (Required for JSON)

JSONPath expression to the array of findings in the JSON file.

**Type**: String
**Required**: Yes (when `file_format: "json"`)

**Syntax**: JSONPath (similar to XPath for JSON)

**Examples**:
```yaml
# Simple array at root
json_root_path: "$.vulnerabilities[*]"

# Nested array
json_root_path: "$.scan_results.findings[*]"

# Multiple levels
json_root_path: "$.report.data.issues[*]"

# Array in array
json_root_path: "$.scans[*].vulnerabilities[*]"
```

**JSONPath Syntax**:
- `$` - Root object
- `.` - Child element
- `[*]` - All elements in array
- `[0]` - First element
- `..` - Recursive descent

**Test Your JSONPath**:
```bash
# Using jq (similar to JSONPath)
jq '.vulnerabilities[]' scan.json
```

---

#### XML Format Options

##### `xml_finding_xpath` (Required for XML)

XPath expression to select finding elements.

**Type**: String
**Required**: Yes (when `file_format: "xml"`)

**Examples**:
```yaml
# Direct path
xml_finding_xpath: "//vulnerability"

# With namespace
xml_finding_xpath: "//ns:vulnerability"

# Nested path
xml_finding_xpath: "//report/findings/issue"

# With attributes
xml_finding_xpath: "//finding[@type='vulnerability']"
```

**Test Your XPath**:
```bash
# Using xmllint
xmllint --xpath "//vulnerability" scan.xml
```

---

#### CSV Format Options

##### `csv_delimiter` (Optional)

Character used to separate fields in CSV.

**Type**: String
**Required**: No
**Default**: `","`

**Examples**:
```yaml
csv_delimiter: ","      # Comma
csv_delimiter: ";"      # Semicolon
csv_delimiter: "\t"     # Tab
csv_delimiter: "|"      # Pipe
```

---

##### `csv_has_header` (Optional)

Whether the CSV file has a header row.

**Type**: Boolean
**Required**: No
**Default**: `true`

**Examples**:
```yaml
csv_has_header: true   # First row is header
csv_has_header: false  # No header, use column indices
```

---

##### `csv_skip_rows` (Optional)

Number of rows to skip before the header row.

**Type**: Integer
**Required**: No
**Default**: `0`

**Examples**:
```yaml
csv_skip_rows: 0   # No rows to skip
csv_skip_rows: 3   # Skip first 3 rows (e.g., metadata)
```

---

### Field Mappings

Field mappings define how to extract data from scan files and map to DefectDojo fields.

#### Field Mapping Structure

Each field mapping has the following structure:

```yaml
field_mappings:
  # Option 1: Single source field
  - source_field: string      # Single field path
    target_field: string      # REQUIRED
    data_type: string         # REQUIRED
    active: boolean           # OPTIONAL (default: true)
    severity_mapping: dict    # REQUIRED for severity type
    date_format: string       # OPTIONAL for date type
    default: any              # OPTIONAL

  # Option 2: Priority chain (alternative field names)
  - source_fields: [string]   # List of field paths to try in order
    target_field: string      # REQUIRED
    data_type: string         # REQUIRED
    # ... same options as above

  # Option 3: Template string
  - target_field: string      # REQUIRED
    data_type: "template"     # Must be "template"
    template: string          # Template with {field} placeholders
```

**Note**: Use `source_field` OR `source_fields`, not both. Templates don't need either.

---

#### `source_fields` - Priority Chain / Alternative Fields

Use `source_fields` when the same data might appear under different field names in the scan file.
This is common with tools like Tenable that have 20+ alternative names for the same data.

**Semantics**:
1. Try each field path in order
2. Return the first non-null, non-empty value found
3. If all sources fail, use `default` value (if provided)
4. Apply `data_type` parser to the extracted value

**Example - Tenable CSV alternative field names**:
```yaml
field_mappings:
  # Title can come from multiple fields
  - source_fields: ["Name", "Plugin Name", "asset.name"]
    target_field: "title"
    data_type: "string"

  # Description has 3 possible sources
  - source_fields: ["Synopsis", "definition.synopsis", "Description"]
    target_field: "description"
    data_type: "string"

  # Mitigation with fallback default
  - source_fields: ["Solution", "definition.solution", "Steps to Remediate"]
    target_field: "mitigation"
    data_type: "string"
    default: "N/A"
```

**Example - Nested field priority**:
```yaml
field_mappings:
  # Try nested paths in order
  - source_fields: ["vuln.name", "metadata.title", "name"]
    target_field: "title"
    data_type: "string"
```

**When to use `source_fields`**:
- Security tool has multiple export formats
- Fields have different names across tool versions
- Alternative field names for backward compatibility
- CSV tools with inconsistent column naming

---

#### `source_field` (Required*)

Path to a single field in the scan file.

**Type**: String
**Required**: Yes, unless using `source_fields` or `data_type: "template"`

*Use `source_field` for single-field extraction, or `source_fields` for priority chains.

**JSON Examples**:
```yaml
# Simple field
source_field: "title"

# Nested field (dot notation)
source_field: "vulnerability.name"
source_field: "details.description"

# Array index
source_field: "tags[0]"
```

**XML Examples**:
```yaml
# Element
source_field: "title"

# Nested element
source_field: "classification/severity"

# Attribute
source_field: "@id"
```

**CSV Examples**:
```yaml
# Column name (if csv_has_header: true)
source_field: "Title"
source_field: "Severity Level"

# Column index (if csv_has_header: false)
source_field: "0"  # First column
source_field: "3"  # Fourth column
```

---

#### `target_field` (Required)

DefectDojo Finding field to populate.

**Type**: String
**Required**: Yes

See [Target Fields](#target-fields) for complete list.

**Required Target Fields**:
- `title` - Finding title
- `description` - Finding description
- `severity` - Severity level

**Examples**:
```yaml
target_field: "title"
target_field: "severity"
target_field: "cwe"
target_field: "file_path"
```

---

#### `data_type` (Required)

Type of data parser to use for this field.

**Type**: String
**Required**: Yes
**Allowed Values**: `string`, `severity`

**Currently Implemented**:
- `string` - String values (text, paths, descriptions)
- `severity` - Severity normalization (Critical, High, Medium, Low, Info)

**Planned for Future**:
- `integer` - Integer values (line numbers, CWE IDs)
- `float` - Floating point (CVSS scores)
- `boolean` - Boolean values (active, verified)
- `date` - Date values with format parsing
- `cve` - CVE identifier extraction
- `cwe` - CWE identifier extraction and normalization

**Examples**:
```yaml
data_type: "string"    # For text fields
data_type: "severity"  # For severity with mapping
```

---

#### `active` (Optional)

Whether this field mapping is enabled.

**Type**: Boolean
**Required**: No
**Default**: `true`

**Use Cases**:
- Temporarily disable a mapping without deleting it
- Test different field configurations
- Keep old mappings for reference

**Examples**:
```yaml
active: true   # Mapping is enabled
active: false  # Mapping is disabled (ignored)
```

---

#### `severity_mapping` (Required for severity type)

Mapping table for normalizing severity values from the tool to DefectDojo standard values.

**Type**: Dictionary
**Required**: Yes (when `data_type: "severity"`)

**Target Values (DefectDojo Standard)**:
- `Critical`
- `High`
- `Medium`
- `Low`
- `Info`

**Examples**:

```yaml
# Standard severity levels
severity_mapping:
  "CRITICAL": "Critical"
  "HIGH": "High"
  "MEDIUM": "Medium"
  "LOW": "Low"
  "INFO": "Info"

# Numeric severity (1-5)
severity_mapping:
  "5": "Critical"
  "4": "High"
  "3": "Medium"
  "2": "Low"
  "1": "Info"

# Mixed formats
severity_mapping:
  "Critical": "Critical"
  "High": "High"
  "Medium": "Medium"
  "Low": "Low"
  "Informational": "Info"
  "Info": "Info"

# Lowercase handling
severity_mapping:
  "critical": "Critical"
  "high": "High"
  "medium": "Medium"
  "low": "Low"
  "info": "Info"
```

**Best Practices**:
- Include all possible values from your tool
- Test with real scan files
- Add variations (uppercase, lowercase, abbreviations)
- Use consistent target values

---

#### `date_format` (Optional)

Format string for parsing date values (planned feature).

**Type**: String
**Required**: No
**Status**: Planned for future implementation

**Examples**:
```yaml
date_format: "%Y-%m-%d"           # 2025-01-15
date_format: "%m/%d/%Y"           # 01/15/2025
date_format: "%Y-%m-%d %H:%M:%S"  # 2025-01-15 14:30:00
```

---

#### `default` (Optional)

Default value to use if the source field is missing or null.

**Type**: Any
**Required**: No

**Examples**:
```yaml
# String default
- source_field: "mitigation"
  target_field: "mitigation"
  data_type: "string"
  default: "No mitigation available"

# Boolean default
- source_field: "verified"
  target_field: "verified"
  data_type: "boolean"
  default: false

# Severity default
- source_field: "severity"
  target_field: "severity"
  data_type: "severity"
  default: "Medium"
  severity_mapping: {...}
```

---

### Deduplication

Deduplication configuration determines how DefectDojo identifies duplicate findings.

#### `deduplication_fields` (Optional)

List of DefectDojo field names to use for generating a unique hash for deduplication.

**Type**: Array of Strings
**Required**: No
**Default**: `["title"]`

**How It Works**:
DefectDojo creates a hash from the values of these fields. If a finding with the same hash exists, it's considered a duplicate and will be updated instead of creating a new finding.

**Good Deduplication Fields**:
- `title` - Finding name
- `file_path` - Source code file
- `line` - Line number
- `cwe` - CWE identifier
- `unique_id_from_tool` - Tool's own unique ID

**Examples**:

```yaml
# Minimal (just title)
deduplication_fields:
  - "title"

# File and location
deduplication_fields:
  - "title"
  - "file_path"
  - "line"

# With CWE
deduplication_fields:
  - "title"
  - "file_path"
  - "cwe"

# Using tool's unique ID
deduplication_fields:
  - "unique_id_from_tool"

# Very specific
deduplication_fields:
  - "title"
  - "file_path"
  - "line"
  - "cwe"
  - "severity"
```

**Best Practices**:
- Include enough fields to uniquely identify a finding
- Don't include fields that change between scans (like `date`)
- Don't include too many fields (makes deduplication too strict)
- Use `unique_id_from_tool` if your tool provides stable IDs

**Validation**:
All fields in `deduplication_fields` must be in the active `field_mappings`.

---

## Data Types

### string

Basic string parser for text fields.

**Use For**:
- Titles
- Descriptions
- File paths
- References
- Mitigation text
- Impact descriptions

**Features**:
- Strips leading/trailing whitespace
- Converts to string type
- Handles null values

**Example**:
```yaml
- source_field: "title"
  target_field: "title"
  data_type: "string"
  active: true
```

---

### severity

Severity normalization parser with mapping.

**Use For**:
- Severity levels
- Risk ratings
- Priority values

**Features**:
- Maps tool-specific values to DefectDojo standard
- Case-sensitive matching
- Validates target values
- Requires `severity_mapping`

**Target Values**:
- `Critical`
- `High`
- `Medium`
- `Low`
- `Info`

**Example**:
```yaml
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
```

---

### Future Data Types

The following data types are planned for future implementation:

#### integer (Planned)

Integer parser for numeric values.

**Planned Use For**:
- CWE IDs
- Line numbers
- Port numbers

#### float (Planned)

Floating-point parser.

**Planned Use For**:
- CVSS scores
- Confidence scores

#### boolean (Planned)

Boolean parser.

**Planned Use For**:
- active
- verified
- false_p

#### date (Planned)

Date parser with format support.

**Planned Use For**:
- Finding date
- Scan date
- Discovery date

#### cve (Planned)

CVE identifier extractor and validator.

**Planned Use For**:
- CVE fields

#### cwe (Planned)

CWE identifier extractor and normalizer.

**Planned Use For**:
- CWE fields

---

## Target Fields

DefectDojo Finding fields that can be populated.

### Required Fields

These fields **must** be mapped and active:

| Field | Type | Description |
|-------|------|-------------|
| `title` | string | Finding title/name |
| `description` | string | Detailed description |
| `severity` | severity | Severity level (Critical/High/Medium/Low/Info) |

---

### Optional Fields

#### Vulnerability Details

| Field | Type | Description |
|-------|------|-------------|
| `cwe` | integer | CWE identifier (e.g., 89 for SQL Injection) |
| `mitigation` | string | Recommended mitigation steps |
| `impact` | string | Impact description |
| `references` | string | References/links (newline-separated) |

#### CVSS Scoring

| Field | Type | Description |
|-------|------|-------------|
| `cvssv3` | string | CVSS v3 vector string |
| `cvssv3_score` | float | CVSS v3 base score (0.0-10.0) |
| `cvssv4` | string | CVSS v4 vector string |
| `cvssv4_score` | float | CVSS v4 base score (0.0-10.0) |

#### Location

| Field | Type | Description |
|-------|------|-------------|
| `file_path` | string | File path where vulnerability found |
| `line` | integer | Line number |

#### Component Information

| Field | Type | Description |
|-------|------|-------------|
| `component_name` | string | Component/library name |
| `component_version` | string | Component/library version |

#### Finding Status

| Field | Type | Description |
|-------|------|-------------|
| `active` | boolean | Finding is active |
| `verified` | boolean | Finding is verified |
| `false_p` | boolean | Finding is false positive |
| `duplicate` | boolean | Finding is duplicate |
| `out_of_scope` | boolean | Finding is out of scope |
| `risk_accepted` | boolean | Risk has been accepted |

#### Finding Type

| Field | Type | Description |
|-------|------|-------------|
| `static_finding` | boolean | Finding from SAST tool |
| `dynamic_finding` | boolean | Finding from DAST tool |

#### Deduplication

| Field | Type | Description |
|-------|------|-------------|
| `unique_id_from_tool` | string | Tool's unique identifier for deduplication |
| `date` | date | Date finding was discovered |

---

## Validation Rules

### Parser Validation

1. **Metadata**:
   - `parser_name`, `parser_version`, `tool_name`, `tool_type` must be present
   - Version should follow semantic versioning

2. **File Format**:
   - Must be `json`, `xml`, or `csv`
   - Format-specific fields required:
     - JSON requires `json_root_path`
     - XML requires `xml_finding_xpath`
     - CSV optionally uses `csv_delimiter`, `csv_has_header`, `csv_skip_rows`

3. **Field Mappings**:
   - At least one mapping must exist
   - Required fields must be mapped and active: `title`, `description`, `severity`
   - All `target_field` values should be valid DefectDojo fields (warning if not)
   - All `data_type` values must be supported

4. **Severity Mapping**:
   - Required when `data_type: "severity"`
   - All target values must be valid: `Critical`, `High`, `Medium`, `Low`, `Info`

5. **Deduplication**:
   - All fields in `deduplication_fields` must exist in active `field_mappings`
   - Defaults to `["title"]` if not specified

---

## Examples

### Example 1: Complete JSON Parser

```yaml
parser_name: "Acunetix360JSONParser"
parser_version: "1.0.0"
tool_name: "Acunetix 360"
tool_type: "DAST"

file_format: "json"
json_root_path: "$.Vulnerabilities[*]"

field_mappings:
  # Required fields
  - source_field: "Name"
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
      "4": "Critical"
      "3": "High"
      "2": "Medium"
      "1": "Low"
      "0": "Info"

  # Optional fields
  - source_field: "Classification.Cwe"
    target_field: "cwe"
    data_type: "string"
    active: true

  - source_field: "Classification.CVSS3.Score"
    target_field: "cvssv3_score"
    data_type: "string"
    active: true

  - source_field: "LookupId"
    target_field: "unique_id_from_tool"
    data_type: "string"
    active: true

deduplication_fields:
  - "title"
  - "unique_id_from_tool"
```

---

### Example 2: Simple CSV Parser

```yaml
parser_name: "GenericCSVParser"
parser_version: "1.0.0"
tool_name: "Generic Tool"
tool_type: "SAST"

file_format: "csv"
csv_delimiter: ","
csv_has_header: true

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
      "Critical": "Critical"
      "High": "High"
      "Medium": "Medium"
      "Low": "Low"

  - source_field: "File"
    target_field: "file_path"
    data_type: "string"
    active: true

deduplication_fields:
  - "title"
  - "file_path"
```

---

### Example 3: XML Parser with Namespaces

```yaml
parser_name: "BurpSuiteXMLParser"
parser_version: "1.0.0"
tool_name: "Burp Suite Professional"
tool_type: "DAST"

file_format: "xml"
xml_finding_xpath: "//issue"

field_mappings:
  - source_field: "name"
    target_field: "title"
    data_type: "string"
    active: true

  - source_field: "issueDetail"
    target_field: "description"
    data_type: "string"
    active: true

  - source_field: "severity"
    target_field: "severity"
    data_type: "severity"
    active: true
    severity_mapping:
      "High": "High"
      "Medium": "Medium"
      "Low": "Low"
      "Information": "Info"

  - source_field: "path"
    target_field: "file_path"
    data_type: "string"
    active: true

deduplication_fields:
  - "title"
  - "file_path"
```

---

## Validation Tools

### Validate YAML Syntax

```bash
# Python validation
python -c "import yaml; yaml.safe_load(open('config.yaml'))"

# Online validators
# https://www.yamllint.com/
```

### Validate with API

```bash
curl -X POST http://localhost:8000/api/validate-yaml \
  -F "yaml_file=@configs/myparser.yaml"
```

### Test JSONPath

```bash
# Install jq
brew install jq  # macOS
apt-get install jq  # Linux

# Test path
jq '.vulnerabilities[]' scan.json
```

### Test XPath

```bash
# Install xmllint (usually pre-installed)
xmllint --xpath "//vulnerability" scan.xml
```

---

## Best Practices

1. **Version Control**: Keep parser configs in git
2. **Testing**: Test with real scan files before deploying
3. **Documentation**: Add comments explaining severity mappings
4. **Naming**: Use descriptive, consistent names
5. **Deduplication**: Choose fields that uniquely identify findings
6. **Required Fields**: Always map title, description, severity
7. **Validation**: Use the validation endpoint before importing
8. **Incremental**: Start simple, add fields as needed

---

## Support

- **Issues**: GitHub Issues (DefectDojo repository)
- **Documentation**: See `docs/` directory
- **Examples**: See `configs/` directory
- **Community**: DefectDojo Slack/Discord

---

**Status**: PoC (Proof of Concept) - Day 7 Complete ✅
**Branch**: `upV2-Poc`
**Author**: T. Walker - DefectDojo
**Created**: October 2025
