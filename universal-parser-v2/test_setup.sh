#!/bin/bash

# Universal Parser V2 - Setup Test Script
# This script verifies the microservice installation and dependencies

set -e

echo "🧪 Testing Universal Parser V2 Setup"
echo "====================================="
echo ""

# Check Python version
echo "1️⃣  Checking Python version..."
PYTHON_VERSION=$(python3 --version 2>&1)
echo "   ✓ $PYTHON_VERSION"
echo ""

# Check if virtual environment exists
echo "2️⃣  Checking virtual environment..."
if [ -d "venv" ]; then
    echo "   ✓ Virtual environment exists"
else
    echo "   ⚠️  Virtual environment not found"
    echo "   Creating virtual environment..."
    python3 -m venv venv
    echo "   ✓ Virtual environment created"
fi
echo ""

# Activate virtual environment
echo "3️⃣  Activating virtual environment..."
source venv/bin/activate
echo "   ✓ Virtual environment activated"
echo ""

# Check if dependencies are installed
echo "4️⃣  Checking dependencies..."
if pip show fastapi > /dev/null 2>&1; then
    echo "   ✓ Dependencies already installed"
else
    echo "   ⚠️  Dependencies not installed"
    echo "   Installing dependencies..."
    pip install -r requirements.txt
    echo "   ✓ Dependencies installed"
fi
echo ""

# Test YAML validation
echo "5️⃣  Testing YAML validation..."
python3 << 'PYTHON_TEST'
from app.validators.yaml_validator import YAMLValidator
from app.models.yaml_config import YAMLConfig

yaml_content = """
parser_name: Test
parser_version: "1.0"
tool_name: Test Tool
tool_type: Test_Tool
file_format: json
json_root_path: "$.items"
field_mappings:
  - source_field: name
    target_field: title
    data_type: string
    active: true
  - source_field: desc
    target_field: description
    data_type: string
    active: true
  - source_field: sev
    target_field: severity
    data_type: severity
    active: true
    severity_mapping:
      high: High
      medium: Medium
      low: Low
deduplication_fields:
  - title
"""

try:
    config, checksum = YAMLValidator.validate_with_checksum(yaml_content)
    print("   ✓ YAML validation working")
    print(f"   ✓ Checksum: {checksum[:16]}...")
except Exception as e:
    print(f"   ✗ YAML validation failed: {e}")
    exit(1)
PYTHON_TEST
echo ""

# Test Pydantic models
echo "6️⃣  Testing Pydantic models..."
python3 << 'PYTHON_TEST'
from app.models.yaml_config import FieldMapping, YAMLConfig

try:
    mapping = FieldMapping(
        source_field="test",
        target_field="title",
        data_type="string",
        active=True
    )
    print("   ✓ Pydantic models working")
except Exception as e:
    print(f"   ✗ Pydantic test failed: {e}")
    exit(1)
PYTHON_TEST
echo ""

# Check if sample config is valid
echo "7️⃣  Validating sample Acunetix config..."
python3 << 'PYTHON_TEST'
from app.validators.yaml_validator import YAMLValidator

try:
    with open("configs/acunetix360_json.yaml", "r") as f:
        yaml_content = f.read()

    config, checksum = YAMLValidator.validate_with_checksum(yaml_content)
    print(f"   ✓ Sample config valid: {config.parser_name} v{config.parser_version}")
    print(f"   ✓ Active mappings: {len(config.get_active_field_mappings())}")
    print(f"   ✓ Deduplication fields: {', '.join(config.deduplication_fields)}")
except Exception as e:
    print(f"   ✗ Sample config validation failed: {e}")
    exit(1)
PYTHON_TEST
echo ""

echo "✅ All tests passed!"
echo ""
echo "🚀 Ready to start the microservice!"
echo ""
echo "Run the following command to start the server:"
echo "   python3 -m app.main"
echo ""
echo "Or using uvicorn:"
echo "   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"
echo ""
echo "Then open your browser to:"
echo "   http://localhost:8000"
echo ""
