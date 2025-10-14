"""
Universal Parser V2 - Microservice

FastAPI application for parsing security tool scan files using
YAML configuration files (parser-as-code).

This microservice:
1. Accepts scan file + YAML config uploads
2. Validates YAML configuration
3. Parses scan file according to YAML mappings
4. Normalizes findings to DefectDojo format
5. Sends to DefectDojo API for import

Author: DefectDojo Team
License: BSD-3-Clause
"""

from fastapi import FastAPI, File, UploadFile, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import logging

from app.validators.yaml_validator import YAMLValidator
from app.utils.errors import YAMLValidationError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Universal Parser V2",
    description="Parser-as-code microservice for DefectDojo security tool imports",
    version="0.1.0 (PoC)",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Configure templates
templates = Jinja2Templates(directory="app/templates")


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """
    Render upload form homepage.

    Returns HTML form for uploading scan file + YAML configuration.
    """
    return templates.TemplateResponse(
        "index.html",
        {"request": request}
    )


@app.get("/health")
async def health_check():
    """
    Health check endpoint for monitoring.

    Returns:
        dict: Service status
    """
    return {
        "status": "healthy",
        "service": "universal-parser-v2",
        "version": "0.1.0"
    }


@app.post("/api/validate-yaml")
async def validate_yaml_endpoint(
    yaml_file: UploadFile = File(..., description="YAML configuration file")
):
    """
    Validate YAML configuration file without processing scan.

    This endpoint allows users to test their YAML configuration
    before uploading a scan file.

    Args:
        yaml_file: YAML configuration file upload

    Returns:
        dict: Validation result with config summary

    Raises:
        HTTPException: If YAML is invalid
    """
    try:
        # Read YAML content
        yaml_content = await yaml_file.read()
        yaml_str = yaml_content.decode('utf-8')

        # Validate
        config, checksum = YAMLValidator.validate_with_checksum(yaml_str)

        # Return success with config summary
        return {
            "status": "valid",
            "message": "YAML configuration is valid",
            "config": {
                "parser_name": config.parser_name,
                "parser_version": config.parser_version,
                "tool_name": config.tool_name,
                "tool_type": config.tool_type,
                "file_format": config.file_format,
                "active_field_mappings": len(config.get_active_field_mappings()),
                "deduplication_fields": config.deduplication_fields,
                "yaml_checksum": checksum
            }
        }

    except YAMLValidationError as e:
        logger.warning(f"YAML validation failed: {str(e)}")
        raise HTTPException(
            status_code=400,
            detail=YAMLValidator.format_validation_errors(e)
        )
    except Exception as e:
        logger.error(f"Unexpected error validating YAML: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Internal Server Error",
                "message": "An unexpected error occurred while validating YAML",
                "type": "internal_error"
            }
        )


@app.post("/api/import")
async def import_scan(
    scan_file: UploadFile = File(..., description="Security scan report file"),
    yaml_file: UploadFile = File(..., description="YAML configuration file"),
    defectdojo_url: str = Form(..., description="DefectDojo URL (e.g., http://localhost:8080)"),
    defectdojo_api_token: str = Form(..., description="DefectDojo API token"),
    test_id: int = Form(None, description="Existing Test ID for reimport"),
    product_name: str = Form(None, description="Product name (for auto-create)"),
    engagement_name: str = Form(None, description="Engagement name (for auto-create)"),
    test_title: str = Form(None, description="Test title (for auto-create)")
):
    """
    Import scan file into DefectDojo using YAML configuration.

    This is the main endpoint that orchestrates the full import process:
    1. Validate YAML configuration
    2. Parse scan file according to YAML
    3. Normalize findings to DefectDojo format
    4. Send to DefectDojo API

    Args:
        scan_file: Security scan report (JSON/XML/CSV)
        yaml_file: YAML parser configuration
        defectdojo_url: DefectDojo instance URL
        defectdojo_api_token: API authentication token
        test_id: Existing test ID (for reimport)
        product_name: Product name (for auto-create)
        engagement_name: Engagement name (for auto-create)
        test_title: Test title (for auto-create)

    Returns:
        dict: Import results with statistics

    Raises:
        HTTPException: If validation or import fails

    Example:
        curl -X POST http://localhost:8000/api/import \\
          -F "scan_file=@acunetix_scan.json" \\
          -F "yaml_file=@acunetix360_json.yaml" \\
          -F "defectdojo_url=http://localhost:8080" \\
          -F "defectdojo_api_token=your_token_here" \\
          -F "test_id=123"
    """
    logger.info(f"Import request received: scan_file={scan_file.filename}, yaml_file={yaml_file.filename}")

    try:
        # Step 1: Validate YAML configuration
        logger.info("Step 1: Validating YAML configuration")
        yaml_content = await yaml_file.read()
        yaml_str = yaml_content.decode('utf-8')

        config, checksum = YAMLValidator.validate_with_checksum(yaml_str)
        logger.info(f"YAML validation successful: {config.parser_name} v{config.parser_version}")

        # Step 2: Validate test selection (test_id OR product_name+engagement_name required)
        logger.info("Step 2: Validating test selection")
        if not test_id and not (product_name and engagement_name):
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "Invalid Request",
                    "message": "Either 'test_id' or both 'product_name' and 'engagement_name' must be provided",
                    "type": "validation_error"
                }
            )

        # Step 3: Read scan file
        logger.info("Step 3: Reading scan file")
        scan_content = await scan_file.read()

        # TODO: Step 4: Parse scan file (will implement in Day 2)
        logger.warning("Step 4: Parsing not yet implemented - returning stub response")

        # TODO: Step 5: Normalize findings (will implement in Day 3)
        logger.warning("Step 5: Normalization not yet implemented")

        # TODO: Step 6: Send to DefectDojo API (will implement in Day 6)
        logger.warning("Step 6: DefectDojo API integration not yet implemented")

        # Return stub response for now
        return {
            "status": "success",
            "message": "Import completed successfully (STUB IMPLEMENTATION)",
            "config": {
                "parser_name": config.parser_name,
                "parser_version": config.parser_version,
                "tool_type": config.tool_type,
                "yaml_checksum": checksum
            },
            "scan_file": {
                "filename": scan_file.filename,
                "size_bytes": len(scan_content)
            },
            "defectdojo": {
                "url": defectdojo_url,
                "test_id": test_id,
                "product_name": product_name,
                "engagement_name": engagement_name
            },
            "results": {
                "findings_parsed": 0,  # TODO: Implement
                "findings_created": 0,  # TODO: Implement
                "findings_updated": 0,  # TODO: Implement
                "findings_closed": 0   # TODO: Implement
            },
            "note": "This is a stub response. Full implementation in progress."
        }

    except YAMLValidationError as e:
        logger.warning(f"YAML validation failed: {str(e)}")
        raise HTTPException(
            status_code=400,
            detail=YAMLValidator.format_validation_errors(e)
        )
    except HTTPException:
        # Re-raise HTTP exceptions without modification
        raise
    except Exception as e:
        logger.error(f"Unexpected error during import: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Internal Server Error",
                "message": f"An unexpected error occurred: {str(e)}",
                "type": "internal_error"
            }
        )


# Exception handlers
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Global exception handler for unhandled errors.

    Logs the error and returns a generic 500 response.
    """
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred",
            "type": "internal_error"
        }
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,  # Enable hot-reload for development
        log_level="info"
    )
