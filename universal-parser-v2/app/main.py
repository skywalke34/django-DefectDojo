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

from datetime import date
from fastapi import FastAPI, File, UploadFile, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import logging

from app.validators.yaml_validator import YAMLValidator
from app.services.normalizer import NormalizerService
from app.clients.defectdojo_client import DefectDojoClient
from app.utils.errors import YAMLValidationError, DefectDojoAPIError, ValidationError

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
    test_title: str = Form(None, description="Test title (for auto-create)"),
    scan_date: str = Form(None, description="Scan date (YYYY-MM-DD, defaults to today)"),
    close_old_findings: bool = Form(True, description="Close findings not in scan"),
    verified: bool = Form(False, description="Mark new findings as verified"),
    active: bool = Form(True, description="Mark new findings as active"),
    version: str = Form(None, description="Version string for the test")
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
        scan_date: Scan date in YYYY-MM-DD format (defaults to today)
        close_old_findings: Close findings not present in scan (default: True)
        verified: Mark new findings as verified (default: False)
        active: Mark new findings as active (default: True)
        version: Version string for the test

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

        # Step 4: Parse and normalize scan file
        logger.info("Step 4: Parsing and normalizing scan file")
        normalizer = NormalizerService(config)
        findings = normalizer.normalize(scan_content)
        logger.info(f"Parsed {len(findings)} findings from scan file")

        # Step 5: Connect to DefectDojo and get/create test
        logger.info("Step 5: Connecting to DefectDojo")
        effective_scan_date = scan_date or date.today().isoformat()

        async with DefectDojoClient(
            base_url=defectdojo_url,
            api_token=defectdojo_api_token
        ) as client:
            # Get or create test if test_id not provided
            if not test_id:
                logger.info("Creating product/engagement/test structure")
                # Create/find product
                product = await client.find_or_create_product(name=product_name)

                # Create/find engagement
                engagement = await client.find_or_create_engagement(
                    product_id=product["id"],
                    name=engagement_name,
                    target_start=effective_scan_date,
                    target_end=effective_scan_date
                )

                # Create/find test
                effective_test_title = test_title or f"{config.tool_name} Scan"
                test = await client.find_or_create_test(
                    engagement_id=engagement["id"],
                    test_type_name=config.tool_type,
                    title=effective_test_title,
                    target_start=effective_scan_date,
                    target_end=effective_scan_date
                )
                test_id = test["id"]
                logger.info(f"Using test ID: {test_id}")

            # Step 6: Send findings to DefectDojo
            logger.info(f"Step 6: Sending {len(findings)} findings to DefectDojo")
            result = await client.universal_parser_v2_reimport(
                test_id=test_id,
                findings=findings,
                scan_date=effective_scan_date,
                close_old_findings=close_old_findings,
                verified=verified,
                active=active,
                version=version
            )

        # Extract import statistics
        import_stats = result.get("test_import_finding_action", {})

        return {
            "status": "success",
            "message": "Import completed successfully",
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
                "findings_parsed": len(findings),
                "findings_created": import_stats.get("created", 0),
                "findings_updated": import_stats.get("updated", 0),
                "findings_closed": import_stats.get("closed", 0),
                "findings_reactivated": import_stats.get("reactivated", 0),
                "findings_untouched": import_stats.get("untouched", 0)
            }
        }

    except YAMLValidationError as e:
        logger.warning(f"YAML validation failed: {str(e)}")
        raise HTTPException(
            status_code=400,
            detail=YAMLValidator.format_validation_errors(e)
        )
    except ValidationError as e:
        logger.warning(f"Validation error: {str(e)}")
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Validation Error",
                "message": str(e),
                "type": "validation_error"
            }
        )
    except DefectDojoAPIError as e:
        logger.error(f"DefectDojo API error: {str(e)}")
        raise HTTPException(
            status_code=502,
            detail={
                "error": "DefectDojo API Error",
                "message": str(e),
                "type": "api_error",
                "status_code": e.status_code
            }
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


@app.post("/api/parse")
async def parse_scan(
    scan_file: UploadFile = File(..., description="Security scan report file"),
    yaml_file: UploadFile = File(..., description="YAML configuration file"),
    limit: int = Form(None, description="Limit number of findings returned (for debugging)")
):
    """
    Parse scan file and return normalized findings without sending to DefectDojo.

    This endpoint is useful for testing YAML configurations and debugging
    field mappings before performing actual imports.

    Args:
        scan_file: Security scan report (JSON/XML/CSV)
        yaml_file: YAML parser configuration
        limit: Optional limit on number of findings to return

    Returns:
        dict: Parsed findings and statistics

    Example:
        curl -X POST http://localhost:8000/api/parse \\
          -F "scan_file=@acunetix_scan.json" \\
          -F "yaml_file=@acunetix360_json.yaml" \\
          -F "limit=5"
    """
    logger.info(f"Parse request received: scan_file={scan_file.filename}, yaml_file={yaml_file.filename}")

    try:
        # Step 1: Validate YAML configuration
        yaml_content = await yaml_file.read()
        yaml_str = yaml_content.decode('utf-8')

        config, checksum = YAMLValidator.validate_with_checksum(yaml_str)
        logger.info(f"YAML validation successful: {config.parser_name}")

        # Step 2: Read and parse scan file
        scan_content = await scan_file.read()
        normalizer = NormalizerService(config)
        findings = normalizer.normalize(scan_content)
        logger.info(f"Parsed {len(findings)} findings")

        # Apply limit if specified
        returned_findings = findings[:limit] if limit else findings

        return {
            "status": "success",
            "config": {
                "parser_name": config.parser_name,
                "parser_version": config.parser_version,
                "tool_name": config.tool_name,
                "tool_type": config.tool_type,
                "file_format": config.file_format,
                "yaml_checksum": checksum
            },
            "scan_file": {
                "filename": scan_file.filename,
                "size_bytes": len(scan_content)
            },
            "statistics": {
                "total_findings": len(findings),
                "returned_findings": len(returned_findings),
                "limited": limit is not None and limit < len(findings)
            },
            "findings": returned_findings
        }

    except YAMLValidationError as e:
        logger.warning(f"YAML validation failed: {str(e)}")
        raise HTTPException(
            status_code=400,
            detail=YAMLValidator.format_validation_errors(e)
        )
    except ValidationError as e:
        logger.warning(f"Validation error: {str(e)}")
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Validation Error",
                "message": str(e),
                "type": "validation_error"
            }
        )
    except Exception as e:
        logger.error(f"Unexpected error during parse: {str(e)}", exc_info=True)
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
