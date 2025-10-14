"""
Custom exception classes for Universal Parser V2.

These provide clear, actionable error messages for users.
"""


class UniversalParserError(Exception):
    """Base exception for all Universal Parser V2 errors"""
    pass


class YAMLValidationError(UniversalParserError):
    """Raised when YAML configuration is invalid"""
    pass


class FileFormatError(UniversalParserError):
    """Raised when scan file format is invalid or cannot be parsed"""
    pass


class FieldExtractionError(UniversalParserError):
    """Raised when a required field cannot be extracted from scan data"""
    pass


class NormalizationError(UniversalParserError):
    """Raised when finding normalization fails"""
    pass


class ValidationError(UniversalParserError):
    """Raised when finding validation fails (missing required fields, etc.)"""
    pass


class SeverityMappingError(UniversalParserError):
    """Raised when severity value cannot be mapped"""
    def __init__(self, unmapped_value: str, available_mappings: dict):
        self.unmapped_value = unmapped_value
        self.available_mappings = available_mappings
        super().__init__(
            f"Severity value '{unmapped_value}' not found in mapping. "
            f"Available mappings: {list(available_mappings.keys())}"
        )


class DefectDojoAPIError(UniversalParserError):
    """Raised when DefectDojo API call fails"""
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(
            f"DefectDojo API error (HTTP {status_code}): {message}"
        )
