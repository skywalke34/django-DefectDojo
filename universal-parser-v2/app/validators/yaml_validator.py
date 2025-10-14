"""
YAML configuration validator.

Validates YAML parser-as-code configuration files using Pydantic models.
"""

import yaml
from pydantic import ValidationError

from app.models.yaml_config import YAMLConfig
from app.utils.checksum import compute_yaml_checksum
from app.utils.errors import YAMLValidationError


class YAMLValidator:
    """Validates YAML configuration files"""

    @staticmethod
    def validate(yaml_content: str) -> YAMLConfig:
        """
        Validate YAML configuration content.

        Args:
            yaml_content: Raw YAML file content as string

        Returns:
            Validated YAMLConfig object

        Raises:
            YAMLValidationError: If YAML is invalid

        Example:
            >>> yaml_content = '''
            ... parser_name: Test
            ... parser_version: "1.0"
            ... tool_name: Test Tool
            ... tool_type: Test_Tool
            ... file_format: json
            ... json_root_path: "$.items"
            ... field_mappings:
            ...   - source_field: name
            ...     target_field: title
            ...     data_type: string
            ...     active: true
            ... '''
            >>> config = YAMLValidator.validate(yaml_content)
            >>> config.parser_name
            'Test'
        """
        try:
            # Parse YAML
            data = yaml.safe_load(yaml_content)

            if not data:
                raise YAMLValidationError("YAML file is empty")

            if not isinstance(data, dict):
                raise YAMLValidationError("YAML must contain a dictionary at root level")

            # Validate using Pydantic
            config = YAMLConfig(**data)

            return config

        except yaml.YAMLError as e:
            raise YAMLValidationError(
                f"Invalid YAML syntax: {str(e)}"
            )
        except ValidationError as e:
            # Format Pydantic validation errors for user-friendly display
            error_messages = []
            for error in e.errors():
                field_path = ' -> '.join(str(loc) for loc in error['loc'])
                error_messages.append(
                    f"  • {field_path}: {error['msg']}"
                )

            raise YAMLValidationError(
                "YAML configuration validation failed:\n" +
                "\n".join(error_messages)
            )
        except Exception as e:
            raise YAMLValidationError(
                f"Unexpected error validating YAML: {str(e)}"
            )

    @staticmethod
    def validate_with_checksum(yaml_content: str) -> tuple[YAMLConfig, str]:
        """
        Validate YAML and return both config and checksum.

        Args:
            yaml_content: Raw YAML file content as string

        Returns:
            Tuple of (YAMLConfig object, checksum string)

        Raises:
            YAMLValidationError: If YAML is invalid

        Example:
            >>> yaml_content = "parser_name: Test\\n..."
            >>> config, checksum = YAMLValidator.validate_with_checksum(yaml_content)
            >>> checksum.startswith("sha256:")
            True
        """
        config = YAMLValidator.validate(yaml_content)
        checksum = compute_yaml_checksum(yaml_content)
        return config, checksum

    @staticmethod
    def format_validation_errors(error: YAMLValidationError) -> dict:
        """
        Format validation error for JSON response.

        Args:
            error: YAMLValidationError instance

        Returns:
            Dictionary suitable for JSON response

        Example:
            >>> try:
            ...     YAMLValidator.validate("invalid: [")
            ... except YAMLValidationError as e:
            ...     formatted = YAMLValidator.format_validation_errors(e)
            ...     'error' in formatted
            True
        """
        return {
            "error": "YAML Validation Failed",
            "message": str(error),
            "type": "yaml_validation_error"
        }
