"""
Utility functions for computing checksums of YAML configuration files.

Used for version validation to ensure YAML hasn't changed between imports.
"""

import hashlib


def compute_yaml_checksum(yaml_content: str) -> str:
    """
    Compute SHA256 checksum of YAML content.

    Args:
        yaml_content: YAML file content as string

    Returns:
        Checksum in format "sha256:{hex_digest}"

    Example:
        >>> content = "parser_name: Acunetix\\nparser_version: 1.0"
        >>> checksum = compute_yaml_checksum(content)
        >>> checksum.startswith("sha256:")
        True
    """
    # Normalize line endings to \n
    normalized = yaml_content.replace('\r\n', '\n').replace('\r', '\n')

    # Strip trailing whitespace from each line
    lines = [line.rstrip() for line in normalized.split('\n')]
    normalized = '\n'.join(lines)

    # Compute SHA256 hash
    hash_obj = hashlib.sha256(normalized.encode('utf-8'))
    hex_digest = hash_obj.hexdigest()

    return f"sha256:{hex_digest}"


def verify_yaml_checksum(yaml_content: str, expected_checksum: str) -> bool:
    """
    Verify that YAML content matches the expected checksum.

    Args:
        yaml_content: YAML file content as string
        expected_checksum: Expected checksum in format "sha256:{hex_digest}"

    Returns:
        True if checksums match, False otherwise

    Example:
        >>> content = "test"
        >>> checksum = compute_yaml_checksum(content)
        >>> verify_yaml_checksum(content, checksum)
        True
        >>> verify_yaml_checksum(content, "sha256:invalid")
        False
    """
    actual_checksum = compute_yaml_checksum(yaml_content)
    return actual_checksum == expected_checksum
