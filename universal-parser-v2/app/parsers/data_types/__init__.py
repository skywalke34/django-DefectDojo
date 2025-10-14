"""Data type parsers for Universal Parser V2."""

from app.parsers.data_types.string_parser import StringParser
from app.parsers.data_types.severity_parser import SeverityParser

__all__ = ['StringParser', 'SeverityParser']

# Registry of available data type parsers
DATA_TYPE_PARSERS = {
    'string': StringParser(),
    'severity': SeverityParser(),
    # Future: 'date': DateParser(),
    # Future: 'integer': IntegerParser(),
    # Future: 'boolean': BooleanParser(),
    # Future: 'cvss': CVSSParser(),
}


def get_parser(data_type: str):
    """
    Get data type parser by name.

    Args:
        data_type: Data type name ('string', 'severity', 'date', etc.)

    Returns:
        DataTypeParser instance

    Raises:
        ValueError: If data type not supported

    Example:
        >>> parser = get_parser('string')
        >>> isinstance(parser, StringParser)
        True
    """
    if data_type not in DATA_TYPE_PARSERS:
        raise ValueError(
            f"Unsupported data type: '{data_type}'. "
            f"Supported types: {list(DATA_TYPE_PARSERS.keys())}"
        )

    return DATA_TYPE_PARSERS[data_type]
