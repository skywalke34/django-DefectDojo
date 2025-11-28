"""Data type parsers for Universal Parser V2."""

from app.parsers.data_types.string_parser import StringParser
from app.parsers.data_types.severity_parser import SeverityParser
from app.parsers.data_types.date_parser import DateParser
from app.parsers.data_types.integer_parser import IntegerParser
from app.parsers.data_types.boolean_parser import BooleanParser
from app.parsers.data_types.float_parser import FloatParser
from app.parsers.data_types.array_parser import ArrayParser
from app.parsers.data_types.template_parser import TemplateParser

__all__ = ['StringParser', 'SeverityParser', 'DateParser', 'IntegerParser', 'BooleanParser', 'FloatParser', 'ArrayParser', 'TemplateParser']

# Registry of available data type parsers
DATA_TYPE_PARSERS = {
    'string': StringParser(),
    'severity': SeverityParser(),
    'date': DateParser(),
    'integer': IntegerParser(),
    'boolean': BooleanParser(),
    'float': FloatParser(),
    'array': ArrayParser(),
    'template': TemplateParser(),
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
