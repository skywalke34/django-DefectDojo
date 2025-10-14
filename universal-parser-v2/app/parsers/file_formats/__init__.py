"""File format readers for Universal Parser V2."""

from app.parsers.file_formats.json_reader import JSONReader

__all__ = ['JSONReader']

# Registry of available file format readers
FILE_FORMAT_READERS = {
    'json': JSONReader(),
    # Future: 'xml': XMLReader(),
    # Future: 'csv': CSVReader(),
}


def get_reader(file_format: str):
    """
    Get file format reader by name.

    Args:
        file_format: Format name ('json', 'xml', 'csv')

    Returns:
        FileFormatReader instance

    Raises:
        ValueError: If format not supported

    Example:
        >>> reader = get_reader('json')
        >>> isinstance(reader, JSONReader)
        True
    """
    if file_format not in FILE_FORMAT_READERS:
        raise ValueError(
            f"Unsupported file format: '{file_format}'. "
            f"Supported formats: {list(FILE_FORMAT_READERS.keys())}"
        )

    return FILE_FORMAT_READERS[file_format]
