"""
CSV file format reader.

Parses CSV files and extracts findings using column names or indices.
Supports various delimiter formats and header configurations.
"""

import csv
import io
import logging
from typing import Optional

from app.parsers.base import FileFormatReader
from app.utils.errors import FileFormatError

logger = logging.getLogger(__name__)


class CSVReader(FileFormatReader):
    """
    Reads and parses CSV scan files.

    Supports:
    - Configurable delimiter (comma, tab, pipe, semicolon, etc.)
    - Header row detection/configuration
    - Column-name based extraction (when headers present)
    - Column-index based extraction (using _col_N syntax)
    - Skip rows for report headers
    - Quote character handling
    - Various file encodings
    """

    # Common delimiters for auto-detection
    COMMON_DELIMITERS = [',', '\t', ';', '|']

    def read(self, file_content: bytes, config: dict) -> list[dict]:
        """
        Read CSV file and extract findings as dictionaries.

        Args:
            file_content: Raw CSV file content as bytes
            config: Configuration dict with:
                - csv_delimiter: Delimiter character (default: auto-detect)
                - csv_has_header: Whether file has header row (default: True)
                - csv_skip_rows: Number of rows to skip before header (default: 0)
                - csv_quote_char: Quote character (default: ")
                - file_encoding: File encoding (default: utf-8)

        Returns:
            List of finding dictionaries (keyed by column name or _col_N)

        Raises:
            FileFormatError: If CSV cannot be parsed

        Example:
            >>> config = {"csv_delimiter": ",", "csv_has_header": True}
            >>> csv_bytes = b"id,severity\\nCVE-2021-1234,High"
            >>> reader = CSVReader()
            >>> findings = reader.read(csv_bytes, config)
            >>> findings[0]["id"]
            'CVE-2021-1234'
        """
        # Get encoding from config
        encoding = config.get('file_encoding', 'utf-8')

        # Decode bytes to string
        try:
            csv_str = file_content.decode(encoding)
        except UnicodeDecodeError as e:
            # Try common fallback encodings
            for fallback_encoding in ['utf-8-sig', 'latin-1', 'cp1252']:
                try:
                    csv_str = file_content.decode(fallback_encoding)
                    logger.warning(
                        f"Failed to decode as {encoding}, "
                        f"using fallback encoding: {fallback_encoding}"
                    )
                    break
                except UnicodeDecodeError:
                    continue
            else:
                raise FileFormatError(
                    f"Failed to decode CSV file: {str(e)}\n"
                    f"Tried encodings: {encoding}, utf-8-sig, latin-1, cp1252"
                )

        # Get configuration options
        delimiter = config.get('csv_delimiter')
        has_header = config.get('csv_has_header', True)
        skip_rows = config.get('csv_skip_rows', 0) or 0
        quote_char = config.get('csv_quote_char', '"')

        # Skip leading rows if specified
        lines = csv_str.splitlines(keepends=True)
        if skip_rows > 0:
            if skip_rows >= len(lines):
                raise FileFormatError(
                    f"csv_skip_rows ({skip_rows}) exceeds total lines ({len(lines)})"
                )
            csv_str = ''.join(lines[skip_rows:])
            logger.info(f"Skipped {skip_rows} header rows")

        # Auto-detect delimiter if not specified
        if not delimiter:
            delimiter = self._detect_delimiter(csv_str)
            logger.info(f"Auto-detected CSV delimiter: {repr(delimiter)}")

        # Parse CSV
        try:
            findings = self._parse_csv(
                csv_str,
                delimiter=delimiter,
                has_header=has_header,
                quote_char=quote_char
            )
        except csv.Error as e:
            raise FileFormatError(f"CSV parsing error: {str(e)}")

        if not findings:
            raise FileFormatError(
                "No data rows found in CSV file.\n"
                "Check csv_skip_rows and csv_has_header settings."
            )

        logger.info(f"Extracted {len(findings)} findings from CSV file")
        return findings

    def _detect_delimiter(self, csv_str: str) -> str:
        """
        Auto-detect CSV delimiter from file content.

        Uses csv.Sniffer if possible, falls back to frequency analysis.

        Args:
            csv_str: CSV content as string

        Returns:
            Detected delimiter character
        """
        # Try csv.Sniffer first
        try:
            # Use first few lines for detection
            sample = '\n'.join(csv_str.splitlines()[:10])
            dialect = csv.Sniffer().sniff(sample, delimiters=''.join(self.COMMON_DELIMITERS))
            return dialect.delimiter
        except csv.Error:
            pass

        # Fallback: count delimiter occurrences in first line
        first_line = csv_str.splitlines()[0] if csv_str.splitlines() else ""
        counts = {d: first_line.count(d) for d in self.COMMON_DELIMITERS}

        # Return delimiter with highest count (minimum 1)
        best_delimiter = max(counts, key=counts.get)
        if counts[best_delimiter] > 0:
            return best_delimiter

        # Default to comma
        return ','

    def _parse_csv(
        self,
        csv_str: str,
        delimiter: str,
        has_header: bool,
        quote_char: str
    ) -> list[dict]:
        """
        Parse CSV string into list of dictionaries.

        Args:
            csv_str: CSV content as string
            delimiter: Field delimiter character
            has_header: Whether first row is header
            quote_char: Quote character for fields

        Returns:
            List of dictionaries (one per row)
        """
        # Create CSV reader
        reader = csv.reader(
            io.StringIO(csv_str),
            delimiter=delimiter,
            quotechar=quote_char,
            skipinitialspace=True
        )

        rows = list(reader)
        if not rows:
            return []

        findings = []

        if has_header:
            # Use first row as header
            header = rows[0]
            # Clean header names (strip whitespace, handle empty)
            header = [
                col.strip() if col.strip() else f"_col_{i}"
                for i, col in enumerate(header)
            ]

            for row_idx, row in enumerate(rows[1:], start=2):
                finding = self._row_to_dict(row, header, row_idx)
                if finding:  # Skip empty rows
                    findings.append(finding)
        else:
            # No header - use column indices
            for row_idx, row in enumerate(rows, start=1):
                header = [f"_col_{i}" for i in range(len(row))]
                finding = self._row_to_dict(row, header, row_idx)
                if finding:  # Skip empty rows
                    findings.append(finding)

        return findings

    def _row_to_dict(
        self,
        row: list[str],
        header: list[str],
        row_idx: int
    ) -> Optional[dict]:
        """
        Convert CSV row to dictionary.

        Args:
            row: List of cell values
            header: List of column names
            row_idx: Row number (for error messages)

        Returns:
            Dictionary mapping column names to values, or None if empty row
        """
        # Skip completely empty rows
        if not any(cell.strip() for cell in row):
            return None

        finding = {}

        # Map columns to values
        for i, col_name in enumerate(header):
            if i < len(row):
                value = row[i].strip()
                finding[col_name] = value
            else:
                # Row has fewer columns than header
                finding[col_name] = ""

        # Also add indexed access for all columns
        for i, value in enumerate(row):
            finding[f"_col_{i}"] = value.strip()

        # Add row number for debugging
        finding["_row_number"] = row_idx

        return finding

    def get_column_names(self, file_content: bytes, config: dict) -> list[str]:
        """
        Extract column names from CSV file.

        Useful for discovering available fields when creating YAML configs.

        Args:
            file_content: Raw CSV file content
            config: Configuration dict

        Returns:
            List of column names

        Raises:
            FileFormatError: If CSV cannot be parsed
        """
        encoding = config.get('file_encoding', 'utf-8')
        skip_rows = config.get('csv_skip_rows', 0) or 0
        delimiter = config.get('csv_delimiter')

        try:
            csv_str = file_content.decode(encoding)
        except UnicodeDecodeError:
            csv_str = file_content.decode('latin-1')

        # Skip leading rows
        lines = csv_str.splitlines()
        if skip_rows > 0:
            lines = lines[skip_rows:]

        if not lines:
            return []

        # Auto-detect delimiter if needed
        if not delimiter:
            delimiter = self._detect_delimiter('\n'.join(lines[:5]))

        # Parse first line as header
        reader = csv.reader(io.StringIO(lines[0]), delimiter=delimiter)
        header = next(reader, [])

        # Clean and return header
        return [col.strip() for col in header if col.strip()]

    @staticmethod
    def validate_csv_syntax(csv_bytes: bytes, encoding: str = 'utf-8') -> tuple[bool, str]:
        """
        Validate CSV syntax.

        Args:
            csv_bytes: CSV content as bytes
            encoding: File encoding

        Returns:
            Tuple of (is_valid, error_message)

        Example:
            >>> valid, error = CSVReader.validate_csv_syntax(b'a,b\\n1,2')
            >>> valid
            True
        """
        try:
            csv_str = csv_bytes.decode(encoding)
            # Try to parse as CSV
            reader = csv.reader(io.StringIO(csv_str))
            rows = list(reader)
            if not rows:
                return False, "CSV file is empty"
            return True, ""
        except UnicodeDecodeError as e:
            return False, f"Encoding error: {str(e)}"
        except csv.Error as e:
            return False, f"CSV error: {str(e)}"
