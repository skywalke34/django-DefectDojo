"""
CVSS Extractor data type parser.

Handles CVSS extraction with:
- Multi-source priority extraction (Pattern #4)
- Vector reconstruction from individual components (Pattern #5)
- Dual output: cvssv3 (vector string) and cvssv3_score (float)

Uses the `cvss` library for parsing and validation, the same library
DefectDojo uses for consistency.
"""

import logging
from typing import Any, Dict, List, Optional, Union

from cvss import CVSS3
import cvss.parser

from app.parsers.base import DataTypeParser, FieldExtractor

logger = logging.getLogger(__name__)


class CVSSExtractorParser(DataTypeParser):
    """
    Extracts CVSS data from multiple sources with priority fallback.
    Supports both direct vector extraction and vector reconstruction.

    Returns dict with:
    - cvssv3: Normalized CVSS vector string
    - cvssv3_score: Float score (only if provided by source)

    Note: Score is only extracted if provided by the source data.
    DefectDojo automatically calculates score from the vector, so we
    don't need to calculate it here.
    """

    # CVSS v3 component mappings (Dependency-Check style)
    # Maps full names and abbreviations to single-letter codes
    CVSS_V3_MAPPINGS = {
        "attackVector": {
            "NETWORK": "N", "N": "N",
            "ADJACENT": "A", "ADJACENT_NETWORK": "A", "A": "A",
            "LOCAL": "L", "L": "L",
            "PHYSICAL": "P", "P": "P",
        },
        "attackComplexity": {
            "LOW": "L", "L": "L",
            "HIGH": "H", "H": "H",
        },
        "privilegesRequired": {
            "NONE": "N", "N": "N",
            "LOW": "L", "L": "L",
            "HIGH": "H", "H": "H",
        },
        "userInteraction": {
            "NONE": "N", "N": "N",
            "REQUIRED": "R", "R": "R",
        },
        "scope": {
            "UNCHANGED": "U", "U": "U",
            "CHANGED": "C", "C": "C",
        },
        "confidentialityImpact": {
            "NONE": "N", "N": "N",
            "LOW": "L", "L": "L",
            "HIGH": "H", "H": "H",
        },
        "integrityImpact": {
            "NONE": "N", "N": "N",
            "LOW": "L", "L": "L",
            "HIGH": "H", "H": "H",
        },
        "availabilityImpact": {
            "NONE": "N", "N": "N",
            "LOW": "L", "L": "L",
            "HIGH": "H", "H": "H",
        },
    }

    # CVSS v3 metric abbreviations for vector construction
    CVSS_V3_METRIC_ABBREVS = {
        "attackVector": "AV",
        "attackComplexity": "AC",
        "privilegesRequired": "PR",
        "userInteraction": "UI",
        "scope": "S",
        "confidentialityImpact": "C",
        "integrityImpact": "I",
        "availabilityImpact": "A",
    }

    # Required metrics for a valid CVSS v3 vector
    CVSS_V3_REQUIRED_METRICS = [
        "attackVector",
        "attackComplexity",
        "privilegesRequired",
        "userInteraction",
        "scope",
        "confidentialityImpact",
        "integrityImpact",
        "availabilityImpact",
    ]

    def parse(self, value: Any, config: dict = None) -> Dict[str, Any]:
        """
        Parse CVSS vector string(s) with priority fallback or reconstruct from components.

        Args:
            value: Raw finding dict (entire finding for multi-source extraction)
                   OR single CVSS vector string for simple parsing
            config: Configuration with:
                - cvss_sources: List of {path, score_path} dicts for direct extraction
                - cvss_reconstruct: Dict with version and components for reconstruction

        Returns:
            Dict with:
            - cvssv3: Normalized CVSS vector string (or None if not found)
            - cvssv3_score: Float score if provided by source (or None)

        Examples:
            >>> parser = CVSSExtractorParser()
            >>> # Direct extraction from finding
            >>> config = {"cvss_sources": [{"path": "cvss.vector", "score_path": "cvss.score"}]}
            >>> finding = {"cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8}}
            >>> result = parser.parse(finding, config)
            >>> result["cvssv3"]
            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
            >>> result["cvssv3_score"]
            9.8
        """
        config = config or {}
        result = {"cvssv3": None, "cvssv3_score": None}

        # Handle direct string input (simple mode)
        if isinstance(value, str):
            return self._parse_vector_string(value)

        # Handle dict input (multi-source extraction mode)
        if not isinstance(value, dict):
            logger.warning(f"CVSSExtractor expected dict or string, got {type(value).__name__}")
            return result

        raw_finding = value

        # Mode 1: Try direct vector extraction from sources
        cvss_sources = config.get("cvss_sources", [])
        if cvss_sources:
            extracted = self._extract_from_sources(raw_finding, cvss_sources)
            if extracted.get("cvssv3"):
                return extracted

        # Mode 2: If no vector found, try reconstruction from components
        cvss_reconstruct = config.get("cvss_reconstruct")
        if cvss_reconstruct:
            reconstructed = self._reconstruct_vector(raw_finding, cvss_reconstruct)
            if reconstructed.get("cvssv3"):
                return reconstructed

        # No CVSS data found
        logger.debug("No CVSS data found from sources or reconstruction")
        return result

    def _extract_from_sources(
        self,
        raw_finding: dict,
        cvss_sources: List[dict]
    ) -> Dict[str, Any]:
        """
        Extract CVSS data from priority-ordered sources.

        Tries each source in order until a valid CVSS vector is found.

        Args:
            raw_finding: Raw finding dictionary
            cvss_sources: List of {path, score_path} source definitions

        Returns:
            Dict with cvssv3 and cvssv3_score (if found)
        """
        result = {"cvssv3": None, "cvssv3_score": None}

        for source in cvss_sources:
            vector_path = source.get("path")
            score_path = source.get("score_path")

            if not vector_path:
                continue

            # Extract vector string
            vector_str = FieldExtractor.extract(raw_finding, vector_path, default=None)
            if not vector_str or not isinstance(vector_str, str):
                continue

            vector_str = vector_str.strip()
            if not vector_str:
                continue

            # Parse and validate the vector
            parsed = self._parse_vector_string(vector_str)
            if parsed.get("cvssv3"):
                result["cvssv3"] = parsed["cvssv3"]

                # Extract score from source if path provided (don't calculate)
                if score_path:
                    score_value = FieldExtractor.extract(raw_finding, score_path, default=None)
                    if score_value is not None:
                        result["cvssv3_score"] = self._parse_score(score_value)

                logger.debug(f"CVSS extracted from '{vector_path}': {result['cvssv3']}")
                return result

        return result

    def _reconstruct_vector(
        self,
        raw_finding: dict,
        cvss_reconstruct: dict
    ) -> Dict[str, Any]:
        """
        Reconstruct CVSS vector from individual component fields.

        Follows the Dependency-Check pattern of building the vector string
        from separate metric fields.

        Args:
            raw_finding: Raw finding dictionary
            cvss_reconstruct: Configuration with:
                - version: CVSS version ("3.0" or "3.1")
                - components: Dict mapping metric name to source field path
                - score_path: Optional path to extract score

        Returns:
            Dict with cvssv3 and cvssv3_score (if found)
        """
        result = {"cvssv3": None, "cvssv3_score": None}

        version = cvss_reconstruct.get("version", "3.1")
        components = cvss_reconstruct.get("components", {})
        score_path = cvss_reconstruct.get("score_path")

        if not components:
            logger.warning("cvss_reconstruct has no components defined")
            return result

        # Build vector parts from components
        vector_parts = []
        missing_metrics = []

        for metric_name in self.CVSS_V3_REQUIRED_METRICS:
            field_path = components.get(metric_name)
            if not field_path:
                missing_metrics.append(metric_name)
                continue

            # Extract the metric value
            raw_value = FieldExtractor.extract(raw_finding, field_path, default=None)
            if raw_value is None:
                missing_metrics.append(metric_name)
                continue

            # Convert to string and normalize
            raw_value = str(raw_value).strip().upper()
            if not raw_value:
                missing_metrics.append(metric_name)
                continue

            # Map to single-letter code
            mapping = self.CVSS_V3_MAPPINGS.get(metric_name, {})
            code = mapping.get(raw_value)
            if not code:
                logger.warning(
                    f"Unknown CVSS value '{raw_value}' for metric '{metric_name}'"
                )
                missing_metrics.append(metric_name)
                continue

            # Add to vector parts
            abbrev = self.CVSS_V3_METRIC_ABBREVS[metric_name]
            vector_parts.append(f"{abbrev}:{code}")

        # Check if we have all required metrics
        if missing_metrics:
            logger.debug(
                f"Cannot reconstruct CVSS vector, missing metrics: {missing_metrics}"
            )
            return result

        # Build the full vector string
        vector_str = f"CVSS:{version}/" + "/".join(vector_parts)

        # Validate the reconstructed vector
        parsed = self._parse_vector_string(vector_str)
        if parsed.get("cvssv3"):
            result["cvssv3"] = parsed["cvssv3"]

            # Extract score from source if path provided (don't calculate)
            if score_path:
                score_value = FieldExtractor.extract(raw_finding, score_path, default=None)
                if score_value is not None:
                    result["cvssv3_score"] = self._parse_score(score_value)

            logger.debug(f"CVSS reconstructed: {result['cvssv3']}")

        return result

    def _parse_vector_string(self, vector_str: str) -> Dict[str, Any]:
        """
        Parse and validate a CVSS vector string using the cvss library.

        Args:
            vector_str: CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/...")

        Returns:
            Dict with:
            - cvssv3: Normalized vector string (or None if invalid)
            - cvssv3_score: None (we don't calculate score from vector)
        """
        result = {"cvssv3": None, "cvssv3_score": None}

        if not vector_str or not isinstance(vector_str, str):
            return result

        vector_str = vector_str.strip()
        if not vector_str:
            return result

        try:
            # Use cvss library to parse the vector
            vectors = cvss.parser.parse_cvss_from_text(vector_str)
            if not vectors:
                logger.debug(f"No valid CVSS vector found in '{vector_str}'")
                return result

            # Get the first valid vector
            vector = vectors[0]

            # Only handle CVSS v3 for now
            if isinstance(vector, CVSS3):
                # Get the clean/normalized vector string
                result["cvssv3"] = vector.clean_vector()
                logger.debug(f"Parsed CVSS vector: {result['cvssv3']}")
            else:
                logger.debug(f"Found CVSS vector but not v3: {type(vector).__name__}")

        except Exception as e:
            logger.warning(f"Failed to parse CVSS vector '{vector_str}': {str(e)}")

        return result

    def _parse_score(self, score_value: Any) -> Optional[float]:
        """
        Parse a CVSS score value to float.

        Args:
            score_value: Raw score value (string, int, or float)

        Returns:
            Validated float score (0.0-10.0) or None if invalid
        """
        if score_value is None:
            return None

        try:
            if isinstance(score_value, (int, float)):
                score = float(score_value)
            elif isinstance(score_value, str):
                score = float(score_value.strip())
            else:
                return None

            # Validate CVSS score range
            if 0.0 <= score <= 10.0:
                return round(score, 1)  # CVSS scores are typically 1 decimal place
            else:
                logger.warning(f"CVSS score {score} outside valid range 0.0-10.0")
                return None

        except (ValueError, TypeError) as e:
            logger.warning(f"Failed to parse CVSS score '{score_value}': {str(e)}")
            return None

    @staticmethod
    def is_valid_cvss_vector(vector_str: str) -> bool:
        """
        Check if a string is a valid CVSS v3 vector.

        Args:
            vector_str: String to validate

        Returns:
            True if valid CVSS v3 vector, False otherwise

        Example:
            >>> CVSSExtractorParser.is_valid_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
            True
            >>> CVSSExtractorParser.is_valid_cvss_vector("invalid")
            False
        """
        if not vector_str or not isinstance(vector_str, str):
            return False

        try:
            vectors = cvss.parser.parse_cvss_from_text(vector_str)
            return len(vectors) > 0 and isinstance(vectors[0], CVSS3)
        except Exception:
            return False

    @staticmethod
    def is_valid_cvss_score(score: float) -> bool:
        """
        Check if a float is a valid CVSS score (0.0-10.0).

        Args:
            score: Score to validate

        Returns:
            True if valid CVSS score, False otherwise

        Example:
            >>> CVSSExtractorParser.is_valid_cvss_score(8.5)
            True
            >>> CVSSExtractorParser.is_valid_cvss_score(12.0)
            False
        """
        try:
            return 0.0 <= float(score) <= 10.0
        except (ValueError, TypeError):
            return False
