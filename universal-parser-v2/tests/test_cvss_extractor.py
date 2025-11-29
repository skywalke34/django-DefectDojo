"""
Unit tests for CVSS Extractor parser.

Tests:
- Direct vector extraction (Pattern #4)
- Priority chain fallback
- Vector reconstruction from components (Pattern #5)
- CVSS score extraction
- Invalid vector handling
- Integration with normalizer
"""

import pytest

from app.parsers.data_types.cvss_extractor import CVSSExtractorParser


class TestCVSSExtractorParser:
    """Test CVSSExtractorParser"""

    @pytest.fixture
    def parser(self):
        """Create parser instance"""
        return CVSSExtractorParser()

    # ==========================================================================
    # Test 1: Direct Vector Extraction
    # ==========================================================================

    def test_parse_simple_vector_string(self, parser):
        """Test parsing a simple CVSS v3.1 vector string directly"""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        result = parser.parse(vector)

        assert result["cvssv3"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert result["cvssv3_score"] is None  # Score not calculated, only extracted

    def test_parse_cvss_30_vector(self, parser):
        """Test parsing a CVSS v3.0 vector string"""
        vector = "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N"
        result = parser.parse(vector)

        assert result["cvssv3"] == "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N"
        assert result["cvssv3_score"] is None

    def test_parse_vector_with_whitespace(self, parser):
        """Test parsing vector with leading/trailing whitespace"""
        vector = "  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  "
        result = parser.parse(vector)

        assert result["cvssv3"] is not None
        assert "AV:N" in result["cvssv3"]

    # ==========================================================================
    # Test 2: Priority Chain Extraction
    # ==========================================================================

    def test_priority_chain_first_valid_wins(self, parser):
        """Test that first valid CVSS source wins in priority chain"""
        raw_finding = {
            "cvss31": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            "cvss30": {"vector": "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N"}
        }
        config = {
            "cvss_sources": [
                {"path": "cvss31.vector"},
                {"path": "cvss30.vector"}
            ]
        }

        result = parser.parse(raw_finding, config)

        assert result["cvssv3"] is not None
        assert "CVSS:3.1" in result["cvssv3"]  # First source wins

    def test_priority_chain_fallback_when_first_null(self, parser):
        """Test fallback to second source when first is null"""
        raw_finding = {
            "cvss31": {"vector": None},
            "cvss30": {"vector": "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N"}
        }
        config = {
            "cvss_sources": [
                {"path": "cvss31.vector"},
                {"path": "cvss30.vector"}
            ]
        }

        result = parser.parse(raw_finding, config)

        assert result["cvssv3"] is not None
        assert "CVSS:3.0" in result["cvssv3"]  # Falls back to second

    def test_priority_chain_fallback_when_first_missing(self, parser):
        """Test fallback when first source path doesn't exist"""
        raw_finding = {
            "cvss30": {"vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        }
        config = {
            "cvss_sources": [
                {"path": "cvss31.vector"},  # Doesn't exist
                {"path": "cvss30.vector"}
            ]
        }

        result = parser.parse(raw_finding, config)

        assert result["cvssv3"] is not None
        assert "CVSS:3.0" in result["cvssv3"]

    def test_priority_chain_no_valid_sources(self, parser):
        """Test when no valid CVSS sources are found"""
        raw_finding = {
            "cvss31": {"vector": None},
            "cvss30": {"vector": ""}
        }
        config = {
            "cvss_sources": [
                {"path": "cvss31.vector"},
                {"path": "cvss30.vector"}
            ]
        }

        result = parser.parse(raw_finding, config)

        assert result["cvssv3"] is None
        assert result["cvssv3_score"] is None

    # ==========================================================================
    # Test 3: Score Extraction
    # ==========================================================================

    def test_extract_score_from_source(self, parser):
        """Test extracting CVSS score from source field"""
        raw_finding = {
            "cvss": {
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "score": 9.8
            }
        }
        config = {
            "cvss_sources": [
                {"path": "cvss.vector", "score_path": "cvss.score"}
            ]
        }

        result = parser.parse(raw_finding, config)

        assert result["cvssv3"] is not None
        assert result["cvssv3_score"] == 9.8

    def test_extract_score_as_string(self, parser):
        """Test extracting CVSS score when it's a string"""
        raw_finding = {
            "cvss": {
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "score": "7.5"
            }
        }
        config = {
            "cvss_sources": [
                {"path": "cvss.vector", "score_path": "cvss.score"}
            ]
        }

        result = parser.parse(raw_finding, config)

        assert result["cvssv3_score"] == 7.5

    def test_score_validation_range(self, parser):
        """Test that invalid score values are rejected"""
        raw_finding = {
            "cvss": {
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "score": 15.0  # Invalid - above 10.0
            }
        }
        config = {
            "cvss_sources": [
                {"path": "cvss.vector", "score_path": "cvss.score"}
            ]
        }

        result = parser.parse(raw_finding, config)

        assert result["cvssv3"] is not None
        assert result["cvssv3_score"] is None  # Invalid score rejected

    def test_no_score_calculation(self, parser):
        """Test that score is NOT calculated from vector"""
        raw_finding = {
            "cvss": {
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                # No score field - should remain None
            }
        }
        config = {
            "cvss_sources": [
                {"path": "cvss.vector"}  # No score_path
            ]
        }

        result = parser.parse(raw_finding, config)

        assert result["cvssv3"] is not None
        assert result["cvssv3_score"] is None  # Not calculated

    # ==========================================================================
    # Test 4: Vector Reconstruction (Pattern #5)
    # ==========================================================================

    def test_reconstruct_vector_from_components(self, parser):
        """Test reconstructing CVSS vector from individual components"""
        raw_finding = {
            "cvssV3": {
                "attackVector": "NETWORK",
                "attackComplexity": "LOW",
                "privilegesRequired": "NONE",
                "userInteraction": "NONE",
                "scope": "UNCHANGED",
                "confidentialityImpact": "HIGH",
                "integrityImpact": "HIGH",
                "availabilityImpact": "HIGH"
            }
        }
        config = {
            "cvss_reconstruct": {
                "version": "3.1",
                "components": {
                    "attackVector": "cvssV3.attackVector",
                    "attackComplexity": "cvssV3.attackComplexity",
                    "privilegesRequired": "cvssV3.privilegesRequired",
                    "userInteraction": "cvssV3.userInteraction",
                    "scope": "cvssV3.scope",
                    "confidentialityImpact": "cvssV3.confidentialityImpact",
                    "integrityImpact": "cvssV3.integrityImpact",
                    "availabilityImpact": "cvssV3.availabilityImpact"
                }
            }
        }

        result = parser.parse(raw_finding, config)

        assert result["cvssv3"] is not None
        assert "CVSS:3.1" in result["cvssv3"]
        assert "AV:N" in result["cvssv3"]
        assert "AC:L" in result["cvssv3"]
        assert "C:H" in result["cvssv3"]

    def test_reconstruct_with_abbreviations(self, parser):
        """Test reconstruction when source uses single-letter abbreviations"""
        raw_finding = {
            "cvss": {
                "av": "N",
                "ac": "L",
                "pr": "N",
                "ui": "N",
                "s": "U",
                "c": "H",
                "i": "H",
                "a": "H"
            }
        }
        config = {
            "cvss_reconstruct": {
                "version": "3.0",
                "components": {
                    "attackVector": "cvss.av",
                    "attackComplexity": "cvss.ac",
                    "privilegesRequired": "cvss.pr",
                    "userInteraction": "cvss.ui",
                    "scope": "cvss.s",
                    "confidentialityImpact": "cvss.c",
                    "integrityImpact": "cvss.i",
                    "availabilityImpact": "cvss.a"
                }
            }
        }

        result = parser.parse(raw_finding, config)

        assert result["cvssv3"] is not None
        assert "CVSS:3.0" in result["cvssv3"]

    def test_reconstruct_with_score(self, parser):
        """Test reconstruction with score extraction"""
        raw_finding = {
            "cvssV3": {
                "attackVector": "NETWORK",
                "attackComplexity": "LOW",
                "privilegesRequired": "NONE",
                "userInteraction": "NONE",
                "scope": "UNCHANGED",
                "confidentialityImpact": "HIGH",
                "integrityImpact": "HIGH",
                "availabilityImpact": "HIGH",
                "baseScore": 9.8
            }
        }
        config = {
            "cvss_reconstruct": {
                "version": "3.1",
                "components": {
                    "attackVector": "cvssV3.attackVector",
                    "attackComplexity": "cvssV3.attackComplexity",
                    "privilegesRequired": "cvssV3.privilegesRequired",
                    "userInteraction": "cvssV3.userInteraction",
                    "scope": "cvssV3.scope",
                    "confidentialityImpact": "cvssV3.confidentialityImpact",
                    "integrityImpact": "cvssV3.integrityImpact",
                    "availabilityImpact": "cvssV3.availabilityImpact"
                },
                "score_path": "cvssV3.baseScore"
            }
        }

        result = parser.parse(raw_finding, config)

        assert result["cvssv3"] is not None
        assert result["cvssv3_score"] == 9.8

    def test_reconstruct_missing_component(self, parser):
        """Test reconstruction fails gracefully with missing component"""
        raw_finding = {
            "cvssV3": {
                "attackVector": "NETWORK",
                "attackComplexity": "LOW",
                # Missing: privilegesRequired, userInteraction, etc.
            }
        }
        config = {
            "cvss_reconstruct": {
                "version": "3.1",
                "components": {
                    "attackVector": "cvssV3.attackVector",
                    "attackComplexity": "cvssV3.attackComplexity",
                    "privilegesRequired": "cvssV3.privilegesRequired",
                    "userInteraction": "cvssV3.userInteraction",
                    "scope": "cvssV3.scope",
                    "confidentialityImpact": "cvssV3.confidentialityImpact",
                    "integrityImpact": "cvssV3.integrityImpact",
                    "availabilityImpact": "cvssV3.availabilityImpact"
                }
            }
        }

        result = parser.parse(raw_finding, config)

        # Should fail gracefully - missing required components
        assert result["cvssv3"] is None

    # ==========================================================================
    # Test 5: Combined Mode (Sources + Reconstruction Fallback)
    # ==========================================================================

    def test_combined_sources_then_reconstruct(self, parser):
        """Test that sources are tried first, then reconstruction as fallback"""
        raw_finding = {
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvssV3": {
                "attackVector": "LOCAL",
                "attackComplexity": "HIGH",
                # ... other components (won't be used)
            }
        }
        config = {
            "cvss_sources": [
                {"path": "cvss_vector"}
            ],
            "cvss_reconstruct": {
                "version": "3.1",
                "components": {
                    # ... (won't be used since sources found first)
                }
            }
        }

        result = parser.parse(raw_finding, config)

        # Should use sources (AV:N), not reconstruction (would be AV:L)
        assert result["cvssv3"] is not None
        assert "AV:N" in result["cvssv3"]

    def test_combined_fallback_to_reconstruction(self, parser):
        """Test fallback to reconstruction when no sources found"""
        raw_finding = {
            "cvss_vector": None,  # No direct vector
            "cvssV3": {
                "attackVector": "LOCAL",
                "attackComplexity": "HIGH",
                "privilegesRequired": "LOW",
                "userInteraction": "REQUIRED",
                "scope": "CHANGED",
                "confidentialityImpact": "LOW",
                "integrityImpact": "LOW",
                "availabilityImpact": "NONE"
            }
        }
        config = {
            "cvss_sources": [
                {"path": "cvss_vector"}  # Will be null
            ],
            "cvss_reconstruct": {
                "version": "3.1",
                "components": {
                    "attackVector": "cvssV3.attackVector",
                    "attackComplexity": "cvssV3.attackComplexity",
                    "privilegesRequired": "cvssV3.privilegesRequired",
                    "userInteraction": "cvssV3.userInteraction",
                    "scope": "cvssV3.scope",
                    "confidentialityImpact": "cvssV3.confidentialityImpact",
                    "integrityImpact": "cvssV3.integrityImpact",
                    "availabilityImpact": "cvssV3.availabilityImpact"
                }
            }
        }

        result = parser.parse(raw_finding, config)

        # Should use reconstruction
        assert result["cvssv3"] is not None
        assert "AV:L" in result["cvssv3"]

    # ==========================================================================
    # Test 6: Invalid Vectors
    # ==========================================================================

    def test_invalid_vector_string(self, parser):
        """Test handling of invalid CVSS vector string"""
        result = parser.parse("this is not a valid cvss vector")

        assert result["cvssv3"] is None
        assert result["cvssv3_score"] is None

    def test_partial_vector_string(self, parser):
        """Test handling of partial/incomplete vector"""
        result = parser.parse("CVSS:3.1/AV:N/AC:L")  # Missing required components

        # The cvss library may still parse partial vectors
        # but we should handle gracefully either way
        assert result["cvssv3_score"] is None

    def test_empty_string(self, parser):
        """Test handling of empty string"""
        result = parser.parse("")

        assert result["cvssv3"] is None
        assert result["cvssv3_score"] is None

    def test_none_value(self, parser):
        """Test handling of None value"""
        result = parser.parse(None)

        assert result["cvssv3"] is None
        assert result["cvssv3_score"] is None

    def test_wrong_type(self, parser):
        """Test handling of wrong type (not string or dict)"""
        result = parser.parse(12345)

        assert result["cvssv3"] is None
        assert result["cvssv3_score"] is None

    # ==========================================================================
    # Test 7: Static Helper Methods
    # ==========================================================================

    def test_is_valid_cvss_vector_valid(self):
        """Test is_valid_cvss_vector with valid vector"""
        assert CVSSExtractorParser.is_valid_cvss_vector(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        ) is True

    def test_is_valid_cvss_vector_invalid(self):
        """Test is_valid_cvss_vector with invalid vector"""
        assert CVSSExtractorParser.is_valid_cvss_vector("not a vector") is False
        assert CVSSExtractorParser.is_valid_cvss_vector("") is False
        assert CVSSExtractorParser.is_valid_cvss_vector(None) is False

    def test_is_valid_cvss_score_valid(self):
        """Test is_valid_cvss_score with valid scores"""
        assert CVSSExtractorParser.is_valid_cvss_score(0.0) is True
        assert CVSSExtractorParser.is_valid_cvss_score(5.5) is True
        assert CVSSExtractorParser.is_valid_cvss_score(10.0) is True

    def test_is_valid_cvss_score_invalid(self):
        """Test is_valid_cvss_score with invalid scores"""
        assert CVSSExtractorParser.is_valid_cvss_score(-1.0) is False
        assert CVSSExtractorParser.is_valid_cvss_score(10.1) is False
        assert CVSSExtractorParser.is_valid_cvss_score(100) is False


class TestCVSSExtractorYAMLConfig:
    """Test CVSS extractor YAML configuration validation"""

    def test_cvss_extractor_requires_sources_or_reconstruct(self):
        """Test that cvss_extractor requires at least one of cvss_sources or cvss_reconstruct"""
        from app.models.yaml_config import FieldMapping
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            FieldMapping(
                target_field="_cvss",
                data_type="cvss_extractor"
                # Missing both cvss_sources and cvss_reconstruct
            )

        assert "cvss_extractor requires at least one of" in str(exc_info.value)

    def test_cvss_extractor_with_sources_valid(self):
        """Test valid cvss_extractor config with cvss_sources"""
        from app.models.yaml_config import FieldMapping, CVSSSource

        mapping = FieldMapping(
            target_field="_cvss",
            data_type="cvss_extractor",
            cvss_sources=[
                CVSSSource(path="cvss.vector", score_path="cvss.score")
            ]
        )

        assert mapping.data_type == "cvss_extractor"
        assert len(mapping.cvss_sources) == 1
        assert mapping.cvss_sources[0].path == "cvss.vector"

    def test_cvss_extractor_with_reconstruct_valid(self):
        """Test valid cvss_extractor config with cvss_reconstruct"""
        from app.models.yaml_config import FieldMapping, CVSSReconstruct

        mapping = FieldMapping(
            target_field="_cvss",
            data_type="cvss_extractor",
            cvss_reconstruct=CVSSReconstruct(
                version="3.1",
                components={
                    "attackVector": "av",
                    "attackComplexity": "ac",
                    "privilegesRequired": "pr",
                    "userInteraction": "ui",
                    "scope": "s",
                    "confidentialityImpact": "c",
                    "integrityImpact": "i",
                    "availabilityImpact": "a"
                }
            )
        )

        assert mapping.data_type == "cvss_extractor"
        assert mapping.cvss_reconstruct.version == "3.1"

    def test_cvss_reconstruct_invalid_version(self):
        """Test that invalid CVSS version is rejected"""
        from app.models.yaml_config import CVSSReconstruct
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            CVSSReconstruct(
                version="4.0",  # Invalid - only 3.0 and 3.1 supported
                components={"attackVector": "av"}
            )

        assert "CVSS version must be one of" in str(exc_info.value)
