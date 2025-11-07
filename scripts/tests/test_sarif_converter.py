#!/usr/bin/env python3
"""
Unit tests for SARIF to OCSF converter.
"""

import json
import logging
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import pytest

# Add parent directory to path to import the module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import enrichment_utils
from converters import SARIFToOCSFConverter


# Pytest fixtures for converter tests
@pytest.fixture
def converter():
    """Provide a SARIF converter instance."""
    return SARIFToOCSFConverter()


class TestSARIFConverterMethods:
    """Unit tests for individual SARIF converter methods (pytest style)."""

    @pytest.mark.parametrize(
        "level,expected_id,expected_name",
        [
            ("error", 5, "High"),
            ("warning", 4, "Medium"),
            ("note", 2, "Informational"),
            ("none", 1, "Unknown"),
            (None, 1, "Unknown"),  # Missing level defaults to Unknown
        ],
    )
    def test_severity_mapping(self, converter, level, expected_id, expected_name):
        """Test severity mapping for all SARIF levels."""
        result = {"level": level} if level is not None else {}
        severity = converter._extract_severity(result)
        assert severity["id"] == expected_id
        assert severity["name"] == expected_name

    @pytest.mark.parametrize(
        "scenario,run,expected_metadata",
        [
            (
                "complete_with_semantic_version",
                {"tool": {"driver": {"name": "csmock", "semanticVersion": "3.5.0"}}},
                {"name": "csmock", "version": "3.5.0"},
            ),
            (
                "fallback_to_version_field",
                {"tool": {"driver": {"name": "TestTool", "version": "1.2.3"}}},
                {"name": "TestTool", "version": "1.2.3"},
            ),
            ("missing_version", {"tool": {"driver": {"name": "TestTool"}}}, {"name": "TestTool"}),
            ("missing_name_defaults_to_unknown", {"tool": {"driver": {}}}, {"name": "Unknown"}),
        ],
    )
    def test_extract_tool_metadata(self, converter, scenario, run, expected_metadata):
        """Test tool metadata extraction with various scenarios."""
        metadata = converter._extract_tool_metadata(run)
        assert metadata == expected_metadata

    def test_extract_finding_info_basic(self, converter):
        """Test basic finding info extraction."""
        result = {"ruleId": "CWE-457", "message": {"text": "Using uninitialized value"}}
        finding_info = converter._extract_finding_info(result, 1234567890000, {})

        assert finding_info["uid"] == "PLACEHOLDER_UID"
        assert finding_info["title"] == "CWE-457"
        assert finding_info["desc"] == "Using uninitialized value"
        assert finding_info["created_time"] == 1234567890000

    def test_extract_finding_info_with_rule_description(self, converter):
        """Test finding info extraction with rule shortDescription."""
        result = {"ruleId": "CWE-457", "message": {"text": "Using uninitialized value"}}
        rules_lookup = {"CWE-457": {"shortDescription": {"text": "Use of uninitialized variable"}}}
        finding_info = converter._extract_finding_info(result, 1234567890000, rules_lookup)

        assert finding_info["title"] == "CWE-457: Use of uninitialized variable"

    def test_extract_finding_info_fallback_to_snippet(self, converter):
        """Test finding info extraction falls back to snippet for description."""
        result = {
            "ruleId": "TEST-001",
            "message": {},
            "locations": [{"physicalLocation": {"region": {"snippet": {"text": "int x; return x;"}}}}],
        }
        finding_info = converter._extract_finding_info(result, 1234567890000, {})

        assert finding_info["desc"] == "int x; return x;"

    def test_extract_vulnerabilities_with_cwe(self, converter):
        """Test vulnerability extraction with CWE."""
        result = {
            "ruleId": "TEST-001",
            "properties": {"cwe": "CWE-457"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/main.c"},
                        "region": {"startLine": 42, "endLine": 42},
                    }
                }
            ],
        }
        vulnerability = converter._extract_vulnerabilities(result, {})

        assert vulnerability is not None
        assert vulnerability["cwe"]["uid"] == "CWE-457"
        assert vulnerability["affected_code"]["file"] == "src/main.c"
        assert vulnerability["affected_code"]["start_line"] == 42
        assert vulnerability["affected_code"]["end_line"] == 42

    def test_extract_vulnerabilities_cwe_from_rule(self, converter):
        """Test vulnerability extraction with CWE from rule properties."""
        result = {"ruleId": "TEST-001", "locations": []}
        rules_lookup = {"TEST-001": {"properties": {"cwe": "CWE-789"}}}
        vulnerability = converter._extract_vulnerabilities(result, rules_lookup)

        assert vulnerability is not None
        assert vulnerability["cwe"]["uid"] == "CWE-789"

    def test_extract_vulnerabilities_multiple_cwes(self, converter):
        """Test vulnerability extraction with multiple CWEs (joined)."""
        result = {"ruleId": "TEST-001", "properties": {"cwe": ["CWE-457", "CWE-789"]}}
        vulnerability = converter._extract_vulnerabilities(result, {})

        assert vulnerability is not None
        assert vulnerability["cwe"]["uid"] == "CWE-457, CWE-789"

    def test_extract_vulnerabilities_empty(self, converter):
        """Test vulnerability extraction returns None when no data."""
        result = {"ruleId": "TEST-001"}
        vulnerability = converter._extract_vulnerabilities(result, {})

        assert vulnerability is None

    def test_extract_enrichments_with_fingerprints(self, converter):
        """Test enrichment extraction with fingerprints."""
        result = {
            "fingerprints": {
                "csdiff/v0": "55ebf10003c842e4a2030da5ab067b1d8087cc9a",
                "csdiff/v1": "2fa0ad587f4795fc6c8fb440da205625be0bb095",
            }
        }
        enrichments = converter._extract_enrichments(result)

        assert enrichments is not None
        assert len(enrichments) == 1
        assert enrichments[0]["name"] == "fingerprints"
        assert enrichments[0]["type"] == "fingerprints"
        assert enrichments[0]["value"] == "SARIF fingerprints"
        assert enrichments[0]["data"]["csdiff/v0"] == "55ebf10003c842e4a2030da5ab067b1d8087cc9a"

    def test_extract_enrichments_with_partial_fingerprints(self, converter):
        """Test enrichment extraction with partialFingerprints."""
        result = {"partialFingerprints": {"primaryLocationLineHash": "abc123"}}
        enrichments = converter._extract_enrichments(result)

        assert enrichments is not None
        assert enrichments[0]["name"] == "fingerprints"
        assert enrichments[0]["type"] == "fingerprints"
        assert enrichments[0]["data"]["primaryLocationLineHash"] == "abc123"

    def test_extract_enrichments_none(self, converter):
        """Test enrichment extraction returns None when no fingerprints."""
        result = {}
        enrichments = converter._extract_enrichments(result)

        assert enrichments is None

    def test_build_rules_lookup(self, converter):
        """Test building rules lookup dictionary."""
        run = {
            "tool": {
                "driver": {
                    "rules": [
                        {"id": "RULE-001", "shortDescription": {"text": "Test rule 1"}},
                        {"id": "RULE-002", "shortDescription": {"text": "Test rule 2"}},
                    ]
                }
            }
        }
        lookup = converter._build_rules_lookup(run)

        assert len(lookup) == 2
        assert "RULE-001" in lookup
        assert "RULE-002" in lookup
        assert lookup["RULE-001"]["shortDescription"]["text"] == "Test rule 1"

    def test_class_constants_from_base(self, converter):
        """Test that OCSF constants are inherited from base class."""
        assert converter.CLASS_UID == 2007
        assert converter.CLASS_NAME == "Application Security Posture Finding"
        assert converter.CATEGORY_UID == 2
        assert converter.CATEGORY_NAME == "Findings"
        assert converter.ACTIVITY_ID == 2
        assert converter.ACTIVITY_NAME == "Update"
        assert converter.OCSF_VERSION == "1.5.0"

    def test_convert_file_nonexistent_raises_error(self, converter):
        """Test that converting nonexistent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError) as exc_info:
            converter.convert_file("/nonexistent/path/to/file.sarif")

        assert "not found" in str(exc_info.value)

    def test_extract_created_time_with_invalid_timestamp(self, converter):
        """Test created time extraction with invalid timestamp format."""
        run = {"invocations": [{"startTimeUtc": "invalid-timestamp-format"}]}
        created_time = converter._extract_created_time(run)

        # Should fallback to current time (epoch timestamp in milliseconds)
        assert isinstance(created_time, int)
        assert created_time > 0

    def test_extract_created_time_with_valid_timestamp(self, converter):
        """Test created time extraction with valid ISO 8601 timestamp."""
        run = {"invocations": [{"startTimeUtc": "2024-01-15T10:30:00Z"}]}
        created_time = converter._extract_created_time(run)

        # Verify the timestamp was parsed correctly (epoch in milliseconds)
        assert created_time == 1705314600000

    def test_extract_created_time_fallback_to_current_time(self, converter):
        """Test created time extraction falls back to current time when no invocations."""
        run = {}
        created_time = converter._extract_created_time(run)

        # Should return current time as epoch timestamp in milliseconds
        assert isinstance(created_time, int)
        assert created_time > 0


class TestSARIFIntegration(unittest.TestCase):
    """Integration tests for the full SARIF converter with enrichments."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = Path(__file__).parent / "fixtures" / "test_enrichments"
        self.sarif_file = Path(__file__).parent / "fixtures" / "sample.sarif"
        self.logger = logging.getLogger("test")
        self.logger.setLevel(logging.CRITICAL)

    def test_conversion_without_enrichments(self):
        """Test that conversion works without enrichments."""
        converter = SARIFToOCSFConverter()
        findings = converter.convert_file(str(self.sarif_file))

        self.assertIsInstance(findings, list)
        self.assertGreater(len(findings), 0)
        self.assertIn("finding_info", findings[0])
        self.assertIn("metadata", findings[0])

    def test_conversion_with_enrichments(self):
        """Test conversion with enrichments applied."""
        # Discover and instantiate enrichments
        enrichment_classes = enrichment_utils.discover_enrichments([str(self.test_dir)], self.logger)
        simple_class = [c for c in enrichment_classes if c.__name__ == "SimpleEnrichment"][0]
        enrichments = enrichment_utils.instantiate_enrichments([simple_class], {}, self.logger)

        converter = SARIFToOCSFConverter(enrichments=enrichments)
        findings = converter.convert_file(str(self.sarif_file))

        self.assertGreater(len(findings), 0)
        self.assertIn("enrichments", findings[0])

        # Verify the enrichment was applied
        enrichment_names = [e["name"] for e in findings[0]["enrichments"]]
        self.assertIn("test_simple", enrichment_names)

    def test_conversion_with_multiple_enrichments(self):
        """Test conversion with multiple enrichments applied."""
        # Discover and instantiate multiple enrichments
        enrichment_classes = enrichment_utils.discover_enrichments([str(self.test_dir)], self.logger)
        simple_class = [c for c in enrichment_classes if c.__name__ == "SimpleEnrichment"][0]
        another_class = [c for c in enrichment_classes if c.__name__ == "AnotherEnrichment"][0]

        enrichments = enrichment_utils.instantiate_enrichments([simple_class, another_class], {}, self.logger)

        converter = SARIFToOCSFConverter(enrichments=enrichments)
        findings = converter.convert_file(str(self.sarif_file))

        self.assertGreater(len(findings), 0)
        self.assertIn("enrichments", findings[0])

        # Verify both enrichments were applied
        enrichment_names = [e["name"] for e in findings[0]["enrichments"]]
        self.assertIn("test_simple", enrichment_names)
        self.assertIn("test_another", enrichment_names)

    def test_conversion_with_parametric_enrichment(self):
        """Test conversion with parametric enrichment."""
        # Discover and instantiate parametric enrichment with custom args
        enrichment_classes = enrichment_utils.discover_enrichments([str(self.test_dir)], self.logger)
        parametric_class = [c for c in enrichment_classes if c.__name__ == "ParametricEnrichment"][0]

        enrichments = enrichment_utils.instantiate_enrichments(
            [parametric_class],
            {"ParametricEnrichment": {"param1": "custom1", "param2": "custom2"}},
            self.logger,
        )

        converter = SARIFToOCSFConverter(enrichments=enrichments)
        findings = converter.convert_file(str(self.sarif_file))

        self.assertGreater(len(findings), 0)
        self.assertIn("enrichments", findings[0])

        # Verify the parametric enrichment was applied with custom values
        parametric_enrichment = [e for e in findings[0]["enrichments"] if e["name"] == "test_parametric"][0]
        self.assertEqual(parametric_enrichment["value"], "custom1:custom2")

    def test_save_to_file(self):
        """Test saving findings to a file."""
        converter = SARIFToOCSFConverter()
        findings = converter.convert_file(str(self.sarif_file))

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_file = f.name

        try:
            converter.save_to_file(findings, output_file)

            # Verify file was created and contains valid JSON
            self.assertTrue(Path(output_file).exists())

            with open(output_file) as f:
                loaded_findings = json.load(f)

            self.assertEqual(len(loaded_findings), len(findings))
            self.assertEqual(loaded_findings[0]["finding_info"]["title"], findings[0]["finding_info"]["title"])
        finally:
            # Clean up
            if Path(output_file).exists():
                Path(output_file).unlink()


# CLI Integration Tests
def test_sarif_to_ocsf_cli_no_argument():
    """Test that sarif_to_ocsf.py CLI script runs without argument"""
    # Regression test for the bug where sarif_to_ocsf.py failed with
    # "conflicting option string: --log-level" due to duplicate argument definitions
    # between BaseToolCLI and add_enrichment_arguments()

    # Get path to the sarif_to_ocsf.py script
    script_dir = Path(__file__).parent.parent
    script_path = script_dir / "sarif_to_ocsf.py"

    result = subprocess.run([sys.executable, str(script_path), "--help"], capture_output=True, text=True)

    assert result.returncode == 0


if __name__ == "__main__":
    unittest.main()
