#!/usr/bin/env python3
"""
Integration tests for SARIF converter with default UID generation.

Tests SARIFToOCSFConverter configuration:
- UID generation enabled by default
- Disabling UID generation
- Custom enrichments alongside default UID generation
"""

import json
import os
import sys
import tempfile

import pytest

# Add parent directory to path to import the module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from converters import SARIFToOCSFConverter


@pytest.fixture
def sarif_data():
    """Create a minimal SARIF file fixture."""
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "TestTool", "version": "1.0.0"}},
                "results": [
                    {
                        "ruleId": "TEST-001",
                        "level": "warning",
                        "message": {"text": "Test finding message"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/test.py"},
                                    "region": {"startLine": 10, "endLine": 12},
                                }
                            }
                        ],
                        "fingerprints": {"0": "abc123", "1": "def456"},
                    }
                ],
            }
        ],
    }


def test_uid_generation_enabled_by_default(sarif_data):
    """Test that SARIFToOCSFConverter has UID generation enabled by default."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
        json.dump(sarif_data, f)
        sarif_path = f.name

    try:
        # Create converter with default settings
        converter = SARIFToOCSFConverter()
        findings = converter.convert_file(sarif_path)

        assert len(findings) == 1
        uid = findings[0]["finding_info"]["uid"]

        # Should have a generated UID, not placeholder
        assert uid != "PLACEHOLDER_UID"
        assert uid.startswith("boann:sast:")

    finally:
        os.unlink(sarif_path)


def test_disable_uid_generation(sarif_data):
    """Test that SARIFToOCSFConverter can disable UID generation."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
        json.dump(sarif_data, f)
        sarif_path = f.name

    try:
        # Create converter with UID generation disabled
        converter = SARIFToOCSFConverter(enable_uid_generation=False)
        findings = converter.convert_file(sarif_path)

        assert len(findings) == 1
        uid = findings[0]["finding_info"]["uid"]

        # Should still have placeholder UID
        assert uid == "PLACEHOLDER_UID"

    finally:
        os.unlink(sarif_path)


def test_custom_enrichments_with_default_uid(sarif_data):
    """Test that SARIFToOCSFConverter integrates custom enrichments with default UID generation."""
    from enrichments import EnrichmentPlugin

    class TestEnrichment(EnrichmentPlugin):
        def enrich(self, finding):
            if "enrichments" not in finding:
                finding["enrichments"] = []
            finding["enrichments"].append({"name": "test_field", "value": "test_value"})
            return finding

    with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
        json.dump(sarif_data, f)
        sarif_path = f.name

    try:
        # Create converter with custom enrichment
        converter = SARIFToOCSFConverter(enrichments=[TestEnrichment()])
        findings = converter.convert_file(sarif_path)

        assert len(findings) == 1
        finding = findings[0]

        # Should have generated UID (from default enrichment)
        uid = finding["finding_info"]["uid"]
        assert uid != "PLACEHOLDER_UID"
        assert uid.startswith("boann:sast:")

        # Should have both SARIF fingerprints and test enrichment
        enrichments = finding.get("enrichments", [])
        enrichment_names = [e["name"] for e in enrichments]
        assert "fingerprints" in enrichment_names
        assert "test_field" in enrichment_names

    finally:
        os.unlink(sarif_path)
