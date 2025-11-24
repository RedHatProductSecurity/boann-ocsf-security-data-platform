"""
Base Converter Interface

Provides abstract base class for OCSF converters.
All converters should extend this class to ensure consistency.
"""

import os
import sys
from abc import ABC, abstractmethod
from typing import Any

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from enrichments.base import EnrichmentPlugin


class BaseOCSFConverter(ABC):
    """
    Abstract base class for OCSF converters.

    All converters must implement the convert_file() method.
    Converters can optionally accept enrichments to extend
    the base OCSF findings with organization-specific metadata.

    Example:
        class MyConverter(BaseOCSFConverter):
            def convert_file(self, input_path: str) -> List[Dict[str, Any]]:
                # Conversion logic here
                findings = []
                # ... parse input and create OCSF findings ...

                # Apply enrichments
                for finding in findings:
                    finding = self.apply_enrichments(finding)

                return findings
    """

    # Common OCSF constants for Application Security Posture Finding
    # These values are consistent across all security finding converters
    CLASS_NAME = "Application Security Posture Finding"
    CLASS_UID = 2007
    CATEGORY_UID = 2
    CATEGORY_NAME = "Findings"
    ACTIVITY_ID = 2  # Update
    ACTIVITY_NAME = "Update"
    OCSF_VERSION = "1.5.0"

    # Default value for unknown/missing fields
    UNKNOWN = "UNKNOWN"

    # OCSF file type_id mapping
    # See: https://schema.ocsf.io/1.5.0/objects/file
    FILE_TYPE_REGULAR = 1  # Regular File
    FILE_TYPE_FOLDER = 2  # Folder
    FILE_TYPE_CHARACTER_DEVICE = 3  # Character Device
    FILE_TYPE_BLOCK_DEVICE = 4  # Block Device
    FILE_TYPE_PIPE = 5  # Local Socket
    FILE_TYPE_SYMBOLIC_LINK = 6  # Symbolic Link
    FILE_TYPE_UNKNOWN = 99  # Unknown

    def __init__(self, enrichments: list[EnrichmentPlugin] | None = None):
        """
        Initialize the converter.

        Args:
            enrichments: List of enrichments to apply to findings
        """
        self.enrichments = enrichments or []

    @abstractmethod
    def convert_file(self, input_path: str) -> list[dict[str, Any]]:
        """
        Convert an input file to OCSF format.

        Args:
            input_path: Path to the input file

        Returns:
            List of OCSF finding dictionaries

        Raises:
            FileNotFoundError: If input file doesn't exist
            ValueError: If input file format is invalid
        """
        pass

    def apply_enrichments(self, finding: dict[str, Any]) -> dict[str, Any]:
        """
        Apply enrichments to a finding.

        Args:
            finding: OCSF finding to enrich

        Returns:
            Enriched finding
        """
        for enrichment in self.enrichments:
            try:
                if enrichment.validate_finding(finding):
                    finding = enrichment.enrich(finding)
            except Exception as e:
                # Log but don't fail - enrichment is optional
                import logging

                logging.error(f"Enrichment {enrichment.get_name()} failed: {e}", exc_info=True)

        return finding

    def save_to_file(self, findings: list[dict], output_path: str) -> None:
        """
        Save OCSF findings to a JSON file.

        Args:
            findings: List of OCSF finding dictionaries
            output_path: Path to save the output file
        """
        import json
        from pathlib import Path

        output_path_obj = Path(output_path)
        output_path_obj.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)
