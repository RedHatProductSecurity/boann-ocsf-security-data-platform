"""
Base Converter Interface

Provides abstract base class for OCSF converters.
All converters should extend this class to ensure consistency.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
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

    def __init__(self, enrichments: Optional[List[EnrichmentPlugin]] = None):
        """
        Initialize the converter.

        Args:
            enrichments: List of enrichments to apply to findings
        """
        self.enrichments = enrichments or []

    @abstractmethod
    def convert_file(self, input_path: str) -> List[Dict[str, Any]]:
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

    def apply_enrichments(self, finding: Dict[str, Any]) -> Dict[str, Any]:
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

    def save_to_file(self, findings: List[Dict], output_path: str) -> None:
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

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(findings, f, indent=2)
