"""
Scan Metadata Enrichment

Enriches OCSF findings with scan-level metadata for tracking and grouping.
"""

import logging
from dataclasses import asdict, dataclass
from typing import Any

from .base import EnrichmentPlugin

logger = logging.getLogger(__name__)


@dataclass
class ScanMetadata:
    """
    Metadata about a security scan run.

    This dataclass holds scan-level information that will be added to OCSF
    findings as a single enrichment entry with all properties in the 'data' field.

    Attributes:
        scan_run_id: Unique identifier for a specific scan execution/run.
                     Required field used for idempotent reingestion and
                     proper grouping of findings from the same scan run.
                     Examples: 'semgrep_run_abc123', 'ci_pipeline_12345',
                              'sarif_scan_xyz789'
    """

    scan_run_id: str

    def __post_init__(self):
        """Validate required fields."""
        if not self.scan_run_id:
            raise ValueError("scan_run_id is required and cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        """
        Convert to dictionary for OCSF enrichment data field.

        Only includes non-None values to keep enrichment data clean.

        Returns:
            Dictionary with scan metadata suitable for OCSF enrichment data field
        """
        return {k: v for k, v in asdict(self).items() if v is not None}


class ScanMetadataEnrichment(EnrichmentPlugin):
    """
    Enriches OCSF findings with scan-level metadata for deterministic grouping.

    Adds a single enrichment entry containing all scan metadata in the 'data' field,
    following the OCSF enrichment pattern. This enables deterministic grouping of
    findings from the same scan run regardless of timestamp precision.

    Example enrichment added to finding['enrichments']:
        {
            'name': 'scan_metadata',
            'type': 'custom',
            'value': 'Scan metadata',
            'data': {
                'scan_run_id': 'semgrep_run_abc123'
            }
        }

    Usage:
        metadata = ScanMetadata(scan_run_id='semgrep_run_abc123')
        enrichment = ScanMetadataEnrichment(metadata=metadata)
        finding = enrichment.enrich(finding)
    """

    def __init__(self, metadata: ScanMetadata):
        """
        Initialize the scan metadata enrichment plugin.

        Args:
            metadata: ScanMetadata dataclass containing scan information.
                     At minimum, must have scan_run_id set.

        Raises:
            ValueError: If metadata.scan_run_id is empty or None
        """
        self.metadata = metadata

    def enrich(self, finding: dict[str, Any]) -> dict[str, Any]:
        """
        Enrich finding with scan metadata.

        Adds a single enrichment entry with all scan metadata in the 'data' field.
        Only non-None metadata fields are included.

        Args:
            finding: OCSF finding to enrich

        Returns:
            Enriched finding with scan_metadata added to enrichments array
        """
        if "enrichments" not in finding:
            finding["enrichments"] = []

        finding["enrichments"].append(
            {"name": "scan_metadata", "type": "custom", "value": "Scan metadata", "data": self.metadata.to_dict()}
        )

        logger.debug(f"Added scan_metadata with scan_run_id: {self.metadata.scan_run_id}")

        return finding
