"""
Enrichment Plugin Interface

Provides abstract base class for creating OCSF enrichment plugins.
Plugins can add organization-specific metadata to OCSF findings during conversion.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class EnrichmentPlugin(ABC):
    """
    Abstract base class for OCSF finding enrichment plugins.

    Plugins allow adding custom fields to OCSF findings without modifying
    core converter logic. Enrichments can be added to:
    - finding['resources']: Additional resource objects (e.g., product info)
    - finding['enrichments']: Key-value enrichment data (e.g., source type)

    Example:
        class MyEnrichmentPlugin(EnrichmentPlugin):
            def enrich(self, finding: Dict, context: Dict) -> Dict:
                # Add custom enrichment
                if 'enrichments' not in finding:
                    finding['enrichments'] = []

                finding['enrichments'].append({
                    'name': 'my_custom_field',
                    'value': 'my_value',
                    'type': 'custom'
                })
                return finding
    """

    @abstractmethod
    def enrich(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich an OCSF finding with organization-specific metadata.

        Args:
            finding: OCSF finding dictionary to enrich (modified in-place)
                    Contains all metadata including tool info, source file, etc.

        Returns:
            The enriched finding dictionary (same object as input)

        Note:
            Plugins should modify the finding in-place and return it.
            If enrichment fails or is not applicable, return the finding unchanged.
        """
        pass

    def get_name(self) -> str:
        """
        Get the plugin name for logging and debugging.

        Returns:
            Plugin name (defaults to class name)
        """
        return self.__class__.__name__

    def validate_finding(self, finding: Dict[str, Any]) -> bool:
        """
        Validate that the finding has required fields before enrichment.

        Args:
            finding: OCSF finding dictionary

        Returns:
            True if finding is valid for enrichment, False otherwise
        """
        # Basic OCSF validation - check for required top-level fields
        required_fields = ['finding_info', 'metadata']
        return all(field in finding for field in required_fields)
