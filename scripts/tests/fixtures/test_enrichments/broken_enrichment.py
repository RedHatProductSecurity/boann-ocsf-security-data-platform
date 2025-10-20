"""
Broken enrichment that will fail to instantiate.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../../'))
from enrichments import EnrichmentPlugin


class BrokenEnrichment(EnrichmentPlugin):
    """Enrichment that fails to instantiate."""

    def __init__(self, required_param):
        """Initialize with a required parameter (will fail if not provided)."""
        if not required_param:
            raise ValueError("required_param is required")
        self.required_param = required_param

    def enrich(self, finding):
        """This won't be reached in tests."""
        return finding


