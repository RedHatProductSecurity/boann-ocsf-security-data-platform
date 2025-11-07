"""
This enrichment starts with underscore and should be ignored by discovery.
"""

import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "../../../"))
from enrichments import EnrichmentPlugin


class IgnoredEnrichment(EnrichmentPlugin):
    """This should never be discovered."""

    def enrich(self, finding):
        """This should never be called."""
        finding["should_not_exist"] = True
        return finding
