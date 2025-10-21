"""
Another test enrichment for testing multiple enrichments.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../../'))
from enrichments import EnrichmentPlugin


class AnotherEnrichment(EnrichmentPlugin):
    """Another test enrichment."""

    def enrich(self, finding):
        """Add another test enrichment."""
        if 'enrichments' not in finding:
            finding['enrichments'] = []

        finding['enrichments'].append({
            'name': 'test_another',
            'value': 'another_value',
            'type': 'test'
        })
        return finding


