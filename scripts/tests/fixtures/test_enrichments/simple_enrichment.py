"""
Simple test enrichment for unit testing.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../../'))
from enrichments import EnrichmentPlugin


class SimpleEnrichment(EnrichmentPlugin):
    """A simple test enrichment that adds a test field."""

    def enrich(self, finding):
        """Add a simple test enrichment."""
        if 'enrichments' not in finding:
            finding['enrichments'] = []

        finding['enrichments'].append({
            'name': 'test_simple',
            'value': 'simple_value',
            'type': 'test'
        })
        return finding


