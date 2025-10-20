"""
Parametric test enrichment for unit testing.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../../'))
from enrichments import EnrichmentPlugin


class ParametricEnrichment(EnrichmentPlugin):
    """Test enrichment that accepts parameters."""

    def __init__(self, param1='default1', param2='default2'):
        """Initialize with parameters."""
        self.param1 = param1
        self.param2 = param2

    def enrich(self, finding):
        """Add parametric enrichment."""
        if 'enrichments' not in finding:
            finding['enrichments'] = []

        finding['enrichments'].append({
            'name': 'test_parametric',
            'value': f"{self.param1}:{self.param2}",
            'type': 'test'
        })
        return finding


