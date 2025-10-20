"""
OCSF Enrichment System

This module provides the base interface for enriching OCSF findings with
organization-specific metadata. Enrichments allow extending OCSF data without
modifying core converter logic.
"""

from .base import EnrichmentPlugin

__all__ = ['EnrichmentPlugin']
