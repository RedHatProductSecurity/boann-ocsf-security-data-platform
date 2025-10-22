"""
Finding UID Generator Enrichment Plugin

Generates stable, unique finding UIDs for OCSF SAST findings.

UID Format: boann:<sdlc-type>:<tool>:<uid-type>:<uid-unique-to-the-tool>

Default Implementation (SAST):
1. Fingerprint-based: Uses latest available SARIF fingerprint (hashed)
2. Hash-based: Generates hash from title, file path, and message

For other SDLC types (pentest, dast, etc.), use the uid_generator parameter
to provide custom UID generation logic.
"""

import logging
import hashlib
import re
from typing import Dict, Any, Optional

from .base import EnrichmentPlugin


logger = logging.getLogger(__name__)


class FindingUIDGenerator(EnrichmentPlugin):
    """
    Enriches OCSF findings with stable, unique finding UIDs.

    Default implementation is for SAST findings using SARIF data.
    For other SDLC types, provide a custom uid_generator function.

    UID Format: boann:<sdlc-type>:<tool>:<uid-type>:<uid-unique-to-the-tool>

    SAST (default implementation):
    - With fingerprints: boann:sast:<tool>:fingerprint:<sha256-hash>
    - Without fingerprints: boann:sast:<tool>:hash:<sha256-hash>

    Examples:
        >>> # SAST (default) - automatic fingerprint/hash-based UID
        >>> enrichment = FindingUIDGenerator(sdlc_type='sast')
        >>> finding = enrichment.enrich(finding)
        >>> finding['finding_info']['uid']
        'boann:sast:snyk:fingerprint:7f3e9c8b2a1d...'

        >>> # Custom SDLC type (e.g., pentest) - provide custom logic
        >>> def pentest_uid_generator(finding):
        ...     # Extract Jira key and return UID suffix
        ...     jira_key = finding.get('jira_key', 'UNKNOWN')
        ...     return f'jira:key:{jira_key}'
        >>> enrichment = FindingUIDGenerator(
        ...     sdlc_type='pentest',
        ...     uid_generator=pentest_uid_generator
        ... )
        >>> # Result: boann:pentest:jira:key:RHEL-12345
    """

    def __init__(
        self,
        sdlc_type: str = 'sast',
        uid_generator: Optional[callable] = None
    ):
        """
        Initialize the UID generator plugin.

        Args:
            sdlc_type: SDLC source type (default: 'sast').
                      For SAST, uses built-in fingerprint/hash-based strategy.
                      For other types (pentest, dast, sar, etc.), must provide uid_generator.
            uid_generator: Custom UID generator function for non-SAST SDLC types.
                          Called with the finding dict, should return the UID suffix
                          (everything after 'boann:<sdlc_type>:').
                          If None, uses default SAST fingerprint/hash strategy.

        Example for custom SDLC type:
            >>> def my_uid_gen(finding):
            ...     tool = finding['metadata']['product']['name'].lower()
            ...     unique_id = finding['custom_id']
            ...     return f'{tool}:id:{unique_id}'
            >>> gen = FindingUIDGenerator(sdlc_type='pentest', uid_generator=my_uid_gen)
        """
        self.sdlc_type = self._normalize_name(sdlc_type)
        self.uid_generator = uid_generator
        self.uid_prefix = 'boann'

    def enrich(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich finding with generated UID.

        Args:
            finding: OCSF finding to enrich

        Returns:
            Enriched finding with updated finding_info.uid
        """
        try:
            # Use custom generator if provided
            if self.uid_generator:
                uid_suffix = self.uid_generator(finding)
                uid = f"{self.uid_prefix}:{self.sdlc_type}:{uid_suffix}"
            else:
                # Use default SAST strategy
                uid = self._generate_sast_uid(finding)

            # Update finding_info.uid
            if 'finding_info' not in finding:
                finding['finding_info'] = {}

            finding['finding_info']['uid'] = uid
            logger.debug(f"Generated UID: {uid}")

        except Exception as e:
            # Only include stack trace if debug logging is enabled
            logger.error(
                f"Failed to generate UID: {e}",
                exc_info=logger.isEnabledFor(logging.DEBUG)
            )
            # Don't fail the enrichment, just log the error
            # The finding will keep its placeholder UID

        return finding

    def _generate_sast_uid(self, finding: Dict[str, Any]) -> str:
        """
        Generate SAST UID using fingerprint or hash-based approach.

        Strategy:
        1. Try fingerprint-based approach (if fingerprints available)
        2. Fallback to hash-based approach

        Version information is stored in enrichments, not in the UID itself,
        to ensure UID stability across future changes to generation logic.

        Args:
            finding: OCSF finding

        Returns:
            Complete UID string
        """
        tool_name = self._extract_tool_name(finding)

        # Try fingerprint-based approach first
        fingerprint_hash = self._try_fingerprint_approach(finding)
        if fingerprint_hash:
            self._add_uid_generation_metadata(finding, method='fingerprint', version='v1')
            return f"{self.uid_prefix}:{self.sdlc_type}:{tool_name}:fingerprint:{fingerprint_hash}"

        # Fallback to hash-based approach
        hash_value = self._hash_based_approach(finding)
        self._add_uid_generation_metadata(finding, method='hash', version='v1')
        return f"{self.uid_prefix}:{self.sdlc_type}:{tool_name}:hash:{hash_value}"

    def _normalize_name(self, name: str) -> str:
        """
        Normalize a name for use in UID components.

        Converts to lowercase and replaces all non-alphanumeric characters
        with hyphens. Collapses consecutive special characters into a single
        hyphen and removes leading/trailing hyphens.

        Args:
            name: Name to normalize

        Returns:
            Normalized name (lowercased, non-alphanumeric chars replaced with hyphens)
        """
        # Normalize: lowercase, replace non-alphanumeric characters with hyphens
        normalized = name.lower()
        normalized = re.sub(r'[^a-z0-9]+', '-', normalized)
        # Remove leading/trailing hyphens
        normalized = normalized.strip('-')

        return normalized

    def _extract_tool_name(self, finding: Dict[str, Any]) -> str:
        """
        Extract and normalize tool name from finding metadata.

        Args:
            finding: OCSF finding

        Returns:
            Normalized tool name
        """
        tool_name = finding.get('metadata', {}).get('product', {}).get('name', 'unknown')
        return self._normalize_name(tool_name)

    def _try_fingerprint_approach(self, finding: Dict[str, Any]) -> Optional[str]:
        """
        Try to generate UID using fingerprint-based approach.

        Strategy:
        1. Find fingerprints in enrichments array
        2. Sort fingerprint keys alphabetically
        3. Select the last (latest) fingerprint
        4. Hash the fingerprint value with SHA-256

        Args:
            finding: OCSF finding

        Returns:
            SHA-256 hash of fingerprint value, or None if no fingerprints available
        """
        # Look for fingerprints in enrichments
        enrichments = finding.get('enrichments', [])

        for enrichment in enrichments:
            if enrichment.get('name') == 'fingerprints':
                fingerprints_data = enrichment.get('data', {})

                if not fingerprints_data:
                    continue

                # Sort fingerprint keys alphabetically and select the last one
                sorted_keys = sorted(fingerprints_data.keys())
                if not sorted_keys:
                    continue

                latest_key = sorted_keys[-1]
                fingerprint_value = fingerprints_data[latest_key]

                # Hash the fingerprint value
                hash_value = self._sha256_hash(str(fingerprint_value))

                logger.debug(f"Using fingerprint key '{latest_key}' (latest of {len(sorted_keys)} available)")
                return hash_value

        return None

    def _hash_based_approach(self, finding: Dict[str, Any]) -> str:
        """
        Generate UID using hash-based approach.

        Extracts hash components and calculates SHA-256 hash.
        Override _extract_hash_components() to customize for different SDLC types.

        Args:
            finding: OCSF finding

        Returns:
            SHA-256 hash of the concatenated components
        """
        # Extract hash components (can be overridden by subclasses)
        hash_components = self._extract_hash_components(finding)

        # Concatenate with newlines
        hash_input = '\n'.join(hash_components)

        # Calculate SHA-256 hash
        hash_value = self._sha256_hash(hash_input)

        logger.debug(f"Generated hash from components: {[c[:30] + '...' if len(c) > 30 else c for c in hash_components]}")

        return hash_value

    def _extract_hash_components(self, finding: Dict[str, Any]) -> list[str]:
        """
        Extract components for hash-based UID generation.

        SAST implementation extracts:
        1. Title: full finding_info.title
        2. File URI: from vulnerabilities[0].affected_code.file
        3. Message Text: from finding_info.desc

        Note: This is SAST-specific. For other SDLC types, use the uid_generator
        parameter instead of overriding this method.

        Args:
            finding: OCSF finding

        Returns:
            List of string components to hash
        """
        components = []

        title = finding.get('finding_info', {}).get('title', '')
        components.append(title)

        file_uri = ''
        vulnerabilities = finding.get('vulnerabilities', [])
        if vulnerabilities:
            affected_code = vulnerabilities[0].get('affected_code', {})
            file_uri = affected_code.get('file', '')

        components.append(file_uri)

        message_text = finding.get('finding_info', {}).get('desc', '')
        components.append(message_text)

        return components

    def _sha256_hash(self, value: str) -> str:
        """
        Calculate SHA-256 hash of a string.

        Args:
            value: String to hash

        Returns:
            Hexadecimal SHA-256 hash
        """
        return hashlib.sha256(value.encode('utf-8')).hexdigest()

    def _add_uid_generation_metadata(
        self,
        finding: Dict[str, Any],
        method: str,
        version: str
    ) -> None:
        """
        Add UID generation metadata to finding enrichments.

        This provides traceability for how the UID was generated without
        coupling the version to the UID itself.

        Args:
            finding: OCSF finding to enrich
            method: Generation method ('fingerprint' or 'hash')
            version: Version of the generation logic
        """
        if 'enrichments' not in finding:
            finding['enrichments'] = []

        # Add uid_generation enrichment
        uid_metadata = {
            'name': 'uid_generation',
            'data': {
                'method': method,
                'version': version,
                'algorithm': 'sha256'
            }
        }

        finding['enrichments'].append(uid_metadata)
        logger.debug(f"Added UID generation metadata: method={method}, version={version}")

    def get_name(self) -> str:
        """Get plugin name."""
        return "FindingUIDGenerator"
