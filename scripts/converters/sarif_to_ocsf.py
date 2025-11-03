"""
SARIF to OCSF Converter

Converts SARIF (Static Analysis Results Interchange Format) security findings
to OCSF (Open Cybersecurity Schema Framework) format.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from .base_converter import BaseOCSFConverter

logger = logging.getLogger(__name__)


class SARIFToOCSFConverter(BaseOCSFConverter):
    """
    Converts SARIF format security findings to OCSF format.

    By default, automatically generates finding UIDs using the FindingUIDGenerator
    enrichment with the 'boann' prefix. This can be disabled if downstream implementations
    want to provide their own UID generation logic.

    Examples:
        # Default usage (UID generation enabled with 'boann' prefix)
        converter = SARIFToOCSFConverter()
        ocsf_findings = converter.convert_file('scan.sarif')
        # UIDs: boann:sast:tool:fingerprint-v1:hash...

        # Disable automatic UID generation
        converter = SARIFToOCSFConverter(enable_uid_generation=False)

        # Add custom enrichments alongside default UID generation
        converter = SARIFToOCSFConverter(
            enrichments=[MyEnrichment()]
        )
    """

    # Severity mapping from SARIF level to OCSF
    # SARIF levels: none, note, warning, error
    # OCSF severity IDs: 1=Unknown, 2=Informational, 3=Low, 4=Medium, 5=High, 6=Critical, 7=Fatal, 99=Other
    SEVERITY_MAP = {
        "error": {"id": 5, "name": "High"},
        "warning": {"id": 4, "name": "Medium"},
        "note": {"id": 2, "name": "Informational"},
        "none": {"id": 1, "name": "Unknown"},
    }

    def __init__(
        self,
        enrichments: list | None = None,
        enable_uid_generation: bool = True,
        sdlc_type: str = "sast",
    ):
        """
        Initialize the SARIF to OCSF converter.

        Args:
            enrichments: Additional enrichments to apply (beyond default UID generation)
            enable_uid_generation: If True, automatically generates finding UIDs (default: True)
            sdlc_type: SDLC type for generated UIDs (default: 'sast')
        """
        # Import here to avoid circular dependencies
        import os
        import sys

        sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
        from enrichments import FindingUIDGenerator

        # Build enrichments list
        all_enrichments = []

        # Add default UID generator if enabled
        if enable_uid_generation:
            uid_generator = FindingUIDGenerator(sdlc_type=sdlc_type)
            all_enrichments.append(uid_generator)
            logger.debug(f"UID generation enabled with sdlc_type='{sdlc_type}'")

        # Add user-provided enrichments
        if enrichments:
            all_enrichments.extend(enrichments)

        # Initialize base converter with all enrichments
        super().__init__(enrichments=all_enrichments)

    def convert_file(self, input_path: str) -> list[dict[str, Any]]:
        """
        Convert a SARIF file to OCSF format.

        Args:
            input_path: Path to the SARIF file

        Returns:
            List of OCSF finding dictionaries
        """
        sarif_path_obj = Path(input_path)

        if not sarif_path_obj.exists():
            raise FileNotFoundError(f"SARIF file not found: {input_path}")

        logger.info(f"Converting SARIF file: {input_path}")

        with open(input_path, encoding="utf-8") as f:
            sarif_data = json.load(f)

        ocsf_findings = []

        # Process each run in the SARIF file
        for run in sarif_data.get("runs", []):
            # Extract tool metadata once per run
            tool_metadata = self._extract_tool_metadata(run)
            created_time = self._extract_created_time(run)

            # Build rules lookup for enriching findings
            rules_lookup = self._build_rules_lookup(run)

            # Process each result (finding)
            for result in run.get("results", []):
                try:
                    ocsf_finding = self._convert_result(result, tool_metadata, created_time, rules_lookup)

                    # Apply enrichments
                    ocsf_finding = self.apply_enrichments(ocsf_finding)

                    ocsf_findings.append(ocsf_finding)
                except Exception as e:
                    logger.error(
                        f"Failed to convert SARIF result: {e}",
                        exc_info=logger.isEnabledFor(logging.DEBUG),
                    )

        logger.info(f"Converted {len(ocsf_findings)} findings from SARIF file")
        return ocsf_findings

    def _convert_result(
        self,
        result: dict[str, Any],
        tool_metadata: dict[str, Any],
        created_time: int,
        rules_lookup: dict[str, dict],
    ) -> dict[str, Any]:
        """
        Convert a single SARIF result to an OCSF finding.

        Args:
            result: SARIF result object
            tool_metadata: Tool metadata extracted from the run
            created_time: Finding creation timestamp
            rules_lookup: Dictionary mapping rule IDs to rule objects

        Returns:
            OCSF finding dictionary
        """
        # Extract severity
        severity = self._extract_severity(result)

        # Extract finding info
        finding_info = self._extract_finding_info(result, created_time, rules_lookup)

        # Extract vulnerabilities
        vulnerabilities = self._extract_vulnerabilities(result, rules_lookup)

        # Extract enrichments (fingerprints)
        enrichments = self._extract_enrichments(result)

        # Build OCSF finding
        ocsf_finding = {
            "class_name": self.CLASS_NAME,
            "class_uid": self.CLASS_UID,
            "category_uid": self.CATEGORY_UID,
            "category_name": self.CATEGORY_NAME,
            "activity_id": self.ACTIVITY_ID,
            "activity_name": self.ACTIVITY_NAME,
            "type_uid": self.CLASS_UID * 100 + self.ACTIVITY_ID,  # 200702
            "time": int(datetime.now().timestamp() * 1000),
            "severity_id": severity["id"],
            "severity": severity["name"],
            "metadata": {
                "product": tool_metadata,
                "version": self.OCSF_VERSION,
            },
            "finding_info": finding_info,
        }

        # Add optional fields if present
        if vulnerabilities:
            ocsf_finding["vulnerabilities"] = [vulnerabilities]

        if enrichments:
            ocsf_finding["enrichments"] = enrichments

        return ocsf_finding

    def _extract_tool_metadata(self, run: dict[str, Any]) -> dict[str, Any]:
        """
        Extract tool name and version from SARIF run.

        Args:
            run: SARIF run object

        Returns:
            Dictionary with 'name' and 'version' keys
        """
        tool = run.get("tool", {}).get("driver", {})

        metadata = {
            "name": tool.get("name", "Unknown"),
        }

        # Try semanticVersion first, fallback to version
        version = tool.get("semanticVersion") or tool.get("version")
        if version:
            metadata["version"] = version

        return metadata

    def _extract_created_time(self, run: dict[str, Any]) -> int:
        """
        Extract finding creation time from SARIF run.

        Args:
            run: SARIF run object

        Returns:
            Unix epoch timestamp in milliseconds
        """
        # Try to get from invocations[].startTimeUtc
        invocations = run.get("invocations", [])
        for invocation in invocations:
            start_time = invocation.get("startTimeUtc")
            if start_time:
                try:
                    # Parse ISO 8601 timestamp
                    dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
                    return int(dt.timestamp() * 1000)
                except Exception as e:
                    logger.warning(f"Failed to parse timestamp {start_time}: {e}")

        # Fallback to current time
        return int(datetime.now().timestamp() * 1000)

    def _build_rules_lookup(self, run: dict[str, Any]) -> dict[str, dict]:
        """
        Build a lookup dictionary for rules by ID.

        Args:
            run: SARIF run object

        Returns:
            Dictionary mapping rule IDs to rule objects
        """
        rules_lookup = {}
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])

        for rule in rules:
            rule_id = rule.get("id")
            if rule_id:
                rules_lookup[rule_id] = rule

        return rules_lookup

    def _extract_severity(self, result: dict[str, Any]) -> dict[str, Any]:
        """
        Extract and map SARIF level to OCSF severity.

        Args:
            result: SARIF result object

        Returns:
            Dictionary with 'id' and 'name' keys
        """
        level = result.get("level", "none")
        return self.SEVERITY_MAP.get(level, self.SEVERITY_MAP["none"])

    def _extract_finding_info(
        self, result: dict[str, Any], created_time: int, rules_lookup: dict[str, dict]
    ) -> dict[str, Any]:
        """
        Extract finding_info from SARIF result.

        Args:
            result: SARIF result object
            created_time: Finding creation timestamp
            rules_lookup: Dictionary mapping rule IDs to rule objects

        Returns:
            finding_info dictionary
        """
        rule_id = result.get("ruleId", "Unknown")

        # Build title from ruleId + optional shortDescription
        title = rule_id
        rule = rules_lookup.get(rule_id, {})
        short_desc = rule.get("shortDescription", {}).get("text")
        if short_desc:
            title = f"{rule_id}: {short_desc}"

        # Build description from message.text or snippet.text
        desc = result.get("message", {}).get("text", "")
        if not desc:
            # Try to get from snippet
            locations = result.get("locations", [])
            if locations:
                snippet = locations[0].get("physicalLocation", {}).get("region", {}).get("snippet", {}).get("text")
                if snippet:
                    desc = snippet

        finding_info = {
            "uid": "PLACEHOLDER_UID",  # Will be replaced by FindingUIDGenerator enrichment
            "title": title,
            "desc": desc,
            "created_time": created_time,
        }

        return finding_info

    def _extract_vulnerabilities(self, result: dict[str, Any], rules_lookup: dict[str, dict]) -> dict[str, Any] | None:
        """
        Extract vulnerability information from SARIF result.

        Args:
            result: SARIF result object
            rules_lookup: Dictionary mapping rule IDs to rule objects

        Returns:
            Vulnerability dictionary or None if no relevant data
        """
        vulnerability = {}

        # Extract CWE
        rule_id = result.get("ruleId")

        # Try result.properties.cwe first
        cwe = result.get("properties", {}).get("cwe")

        # Fallback to rule.properties.cwe
        if not cwe and rule_id:
            rule = rules_lookup.get(rule_id, {})
            cwe = rule.get("properties", {}).get("cwe")

        if cwe:
            # Handle multiple CWEs by joining them
            if isinstance(cwe, list):
                cwe = ", ".join(str(c) for c in cwe)
            vulnerability["cwe"] = {"uid": str(cwe)}

        # Extract affected_code
        locations = result.get("locations", [])
        if locations:
            physical_location = locations[0].get("physicalLocation", {})
            artifact_location = physical_location.get("artifactLocation", {})
            region = physical_location.get("region", {})

            file_path = artifact_location.get("uri")
            start_line = region.get("startLine")
            end_line = region.get("endLine")

            if file_path or start_line or end_line:
                affected_code = {}
                if file_path:
                    affected_code["file"] = file_path
                if start_line:
                    affected_code["start_line"] = start_line
                if end_line:
                    affected_code["end_line"] = end_line

                vulnerability["affected_code"] = affected_code

        return vulnerability if vulnerability else None

    def _extract_enrichments(self, result: dict[str, Any]) -> list[dict[str, Any]] | None:
        """
        Extract enrichments (fingerprints) from SARIF result.

        Args:
            result: SARIF result object

        Returns:
            List of enrichment dictionaries or None if no fingerprints
        """
        fingerprints = result.get("fingerprints") or result.get("partialFingerprints")

        if not fingerprints:
            return None

        return [
            {
                "name": "fingerprints",
                "value": "SARIF fingerprints",
                "type": "fingerprints",
                "data": fingerprints,
            }
        ]
