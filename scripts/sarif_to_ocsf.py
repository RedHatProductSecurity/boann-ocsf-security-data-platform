#!/usr/bin/env python3
"""
SARIF to OCSF Converter Script

Basic converter script that transforms SARIF files to OCSF format.
Community users can extend this with their own enrichments.

Usage:
    python sarif_to_ocsf.py <input.sarif> <output.ocsf.json>

Example:
    python sarif_to_ocsf.py scan_results.sarif findings.ocsf.json

With enrichments:
    python sarif_to_ocsf.py scan.sarif output.json \\
        --enrichment-dir /path/to/enrichments \\
        --enrichment-arg MyEnrichment:param=value
"""

import sys
from pathlib import Path

from base_cli import BaseConverterCLI
from converters import SARIFToOCSFConverter


class SARIFConverterCLI(BaseConverterCLI):
    """CLI for SARIF to OCSF converter."""

    def get_description(self) -> str:
        """Get converter description."""
        return 'Convert SARIF files to OCSF format'

    def get_converter_class(self):
        """Get the SARIF converter class."""
        return SARIFToOCSFConverter

    def get_epilog(self) -> str:
        """Get help epilog."""
        return 'Example: python sarif_to_ocsf.py scan.sarif output.ocsf.json --enrichment-dir ./enrichments'

    def add_positional_arguments(self, parser) -> None:
        """Add SARIF-specific positional arguments."""
        parser.add_argument('input_file', help='Path to input SARIF file')

    def validate_arguments(self) -> None:
        """Validate that the input SARIF file exists."""
        if not Path(self.args.input_file).exists():
            self.logger.error(f"Input file not found: {self.args.input_file}")
            sys.exit(1)

    def perform_conversion(self, converter):
        """Perform file-based conversion."""
        self.logger.info(f"Converting file {self.args.input_file}")
        return converter.convert_file(self.args.input_file)


if __name__ == '__main__':
    SARIFConverterCLI().run()
