#!/usr/bin/env python3
"""
Base CLI Classes for OCSF Tools and Converters

Provides base classes that OCSF tool and converter CLI scripts can inherit from
to get consistent argument parsing, logging setup, and error handling.

- BaseToolCLI: General base for all OCSF tools (validators, ingestors, monitors)
- BaseConverterCLI: Specialized base for converter scripts (inherits from BaseToolCLI)
"""

import argparse
import logging
import sys
from abc import ABC, abstractmethod

from converters import BaseOCSFConverter
from enrichment_utils import add_enrichment_arguments, discover_and_load_enrichments


class BaseToolCLI(ABC):
    """
    Abstract base class for OCSF tool CLI scripts.

    This class implements the template method pattern, providing a standard
    workflow for OCSF tools while allowing customization at key points.

    This is a general base class suitable for validators, ingestors, monitors,
    and other OCSF processing tools.

    Usage:
        class MyValidatorCLI(BaseToolCLI):
            def get_description(self) -> str:
                return 'Validate OCSF files against schema'

            def add_arguments(self, parser: argparse.ArgumentParser):
                parser.add_argument('--input-file', required=True)

            def execute(self) -> int:
                # Do validation work
                return 0  # or 1 for failure

        if __name__ == '__main__':
            sys.exit(MyValidatorCLI().run())
    """

    def __init__(self):
        """Initialize the CLI."""
        self.logger: logging.Logger | None = None
        self.args: argparse.Namespace | None = None

    @abstractmethod
    def get_description(self) -> str:
        """
        Get the description for the tool.

        Returns:
            Description string for the ArgumentParser
        """
        pass

    @abstractmethod
    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """
        Add tool-specific arguments to the parser.

        Args:
            parser: ArgumentParser to add arguments to

        Note: --log-level is automatically added by the base class
        """
        pass

    @abstractmethod
    def execute(self) -> int:
        """
        Execute the tool's main logic.

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        pass

    def get_epilog(self) -> str:
        """
        Get the epilog text for help output.

        Returns:
            Epilog string (optional, can be empty)
        """
        return ""

    def setup_logging(self) -> None:
        """
        Set up logging configuration.

        Override this method if you need custom logging configuration.
        """
        from helpers.logging_utils import setup_logging

        setup_logging(self.args.log_level)
        self.logger = logging.getLogger(self.__class__.__name__)

    def validate_arguments(self) -> None:  # noqa: B027
        """
        Validate parsed arguments.

        Override this method to add custom validation logic specific to your tool.
        The base implementation does nothing.

        Raises:
            SystemExit: If validation fails
        """
        pass

    def build_argument_parser(self) -> argparse.ArgumentParser:
        """
        Build the argument parser with all arguments.

        Returns:
            Configured ArgumentParser
        """
        parser = argparse.ArgumentParser(
            description=self.get_description(),
            epilog=self.get_epilog(),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )

        # Add tool-specific arguments (required hook)
        self.add_arguments(parser)

        # Add standard log-level argument
        parser.add_argument(
            "--log-level",
            default="info",
            help="Set the logging level (debug, info, warning, error, critical)",
        )

        return parser

    def run(self) -> int:
        """
        Main entry point for the CLI.

        This implements the template method pattern, calling hooks at key points
        to allow subclasses to customize behavior.

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        try:
            # Build argument parser and parse arguments
            parser = self.build_argument_parser()
            self.args = parser.parse_args()

            # Setup logging
            self.setup_logging()

            # Validate arguments
            self.validate_arguments()

            # Execute tool logic (delegated to subclass)
            return self.execute()

        except KeyboardInterrupt:
            if self.logger:
                self.logger.info("\nInterrupted by user")
            return 1
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error: {e}", exc_info=True)
            else:
                print(f"Error: {e}", file=sys.stderr)
            return 1


class BaseConverterCLI(BaseToolCLI):
    """
    Abstract base class for converter CLI scripts (inherits from BaseToolCLI).

    This class extends BaseToolCLI with converter-specific functionality:
    enrichment handling, output file management, and converter workflows.

    The base class automatically adds the 'output_file' argument - subclasses
    only need to define their input arguments.

    Usage:
        class MySARIFConverterCLI(BaseConverterCLI):
            def get_description(self) -> str:
                return 'Convert SARIF files to OCSF format'

            def get_converter_class(self):
                from converters import SARIFToOCSFConverter
                return SARIFToOCSFConverter

            def add_positional_arguments(self, parser: argparse.ArgumentParser):
                parser.add_argument('input_file', help='Path to input SARIF file')

            def perform_conversion(self, converter):
                self.logger.info(f"Converting {self.args.input_file}")
                return converter.convert_file(self.args.input_file)

        if __name__ == '__main__':
            MySARIFConverterCLI().run()
    """

    @abstractmethod
    def get_converter_class(self):
        """
        Get the converter class to use.

        Returns:
            The converter class (subclass of BaseOCSFConverter)
        """
        pass

    @abstractmethod
    def add_positional_arguments(self, parser: argparse.ArgumentParser) -> None:
        """
        Add converter-specific positional arguments.

        This is where you define the positional arguments for your converter.
        Different converters have different needs - add whatever positional
        arguments your converter requires (input files, API keys, project IDs, etc.).

        NOTE: Do NOT add output_file here - it's automatically added by the base class
        as the last positional argument.

        Args:
            parser: ArgumentParser to add arguments to

        Example (single input file):
            parser.add_argument('input_file', help='Path to input SARIF file')

        Example (multiple inputs):
            parser.add_argument('source_dir', help='Source directory')
            parser.add_argument('config_file', help='Configuration file')

        Example (API-based):
            parser.add_argument('project_key', help='JIRA project key')
        """
        pass

    @abstractmethod
    def perform_conversion(self, converter: BaseOCSFConverter) -> list:
        """
        Perform the conversion using the converter instance.

        This method allows subclasses to control how conversion happens:
        - File-based converters call converter.convert_file(input_file)
        - API-based converters might call converter methods differently

        Args:
            converter: The converter instance to use

        Returns:
            List of OCSF findings

        Example (file-based):
            def perform_conversion(self, converter: BaseOCSFConverter) -> List:
                self.logger.info(f"Converting file {self.args.input_file}")
                return converter.convert_file(self.args.input_file)

        Example (API-based):
            def perform_conversion(self, converter: BaseOCSFConverter) -> List:
                self.logger.info(f"Fetching from API project {self.args.project_key}")
                return converter.convert_from_api(self.args.project_key)
        """
        pass

    def add_converter_arguments(self, parser: argparse.ArgumentParser) -> None:
        """
        Add converter-specific optional arguments to the parser.

        Override this method to add custom arguments specific to your converter.
        The standard arguments (output_file, enrichment args, log-level) are
        already added by the base class.

        Args:
            parser: ArgumentParser to add arguments to
        """
        pass

    def create_converter(self, enrichments: list) -> BaseOCSFConverter:
        """
        Create the converter instance.

        Override this method if you need custom converter initialization logic.

        Args:
            enrichments: List of enrichment plugin instances

        Returns:
            Converter instance
        """
        converter_class = self.get_converter_class()

        if enrichments:
            self.logger.info(f"Initializing {converter_class.__name__} with enrichments")
            return converter_class(enrichments=enrichments)
        else:
            self.logger.info(f"Initializing {converter_class.__name__} (no enrichments)")
            return converter_class()

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """
        Override BaseToolCLI.add_arguments() to add converter-specific arguments.

        This method calls the converter-specific hooks in the right order.
        """
        # Add converter-specific positional arguments (required hook)
        self.add_positional_arguments(parser)

        # Add standard output_file argument (required for all converters)
        parser.add_argument("output_file", help="Path to output OCSF JSON file")

        # Add converter-specific optional arguments (optional hook)
        self.add_converter_arguments(parser)

        # Add standard enrichment arguments
        add_enrichment_arguments(parser)

    def execute(self) -> int:
        """
        Override BaseToolCLI.execute() to perform conversion workflow.

        Returns:
            Exit code (0 for success, 1 for failure)
        """
        # Discover and load enrichments
        enrichments = discover_and_load_enrichments(
            self.args.enrichment_dirs or [], self.args.enrichment_args or [], self.logger
        )

        # Create converter
        converter = self.create_converter(enrichments)

        # Perform conversion (delegated to subclass)
        findings = self.perform_conversion(converter)

        # Save results
        self.logger.info(f"Saving {len(findings)} findings to {self.args.output_file}")
        converter.save_to_file(findings, self.args.output_file)

        # Success
        self.logger.info("Conversion completed successfully")
        if enrichments:
            enrichment_names = ", ".join([e.get_name() for e in enrichments])
            self.logger.info(f"Applied enrichments: {enrichment_names}")

        return 0
