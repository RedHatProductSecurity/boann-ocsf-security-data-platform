"""
Enrichment Discovery Utilities

Provides utility functions for discovering and instantiating enrichment plugins.
Used by converter scripts to enable automatic enrichment discovery.
"""

import argparse
import importlib.util
import inspect
import logging
from pathlib import Path
from typing import Any

from enrichments import EnrichmentPlugin

logger = logging.getLogger(__name__)


def discover_enrichments(enrichment_dirs: list[str], log: logging.Logger = None) -> list[type]:
    """
    Discover enrichment classes from specified directories.

    Args:
        enrichment_dirs: List of directory paths to search for enrichments
        log: Logger instance for logging (uses module logger if None)

    Returns:
        List of enrichment classes that inherit from EnrichmentPlugin
    """
    if log is None:
        log = logger

    enrichment_classes = []

    for enrichment_dir in enrichment_dirs:
        dir_path = Path(enrichment_dir).resolve()

        if not dir_path.exists():
            log.warning(f"Enrichment directory not found: {enrichment_dir}")
            continue

        if not dir_path.is_dir():
            log.warning(f"Enrichment path is not a directory: {enrichment_dir}")
            continue

        log.info(f"Searching for enrichments in: {enrichment_dir}")

        # Find all Python files in the directory (excluding files starting with _)
        python_files = [f for f in dir_path.glob("*.py") if not f.name.startswith("_")]

        for py_file in python_files:
            try:
                # Import the module dynamically
                module_name = py_file.stem
                spec = importlib.util.spec_from_file_location(module_name, py_file)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    import sys

                    sys.modules[module_name] = module
                    spec.loader.exec_module(module)

                    # Find all classes that inherit from EnrichmentPlugin
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if (
                            issubclass(obj, EnrichmentPlugin)
                            and obj is not EnrichmentPlugin
                            and obj not in enrichment_classes
                        ):
                            log.info(f"Discovered enrichment: {name} from {py_file.name}")
                            enrichment_classes.append(obj)

            except Exception as e:
                log.warning(f"Failed to load enrichment from {py_file.name}: {e}")
                continue

    return enrichment_classes


def parse_enrichment_args(enrichment_args: list[str], log: logging.Logger = None) -> dict[str, dict[str, Any]]:
    """
    Parse enrichment arguments from CLI.

    Args:
        enrichment_args: List of argument strings in format "EnrichmentName:arg_name=value"
        log: Logger instance for logging (uses module logger if None)

    Returns:
        Dictionary mapping enrichment class names to their initialization arguments

    Format:
        Simple key=value pairs only. All values are passed as strings.
        For complex types (lists, dicts, etc.), enrichments should handle
        string parsing themselves.

    Example:
        Input:
            ["RHSourceEnrichment:source_type=SAST",
             "RHSourceEnrichment:environment=prod",
             "ProductEnrichment:product_id=12345"]

        Returns:
            {
                "RHSourceEnrichment": {
                    "source_type": "SAST",
                    "environment": "prod"
                },
                "ProductEnrichment": {
                    "product_id": "12345"
                }
            }
    """
    if log is None:
        log = logger

    parsed_args = {}

    for arg_str in enrichment_args:
        try:
            if ":" not in arg_str:
                log.warning(f"Invalid enrichment argument format (missing ':'): {arg_str}")
                continue

            enrichment_name, arg_part = arg_str.split(":", 1)

            if "=" not in arg_part:
                log.warning(f"Invalid enrichment argument format (missing '='): {arg_str}")
                continue

            arg_name, arg_value = arg_part.split("=", 1)

            if enrichment_name not in parsed_args:
                parsed_args[enrichment_name] = {}

            parsed_args[enrichment_name][arg_name] = arg_value
            log.debug(f"Parsed enrichment arg: {enrichment_name}.{arg_name}={arg_value}")

        except Exception as e:
            log.warning(f"Failed to parse enrichment argument '{arg_str}': {e}")
            continue

    return parsed_args


def instantiate_enrichments(
    enrichment_classes: list[type],
    enrichment_args: dict[str, dict[str, Any]],
    log: logging.Logger = None,
) -> list[EnrichmentPlugin]:
    """
    Instantiate enrichment classes with their arguments.

    Args:
        enrichment_classes: List of enrichment classes to instantiate
        enrichment_args: Dictionary of arguments for each enrichment
        log: Logger instance for logging (uses module logger if None)

    Returns:
        List of instantiated enrichment plugin instances
    """
    if log is None:
        log = logger

    enrichments = []

    for enrichment_class in enrichment_classes:
        class_name = enrichment_class.__name__
        args = enrichment_args.get(class_name, {})

        try:
            if args:
                log.info(f"Instantiating {class_name} with args: {args}")
                enrichment = enrichment_class(**args)
            else:
                log.info(f"Instantiating {class_name} with default args")
                enrichment = enrichment_class()

            enrichments.append(enrichment)

        except Exception as e:
            log.error(f"Failed to instantiate enrichment {class_name}: {e}")
            continue

    return enrichments


def discover_and_load_enrichments(
    enrichment_dirs: list[str], enrichment_args: list[str] = None, log: logging.Logger = None
) -> list[EnrichmentPlugin]:
    """
    Convenience function that combines discovery, parsing, and instantiation.

    Args:
        enrichment_dirs: List of directory paths to search for enrichments
        enrichment_args: List of argument strings in format "EnrichmentName:arg_name=value"
        log: Logger instance for logging (uses module logger if None)

    Returns:
        List of instantiated enrichment plugin instances
    """
    if log is None:
        log = logger

    if not enrichment_dirs:
        return []

    # Discover enrichment classes
    log.info("Discovering enrichments from specified directories")
    enrichment_classes = discover_enrichments(enrichment_dirs, log)

    if not enrichment_classes:
        log.warning("No enrichments discovered from specified directories")
        return []

    # Parse arguments
    parsed_args = parse_enrichment_args(enrichment_args or [], log)

    # Instantiate enrichments
    enrichments = instantiate_enrichments(enrichment_classes, parsed_args, log)

    if enrichments:
        log.info(f"Loaded {len(enrichments)} enrichment(s)")

    return enrichments


def add_enrichment_arguments(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """
    Add standard enrichment-related CLI arguments to an ArgumentParser.

    This helper function adds the common enrichment discovery arguments
    that all converter scripts need. Use this to avoid duplicating
    argument definitions across multiple converter CLI scripts.

    Args:
        parser: ArgumentParser instance to add arguments to

    Returns:
        The same parser instance (for chaining)

    Example:
        parser = argparse.ArgumentParser(description='My Converter')
        parser.add_argument('input_file', help='Input file')
        parser.add_argument('output_file', help='Output file')
        add_enrichment_arguments(parser)  # Adds enrichment args
        parser.add_argument('--my-custom-arg', help='Custom arg')
    """
    parser.add_argument(
        "--enrichment-dir",
        action="append",
        dest="enrichment_dirs",
        metavar="DIR",
        help="Directory to search for enrichment plugins (can be specified multiple times)",
    )
    parser.add_argument(
        "--enrichment-arg",
        action="append",
        dest="enrichment_args",
        metavar="NAME:KEY=VALUE",
        help="Argument for enrichment in format EnrichmentName:arg_name=value. "
        "Values are passed as strings. (can be specified multiple times)",
    )

    return parser
