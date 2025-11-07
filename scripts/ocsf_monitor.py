#!/usr/bin/env python3
"""
Local OCSF File Monitor and Processor

Monitors a local directory for new OCSF files, ingests them using OCSFIngestor,
and moves files to processed/ or failed/ folders based on ingestion results.

Usage Examples:
    # Basic monitoring with required arguments
    python ocsf_monitor.py \
        --source-folder /path/to/files/ \
        --processed-folder /path/processed/ \
        --failed-folder /path/failed/

    # With custom database schema
    python ocsf_monitor.py \
        --source-folder /path/to/files/ \
        --processed-folder /path/processed/ \
        --failed-folder /path/failed/ \
        --schema custom_landing

    # With debug logging
    python ocsf_monitor.py \
        --source-folder /path/to/files/ \
        --processed-folder /path/processed/ \
        --failed-folder /path/failed/ \
        --log-level debug

Arguments:
    Required:
        --source-folder      : Directory to monitor for OCSF files
        --processed-folder   : Where to move successfully processed files
        --failed-folder      : Where to move failed files

    Optional:
        --schema             : Database schema name (default: boann_landing)
        --log-level          : Logging level (default: info)

Processing Model:
    1. Scans source folder for *.ocsf.json files
    2. For each file:
       a. Ingests using OCSFIngestor
    3. Moves files to processed/ (success) or failed/ (failure) folders
    4. Next run only processes new files (processed/failed ones are moved)
"""

import os
import shutil
import signal
import sys
import time
from pathlib import Path

# Import the OCSF classes and base CLI
from base_cli import BaseToolCLI
from ingest_raw_ocsf_findings import OCSFIngestor

# Global variables for signal handling
shutdown_flag = False
_logger = None


def signal_handler(signum, frame):
    """Handles SIGINT/SIGTERM for graceful shutdown."""
    global shutdown_flag
    if _logger:
        _logger.info(f"\n--- Signal {signum} received. Initiating graceful shutdown. ---")
    shutdown_flag = True


def process_local_files(args, ingestor, logger):
    """
    Monitors a local directory for new OCSF files and processes them.
    Ingests files, then moves based on results.

    Args:
        args: Parsed command-line arguments
        ingestor: OCSFIngestor instance for ingestion
        logger: Logger instance to use

    Returns:
        bool: True if all files processed successfully, False if any failed
    """
    logger.info("\n--- Local OCSF File Monitor ---")
    logger.info(f"Source folder: '{args.source_folder}'")
    logger.info(f"Processed folder: '{args.processed_folder}'")
    logger.info(f"Failed folder: '{args.failed_folder}'")

    # Scan directory for OCSF files
    logger.info(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] Scanning for OCSF files in '{args.source_folder}'...")

    source_path = Path(args.source_folder)
    if not source_path.exists():
        logger.error(f"Source directory does not exist: {args.source_folder}")
        return False

    # Find all .ocsf.json files in source folder
    ocsf_files = sorted(source_path.glob("*.ocsf.json"))

    if not ocsf_files:
        logger.info("No OCSF files found.")
        return True  # No files is not a failure

    logger.info(f"Found {len(ocsf_files)} file(s) to process.")

    # Track success/failure
    all_successful = True

    # Process each file
    for file_path in ocsf_files:
        if shutdown_flag:
            logger.info("Shutdown signal received, stopping processing.")
            all_successful = False
            break

        file_name = file_path.name
        logger.info(f"\nProcessing file: '{file_name}'")

        # Ingest file
        ingestion_success = ingestor.ingest_file(str(file_path))

        # Move file based on success/failure
        try:
            if ingestion_success:
                dest_path = os.path.join(args.processed_folder, file_name)
                shutil.move(str(file_path), dest_path)
                logger.info(f"Successfully processed '{file_name}' -> {dest_path}")
            else:
                dest_path = os.path.join(args.failed_folder, file_name)
                shutil.move(str(file_path), dest_path)
                logger.error(f"Failed to process '{file_name}' -> {dest_path}")
                all_successful = False
        except Exception as move_error:
            logger.error(f"Error moving file '{file_name}': {move_error}")
            all_successful = False

    return all_successful


class MonitorCLI(BaseToolCLI):
    """CLI interface for OCSF Monitor."""

    def get_description(self) -> str:
        return "Local OCSF File Monitor and Processor"

    def get_epilog(self) -> str:
        return (
            "Example: ocsf_monitor.py --source-folder /path/to/files/ "
            "--processed-folder /path/processed --failed-folder /path/failed"
        )

    def add_arguments(self, parser):
        # Required arguments
        parser.add_argument("--source-folder", required=True, help="Local directory to monitor for OCSF files")
        parser.add_argument(
            "--processed-folder",
            required=True,
            help="Directory where successfully processed files will be moved",
        )
        parser.add_argument("--failed-folder", required=True, help="Directory where failed files will be moved")
        # Database configuration
        parser.add_argument(
            "--schema",
            type=str,
            default="boann_landing",
            help="Database schema name (default: boann_landing) where findings will be inserted",
        )

    def validate_arguments(self):
        """Validate monitor-specific arguments."""
        if not os.path.exists(self.args.source_folder):
            self.logger.error(f"Error: Source folder does not exist: {self.args.source_folder}")
            sys.exit(1)
        if not os.path.isdir(self.args.source_folder):
            self.logger.error(f"Error: Source path is not a directory: {self.args.source_folder}")
            sys.exit(1)

        # Create processed and failed directories if they don't exist
        os.makedirs(self.args.processed_folder, exist_ok=True)
        os.makedirs(self.args.failed_folder, exist_ok=True)

    def execute(self) -> int:
        """Execute monitor."""
        # Set global logger for signal handler
        global _logger
        _logger = self.logger

        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            # Create OCSFIngestor instance
            ingestor = OCSFIngestor(schema=self.args.schema)
            self.logger.info("OCSFIngestor initialized successfully")

            # Process local files
            success = process_local_files(self.args, ingestor, self.logger)

            # Return appropriate exit code
            if not success:
                self.logger.error("\n--- OCSF Monitor completed with failures ---")
                return 1
            else:
                self.logger.info("\n--- OCSF Monitor completed successfully ---")
                return 0

        except Exception as e:
            self.logger.error(f"Failed to initialize monitor: {e}", exc_info=True)
            return 1


if __name__ == "__main__":
    sys.exit(MonitorCLI().run())
