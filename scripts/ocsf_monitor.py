#!/usr/bin/env python3
"""
OCSF File Monitor and Processor

Monitors OCSF files from local or GCS storage, ingests them using OCSFIngestor,
and moves files to processed/ or failed/ folders based on ingestion results.

Storage Backends:
    - local: Monitor local filesystem directory
    - gcs: Monitor Google Cloud Storage bucket

Usage Examples:
    # Local backend - Basic monitoring
    python ocsf_monitor.py \
        --storage-backend local \
        --source-folder /path/to/files/ \
        --processed-folder /path/processed/ \
        --failed-folder /path/failed/

    # Local backend - With custom database schema
    python ocsf_monitor.py \
        --storage-backend local \
        --source-folder /path/to/files/ \
        --processed-folder /path/processed/ \
        --failed-folder /path/failed/ \
        --schema custom_landing

    # GCS backend - Monitor GCS bucket
    python ocsf_monitor.py \
        --storage-backend gcs \
        --gcs-bucket-name my-bucket \
        --gcs-source-folder OCSF_input/todo/ \
        --gcs-processed-folder OCSF_input/processed/ \
        --gcs-failed-folder OCSF_input/failed/ \
        --local-destination-folder /tmp/OCSF/

Arguments:
    Required for all backends:
        --storage-backend    : Storage backend (local or gcs)

    Required for local backend:
        --source-folder      : Directory to monitor for OCSF files
        --processed-folder   : Where to move successfully processed files
        --failed-folder      : Where to move failed files

    Required for GCS backend:
        --gcs-bucket-name       : GCS bucket name to monitor
        --gcs-source-folder     : GCS folder/prefix to monitor for new files
        --gcs-processed-folder  : GCS folder/prefix for successfully processed files
        --gcs-failed-folder     : GCS folder/prefix for failed processed files
        --local-destination-folder : Local directory for temporary file downloads

    Optional:
        --schema             : Database schema name (default: boann_landing)
        --log-level          : Logging level (default: info)

Processing Model:
    1. Scans source (local or GCS) for *.ocsf.json files
    2. For each file:
       a. Downloads (if GCS) or accesses directly (if local)
       b. Ingests using OCSFIngestor
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

# GCS utils will be imported conditionally from helpers
gcs_utils = None

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


def process_gcs_files(args, ingestor, logger):
    """
    Monitors a GCS bucket for new OCSF files and processes them.
    Downloads files, ingests them, then moves in GCS based on results.

    Args:
        args: Parsed command-line arguments
        ingestor: OCSFIngestor instance for ingestion
        logger: Logger instance to use

    Returns:
        bool: True if all files processed successfully, False if any failed
    """
    global gcs_utils

    # Import gcs_utils if not already imported
    if gcs_utils is None:
        try:
            from helpers import gcs_utils as gcs_utils_module

            gcs_utils = gcs_utils_module
        except ImportError:
            logger.error(
                "google-cloud-storage is required for GCS backend. "
                "Install it with: pip install google-cloud-storage"
            )
            return False

    logger.info("\n--- GCS OCSF File Monitor ---")
    logger.info(f"GCS Bucket: '{args.gcs_bucket_name}'")
    logger.info(f"GCS Source folder: '{args.gcs_source_folder}'")
    logger.info(f"GCS Processed folder: '{args.gcs_processed_folder}'")
    logger.info(f"GCS Failed folder: '{args.gcs_failed_folder}'")
    logger.info(f"Local destination: '{args.local_destination_folder}'")

    # Create local directories
    local_input_folder = os.path.join(args.local_destination_folder, "input")
    local_processed_folder = os.path.join(args.local_destination_folder, "processed")
    local_failed_folder = os.path.join(args.local_destination_folder, "failed")
    os.makedirs(local_input_folder, exist_ok=True)
    os.makedirs(local_processed_folder, exist_ok=True)
    os.makedirs(local_failed_folder, exist_ok=True)

    # Initialize GCS client and verify connection
    try:
        gcs_utils.init(args.gcs_bucket_name)
        logger.info(f"Successfully connected to GCS bucket: {args.gcs_bucket_name}")
    except Exception as e:
        logger.error(f"Error initializing GCS client or connecting to bucket: {e}")
        logger.error(
            "Please ensure your GOOGLE_APPLICATION_CREDENTIALS are set or you are running in a GCP environment."
        )
        return False

    # Track failures
    failed_files_count = 0

    # Scan GCS for files
    logger.info(
        f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] Checking for new files in '{args.gcs_source_folder}'..."
    )
    source_blobs = gcs_utils.list_files(args.gcs_source_folder)

    if not source_blobs:
        logger.info("No new files found.")
        return True  # No files is not a failure

    logger.info(f"Found {len(source_blobs)} file(s) to process.")

    # Process each blob
    for blob in source_blobs:
        if shutdown_flag:
            logger.info("Shutdown signal received, stopping processing.")
            failed_files_count += 1
            break

        file_name = os.path.basename(blob.name)
        local_file_path = os.path.join(local_input_folder, file_name)

        logger.info(f"\nProcessing file: '{blob.name}'")

        # 1. Download to local folder
        if not gcs_utils.download(blob, local_file_path):
            logger.error(f"Skipping processing for '{blob.name}' due to download failure.")
            failed_files_count += 1
            # Move to failed if download itself fails
            if not gcs_utils.move_preserving_structure(blob, args.gcs_source_folder, args.gcs_failed_folder):
                logger.error(f"Failed to move '{blob.name}' to failed folder after download failure.")
            continue

        # 2. Ingest file
        ingestion_success = ingestor.ingest_file(local_file_path)

        # 3. Move GCS file based on ingestion outcome
        if ingestion_success:
            logger.info(f"Successfully ingested '{file_name}'. Moving to processed folder.")
            if not gcs_utils.move_preserving_structure(blob, args.gcs_source_folder, args.gcs_processed_folder):
                logger.error(f"Failed to move '{blob.name}' to processed folder.")
                failed_files_count += 1
        else:
            logger.error(f"Failed to ingest '{file_name}'. Moving to failed folder.")
            failed_files_count += 1
            if not gcs_utils.move_preserving_structure(blob, args.gcs_source_folder, args.gcs_failed_folder):
                logger.error(f"Failed to move '{blob.name}' to failed folder.")

    # Report results
    if failed_files_count > 0:
        logger.error(f"\n--- Processing completed with {failed_files_count} failed file(s) ---")
        return False
    else:
        logger.info("\n--- All files processed successfully ---")
        return True


class MonitorCLI(BaseToolCLI):
    """CLI interface for OCSF Monitor."""

    def get_description(self) -> str:
        return "OCSF File Monitor and Processor (supports local and GCS storage backends)"

    def get_epilog(self) -> str:
        return (
            "Examples:\n"
            "  Local: ocsf_monitor.py --storage-backend local --source-folder /path/to/files/ "
            "--processed-folder /path/processed --failed-folder /path/failed\n"
            "  GCS: ocsf_monitor.py --storage-backend gcs --gcs-bucket-name my-bucket "
            "--gcs-source-folder input/ --gcs-processed-folder processed/ --gcs-failed-folder failed/ "
            "--local-destination-folder /tmp/OCSF/"
        )

    def add_arguments(self, parser):
        # Storage backend selection
        parser.add_argument(
            "--storage-backend",
            choices=["local", "gcs"],
            default="local",
            help="Storage backend to use: local filesystem or Google Cloud Storage (default: local)",
        )

        # Local backend arguments
        parser.add_argument("--source-folder", help="Local directory to monitor for OCSF files (required for local)")
        parser.add_argument(
            "--processed-folder",
            help="Directory where successfully processed files will be moved (required for local)",
        )
        parser.add_argument("--failed-folder", help="Directory where failed files will be moved (required for local)")

        # GCS backend arguments
        parser.add_argument("--gcs-bucket-name", help="GCS bucket name to monitor (required for gcs)")
        parser.add_argument(
            "--gcs-source-folder",
            help="GCS folder/prefix to monitor for new files (required for gcs)",
        )
        parser.add_argument(
            "--gcs-processed-folder",
            help="GCS folder/prefix for successfully processed files (required for gcs)",
        )
        parser.add_argument(
            "--gcs-failed-folder",
            help="GCS folder/prefix for failed processed files (required for gcs)",
        )
        parser.add_argument(
            "--local-destination-folder",
            help="Local directory for temporary file downloads from GCS (required for gcs)",
        )

        # Database configuration
        parser.add_argument(
            "--schema",
            type=str,
            default="boann_landing",
            help="Database schema name (default: boann_landing) where findings will be inserted",
        )

    def validate_arguments(self):
        """Validate monitor-specific arguments based on storage backend."""
        if self.args.storage_backend == "local":
            # Validate local backend arguments
            if not self.args.source_folder:
                self.logger.error("Error: --source-folder is required for local backend")
                sys.exit(1)
            if not self.args.processed_folder:
                self.logger.error("Error: --processed-folder is required for local backend")
                sys.exit(1)
            if not self.args.failed_folder:
                self.logger.error("Error: --failed-folder is required for local backend")
                sys.exit(1)

            if not os.path.exists(self.args.source_folder):
                self.logger.error(f"Error: Source folder does not exist: {self.args.source_folder}")
                sys.exit(1)
            if not os.path.isdir(self.args.source_folder):
                self.logger.error(f"Error: Source path is not a directory: {self.args.source_folder}")
                sys.exit(1)

            # Create processed and failed directories if they don't exist
            os.makedirs(self.args.processed_folder, exist_ok=True)
            os.makedirs(self.args.failed_folder, exist_ok=True)

        elif self.args.storage_backend == "gcs":
            # Validate GCS backend arguments
            if not self.args.gcs_bucket_name:
                self.logger.error("Error: --gcs-bucket-name is required for gcs backend")
                sys.exit(1)
            if not self.args.gcs_source_folder:
                self.logger.error("Error: --gcs-source-folder is required for gcs backend")
                sys.exit(1)
            if not self.args.gcs_processed_folder:
                self.logger.error("Error: --gcs-processed-folder is required for gcs backend")
                sys.exit(1)
            if not self.args.gcs_failed_folder:
                self.logger.error("Error: --gcs-failed-folder is required for gcs backend")
                sys.exit(1)
            if not self.args.local_destination_folder:
                self.logger.error("Error: --local-destination-folder is required for gcs backend")
                sys.exit(1)

    def execute(self) -> int:
        """Execute monitor with selected storage backend."""
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

            # Process files based on storage backend
            if self.args.storage_backend == "local":
                success = process_local_files(self.args, ingestor, self.logger)
            elif self.args.storage_backend == "gcs":
                success = process_gcs_files(self.args, ingestor, self.logger)
            else:
                self.logger.error(f"Unknown storage backend: {self.args.storage_backend}")
                return 1

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
