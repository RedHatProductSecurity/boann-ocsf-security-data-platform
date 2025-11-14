#!/usr/bin/env python3
"""
OCSF File Monitor and Processor

Monitors OCSF files from local filesystem or GCS storage, ingests them using OCSFIngestor,
and moves files to processed/ or failed/ folders based on ingestion results.

Storage backend is automatically detected from folder paths:
    - Local paths: /path/to/folder
    - GCS paths: gs://bucket-name/path/to/folder

Usage Examples:
    # Local backend (auto-detected from path)
    python ocsf_monitor.py \
        --source-folder /path/to/files/ \
        --processed-folder /path/processed/ \
        --failed-folder /path/failed/

    # Local backend - With custom database schema
    python ocsf_monitor.py \
        --source-folder /path/to/files/ \
        --processed-folder /path/processed/ \
        --failed-folder /path/failed/ \
        --schema custom_landing

    # GCS backend (auto-detected from gs:// prefix)
    python ocsf_monitor.py \
        --source-folder gs://my-bucket/OCSF_input/todo/ \
        --processed-folder gs://my-bucket/OCSF_input/processed/ \
        --failed-folder gs://my-bucket/OCSF_input/failed/ \
        --local-temp-folder /tmp/OCSF/

Arguments:
    Required:
        --source-folder      : Directory to monitor for OCSF files (local path or gs:// URI)
        --processed-folder   : Where to move successfully processed files (local path or gs:// URI)
        --failed-folder      : Where to move failed files (local path or gs:// URI)

    Optional:
        --local-temp-folder  : Local directory for temporary GCS downloads (default: /tmp/ocsf-monitor-temp/)
        --schema             : Database schema name (default: boann_landing)
        --log-level          : Logging level (default: info)

Processing Model:
    1. Scans source (local or GCS) for *.ocsf.json files
    2. For each file:
       a. Downloads to temp folder (if GCS) or accesses directly (if local)
       b. Ingests using OCSFIngestor
    3. Moves files to processed/ (success) or failed/ (failure) folders
    4. Next run only processes new files (processed/failed ones are moved)
"""

import os
import shutil
import signal
import subprocess
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


def validate_ocsf_file(file_path, validator_cmd, schema_file, logger):
    """
    Validates an OCSF file against a schema using an external validator tool.

    Args:
        file_path: Path to the OCSF file to validate
        validator_cmd: Path to the validator command
        schema_file: Path to the OCSF JSON schema file
        logger: Logger instance

    Returns:
        bool: True if validation passes, False otherwise
    """
    try:
        command = [validator_cmd, "--schema-file", schema_file, "--data-file", file_path]
        logger.debug(f"Running validation: {' '.join(command)}")

        start_time = time.perf_counter()
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        duration = time.perf_counter() - start_time

        logger.debug(f"Validation completed in {duration:.4f}s (exit code: {result.returncode})")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Validation failed for {file_path}: {e}")
        if e.stdout:
            logger.error(f"Validator stdout: {e.stdout}")
        if e.stderr:
            logger.error(f"Validator stderr: {e.stderr}")
        return False
    except FileNotFoundError:
        logger.error(f"Validator command not found: {validator_cmd}")
        logger.error("Please ensure the validator tool is installed or disable validation")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during validation: {e}")
        return False


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

    # Show validation status
    if args.validator and args.schema_file:
        logger.info(f"Schema validation: ENABLED (validator: {args.validator})")
    else:
        logger.info("Schema validation: DISABLED")

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

        # Step 1: Optional schema validation
        if args.validator and args.schema_file:
            logger.info(f"Validating '{file_name}' against schema...")
            if not validate_ocsf_file(str(file_path), args.validator, args.schema_file, logger):
                logger.error(f"Schema validation failed for '{file_name}'")
                dest_path = os.path.join(args.failed_folder, file_name)
                try:
                    shutil.move(str(file_path), dest_path)
                    logger.error(f"Moved invalid file '{file_name}' -> {dest_path}")
                except Exception as move_error:
                    logger.error(f"Error moving file '{file_name}': {move_error}")
                all_successful = False
                continue
            logger.info(f"Validation passed for '{file_name}'")

        # Step 2: Ingest file
        ingestion_success = ingestor.ingest_file(str(file_path))

        # Step 3: Move file based on success/failure
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


def process_gcs_files(args, ingestor, logger, gcs_config):
    """
    Monitors a GCS bucket for new OCSF files and processes them.
    Downloads files, ingests them, then moves in GCS based on results.

    Args:
        args: Parsed command-line arguments
        ingestor: OCSFIngestor instance for ingestion
        logger: Logger instance to use
        gcs_config: Dict with bucket_name, source_prefix, processed_prefix, failed_prefix

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
                "google-cloud-storage is required for GCS backend. Install it with: pip install google-cloud-storage"
            )
            return False

    logger.info("\n--- GCS OCSF File Monitor ---")
    logger.info(f"GCS Bucket: '{gcs_config['bucket_name']}'")
    logger.info(f"GCS Source folder: '{gcs_config['source_prefix']}'")
    logger.info(f"GCS Processed folder: '{gcs_config['processed_prefix']}'")
    logger.info(f"GCS Failed folder: '{gcs_config['failed_prefix']}'")
    logger.info(f"Local temp folder: '{args.local_temp_folder}'")

    # Show validation status
    if args.validator and args.schema_file:
        logger.info(f"Schema validation: ENABLED (validator: {args.validator})")
    else:
        logger.info("Schema validation: DISABLED")

    # Create local directories
    local_input_folder = os.path.join(args.local_temp_folder, "input")
    local_processed_folder = os.path.join(args.local_temp_folder, "processed")
    local_failed_folder = os.path.join(args.local_temp_folder, "failed")
    os.makedirs(local_input_folder, exist_ok=True)
    os.makedirs(local_processed_folder, exist_ok=True)
    os.makedirs(local_failed_folder, exist_ok=True)

    # Initialize GCS client and verify connection
    try:
        gcs_utils.init(gcs_config["bucket_name"])
        logger.info(f"Successfully connected to GCS bucket: {gcs_config['bucket_name']}")
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
        f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] Checking for new files in '{gcs_config['source_prefix']}'..."
    )
    source_blobs = gcs_utils.list_files(gcs_config["source_prefix"])

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
            if not gcs_utils.move_preserving_structure(blob, gcs_config["source_prefix"], gcs_config["failed_prefix"]):
                logger.error(f"Failed to move '{blob.name}' to failed folder after download failure.")
            continue

        # 2. Optional schema validation
        if args.validator and args.schema_file:
            logger.info(f"Validating '{file_name}' against schema...")
            if not validate_ocsf_file(local_file_path, args.validator, args.schema_file, logger):
                logger.error(f"Schema validation failed for '{file_name}'")
                failed_files_count += 1
                if not gcs_utils.move_preserving_structure(
                    blob, gcs_config["source_prefix"], gcs_config["failed_prefix"]
                ):
                    logger.error(f"Failed to move '{blob.name}' to failed folder after validation failure.")
                continue
            logger.info(f"Validation passed for '{file_name}'")

        # 3. Ingest file
        ingestion_success = ingestor.ingest_file(local_file_path)

        # 4. Move GCS file based on ingestion outcome
        if ingestion_success:
            logger.info(f"Successfully ingested '{file_name}'. Moving to processed folder.")
            if not gcs_utils.move_preserving_structure(
                blob, gcs_config["source_prefix"], gcs_config["processed_prefix"]
            ):
                logger.error(f"Failed to move '{blob.name}' to processed folder.")
                failed_files_count += 1
        else:
            logger.error(f"Failed to ingest '{file_name}'. Moving to failed folder.")
            failed_files_count += 1
            if not gcs_utils.move_preserving_structure(blob, gcs_config["source_prefix"], gcs_config["failed_prefix"]):
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
        return "OCSF File Monitor and Processor (auto-detects local vs GCS from folder paths)"

    def get_epilog(self) -> str:
        return (
            "Examples:\n"
            "  Local: ocsf_monitor.py --source-folder /path/to/files/ "
            "--processed-folder /path/processed --failed-folder /path/failed\n"
            "  GCS: ocsf_monitor.py --source-folder gs://my-bucket/input/ "
            "--processed-folder gs://my-bucket/processed/ --failed-folder gs://my-bucket/failed/"
        )

    def add_arguments(self, parser):
        # Folder arguments (auto-detect backend from gs:// prefix)
        parser.add_argument(
            "--source-folder",
            required=True,
            help="Directory to monitor for OCSF files (local path or gs://bucket/path URI)",
        )
        parser.add_argument(
            "--processed-folder",
            required=True,
            help="Directory where successfully processed files will be moved (local path or gs://bucket/path URI)",
        )
        parser.add_argument(
            "--failed-folder",
            required=True,
            help="Directory where failed files will be moved (local path or gs://bucket/path URI)",
        )

        # Optional GCS temp folder
        parser.add_argument(
            "--local-temp-folder",
            default="/tmp/ocsf-monitor-temp",
            help="Local directory for temporary GCS downloads (default: /tmp/ocsf-monitor-temp/)",
        )

        # Database configuration
        parser.add_argument(
            "--schema",
            type=str,
            default="boann_landing",
            help="Database schema name (default: boann_landing) where findings will be inserted",
        )

        # Optional schema validation
        parser.add_argument(
            "--validator",
            type=str,
            help=(
                "Path to OCSF validator command (e.g., validate-ocsf-file). "
                "If provided, files will be validated before ingestion"
            ),
        )
        parser.add_argument(
            "--schema-file",
            type=str,
            help="Path to OCSF JSON schema file for validation (required if --validator is provided)",
        )

    def _parse_gcs_uri(self, uri: str) -> tuple[str, str]:
        """
        Parse a GCS URI into bucket and path components.

        Args:
            uri: GCS URI in format gs://bucket-name/path/to/folder

        Returns:
            Tuple of (bucket_name, path)
        """
        if not uri.startswith("gs://"):
            raise ValueError(f"Invalid GCS URI: {uri} (must start with gs://)")

        # Remove gs:// prefix
        uri_without_prefix = uri[5:]

        # Split into bucket and path
        parts = uri_without_prefix.split("/", 1)
        bucket_name = parts[0]
        path = parts[1] if len(parts) > 1 else ""

        if not bucket_name:
            raise ValueError(f"Invalid GCS URI: {uri} (no bucket name specified)")

        return bucket_name, path

    def _detect_backend(self) -> str:
        """
        Detect storage backend from folder paths.

        Returns:
            "gcs" if any folder starts with gs://, "local" otherwise
        """
        if (
            self.args.source_folder.startswith("gs://")
            or self.args.processed_folder.startswith("gs://")
            or self.args.failed_folder.startswith("gs://")
        ):
            return "gcs"
        return "local"

    def validate_arguments(self):
        """Validate monitor-specific arguments and detect backend."""
        # Validate schema validation arguments
        if (self.args.validator and not self.args.schema_file) or (self.args.schema_file and not self.args.validator):
            self.logger.error("Error: --validator and --schema-file must be provided together")
            sys.exit(1)

        if self.args.validator and not os.path.isfile(self.args.validator):
            self.logger.error(f"Error: Validator command not found: {self.args.validator}")
            sys.exit(1)

        if self.args.schema_file and not os.path.isfile(self.args.schema_file):
            self.logger.error(f"Error: Schema file not found: {self.args.schema_file}")
            sys.exit(1)

        backend = self._detect_backend()

        if backend == "local":
            # Validate local backend arguments
            if not os.path.exists(self.args.source_folder):
                self.logger.error(f"Error: Source folder does not exist: {self.args.source_folder}")
                sys.exit(1)
            if not os.path.isdir(self.args.source_folder):
                self.logger.error(f"Error: Source path is not a directory: {self.args.source_folder}")
                sys.exit(1)

            # Create processed and failed directories if they don't exist
            os.makedirs(self.args.processed_folder, exist_ok=True)
            os.makedirs(self.args.failed_folder, exist_ok=True)

        elif backend == "gcs":
            # Validate all folders are GCS URIs
            for folder_name, folder_path in [
                ("source", self.args.source_folder),
                ("processed", self.args.processed_folder),
                ("failed", self.args.failed_folder),
            ]:
                if not folder_path.startswith("gs://"):
                    self.logger.error(
                        f"Error: When using GCS, all folders must be GCS URIs. "
                        f"{folder_name} folder is not a GCS URI: {folder_path}"
                    )
                    sys.exit(1)

                # Validate URI format
                try:
                    self._parse_gcs_uri(folder_path)
                except ValueError as e:
                    self.logger.error(f"Error: Invalid {folder_name} folder URI: {e}")
                    sys.exit(1)

            # Validate all URIs use the same bucket
            source_bucket, _ = self._parse_gcs_uri(self.args.source_folder)
            processed_bucket, _ = self._parse_gcs_uri(self.args.processed_folder)
            failed_bucket, _ = self._parse_gcs_uri(self.args.failed_folder)

            if source_bucket != processed_bucket or source_bucket != failed_bucket:
                self.logger.error(
                    f"Error: All GCS folders must use the same bucket. "
                    f"Found: source={source_bucket}, processed={processed_bucket}, failed={failed_bucket}"
                )
                sys.exit(1)

            # Create local temp folder
            os.makedirs(self.args.local_temp_folder, exist_ok=True)

    def execute(self) -> int:
        """Execute monitor with auto-detected storage backend."""
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

            # Detect backend and process files
            backend = self._detect_backend()

            if backend == "local":
                success = process_local_files(self.args, ingestor, self.logger)
            elif backend == "gcs":
                # Parse GCS URIs to extract bucket and paths
                bucket_name, source_prefix = self._parse_gcs_uri(self.args.source_folder)
                _, processed_prefix = self._parse_gcs_uri(self.args.processed_folder)
                _, failed_prefix = self._parse_gcs_uri(self.args.failed_folder)

                gcs_config = {
                    "bucket_name": bucket_name,
                    "source_prefix": source_prefix,
                    "processed_prefix": processed_prefix,
                    "failed_prefix": failed_prefix,
                }

                success = process_gcs_files(self.args, ingestor, self.logger, gcs_config)
            else:
                self.logger.error(f"Unknown storage backend: {backend}")
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
