# gcs_utils.py
"""
Google Cloud Storage utilities for OCSF data platform.

Provides helper functions for interacting with GCS buckets, including
file upload, download, move, and listing operations.

Note: This module requires google-cloud-storage to be installed.
Install it with: pip install google-cloud-storage
"""

import logging
import os

# Get a logger for this module
logger = logging.getLogger(__name__)


class _GCSHandler:
    """
    A handler for interacting with a specific Google Cloud Storage bucket.
    This class is intended for internal use within this module.
    """

    def __init__(self, bucket_name: str):
        """Initializes the GCS client and bucket."""
        try:
            from google.cloud import storage
        except ImportError:
            raise ImportError(
                "google-cloud-storage is required for GCS functionality. "
                "Install it with: pip install google-cloud-storage"
            )

        self.storage = storage
        self.client = storage.Client()
        self.bucket = self.client.bucket(bucket_name)
        logger.info(f"GCS client initialized for bucket: gs://{self.bucket.name}")

    def get(self, path: str) -> bytes:
        """Retrieves file content from the bucket."""
        blob = self.bucket.blob(path)
        return blob.download_as_bytes()

    def push(self, path: str, data: bytes):
        """Pushes bytes content to a file in the bucket."""
        blob = self.bucket.blob(path)
        blob.upload_from_string(data)
        logger.info(f"Pushed data to gs://{self.bucket.name}/{path}")

    def move(self, from_path: str, to_path: str):
        """Moves a file to a new location within the same bucket."""
        source_blob = self.bucket.blob(from_path)
        self.bucket.copy_blob(source_blob, self.bucket, to_path)
        source_blob.delete()
        logger.info(f"Moved gs://{self.bucket.name}/{from_path} to gs://{self.bucket.name}/{to_path}")

    def copy(self, local_path: str, remote_path: str):
        """Copies (uploads) a local file to the bucket."""
        blob = self.bucket.blob(remote_path)
        blob.upload_from_filename(local_path)
        logger.info(f"Copied local file '{local_path}' to gs://{self.bucket.name}/{remote_path}")

    def download(self, blob, local_path):
        """Downloads a GCS blob to a local path."""
        try:
            file_content = self.get(blob.name)
            with open(local_path, "wb") as f:
                f.write(file_content)
            logger.info(f"Downloaded '{blob.name}' to '{local_path}'")
            return True
        except Exception as e:
            logger.error(f"Error downloading '{blob.name}': {e}")
            return False

    def list_files(self, prefix: str) -> list:
        """Lists all blobs in a given GCS folder (prefix), sorted alphabetically."""
        try:
            blob_list = self.bucket.list_blobs(prefix=prefix)
            # The GCS prefix includes a timestamp, so we sort the files to ensure that
            # older findings do not overwrite newer ones during processing.
            # Filter out the folder itself and sort blobs by name
            sorted_blobs = sorted([blob for blob in blob_list if blob.name != prefix], key=lambda x: x.name)
            return sorted_blobs
        except Exception as e:
            logger.error(f"Error listing blobs in GCS folder '{prefix}': {e}")
            return []

    def move_preserving_structure(self, blob, source_prefix: str, destination_prefix: str) -> bool:
        """
        Moves a GCS blob to a new folder, preserving its relative structure.
        """
        try:
            if not blob.name.startswith(source_prefix):
                logger.error(
                    f"Source blob '{blob.name}' does not match source prefix '{source_prefix}'. "
                    "Cannot preserve structure."
                )
                return False

            relative_path = blob.name[len(source_prefix) :].lstrip("/")
            new_blob_name = os.path.join(destination_prefix, relative_path).replace("\\", "/")

            self.move(blob.name, new_blob_name)
            return True
        except Exception as e:
            logger.error(f"Error moving GCS file '{blob.name}' to '{destination_prefix}': {e}")
            return False


# The single, module-level instance. It starts as None.
_handler = None


def init(bucket_name: str):
    """
    Initializes the module-level GCS handler.
    This must be called once before using the other functions.
    """
    global _handler
    if _handler is None:
        _handler = _GCSHandler(bucket_name)
    elif _handler.bucket.name != bucket_name:
        raise ValueError(
            f"Error: the gcs_utils module was initialized with {_handler.bucket.name}, NOT {bucket_name}!"
        )


def _get_handler():
    """Helper to ensure the handler is initialized."""
    if _handler is None:
        # Log a critical error before raising the exception
        logger.critical("GCS handler is not initialized. Call gcs_utils.init() first.")
        raise RuntimeError("GCS handler is not initialized. Call gcs_utils.init() first.")
    return _handler


# --- Public API ---


def get(path: str) -> bytes:
    """Retrieves file content from the configured GCS bucket."""
    return _get_handler().get(path)


def push(path: str, data: bytes):
    """Pushes content to a file in the configured GCS bucket."""
    logging.info(f"Writing {path}")
    _get_handler().push(path, data)


def move(from_path: str, to_path: str):
    """Moves a file within the configured GCS bucket."""
    _get_handler().move(from_path, to_path)


def copy(local: str, remote: str):
    """Copies a local file to the configured GCS bucket."""
    _get_handler().copy(local_path=local, remote_path=remote)


def download(blob, local_path):
    """Downloads a GCS blob to a local path."""
    return _get_handler().download(blob, local_path)


def list_files(prefix: str) -> list:
    """Lists all files in a given GCS folder (prefix), sorted alphabetically."""
    return _get_handler().list_files(prefix)


def move_preserving_structure(blob, source_prefix: str, destination_prefix: str) -> bool:
    """
    Moves a GCS blob to a new folder, preserving its relative structure.
    """
    return _get_handler().move_preserving_structure(blob, source_prefix, destination_prefix)


def smart_get(uri: str) -> bytes:
    """
    Smart file retrieval that works with both GCS URIs and local file paths.

    Args:
        uri: Either a GCS URI (gs://bucket/path/to/file) or a local file path

    Returns:
        File content as bytes

    Raises:
        FileNotFoundError: If local file doesn't exist
        Exception: If GCS retrieval fails

    Examples:
        # GCS file
        content = smart_get("gs://my-bucket/data/file.json")

        # Local file
        content = smart_get("/path/to/local/file.json")
    """
    if uri.startswith("gs://"):
        # GCS file: parse URI and retrieve
        gcs_url = uri[5:]  # Remove 'gs://'
        parts = gcs_url.split("/", 1)
        bucket_name = parts[0]
        file_path = parts[1] if len(parts) > 1 else ""

        if not file_path:
            raise ValueError(f"Invalid GCS URI: {uri} (no file path specified)")

        # Initialize GCS handler if needed
        init(bucket_name)
        return get(file_path)
    else:
        # Local file: read from filesystem
        with open(uri, "rb") as f:
            return f.read()


def smart_push(uri: str, data: bytes):
    """
    Smart file writing that works with both GCS URIs and local file paths.

    Args:
        uri: Either a GCS URI (gs://bucket/path/to/file) or a local file path
        data: File content as bytes

    Raises:
        ValueError: If GCS URI is invalid
        Exception: If file writing fails

    Examples:
        # GCS file
        smart_push("gs://my-bucket/data/file.json", b'{"key": "value"}')

        # Local file
        smart_push("/path/to/local/file.json", b'{"key": "value"}')
    """
    if uri.startswith("gs://"):
        # GCS file: parse URI and push
        gcs_url = uri[5:]  # Remove 'gs://'
        parts = gcs_url.split("/", 1)
        bucket_name = parts[0]
        file_path = parts[1] if len(parts) > 1 else ""

        if not file_path:
            raise ValueError(f"Invalid GCS URI: {uri} (no file path specified)")

        # Initialize GCS handler if needed
        init(bucket_name)
        push(file_path, data)
    else:
        # Local file: write to filesystem
        # Create parent directories if they don't exist
        parent_dir = os.path.dirname(uri)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
        with open(uri, "wb") as f:
            f.write(data)

