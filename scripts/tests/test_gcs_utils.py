#!/usr/bin/env python3
"""
Unit tests for upstream/scripts/helpers/gcs_utils.py

Run with: pytest upstream/scripts/tests/test_gcs_utils.py -v
"""

import os
import sys
from unittest.mock import patch

import pytest

# Add paths for imports
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class TestExtractBucketName:
    """Test the extract_bucket_name utility function."""

    @pytest.mark.parametrize(
        "gcs_path,expected_bucket",
        [
            ("gs://my-bucket/path/to/file", "my-bucket"),
            ("gs://my-bucket", "my-bucket"),
            ("gs://my-bucket/", "my-bucket"),
            ("gs://my-bucket/a/b/c/d/file.json", "my-bucket"),
        ],
    )
    def test_extract_bucket_name_valid_paths(self, gcs_path, expected_bucket):
        """Test extracting bucket name from various valid GCS paths."""
        from helpers import gcs_utils

        assert gcs_utils.extract_bucket_name(gcs_path) == expected_bucket

    @pytest.mark.parametrize(
        "invalid_path,description",
        [
            ("s3://my-bucket/path", "non-GCS path"),
            ("/local/path/to/file", "local path"),
        ],
    )
    def test_extract_bucket_name_invalid_paths(self, invalid_path, description):
        """Test that invalid paths raise ValueError."""
        from helpers import gcs_utils

        with pytest.raises(ValueError, match="Invalid GCS path.*must start with gs://"):
            gcs_utils.extract_bucket_name(invalid_path)


class TestGcsUtilsAuthenticationBehavior:
    """Test that gcs_utils fails fast when GCS authentication is invalid."""

    @pytest.mark.parametrize(
        "exception_class,exception_message,mock_location",
        [
            ("DefaultCredentialsError", "Could not automatically determine credentials", "client"),
            ("RefreshError", "Token has been expired or revoked", "bucket_exists"),
            ("Forbidden", "Permission denied", "bucket_exists"),
            ("NotFound", "Bucket not found", "bucket_exists"),
        ],
    )
    def test_initialization_fails_with_auth_errors(self, exception_class, exception_message, mock_location):
        """Test that handler initialization fails with various authentication errors."""
        from google.api_core.exceptions import Forbidden, NotFound
        from google.auth.exceptions import DefaultCredentialsError, RefreshError
        from helpers import gcs_utils

        # Map exception class names to actual classes
        exception_map = {
            "DefaultCredentialsError": DefaultCredentialsError,
            "RefreshError": RefreshError,
            "Forbidden": Forbidden,
            "NotFound": NotFound,
        }
        exception_cls = exception_map[exception_class]

        with patch("google.cloud.storage.Client") as mock_client:
            if mock_location == "client":
                # Exception raised during Client() initialization
                mock_client.side_effect = exception_cls(exception_message)
            else:
                # Exception raised during bucket.exists()
                mock_client_instance = mock_client.return_value
                mock_bucket = mock_client_instance.bucket.return_value
                mock_bucket.exists.side_effect = exception_cls(exception_message)

            with pytest.raises(exception_cls):
                gcs_utils._GCSHandler("test-bucket")

    def test_initialization_succeeds_with_valid_credentials(self):
        """Test that handler initializes successfully with valid credentials."""
        from helpers import gcs_utils

        with patch("google.cloud.storage.Client") as mock_client:
            mock_client_instance = mock_client.return_value
            mock_bucket = mock_client_instance.bucket.return_value
            mock_bucket.exists.return_value = True
            mock_bucket.name = "test-bucket"

            # Should not raise any exception
            handler = gcs_utils._GCSHandler("test-bucket")
            assert handler is not None
