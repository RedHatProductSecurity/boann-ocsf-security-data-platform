#!/usr/bin/env python3
"""
Unit tests for OCSF Ingestor

Tests both the OCSFIngestor class and IngestorCLI interface.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ingest_raw_ocsf_findings import OCSFIngestor, IngestorCLI


# Fixtures
@pytest.fixture
def mock_engine():
    """Fixture for mock database engine"""
    with patch('ingest_raw_ocsf_findings.create_engine') as mock_create_engine:
        engine = Mock()
        mock_create_engine.return_value = engine
        yield engine


@pytest.fixture
def ingestor(mock_engine):
    """Fixture for OCSFIngestor instance"""
    with patch.dict(os.environ, {'DATABASE_URL': 'postgresql://test:test@localhost/test'}):
        return OCSFIngestor(schema="test_schema")


@pytest.fixture
def ingestor_cli():
    """Fixture for IngestorCLI instance"""
    return IngestorCLI()


# TestOCSFIngestor Tests
@patch('ingest_raw_ocsf_findings.create_engine')
@patch('ingest_raw_ocsf_findings.load_dotenv')
@patch.dict(os.environ, {'DATABASE_URL': 'postgresql://test:test@localhost/test'})
def test_init_default_schema(mock_load_dotenv, mock_create_engine):
    """Test initialization with default schema"""
    mock_engine = Mock()
    mock_create_engine.return_value = mock_engine

    ingestor = OCSFIngestor()

    assert ingestor.schema == "boann_landing"
    mock_load_dotenv.assert_called_once()
    mock_create_engine.assert_called_once()


@patch('ingest_raw_ocsf_findings.create_engine')
@patch('ingest_raw_ocsf_findings.load_dotenv')
@patch.dict(os.environ, {'DATABASE_URL': 'postgresql://test:test@localhost/test'})
def test_init_custom_schema(mock_load_dotenv, mock_create_engine):
    """Test initialization with custom schema"""
    mock_engine = Mock()
    mock_create_engine.return_value = mock_engine

    ingestor = OCSFIngestor(schema="custom_schema")

    assert ingestor.schema == "custom_schema"


@patch('ingest_raw_ocsf_findings.create_engine')
@patch('ingest_raw_ocsf_findings.load_dotenv')
@patch.dict(os.environ, {}, clear=True)
def test_init_no_database_url(mock_load_dotenv, mock_create_engine):
    """Test initialization fails without DATABASE_URL"""
    with pytest.raises(EnvironmentError) as excinfo:
        OCSFIngestor()

    assert "DATABASE_URL" in str(excinfo.value)


@patch('ingest_raw_ocsf_findings.create_engine')
@patch.dict(os.environ, {'DATABASE_URL': 'postgresql://test:test@localhost/test'})
def test_init_custom_database_url(mock_create_engine):
    """Test initialization with custom database URL"""
    custom_url = "postgresql://custom:custom@localhost/custom"
    mock_engine = Mock()
    mock_create_engine.return_value = mock_engine

    ingestor = OCSFIngestor(database_url=custom_url)

    assert ingestor.database_url == custom_url
    mock_create_engine.assert_called_once_with(custom_url)


def test_store_findings_to_db_success(ingestor, mock_engine):
    """Test successful storage of findings"""
    # Mock database connection context manager
    mock_conn = Mock()
    mock_context = MagicMock()
    mock_context.__enter__.return_value = mock_conn
    mock_context.__exit__.return_value = None
    mock_engine.begin.return_value = mock_context

    # Test data
    findings = [
        {
            "finding_info": {"uid": "test-1"},
            "severity": "High",
            "message": "Test finding 1"
        },
        {
            "finding_info": {"uid": "test-2"},
            "severity": "Medium",
            "message": "Test finding 2"
        }
    ]

    # Execute
    count = ingestor.store_findings_to_db(findings, "test.ocsf.json")

    # Assertions
    assert count == 2
    assert mock_conn.execute.call_count == 2


def test_store_findings_to_db_failure(ingestor, mock_engine):
    """Test storage failure propagates exception"""
    # Mock database connection to raise exception
    mock_conn = Mock()
    mock_conn.execute.side_effect = Exception("Database error")
    mock_context = MagicMock()
    mock_context.__enter__.return_value = mock_conn
    mock_context.__exit__.return_value = None
    mock_engine.begin.return_value = mock_context

    # Test data
    findings = [
        {"finding_info": {"uid": "test-1"}, "message": "Test"}
    ]

    # Execute and assert exception is raised
    with pytest.raises(Exception) as excinfo:
        ingestor.store_findings_to_db(findings, "test.ocsf.json")

    assert "Database error" in str(excinfo.value)


def test_ingest_file_not_exists(ingestor):
    """Test ingestion fails when file doesn't exist"""
    result = ingestor.ingest_file("/nonexistent/file.ocsf.json")
    assert result is False


def test_ingest_file_wrong_extension(ingestor):
    """Test ingestion fails with wrong file extension"""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        temp_file = f.name

    try:
        result = ingestor.ingest_file(temp_file)
        assert result is False
    finally:
        os.unlink(temp_file)


def test_ingest_file_success(ingestor, mock_engine):
    """Test successful file ingestion"""
    # Create test OCSF file
    test_data = [
        {"finding_info": {"uid": "test-1"}, "message": "Test finding"}
    ]

    with tempfile.NamedTemporaryFile(
        suffix=".ocsf.json",
        mode='w',
        delete=False
    ) as f:
        json.dump(test_data, f)
        temp_file = f.name

    try:
        # Mock database operations
        mock_conn = Mock()
        mock_context = MagicMock()
        mock_context.__enter__.return_value = mock_conn
        mock_context.__exit__.return_value = None
        mock_engine.begin.return_value = mock_context

        # Execute
        result = ingestor.ingest_file(temp_file)

        # Assertions
        assert result is True
        mock_conn.execute.assert_called_once()
    finally:
        os.unlink(temp_file)


def test_ingest_file_empty(ingestor, mock_engine):
    """Test ingestion of empty file"""
    test_data = []

    with tempfile.NamedTemporaryFile(
        suffix=".ocsf.json",
        mode='w',
        delete=False
    ) as f:
        json.dump(test_data, f)
        temp_file = f.name

    try:
        # Mock database operations (not used for empty file)
        mock_conn = Mock()
        mock_context = MagicMock()
        mock_context.__enter__.return_value = mock_conn
        mock_context.__exit__.return_value = None
        mock_engine.begin.return_value = mock_context

        # Execute
        result = ingestor.ingest_file(temp_file)

        # Assertions
        assert result is True  # Empty file is still valid
        mock_conn.execute.assert_not_called()  # But no inserts
    finally:
        os.unlink(temp_file)


def test_ingest_file_invalid_json(ingestor):
    """Test ingestion fails with invalid JSON"""
    with tempfile.NamedTemporaryFile(
        suffix=".ocsf.json",
        mode='w',
        delete=False
    ) as f:
        f.write("invalid json {")
        temp_file = f.name

    try:
        result = ingestor.ingest_file(temp_file)
        assert result is False
    finally:
        os.unlink(temp_file)


def test_ingest_file_database_error(ingestor, mock_engine):
    """Test ingestion fails on database error"""
    test_data = [
        {"finding_info": {"uid": "test-1"}, "message": "Test"}
    ]

    with tempfile.NamedTemporaryFile(
        suffix=".ocsf.json",
        mode='w',
        delete=False
    ) as f:
        json.dump(test_data, f)
        temp_file = f.name

    try:
        # Mock database to raise exception
        mock_conn = Mock()
        mock_conn.execute.side_effect = Exception("DB error")
        mock_context = MagicMock()
        mock_context.__enter__.return_value = mock_conn
        mock_context.__exit__.return_value = None
        mock_engine.begin.return_value = mock_context

        # Execute
        result = ingestor.ingest_file(temp_file)

        # Assertions
        assert result is False
    finally:
        os.unlink(temp_file)


# TestIngestorCLI Tests
@patch('ingest_raw_ocsf_findings.OCSFIngestor')
def test_execute_success(mock_ingestor_class, ingestor_cli):
    """Test CLI execution with successful ingestion"""
    # Mock ingestor instance
    mock_ingestor = Mock()
    mock_ingestor.ingest_file.return_value = True
    mock_ingestor_class.return_value = mock_ingestor

    # Setup CLI with mock args
    ingestor_cli.args = Mock()
    ingestor_cli.args.input_file = "/test/file.ocsf.json"
    ingestor_cli.args.schema = "test_schema"
    ingestor_cli.logger = Mock()

    # Execute
    exit_code = ingestor_cli.execute()

    # Assertions
    assert exit_code == 0
    mock_ingestor_class.assert_called_once_with(schema="test_schema")
    mock_ingestor.ingest_file.assert_called_once_with("/test/file.ocsf.json")


@patch('ingest_raw_ocsf_findings.OCSFIngestor')
def test_execute_failure(mock_ingestor_class, ingestor_cli):
    """Test CLI execution with failed ingestion"""
    # Mock ingestor instance
    mock_ingestor = Mock()
    mock_ingestor.ingest_file.return_value = False
    mock_ingestor_class.return_value = mock_ingestor

    # Setup CLI with mock args
    ingestor_cli.args = Mock()
    ingestor_cli.args.input_file = "/test/file.ocsf.json"
    ingestor_cli.args.schema = "test_schema"
    ingestor_cli.logger = Mock()

    # Execute
    exit_code = ingestor_cli.execute()

    # Assertions
    assert exit_code == 1


@patch('ingest_raw_ocsf_findings.OCSFIngestor')
def test_execute_exception(mock_ingestor_class, ingestor_cli):
    """Test CLI execution with exception"""
    # Mock ingestor to raise exception
    mock_ingestor_class.side_effect = Exception("Test error")

    # Setup CLI with mock args
    ingestor_cli.args = Mock()
    ingestor_cli.args.input_file = "/test/file.ocsf.json"
    ingestor_cli.args.schema = "test_schema"
    ingestor_cli.logger = Mock()

    # Execute
    exit_code = ingestor_cli.execute()

    # Assertions
    assert exit_code == 1


# CLI Integration Tests
def test_ingest_raw_ocsf_findings_cli_no_argument():
    """Test that ingest_raw_ocsf_findings.py CLI script runs without argument"""

    # Get path to the ingest_raw_ocsf_findings.py script
    script_dir = Path(__file__).parent.parent
    script_path = script_dir / "ingest_raw_ocsf_findings.py"

    result = subprocess.run(
        [sys.executable, str(script_path), "--help"],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
