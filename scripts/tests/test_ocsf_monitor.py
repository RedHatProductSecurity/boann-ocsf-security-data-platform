#!/usr/bin/env python3
"""
Unit tests for OCSF Monitor

Tests the MonitorCLI class and process_local_files function.
"""

import os
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ocsf_monitor
from ocsf_monitor import MonitorCLI, process_local_files, signal_handler, validate_ocsf_file


# Fixtures
@pytest.fixture
def reset_globals():
    """Fixture to reset global state before each test"""
    ocsf_monitor.shutdown_flag = False
    ocsf_monitor._logger = None
    yield
    # Cleanup after test
    ocsf_monitor.shutdown_flag = False
    ocsf_monitor._logger = None


@pytest.fixture
def temp_directories():
    """Fixture to create and cleanup temporary directories for file processing tests"""
    temp_dir = tempfile.mkdtemp()
    source_folder = os.path.join(temp_dir, "source")
    processed_folder = os.path.join(temp_dir, "processed")
    failed_folder = os.path.join(temp_dir, "failed")

    os.makedirs(source_folder)
    os.makedirs(processed_folder)
    os.makedirs(failed_folder)

    yield {
        "temp_dir": temp_dir,
        "source_folder": source_folder,
        "processed_folder": processed_folder,
        "failed_folder": failed_folder,
    }

    # Cleanup
    shutil.rmtree(temp_dir)


@pytest.fixture
def mock_args(temp_directories):
    """Fixture to create mock args with temporary directories"""
    args = Mock()
    args.source_folder = temp_directories["source_folder"]
    args.processed_folder = temp_directories["processed_folder"]
    args.failed_folder = temp_directories["failed_folder"]
    args.validator = None
    args.schema_file = None
    return args


@pytest.fixture
def monitor_cli():
    """Fixture for MonitorCLI instance"""
    return MonitorCLI()


# TestSignalHandler Tests
def test_signal_handler_without_logger(reset_globals):
    """Test signal handler without logger set"""
    ocsf_monitor.shutdown_flag = False
    signal_handler(signal.SIGINT, None)
    assert ocsf_monitor.shutdown_flag is True


def test_signal_handler_with_logger(reset_globals):
    """Test signal handler with logger set"""
    mock_logger = Mock()
    ocsf_monitor._logger = mock_logger
    ocsf_monitor.shutdown_flag = False

    signal_handler(signal.SIGTERM, None)

    assert ocsf_monitor.shutdown_flag is True
    mock_logger.info.assert_called_once()


# TestProcessLocalFiles Tests
def test_process_local_files_no_files(reset_globals, mock_args):
    """Test processing when no files are present"""
    mock_ingestor = Mock()
    mock_logger = Mock()

    result = process_local_files(mock_args, mock_ingestor, mock_logger)

    assert result is True  # No files is not a failure
    mock_ingestor.ingest_file.assert_not_called()


def test_process_local_files_source_not_exists(reset_globals):
    """Test processing when source folder doesn't exist"""
    args = Mock()
    args.source_folder = "/nonexistent/path"
    mock_ingestor = Mock()
    mock_logger = Mock()

    result = process_local_files(args, mock_ingestor, mock_logger)

    assert result is False


def test_process_local_files_successful_processing(reset_globals, mock_args, temp_directories):
    """Test successful processing of OCSF files"""
    # Create test files
    test_file1 = os.path.join(temp_directories["source_folder"], "test1.ocsf.json")
    test_file2 = os.path.join(temp_directories["source_folder"], "test2.ocsf.json")
    Path(test_file1).write_text("[]")
    Path(test_file2).write_text("[]")

    # Mock successful ingestion
    mock_ingestor = Mock()
    mock_ingestor.ingest_file.return_value = True
    mock_logger = Mock()

    result = process_local_files(mock_args, mock_ingestor, mock_logger)

    # Assertions
    assert result is True
    assert mock_ingestor.ingest_file.call_count == 2

    # Check files moved to processed folder
    assert os.path.exists(os.path.join(temp_directories["processed_folder"], "test1.ocsf.json"))
    assert os.path.exists(os.path.join(temp_directories["processed_folder"], "test2.ocsf.json"))
    assert not os.path.exists(test_file1)
    assert not os.path.exists(test_file2)


def test_process_local_files_ingestion_failure(reset_globals, mock_args, temp_directories):
    """Test processing with ingestion failure"""
    # Create test file
    test_file = os.path.join(temp_directories["source_folder"], "test.ocsf.json")
    Path(test_file).write_text("[]")

    # Mock failed ingestion
    mock_ingestor = Mock()
    mock_ingestor.ingest_file.return_value = False
    mock_logger = Mock()

    result = process_local_files(mock_args, mock_ingestor, mock_logger)

    # Assertions
    assert result is False
    mock_ingestor.ingest_file.assert_called_once()

    # Check file moved to failed folder
    assert os.path.exists(os.path.join(temp_directories["failed_folder"], "test.ocsf.json"))
    assert not os.path.exists(test_file)


def test_process_local_files_shutdown_signal(reset_globals, mock_args, temp_directories):
    """Test processing stops on shutdown signal"""
    # Create multiple test files
    for i in range(5):
        test_file = os.path.join(temp_directories["source_folder"], f"test{i}.ocsf.json")
        Path(test_file).write_text("[]")

    # Set shutdown flag after first file
    def set_shutdown_flag(*args):
        ocsf_monitor.shutdown_flag = True
        return True

    mock_ingestor = Mock()
    mock_ingestor.ingest_file.side_effect = set_shutdown_flag
    mock_logger = Mock()

    result = process_local_files(mock_args, mock_ingestor, mock_logger)

    # Assertions
    assert result is False  # Shutdown is treated as failure
    # Should stop processing after first file
    assert mock_ingestor.ingest_file.call_count == 1


def test_process_local_files_mixed_results(reset_globals, mock_args, temp_directories):
    """Test processing with mixed success/failure results"""
    # Create test files (names chosen to sort in desired order)
    test_file1 = os.path.join(temp_directories["source_folder"], "a_success.ocsf.json")
    test_file2 = os.path.join(temp_directories["source_folder"], "b_failure.ocsf.json")
    Path(test_file1).write_text("[]")
    Path(test_file2).write_text("[]")

    # Mock: first file succeeds, second fails ingestion
    mock_ingestor = Mock()
    mock_ingestor.ingest_file.side_effect = [True, False]
    mock_logger = Mock()

    result = process_local_files(mock_args, mock_ingestor, mock_logger)

    # Assertions
    assert result is False  # At least one failure
    assert os.path.exists(os.path.join(temp_directories["processed_folder"], "a_success.ocsf.json"))
    assert os.path.exists(os.path.join(temp_directories["failed_folder"], "b_failure.ocsf.json"))


# TestMonitorCLI Tests
def test_validate_arguments_source_not_exists(monitor_cli):
    """Test argument validation fails when source doesn't exist"""
    monitor_cli.args = Mock()
    monitor_cli.args.source_folder = "/nonexistent/path"
    monitor_cli.args.processed_folder = "/tmp/processed"
    monitor_cli.args.failed_folder = "/tmp/failed"
    monitor_cli.args.validator = None
    monitor_cli.args.schema_file = None
    monitor_cli.logger = Mock()

    with pytest.raises(SystemExit):
        monitor_cli.validate_arguments()


def test_validate_arguments_source_not_directory(monitor_cli):
    """Test argument validation fails when source is not a directory"""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        temp_file = f.name

    try:
        monitor_cli.args = Mock()
        monitor_cli.args.source_folder = temp_file
        monitor_cli.args.processed_folder = "/tmp/processed"
        monitor_cli.args.failed_folder = "/tmp/failed"
        monitor_cli.args.validator = None
        monitor_cli.args.schema_file = None
        monitor_cli.logger = Mock()

        with pytest.raises(SystemExit):
            monitor_cli.validate_arguments()
    finally:
        os.unlink(temp_file)


def test_validate_arguments_creates_folders(monitor_cli):
    """Test argument validation creates processed/failed folders"""
    temp_dir = tempfile.mkdtemp()
    source_folder = os.path.join(temp_dir, "source")
    processed_folder = os.path.join(temp_dir, "processed")
    failed_folder = os.path.join(temp_dir, "failed")

    os.makedirs(source_folder)

    try:
        monitor_cli.args = Mock()
        monitor_cli.args.source_folder = source_folder
        monitor_cli.args.processed_folder = processed_folder
        monitor_cli.args.failed_folder = failed_folder
        monitor_cli.args.validator = None
        monitor_cli.args.schema_file = None
        monitor_cli.logger = Mock()

        monitor_cli.validate_arguments()

        # Check folders were created
        assert os.path.exists(processed_folder)
        assert os.path.exists(failed_folder)
    finally:
        shutil.rmtree(temp_dir)


@patch("ocsf_monitor.OCSFIngestor")
@patch("ocsf_monitor.process_local_files")
def test_execute_success(mock_process, mock_ingestor_class, monitor_cli):
    """Test CLI execution with successful processing"""
    # Mock the process_local_files function
    mock_process.return_value = True

    # Setup CLI with mock args (local backend auto-detected from paths)
    monitor_cli.args = Mock()
    monitor_cli.args.source_folder = "/tmp/source"
    monitor_cli.args.processed_folder = "/tmp/processed"
    monitor_cli.args.failed_folder = "/tmp/failed"
    monitor_cli.args.schema = "test_schema"
    monitor_cli.args.validator = None
    monitor_cli.args.schema_file = None
    monitor_cli.logger = Mock()

    # Execute
    exit_code = monitor_cli.execute()

    # Assertions
    assert exit_code == 0
    mock_ingestor_class.assert_called_once_with(schema="test_schema")
    mock_process.assert_called_once()


@patch("ocsf_monitor.OCSFIngestor")
@patch("ocsf_monitor.process_local_files")
def test_execute_failure(mock_process, mock_ingestor_class, monitor_cli):
    """Test CLI execution with processing failure"""
    # Mock the process_local_files function to return failure
    mock_process.return_value = False

    # Setup CLI with mock args (local backend auto-detected from paths)
    monitor_cli.args = Mock()
    monitor_cli.args.source_folder = "/tmp/source"
    monitor_cli.args.processed_folder = "/tmp/processed"
    monitor_cli.args.failed_folder = "/tmp/failed"
    monitor_cli.args.schema = "test_schema"
    monitor_cli.args.validator = None
    monitor_cli.args.schema_file = None
    monitor_cli.logger = Mock()

    # Execute
    exit_code = monitor_cli.execute()

    # Assertions
    assert exit_code == 1


@patch("ocsf_monitor.OCSFIngestor")
def test_execute_initialization_error(mock_ingestor_class, monitor_cli):
    """Test CLI execution with initialization error"""
    # Mock ingestor initialization to raise exception
    mock_ingestor_class.side_effect = Exception("Init error")

    # Setup CLI with mock args (local backend auto-detected from paths)
    monitor_cli.args = Mock()
    monitor_cli.args.source_folder = "/tmp/source"
    monitor_cli.args.processed_folder = "/tmp/processed"
    monitor_cli.args.failed_folder = "/tmp/failed"
    monitor_cli.args.schema = "test_schema"
    monitor_cli.args.validator = None
    monitor_cli.args.schema_file = None
    monitor_cli.logger = Mock()

    # Execute
    exit_code = monitor_cli.execute()

    # Assertions
    assert exit_code == 1


@patch("ocsf_monitor.signal.signal")
@patch("ocsf_monitor.OCSFIngestor")
@patch("ocsf_monitor.process_local_files")
def test_execute_registers_signal_handlers(mock_process, mock_ingestor_class, mock_signal, monitor_cli):
    """Test that execute registers signal handlers"""
    mock_process.return_value = True

    # Setup CLI with mock args (local backend auto-detected from paths)
    monitor_cli.args = Mock()
    monitor_cli.args.source_folder = "/tmp/source"
    monitor_cli.args.processed_folder = "/tmp/processed"
    monitor_cli.args.failed_folder = "/tmp/failed"
    monitor_cli.args.schema = "test_schema"
    monitor_cli.args.validator = None
    monitor_cli.args.schema_file = None
    monitor_cli.logger = Mock()

    # Execute
    monitor_cli.execute()

    # Check signal handlers were registered
    signal_calls = [call[0] for call in mock_signal.call_args_list]
    assert (signal.SIGINT, ocsf_monitor.signal_handler) in signal_calls
    assert (signal.SIGTERM, ocsf_monitor.signal_handler) in signal_calls


# validate_ocsf_file Tests
@patch("ocsf_monitor.subprocess.run")
def test_validate_ocsf_file_success(mock_run):
    """Test validate_ocsf_file with successful validation"""
    # Mock successful validation
    mock_result = Mock()
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    mock_logger = Mock()
    file_path = "/tmp/test.ocsf.json"
    validator_cmd = "/usr/bin/validate-ocsf-file"
    schema_file = "/tmp/schema.json"

    result = validate_ocsf_file(file_path, validator_cmd, schema_file, mock_logger)

    # Assertions
    assert result is True
    mock_run.assert_called_once_with(
        [validator_cmd, "--schema-file", schema_file, "--data-file", file_path],
        check=True,
        capture_output=True,
        text=True,
    )
    mock_logger.debug.assert_called()


@patch("ocsf_monitor.subprocess.run")
def test_validate_ocsf_file_validation_failure(mock_run):
    """Test validate_ocsf_file with validation failure (invalid OCSF file)"""
    # Mock validation failure
    mock_run.side_effect = subprocess.CalledProcessError(
        returncode=1,
        cmd=["validate-ocsf-file"],
        output="Validation failed",
        stderr="Error: Invalid OCSF format",
    )

    mock_logger = Mock()
    file_path = "/tmp/invalid.ocsf.json"
    validator_cmd = "/usr/bin/validate-ocsf-file"
    schema_file = "/tmp/schema.json"

    result = validate_ocsf_file(file_path, validator_cmd, schema_file, mock_logger)

    # Assertions
    assert result is False
    mock_logger.error.assert_called()


@patch("ocsf_monitor.subprocess.run")
def test_validate_ocsf_file_with_stdout_and_stderr(mock_run):
    """Test validate_ocsf_file logs stdout and stderr on failure"""
    # Mock validation failure with both stdout and stderr
    error = subprocess.CalledProcessError(
        returncode=1, cmd=["validate-ocsf-file"], output="stdout output", stderr="stderr output"
    )
    error.stdout = "stdout output"
    error.stderr = "stderr output"
    mock_run.side_effect = error

    mock_logger = Mock()
    file_path = "/tmp/test.ocsf.json"
    validator_cmd = "/usr/bin/validate-ocsf-file"
    schema_file = "/tmp/schema.json"

    result = validate_ocsf_file(file_path, validator_cmd, schema_file, mock_logger)

    # Assertions
    assert result is False
    # Check that error logs include stdout and stderr
    error_calls = [str(call) for call in mock_logger.error.call_args_list]
    assert any("stdout output" in str(call) for call in error_calls)
    assert any("stderr output" in str(call) for call in error_calls)


@patch("ocsf_monitor.subprocess.run")
def test_validate_ocsf_file_validator_not_found(mock_run):
    """Test validate_ocsf_file when validator command is not found"""
    # Mock FileNotFoundError (command not found)
    mock_run.side_effect = FileNotFoundError("Validator command not found")

    mock_logger = Mock()
    file_path = "/tmp/test.ocsf.json"
    validator_cmd = "/usr/bin/nonexistent-validator"
    schema_file = "/tmp/schema.json"

    # Should return False and log error (graceful handling)
    result = validate_ocsf_file(file_path, validator_cmd, schema_file, mock_logger)

    assert result is False
    # Check that error was logged
    mock_logger.error.assert_called()
    # Verify error message mentions validator not found
    error_calls = [str(call) for call in mock_logger.error.call_args_list]
    assert any("not found" in str(call).lower() for call in error_calls)


@patch("ocsf_monitor.subprocess.run")
def test_validate_ocsf_file_with_empty_output(mock_run):
    """Test validate_ocsf_file with validation failure but no output"""
    # Mock validation failure with no stdout/stderr
    error = subprocess.CalledProcessError(returncode=1, cmd=["validate-ocsf-file"])
    error.stdout = None
    error.stderr = None
    mock_run.side_effect = error

    mock_logger = Mock()
    file_path = "/tmp/test.ocsf.json"
    validator_cmd = "/usr/bin/validate-ocsf-file"
    schema_file = "/tmp/schema.json"

    result = validate_ocsf_file(file_path, validator_cmd, schema_file, mock_logger)

    # Assertions
    assert result is False
    # Should still log error even without stdout/stderr
    mock_logger.error.assert_called()


@patch("ocsf_monitor.subprocess.run")
def test_validate_ocsf_file_logs_command(mock_run):
    """Test that validate_ocsf_file logs the validation command"""
    # Mock successful validation
    mock_result = Mock()
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    mock_logger = Mock()
    file_path = "/tmp/test.ocsf.json"
    validator_cmd = "/usr/bin/validate-ocsf-file"
    schema_file = "/tmp/schema.json"

    validate_ocsf_file(file_path, validator_cmd, schema_file, mock_logger)

    # Check that debug log includes the command
    debug_calls = [str(call) for call in mock_logger.debug.call_args_list]
    assert any("Running validation" in str(call) for call in debug_calls)
    assert any(validator_cmd in str(call) for call in debug_calls)


# CLI Integration Tests
def test_ocsf_monitor_cli_no_argument():
    """Test that ocsf_monitor.py CLI script runs without argument"""

    # Get path to the ocsf_monitor.py script
    script_dir = Path(__file__).parent.parent
    script_path = script_dir / "ocsf_monitor.py"

    result = subprocess.run([sys.executable, str(script_path), "--help"], capture_output=True, text=True)

    assert result.returncode == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
