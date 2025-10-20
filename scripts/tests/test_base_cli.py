#!/usr/bin/env python3
"""
Unit tests for Base CLI Classes

Tests BaseToolCLI and BaseConverterCLI abstract base classes.
"""

import argparse
import os
import sys
from unittest.mock import Mock, patch

import pytest

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from base_cli import BaseToolCLI, BaseConverterCLI


class ConcreteToolCLI(BaseToolCLI):
    """Concrete implementation of BaseToolCLI for testing"""

    def get_description(self) -> str:
        return "Test Tool Description"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument('--test-arg', help='Test argument')

    def execute(self) -> int:
        return 0


class ConcreteConverterCLI(BaseConverterCLI):
    """Concrete implementation of BaseConverterCLI for testing"""

    def get_description(self) -> str:
        return "Test Converter Description"

    def get_converter_class(self):
        return Mock  # Return a mock converter class

    def add_positional_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument('input_file', help='Input file')

    def perform_conversion(self, converter) -> list:
        return [{"test": "finding"}]


# Fixtures
@pytest.fixture
def tool_cli():
    """Fixture for ConcreteToolCLI instance"""
    return ConcreteToolCLI()


@pytest.fixture
def converter_cli():
    """Fixture for ConcreteConverterCLI instance"""
    return ConcreteConverterCLI()


# BaseToolCLI Tests
def test_build_argument_parser(tool_cli):
    """Test argument parser building with custom and default arguments"""
    parser = tool_cli.build_argument_parser()

    # Parse with custom arguments
    args = parser.parse_args(['--test-arg', 'value', '--log-level', 'debug'])
    assert args.test_arg == 'value'
    assert args.log_level == 'debug'

    # Test default log level
    args_default = parser.parse_args(['--test-arg', 'value'])
    assert args_default.log_level == 'info'


@patch('sys.argv', ['test_cli.py', '--test-arg', 'value'])
def test_run_success(tool_cli):
    """Test successful run workflow"""
    exit_code = tool_cli.run()

    assert exit_code == 0
    assert tool_cli.logger is not None
    assert tool_cli.args is not None


@pytest.mark.parametrize("exception,expected_exit_code", [
    (KeyboardInterrupt(), 1),
    (Exception("Test error"), 1),
])
@patch('sys.argv', ['test_cli.py', '--test-arg', 'value'])
def test_run_error_handling(tool_cli, exception, expected_exit_code):
    """Test run handles exceptions gracefully"""
    tool_cli.execute = Mock(side_effect=exception)

    exit_code = tool_cli.run()

    assert exit_code == expected_exit_code


def test_custom_validate_arguments():
    """Test custom validate_arguments extensibility"""
    class CustomToolCLI(ConcreteToolCLI):
        def validate_arguments(self):
            if self.args.test_arg == 'invalid':
                raise SystemExit(1)

    cli = CustomToolCLI()
    cli.args = Mock()

    # Valid argument should not raise
    cli.args.test_arg = 'valid'
    cli.validate_arguments()

    # Invalid argument should raise SystemExit
    cli.args.test_arg = 'invalid'
    with pytest.raises(SystemExit):
        cli.validate_arguments()


# BaseConverterCLI Tests
def test_converter_adds_required_arguments(converter_cli):
    """Test that converter adds all required arguments"""
    parser = converter_cli.build_argument_parser()

    # Parse with all required arguments
    args = parser.parse_args(['input.txt', 'output.json'])

    assert args.input_file == 'input.txt'
    assert args.output_file == 'output.json'


def test_converter_has_enrichment_args(converter_cli):
    """Test that converter CLI has enrichment arguments"""
    parser = converter_cli.build_argument_parser()

    # Parse with enrichment arguments
    args = parser.parse_args([
        'input.txt',
        'output.json',
        '--enrichment-dir', '/path/to/enrichments',
        '--enrichment-arg', 'MyEnrichment:param=value'
    ])

    assert args.enrichment_dirs == ['/path/to/enrichments']
    assert args.enrichment_args == ['MyEnrichment:param=value']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
