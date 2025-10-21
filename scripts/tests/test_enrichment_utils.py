#!/usr/bin/env python3
"""
Unit tests for enrichment_utils module.

Tests enrichment discovery, argument parsing, instantiation,
and CLI argument helper functions.
"""

import unittest
import sys
import os
import tempfile
import logging
from pathlib import Path

# Add parent directory to path to import the module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import enrichment_utils
from enrichments import EnrichmentPlugin


class TestDiscoverEnrichments(unittest.TestCase):
    """Tests for discover_enrichments function."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = Path(__file__).parent / 'fixtures' / 'test_enrichments'
        self.logger = logging.getLogger('test')
        self.logger.setLevel(logging.CRITICAL)  # Suppress log output during tests

    def test_discover_enrichments_from_valid_directory(self):
        """Test discovering enrichments from a valid directory."""
        enrichment_classes = enrichment_utils.discover_enrichments(
            [str(self.test_dir)],
            self.logger
        )

        # Should discover SimpleEnrichment, ParametricEnrichment, AnotherEnrichment, and BrokenEnrichment
        # Should NOT discover _ignored_enrichment.py (starts with underscore)
        self.assertGreaterEqual(len(enrichment_classes), 3)

        class_names = [cls.__name__ for cls in enrichment_classes]
        self.assertIn('SimpleEnrichment', class_names)
        self.assertIn('ParametricEnrichment', class_names)
        self.assertIn('AnotherEnrichment', class_names)
        self.assertNotIn('IgnoredEnrichment', class_names)

    def test_discover_enrichments_non_existent_directory(self):
        """Test handling of non-existent directory."""
        enrichment_classes = enrichment_utils.discover_enrichments(
            ['/path/that/does/not/exist'],
            self.logger
        )

        # Should return empty list and not crash
        self.assertEqual(len(enrichment_classes), 0)

    def test_discover_enrichments_file_instead_of_directory(self):
        """Test handling when a file path is provided instead of directory."""
        test_file = self.test_dir / 'simple_enrichment.py'
        enrichment_classes = enrichment_utils.discover_enrichments(
            [str(test_file)],
            self.logger
        )

        # Should return empty list and not crash
        self.assertEqual(len(enrichment_classes), 0)

    def test_discover_enrichments_multiple_directories(self):
        """Test discovering enrichments from multiple directories."""
        # Create a temporary second directory with another enrichment
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write a test enrichment to temp directory
            test_enrichment_path = Path(tmpdir) / 'temp_enrichment.py'
            test_enrichment_path.write_text('''
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../'))
from enrichments import EnrichmentPlugin

class TempEnrichment(EnrichmentPlugin):
    def enrich(self, finding):
        return finding
''')

            enrichment_classes = enrichment_utils.discover_enrichments(
                [str(self.test_dir), tmpdir],
                self.logger
            )

            # Should discover enrichments from both directories
            class_names = [cls.__name__ for cls in enrichment_classes]
            self.assertIn('SimpleEnrichment', class_names)
            self.assertIn('TempEnrichment', class_names)

    def test_discover_enrichments_ignores_dunder_files(self):
        """Test that __init__.py files are ignored."""
        # Create a temp directory with __init__.py
        with tempfile.TemporaryDirectory() as tmpdir:
            init_file = Path(tmpdir) / '__init__.py'
            init_file.write_text('# This should be ignored')

            enrichment_classes = enrichment_utils.discover_enrichments(
                [tmpdir],
                self.logger
            )

            # Should return empty list since only __init__.py exists
            self.assertEqual(len(enrichment_classes), 0)


class TestParseEnrichmentArgs(unittest.TestCase):
    """Tests for parse_enrichment_args function."""

    def setUp(self):
        """Set up test fixtures."""
        self.logger = logging.getLogger('test')
        self.logger.setLevel(logging.CRITICAL)

    def test_parse_valid_argument(self):
        """Test parsing a valid enrichment argument."""
        args = ['SimpleEnrichment:param1=value1']
        result = enrichment_utils.parse_enrichment_args(args, self.logger)

        self.assertEqual(result, {
            'SimpleEnrichment': {'param1': 'value1'}
        })

    def test_parse_multiple_arguments_same_enrichment(self):
        """Test parsing multiple arguments for the same enrichment."""
        args = [
            'ParametricEnrichment:param1=value1',
            'ParametricEnrichment:param2=value2'
        ]
        result = enrichment_utils.parse_enrichment_args(args, self.logger)

        self.assertEqual(result, {
            'ParametricEnrichment': {
                'param1': 'value1',
                'param2': 'value2'
            }
        })

    def test_parse_arguments_multiple_enrichments(self):
        """Test parsing arguments for different enrichments."""
        args = [
            'EnrichmentA:param1=valueA',
            'EnrichmentB:param1=valueB'
        ]
        result = enrichment_utils.parse_enrichment_args(args, self.logger)

        self.assertEqual(result, {
            'EnrichmentA': {'param1': 'valueA'},
            'EnrichmentB': {'param1': 'valueB'}
        })

    def test_parse_invalid_format_missing_colon(self):
        """Test handling invalid format without colon."""
        args = ['InvalidFormat']
        result = enrichment_utils.parse_enrichment_args(args, self.logger)

        # Should return empty dict and not crash
        self.assertEqual(result, {})

    def test_parse_invalid_format_missing_equals(self):
        """Test handling invalid format without equals sign."""
        args = ['EnrichmentName:invalid']
        result = enrichment_utils.parse_enrichment_args(args, self.logger)

        # Should return empty dict and not crash
        self.assertEqual(result, {})

    def test_parse_empty_args_list(self):
        """Test parsing an empty arguments list."""
        result = enrichment_utils.parse_enrichment_args([], self.logger)

        self.assertEqual(result, {})

    def test_parse_argument_with_special_characters(self):
        """Test parsing arguments with special characters in values."""
        args = ['Enrichment:url=https://example.com/path?key=value']
        result = enrichment_utils.parse_enrichment_args(args, self.logger)

        self.assertEqual(result, {
            'Enrichment': {'url': 'https://example.com/path?key=value'}
        })


class TestInstantiateEnrichments(unittest.TestCase):
    """Tests for instantiate_enrichments function."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = Path(__file__).parent / 'fixtures' / 'test_enrichments'
        self.logger = logging.getLogger('test')
        self.logger.setLevel(logging.CRITICAL)

        # Discover enrichment classes for testing
        self.enrichment_classes = enrichment_utils.discover_enrichments(
            [str(self.test_dir)],
            self.logger
        )

    def test_instantiate_enrichment_with_default_args(self):
        """Test instantiating enrichment with default arguments."""
        simple_class = [c for c in self.enrichment_classes if c.__name__ == 'SimpleEnrichment'][0]

        enrichments = enrichment_utils.instantiate_enrichments(
            [simple_class],
            {},
            self.logger
        )

        self.assertEqual(len(enrichments), 1)
        self.assertIsInstance(enrichments[0], EnrichmentPlugin)

    def test_instantiate_enrichment_with_custom_args(self):
        """Test instantiating enrichment with custom arguments."""
        parametric_class = [c for c in self.enrichment_classes if c.__name__ == 'ParametricEnrichment'][0]

        enrichments = enrichment_utils.instantiate_enrichments(
            [parametric_class],
            {'ParametricEnrichment': {'param1': 'custom1', 'param2': 'custom2'}},
            self.logger
        )

        self.assertEqual(len(enrichments), 1)
        self.assertEqual(enrichments[0].param1, 'custom1')
        self.assertEqual(enrichments[0].param2, 'custom2')

    def test_instantiate_multiple_enrichments(self):
        """Test instantiating multiple enrichments."""
        simple_class = [c for c in self.enrichment_classes if c.__name__ == 'SimpleEnrichment'][0]
        another_class = [c for c in self.enrichment_classes if c.__name__ == 'AnotherEnrichment'][0]

        enrichments = enrichment_utils.instantiate_enrichments(
            [simple_class, another_class],
            {},
            self.logger
        )

        self.assertEqual(len(enrichments), 2)

    def test_instantiate_enrichment_with_missing_required_arg(self):
        """Test that broken enrichments are skipped gracefully."""
        broken_class = [c for c in self.enrichment_classes if c.__name__ == 'BrokenEnrichment'][0]

        # Should not crash, just skip the broken enrichment
        enrichments = enrichment_utils.instantiate_enrichments(
            [broken_class],
            {},  # Missing required_param
            self.logger
        )

        # Should return empty list since instantiation failed
        self.assertEqual(len(enrichments), 0)


class TestAddEnrichmentArguments(unittest.TestCase):
    """Tests for add_enrichment_arguments helper function."""

    def test_add_enrichment_arguments_adds_all_args(self):
        """Test that add_enrichment_arguments adds all expected arguments."""
        parser = enrichment_utils.argparse.ArgumentParser()
        enrichment_utils.add_enrichment_arguments(parser)

        # Parse a test command with enrichment arguments
        args = parser.parse_args([
            '--enrichment-dir', '/path/to/enrichments',
            '--enrichment-arg', 'TestEnrichment:param=value'
        ])

        self.assertEqual(args.enrichment_dirs, ['/path/to/enrichments'])
        self.assertEqual(args.enrichment_args, ['TestEnrichment:param=value'])

    def test_add_enrichment_arguments_returns_parser(self):
        """Test that add_enrichment_arguments returns the parser for chaining."""
        parser = enrichment_utils.argparse.ArgumentParser()
        result = enrichment_utils.add_enrichment_arguments(parser)

        self.assertIs(result, parser)

    def test_add_enrichment_arguments_allows_chaining(self):
        """Test that arguments can be added before and after calling helper."""
        parser = enrichment_utils.argparse.ArgumentParser()
        parser.add_argument('input_file')
        enrichment_utils.add_enrichment_arguments(parser)
        parser.add_argument('output_file')

        args = parser.parse_args([
            'in.txt',
            '--enrichment-dir', '/path',
            'out.txt'
        ])

        self.assertEqual(args.input_file, 'in.txt')
        self.assertEqual(args.output_file, 'out.txt')
        self.assertEqual(args.enrichment_dirs, ['/path'])


if __name__ == '__main__':
    unittest.main()

