# Contributing to OCSF Converters

## Architecture

### Converters
All converters extend `BaseOCSFConverter` (`converters/base_converter.py`) which provides:
- Enrichment system integration
- Common `save_to_file()` implementation
- Standardized `convert_file()` interface

### Enrichments
Enrichments extend `EnrichmentPlugin` (`enrichments/base.py`) and add metadata to findings without modifying converter logic.

### CLI Scripts
CLI scripts extend `BaseConverterCLI` (`base_cli.py`) for automatic enrichment discovery and consistent CLI interfaces.

## Adding a New Converter

1. Create converter class extending `BaseOCSFConverter` in `converters/`
2. Implement `convert_file()` method
3. Call `self.apply_enrichments(finding)` for each finding
4. Export in `converters/__init__.py`
5. Create CLI script using `BaseConverterCLI`

### Example Converter

```python
# converters/my_format_to_ocsf.py
from .base_converter import BaseOCSFConverter
from typing import List, Dict, Any

class MyFormatToOCSFConverter(BaseOCSFConverter):
    def convert_file(self, input_path: str) -> List[Dict[str, Any]]:
        findings = []
        # ... parse input file ...

        # Apply enrichments to each finding
        for finding in findings:
            finding = self.apply_enrichments(finding)

        return findings
```

## Creating a CLI Script

Extend `BaseConverterCLI` for automatic enrichment support:

```python
#!/usr/bin/env python3
"""My Format to OCSF Converter"""

import sys
from pathlib import Path
from base_cli import BaseConverterCLI
from converters import MyFormatToOCSFConverter


class MyFormatConverterCLI(BaseConverterCLI):
    def get_description(self) -> str:
        return 'Convert My Format files to OCSF'

    def get_converter_class(self):
        return MyFormatToOCSFConverter

    def add_positional_arguments(self, parser):
        parser.add_argument('input_file', help='Input file path')

    def perform_conversion(self, converter):
        """Perform the conversion."""
        self.logger.info(f"Converting file {self.args.input_file}")
        return converter.convert_file(self.args.input_file)

    # Optional: Add validation
    def validate_arguments(self):
        if not Path(self.args.input_file).exists():
            self.logger.error(f"File not found: {self.args.input_file}")
            sys.exit(1)

    # Optional: Add custom arguments
    def add_converter_arguments(self, parser):
        parser.add_argument('--custom-option', help='Custom option')


if __name__ == '__main__':
    MyFormatConverterCLI().run()
```

### Required Methods
- `get_description()` - CLI description
- `get_converter_class()` - Return converter class
- `add_positional_arguments()` - Define positional arguments (output_file is added automatically)
- `perform_conversion(converter)` - Execute the conversion and return findings

### Optional Overrides
- `add_converter_arguments()` - Additional CLI options
- `validate_arguments()` - Input validation logic
- `get_epilog()` - Usage examples in help text
- `setup_logging()` - Custom logging configuration
- `create_converter()` - Custom converter initialization

See `sarif_to_ocsf.py` for a complete example.

## Non-File Converters

For API-based or query-based converters, customize the positional arguments and conversion method:

```python
def add_positional_arguments(self, parser):
    parser.add_argument('project_key', help='JIRA project key')
    # output_file is added automatically by base class

def add_converter_arguments(self, parser):
    parser.add_argument('--api-key', required=True, help='API key')

def perform_conversion(self, converter):
    """Perform API-based conversion."""
    self.logger.info(f"Fetching from project {self.args.project_key}")
    # Assuming your converter has a different method for API access
    return converter.convert_from_api(self.args.project_key, self.args.api_key)

def validate_arguments(self):
    if not self.args.api_key:
        self.logger.error("API key required")
        sys.exit(1)
```

The `perform_conversion()` method allows flexibility in how conversion happens - file-based converters call `convert_file()`, API-based converters can call different methods.

**Note**: The base class automatically adds `output_file` as the last positional argument - you only need to define your converter-specific positional arguments.

## Code Quality

This project uses pre-commit hooks to ensure code quality with Ruff linting and formatting.

### Setup Pre-commit Hooks

```bash
pip install -r requirements-dev.txt
pre-commit install
```

### Running Checks

Run on all files:
```bash
pre-commit run --all-files
```

Run on staged files only:
```bash
pre-commit run
```

Pre-commit will automatically run when you commit.

## Testing

Run all tests:
```bash
cd scripts
python -m unittest discover -s tests -p "test_*.py"
```

Run specific test file:
```bash
python -m unittest tests.test_enrichment_utils
```

