# Contributing to Boann OCSF Security Data Platform

Thank you for your interest in contributing to the Boann OCSF Security Data Platform! This guide will help you set up your local development environment and understand how to contribute effectively.

## Table of Contents

- [Local Development Setup](#local-development-setup)
- [Running the Ingestion Process](#running-the-ingestion-process)
- [Development Workflow](#development-workflow)
- [Architecture](#architecture)
- [Code Quality](#code-quality)
- [Testing](#testing)

## Local Development Setup

### Prerequisites

Before starting, ensure you have the following installed:

- **Podman**: A daemonless container engine. [Install Podman](https://podman.io/docs/installation)
- **Podman Compose**: For defining and running multi-container applications. [Install Podman Compose](https://github.com/containers/podman-compose)
- **Python 3.12+**: Required for running scripts locally (optional if using containers)

### Step-by-Step Setup

#### 1. Clone the Repository

```bash
git clone https://github.com/RedHatProductSecurity/boann-ocsf-security-data-platform.git
cd boann-ocsf-security-data-platform
```

#### 2. Configure Environment Variables

Create a `.env` file in the project root by copying the example:

```bash
cp env.example .env
```

Edit the `.env` file to customize the database credentials if needed:

```bash
DATABASE_URL=postgresql://boann_user:boann_password@localhost:5432/boann_db
```

**Format**: `postgresql://username:password@host:port/database_name`

#### 3. Start the Environment

Use the provided helper script to start PostgreSQL and the application container:

```bash
./scripts/run_podman.sh
```

This script will:
- Parse your `DATABASE_URL` from the `.env` file
- Extract PostgreSQL credentials
- Start both the database and application containers
- Display connection information

#### 4. Verify the Setup

Check that containers are running:

```bash
podman ps
```

You should see two containers:
- `boann-db` - PostgreSQL database
- `boann-app` - Python application container

### Connecting to the Database

#### Using psql

```bash
# Connect from your host machine
psql -h localhost -p 5432 -U boann_user -d boann_db

# Or use the DATABASE_URL directly
psql $DATABASE_URL
```

#### Using the Application Container

```bash
# Execute commands inside the application container
podman exec -it boann-app bash

# From inside the container, you can run scripts
cd /app/scripts
python ingest_raw_ocsf_findings.py --help
```

### Managing the Environment

#### View Logs

```bash
# View logs for all services
podman-compose logs -f

# View logs for specific service
podman-compose logs -f boann_db
podman-compose logs -f boann_app
```

#### Stop the Environment

```bash
# Stop containers (data is preserved)
podman-compose down

# Stop and remove volumes (deletes all data)
podman-compose down -v
```

#### Restart the Environment

```bash
# Start again
./scripts/run_podman.sh

# Or manually
podman-compose up -d
```

## Running the Ingestion Process

### Database Schema Setup with dbt

The database schema is automatically created using **dbt (Data Build Tool)** when you start the environment with `./scripts/run_podman.sh`. 

dbt manages the database schema as code, providing:
- Version-controlled schema definitions
- Automated table creation and updates
- Schema documentation and lineage
- Incremental model support

The `./scripts/run_podman.sh` script automatically:
1. Starts PostgreSQL and application containers
2. Installs dbt packages (`dbt deps`)
3. Creates schemas using `dbt run`

This creates:
- `boann_landing` schema with `raw_ocsf_findings` table (incremental, append-only)
- `boann_staging` schema with `stg_ocsf_findings` table (extracted and flattened OCSF fields)

**No manual steps required!** You can verify the schema was created:

```bash
# Check that the schemas and tables exist
psql $DATABASE_URL -c "\dt boann_landing.*"
psql $DATABASE_URL -c "\dt boann_staging.*"
```

### Manual dbt Operations (if needed)

If you need to manually run dbt or reset the schema:

```bash
# Access the container
podman exec -it boann-app bash
cd /app/dbt_project

# Install/update packages
dbt deps

# Create all schemas
dbt run

# Rebuild specific models
dbt run --select landing  # Just landing layer
dbt run --select staging  # Just staging layer

# Rebuild from scratch
dbt run --full-refresh
```

**Understanding the dbt Project:**

```
dbt_project/
├── dbt_project.yml          # Project configuration
├── profiles.yml             # Database connection config
├── packages.yml             # dbt package dependencies
├── macros/                  # Reusable SQL macros
│   ├── add_new_indexes.sql
│   └── add_finding_uid_constraint.sql
└── models/
    ├── schema.yaml          # Model documentation
    ├── landing/
    │   └── raw_ocsf_findings.sql  # Landing table
    └── staging/
        └── stg_ocsf_findings.sql  # Staging transformations
```

**Data Flow:**
1. Python scripts insert raw OCSF JSON into `raw_ocsf_findings` (landing layer)
2. dbt incrementally processes new records into `stg_ocsf_findings` (staging layer)
3. Staging layer extracts and flattens OCSF fields for downstream use

The landing model defines the table structure, while Python scripts handle data insertion. The staging model runs as part of `dbt run` to transform landing data.

### Complete Workflow Example

Here's a complete workflow from SARIF to database:

#### 1. Convert SARIF to OCSF

```bash
# Using sample data
python sarif_to_ocsf.py \
    tests/fixtures/sample.sarif \
    output.ocsf.json
```

#### 2. Ingest OCSF into Database

```bash
# Ingest the converted file
python ingest_raw_ocsf_findings.py \
    --input-file output.ocsf.json
```

#### 3. Verify Ingestion

```bash
# Check the data in PostgreSQL
psql $DATABASE_URL -c "SELECT finding_uid, loaded_at FROM boann_landing.raw_ocsf_findings LIMIT 5;"
```

### Working with Enrichments

Use custom enrichments during conversion:

```bash
# Create custom enrichment directory
mkdir my_enrichments

# Add your enrichment plugin (see Architecture section)
# Then use it:
python sarif_to_ocsf.py \
    input.sarif output.json \
    --enrichment-dir ./my_enrichments
```

## Development Workflow

### Option 1: Using the Containerized Environment

Best for consistent, isolated development:

```bash
# Start the environment
../scripts/run_podman.sh

# Access the container
podman exec -it boann-app bash

# Inside container, run scripts
cd /app/scripts
python sarif_to_ocsf.py --help

# Edit files on your host - they're mounted and changes reflect immediately
# The scripts directory is volume-mounted for live development
```

### Option 2: Local Development with venv

Best for rapid iteration and debugging:

```bash
# From project root
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run scripts locally
cd scripts
python sarif_to_ocsf.py input.sarif output.json

# Database is still running in container, accessible at localhost:5432
```

### Testing Changes

Always test your changes before submitting:

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_sarif_converter.py -v

# Run with coverage
pytest tests/ --cov=. --cov-report=term-missing
```

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

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_sarif_converter.py -v

# Run with coverage
pytest tests/ --cov=. --cov-report=term-missing

# Run specific test
pytest tests/test_sarif_converter.py::test_severity_mapping
```

### Writing Tests

See the [AGENTS.md](../AGENTS.md) file for comprehensive testing guidelines, including:
- Focus on behavior, not implementation
- Avoid redundancy
- Use parametrized tests
- Create reusable fixtures

### Test Organization

- **Location**: Place tests in `tests/`
- **Naming**: `test_<component>.py` (e.g., `test_sarif_converter.py`)
- **Fixtures**: Store test data in `tests/fixtures/`

## Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `pytest tests/ -v`
5. Run linting: `pre-commit run --all-files`
6. Commit with descriptive message: `git commit -m "Add feature X"`
7. Push to your fork: `git push origin feature/my-feature`
8. Create a Pull Request

## Getting Help

- Check existing [issues](https://github.com/RedHatProductSecurity/boann-ocsf-security-data-platform/issues)
- Review [documentation](../docs/)
- Open a new issue for bugs or feature requests

Thank you for contributing!

