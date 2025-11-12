# Scripts Documentation

This directory contains converters, enrichment plugins, and tools for processing security findings into OCSF format.

> **Note**: For local development setup with PostgreSQL using Podman, see [CONTRIBUTING.md](CONTRIBUTING.md#local-development-setup).

## Available Scripts

### sarif_to_ocsf.py

Convert SARIF files to OCSF format.

```bash
# Basic usage
python sarif_to_ocsf.py input.sarif output.ocsf.json

# With custom enrichments
python sarif_to_ocsf.py scan.sarif output.json \
    --enrichment-dir /path/to/enrichments
```

For all options: `python sarif_to_ocsf.py --help`

### ingest_raw_ocsf_findings.py

Ingest OCSF JSON files into PostgreSQL.

```bash
# Basic usage
python ingest_raw_ocsf_findings.py --input-file findings.ocsf.json

# With custom schema
python ingest_raw_ocsf_findings.py --input-file findings.ocsf.json --schema custom_schema
```

For all options: `python ingest_raw_ocsf_findings.py --help`

### ocsf_monitor.py

Monitor directory for OCSF files and automatically ingest them.

```bash
python ocsf_monitor.py \
    --source-folder /path/to/files/ \
    --processed-folder /path/processed/ \
    --failed-folder /path/failed/
```

For all options: `python ocsf_monitor.py --help`

## Programmatic API Usage

### SARIF Conversion

```python
from converters import SARIFToOCSFConverter

# Basic conversion
converter = SARIFToOCSFConverter()
findings = converter.convert_file('scan.sarif')
converter.save_to_file(findings, 'output.ocsf.json')

# With custom enrichments
from my_enrichments import MyEnrichment
converter = SARIFToOCSFConverter(enrichments=[MyEnrichment()])
findings = converter.convert_file('scan.sarif')
```

### OCSF Ingestion

```python
from ingest_raw_ocsf_findings import OCSFIngestor

ingestor = OCSFIngestor(schema="boann_landing")
success = ingestor.ingest_file("/path/to/file.ocsf.json")
```

## Creating Custom Enrichments

Enrichments add custom metadata to findings during conversion.

```python
from enrichments import EnrichmentPlugin

class MyEnrichment(EnrichmentPlugin):
    def enrich(self, finding):
        if 'enrichments' not in finding:
            finding['enrichments'] = []

        finding['enrichments'].append({
            'name': 'custom_field',
            'value': 'custom_value'
        })
        return finding

    def get_name(self):
        return "MyEnrichment"
```

Save to `my_enrichments/my_enrichment.py` and use with:
```bash
python sarif_to_ocsf.py input.sarif output.json --enrichment-dir ./my_enrichments
```

## Built-in Enrichments

### FindingUIDGenerator

Generates stable unique finding UIDs for deduplication.

- **Format**: `boann:<sdlc-type>:<tool>:<uid-type>:<hash>`
- **UID Type**: `fingerprint` (preferred) or `hash` (fallback)
- **Enabled by default** in SARIFToOCSFConverter

Examples:
```
# Fingerprint-based (when SARIF fingerprints available)
boann:sast:snyk:fingerprint:7f3e9c8b2a1d4f6e...

# Hash-based (fallback when no fingerprints)
boann:sast:bandit:hash:a3f5e2c1b8d9...
```

See [SARIF to OCSF Conversion](../docs/SARIF_to_OCSF.md) for details.

## Directory Structure

```
scripts/
├── converters/              # Format converters
│   ├── base_converter.py
│   └── sarif_to_ocsf.py
├── enrichments/             # Enrichment plugins
│   ├── base.py
│   └── finding_uid_generator.py
├── tests/                   # Unit tests
├── sarif_to_ocsf.py        # SARIF conversion CLI
├── ingest_raw_ocsf_findings.py  # Database ingestion CLI
└── ocsf_monitor.py         # Directory monitoring CLI
```

## Development Setup

### Using venv and pip

For development and testing:

```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Install dependencies for development and testing
pip install -r requirements-dev.txt
```

For running scripts only:

```bash
# Install runtime dependencies only
pip install -r requirements.txt
```

## Environment Configuration

For database ingestion, configure connection using `DATABASE_URL` in `.env`:

```bash
DATABASE_URL=postgresql://username:password@localhost:5432/database_name
```

**Local Development**: If you're using the Podman setup (see [CONTRIBUTING.md](CONTRIBUTING.md#local-development-setup)), copy `env.example` to `.env` and the database will be automatically configured and started.

## Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test
python -m pytest tests/test_finding_uid_generator.py -v
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on creating converters and enrichment plugins.
