# Boann OCSF Security Data Platform

> **WORK IN PROGRESS - HERE BE DRAGONS**
>
> This project is under active development. Features, APIs, and data formats may change without notice. Use at your own risk in production environments.

## Overview

The Boann OCSF Security Data Platform provides tools and converters for processing security findings into the OCSF (Open Cybersecurity Schema Framework) format. This platform serves as a foundation for ingesting, converting, and enriching security data from various sources.

## Features

- **SARIF to OCSF Conversion** - Convert security scan results to OCSF format
- **Enrichment System** - Extensible plugin architecture for metadata augmentation
- **Finding UID Generation** - Stable unique identifiers for deduplication
- **Database Ingestion** - PostgreSQL storage with upsert capabilities
- **File Monitoring** - Automated directory processing

## Quick Start

```bash
# Convert SARIF to OCSF
python scripts/sarif_to_ocsf.py input.sarif output.ocsf.json

# Ingest into PostgreSQL
python scripts/ingest_raw_ocsf_findings.py --input-file findings.ocsf.json

# Monitor directory for automatic processing
python scripts/ocsf_monitor.py \
    --source-folder /path/to/files/ \
    --processed-folder /path/processed/ \
    --failed-folder /path/failed/
```

See [scripts/README.md](scripts/README.md) for detailed usage and examples.

## Documentation

- [Scripts Documentation](scripts/README.md) - Detailed usage for all tools and scripts
- [SARIF to OCSF Conversion](docs/SARIF_to_OCSF.md) - Field mappings and conversion details
- [Contributing Guide](scripts/CONTRIBUTING.md) - How to extend and contribute

## Architecture

```
scripts/
├── converters/         # Format converters (SARIF → OCSF)
├── enrichments/        # Enrichment plugins (UID generation, etc.)
├── sarif_to_ocsf.py   # Conversion CLI
├── ingest_raw_ocsf_findings.py  # Database ingestion
└── ocsf_monitor.py    # Directory monitoring

docs/                  # Additional documentation
```

## Requirements

- Python 3.12+
- PostgreSQL (for ingestion features)
- See individual scripts for specific dependencies

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Status and Limitations

This is an initial release with the following known limitations:

- Not all SARIF fields are converted
- Database schema must be created separately (dbt management tooling planned but not yet available)
- API and data formats subject to change
- Downstream enrichment required for organization-specific data

For issues and questions, please use the GitHub issue tracker.
