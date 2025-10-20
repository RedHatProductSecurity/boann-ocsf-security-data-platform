# OCSF Converters & Enrichments

**NOTE**: This is a design demonstration. The SARIF converter contains placeholder code to showcase the enrichment pattern.

## Overview

This directory contains the generic OCSF converter infrastructure and enrichment system:

- **Converters** (`converters/`) - Transform security tool formats to OCSF
- **Enrichments** (`enrichments/`) - Add organization-specific metadata to findings
- **Enrichment Utilities** (`enrichment_utils.py`) - Automatic enrichment discovery
- **Base CLI** (`base_cli.py`) - Abstract base for converter CLI scripts

## Usage

### Basic Conversion
```bash
python sarif_to_ocsf.py input.sarif output.ocsf.json
```

### With Enrichments
```bash
python sarif_to_ocsf.py scan.sarif output.json \
    --enrichment-dir /path/to/enrichments \
    --enrichment-arg EnrichmentName:key=value
```

### Programmatic API
```python
from converters import SARIFToOCSFConverter
from my_enrichments import MyEnrichment

converter = SARIFToOCSFConverter(enrichments=[MyEnrichment()])
findings = converter.convert_file('scan.sarif')
converter.save_to_file(findings, 'output.ocsf.json')
```

## Creating Custom Enrichments

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
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on creating converters and CLI scripts.
