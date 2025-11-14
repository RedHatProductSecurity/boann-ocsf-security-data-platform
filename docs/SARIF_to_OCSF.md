# SARIF to OCSF Conversion

This document explains how SARIF files are converted to OCSF format.

SARIF (Static Analysis Results Interchange Format) is a standard format used by security scanning tools to report code vulnerabilities and weaknesses.

**Important**: This is an initial version of the SARIF converter. It converts the basic fields needed for tracking and analyzing security findings. Not all SARIF fields are included - only the most important ones for querying and visualization are converted.

## What is Converted

The converter processes SARIF files from security scanning tools and creates OCSF findings. Each security issue found by the scanner becomes one OCSF finding.

## What is Intentionally Excluded

Some SARIF fields are not converted because they contain too much detail for general use or can be found in the original report:

- **Code flows** (`results[x].codeFlows`): Shows the detailed steps of how the code reaches the vulnerability. These are very detailed and best viewed in the original SARIF report.
- **Column positions** (`startColumn` and `endColumn`): Very specific location details. The converter includes line numbers, but exact column positions can be found in the original report.

For complete details about any finding, users should access the original SARIF report through the `finding_info.src_url` field (which is added during downstream enrichment).

## Example

Here is an example of a SARIF finding converted to OCSF (shown in YAML for readability):

```yaml
metadata:
  product:
    name: csmock
    version: 3.5.0
  version: 1.5.0

severity_id: 4        # See Severity Mapping section
severity: Medium

activity_name: Update
activity_id: 2

finding_info:
  uid: boann:sast:csmock:fingerprint:2fa0ad587f4795fc6c8fb440da205625be0bb095
  title: "CWE-457: Use of uninitialized variable"
  desc: "Using uninitialized value 'errsave' when calling 'strerror'"
  created_time: 1705314600000

category_name: Findings
category_uid: 2
class_name: Application Security Posture Finding
class_uid: 2007

vulnerabilities:
  - cwe:
      uid: CWE-457
    affected_code:
      file: src/main.c
      start_line: 42
      end_line: 42

enrichments:
  - name: fingerprints
    value: SARIF fingerprints
    type: fingerprints
    data:
      csdiff/v0: 55ebf10003c842e4a2030da5ab067b1d8087cc9a
      csdiff/v1: 2fa0ad587f4795fc6c8fb440da205625be0bb095
  - name: uid_generation
    data:
      method: fingerprint
      version: v1
      algorithm: sha256

time: 1705314600000
type_uid: 200702
```

## Field Mappings

### Basic OCSF Fields

These fields are the same for all SARIF findings:

- **class_name**: Always "Application Security Posture Finding"
- **class_uid**: Always 2007
- **category_name**: Always "Findings"
- **category_uid**: Always 2
- **activity_id**: Always 2 (Update)
- **activity_name**: Always "Update"
- **metadata.version**: Always "1.5.0" (OCSF schema version)
- **type_uid**: Always 200702 (calculated as class_uid × 100 + activity_id)

### Severity Mapping

SARIF uses four severity levels. We map them to OCSF like this:

| SARIF Level | OCSF Severity | OCSF ID |
|-------------|---------------|---------|
| error       | High          | 5       |
| warning     | Medium        | 4       |
| note        | Informational | 2       |
| none        | Unknown       | 1       |

OCSF has 8 severity levels: Unknown (1), Informational (2), Low (3), Medium (4), High (5), Critical (6), Fatal (7), and Other (99).

### Tool Information

The converter extracts information about the scanning tool from SARIF:

- **metadata.product.name**: Tool name (from `runs[x].tool.driver.name`)
- **metadata.product.version**: Tool version (from `runs[x].tool.driver.semanticVersion` or `runs[x].tool.driver.version`)

### Finding Information

- **finding_info.title**: Created from the rule ID and an optional description
  - Basic: Just the rule ID (example: "CWE-457")
  - With description: Rule ID + description (example: "CWE-457: Use of uninitialized variable")

- **finding_info.desc**: The main description of the issue
  - First choice: Uses `result.message.text`
  - Fallback: Uses code snippet from `result.locations[0].physicalLocation.region.snippet.text`

- **finding_info.created_time**: When the scan was run
  - Uses `runs[x].invocations[].startTimeUtc` converted to milliseconds since 1970
  - If not available, uses current time

- **finding_info.uid**: Generated using FindingUIDGenerator enrichment plugin
  - Format: `boann:sast:<tool-name>:<type>:<value>`
  - Type can be `fingerprint` (when SARIF fingerprints exist) or `hash` (fallback)
  - Value is a SHA-256 hash
  - Example: `boann:sast:snyk:fingerprint:7f3e9c8b2a1d...`
  - Version information is stored separately in enrichments for UID stability

### Vulnerability Details

**OCSF Terminology Note**: In OCSF schema, the term "vulnerabilities" is used broadly to represent both traditional CVEs (Common Vulnerabilities and Exposures) and CWEs (Common Weakness Enumeration). This converter populates the OCSF `vulnerabilities` array with CWE and location information extracted from SARIF results.

If the SARIF result includes CWE or location information, this is added:

- **vulnerabilities[0].cwe.uid**: CWE identifier
  - First looks in `result.properties.cwe`
  - Then looks in the rule definition `rule.properties.cwe`
  - If multiple CWEs exist, they are joined with commas (example: "CWE-457, CWE-789")

- **vulnerabilities[0].affected_code**: Where the issue was found
  - **file**: Path to the file (from `result.locations[0].physicalLocation.artifactLocation.uri`)
  - **start_line**: Starting line number
  - **end_line**: Ending line number

### Enrichments

#### Fingerprints

SARIF files can include fingerprints that help track the same finding across multiple scans.

The converter saves these fingerprints as enrichments:

- **enrichments[0].name**: "fingerprints"
- **enrichments[0].type**: "fingerprints"
- **enrichments[0].value**: "SARIF fingerprints"
- **enrichments[0].data**: The actual fingerprint values
  - Can come from `result.fingerprints` or `result.partialFingerprints`
  - Example: `{"csdiff/v0": "55ebf100...", "csdiff/v1": "2fa0ad58..."}`

#### UID Generation Metadata

When the FindingUIDGenerator plugin is used, it adds metadata about how the UID was generated:

- **enrichments[1].name**: "uid_generation"
- **enrichments[1].data.method**: Generation method (`fingerprint` or `hash`)
- **enrichments[1].data.version**: Version of the generation logic (e.g., `v1`)
- **enrichments[1].data.algorithm**: Hash algorithm used (e.g., `sha256`)

This metadata provides traceability without coupling the version to the UID itself, ensuring UID stability across future changes to generation logic.

## What is NOT Converted (Requires Downstream Enrichment)

The upstream converter focuses on basic, general fields. These fields are not included and should be added during downstream enrichment:

- **Source URL** (`finding_info.src_url`) - **Downstream should add a link to where the original SARIF report is stored.** This allows users to access all the detailed information that was excluded from the conversion (like code flows and column positions).
- **Product and package information** - Organization-specific data about which products and packages are affected. This requires access to build systems or product catalogs.
- **Advanced enrichments** - Organization-specific metadata like SDLC source type (e.g., "Static Application Security Testing (SAST)").

**Why separate upstream and downstream?** The upstream converter remains general and works for any organization using SARIF files. Each organization can then add their own specific information through enrichment plugins during downstream processing.

**Note**: Finding UID generation is handled by the FindingUIDGenerator enrichment plugin and should be configured during the conversion process to ensure proper deduplication.

## Time Format

All timestamps use milliseconds since Unix epoch (January 1, 1970).

Example: `1705314600000` represents January 15, 2024, 10:30:00 UTC

To calculate: `timestamp_in_seconds * 1000`

## Using the Converter

Basic usage:

```python
from converters import SARIFToOCSFConverter

# Without enrichments
converter = SARIFToOCSFConverter()
findings = converter.convert_file('scan.sarif')

# With enrichments
from enrichments import MyEnrichment
converter = SARIFToOCSFConverter(enrichments=[MyEnrichment()])
findings = converter.convert_file('scan.sarif')

# Save to file
converter.save_to_file(findings, 'output.ocsf.json')
```

## Multiple Findings

SARIF files can contain multiple runs and multiple results per run. The converter processes all of them:

- Each run can be from a different tool
- Each result within a run becomes a separate OCSF finding
- All findings are returned in a single list

## Error Handling

If a single result fails to convert, the converter:
1. Logs an error message
2. Continues processing other results
3. Returns all successfully converted findings

This ensures that one bad result doesn't break the entire conversion.
