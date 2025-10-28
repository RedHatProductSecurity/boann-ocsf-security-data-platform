# AGENTS.md

Guidelines for AI assistants (Claude, Cursor, GitHub Copilot, etc.) when working on this project.

## Project Overview

The Boann OCSF Security Data Platform provides tools and converters for processing security findings into the OCSF (Open Cybersecurity Schema Framework) format.

**Key Components:**
- SARIF to OCSF conversion (`scripts/converters/`)
- Enrichment plugin system (`scripts/enrichments/`)
- Database ingestion with PostgreSQL
- File monitoring for automated processing

**Testing:** pytest with fixtures and parametrized tests

See [README.md](README.md) for full project details.

## Development Setup

To run tests, install development dependencies:

```bash
# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies including pytest and pytest-cov
pip install -r requirements-dev.txt
```

See [scripts/README.md](scripts/README.md#development-setup) for complete setup instructions.

## Testing Guidelines

### Focus on Behavior, Not Implementation

Test **what the code does** (observable outcomes), not **how it does it** (internal implementation).

**Good - Tests meaningful behavior:**
```python
def test_severity_error_maps_to_high():
    """Test that SARIF error level maps to OCSF High severity."""
    result = {'level': 'error'}
    severity = converter._extract_severity(result)

    assert severity['id'] == 5
    assert severity['name'] == 'High'
```

**Avoid - Tests language features or obvious behavior:**
```python
def test_multiple_instances_produce_same_result():
    """Test that two instances with same input produce same output."""
    # This tests Python determinism, not business logic
```

### Avoid Redundancy

Before writing a test, check if existing tests already validate the same behavior.

**Ask yourself:**
- Does this test validate a different behavior or outcome than existing tests?
- Does it test a different edge case or scenario?
- Would removing this test reduce confidence in a specific behavior?

If the answer is no to all three, the test is likely redundant.

**Rules:**
- One test per distinct behavior or scenario
- Multiple tests can execute the same code if they test different behaviors
- Don't test Python language features (e.g., string immutability, basic type behavior)

**Check coverage to find gaps:**
```bash
# Check coverage for all tests
pytest scripts/tests/ --cov=scripts --cov-report=term-missing

# Check coverage for specific component
pytest scripts/tests/test_sarif_converter.py --cov=scripts/converters --cov-report=term-missing
```

### What to Test

**DO test:**
- SARIF to OCSF field mappings and transformations
- Enrichment plugin discovery and execution
- Finding UID generation for deduplication
- Database upsert logic
- Edge cases (null, empty, boundary values)
- Error handling and validation
- Configuration from different sources (environment, config file, defaults)

**DON'T test:**
- Python language features (immutability, determinism)
- Trivial getters/setters without logic
- Multiple tests for the same code path
- Obvious behavior that doesn't add value

### Test Naming

Use descriptive names that explain the behavior being tested:

```
test_<what>_<scenario>
```

**Examples:**
- `test_fingerprint_based_uid_generation`
- `test_enrichment_preserves_other_fields`
- `test_severity_error_maps_to_high`
- `test_ingest_file_success`
- `test_empty_fingerprints_falls_back_to_hash`

### Use Parametrized Tests

Use `@pytest.mark.parametrize` to test multiple scenarios efficiently:

```python
@pytest.mark.parametrize("level,expected_id,expected_name", [
    ('error', 5, 'High'),
    ('warning', 4, 'Medium'),
    ('note', 2, 'Informational'),
    ('none', 1, 'Unknown'),
    (None, 1, 'Unknown'),
])
def test_severity_mapping(converter, level, expected_id, expected_name):
    """Test severity mapping for all SARIF levels."""
    result = {'level': level} if level is not None else {}
    severity = converter._extract_severity(result)
    assert severity['id'] == expected_id
    assert severity['name'] == expected_name
```

### Use Fixtures for Reusable Components

Create fixtures for common test setup:

```python
@pytest.fixture
def converter():
    """Provide a SARIF converter instance."""
    return SARIFToOCSFConverter()
```

## Best Practices

### Test Organization

- **Location**: Place tests in `scripts/tests/`
- **Naming**: `test_<component>.py` (e.g., `test_sarif_converter.py`)
- **Fixtures**: Store test data in `scripts/tests/fixtures/`

### Running Tests

```bash
# Run all tests
pytest scripts/tests/

# Run specific test file
pytest scripts/tests/test_sarif_converter.py

# Run with coverage
pytest scripts/tests/ --cov=scripts --cov-report=term-missing

# Run specific test
pytest scripts/tests/test_sarif_converter.py::test_severity_mapping
```

### Coverage Guidelines

- Check coverage before submitting: `pytest --cov=scripts --cov-report=term-missing`
- Focus on meaningful coverage of business logic
- Converters and enrichments should have high coverage
- Skip coverage on CLI boilerplate and trivial code

### Before Submitting Tests

1. Run all tests and verify they pass
2. Check coverage to ensure tests contribute value
3. Remove redundant tests that validate the same behavior
4. Ensure test names clearly describe what behavior is tested
5. Add docstrings explaining the test scenario
6. Verify tests focus on business logic, not implementation details
