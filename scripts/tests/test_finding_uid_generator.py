#!/usr/bin/env python3
"""
Unit tests for FindingUIDGenerator enrichment plugin.

Tests UID generation strategies:
- Fingerprint-based approach (with SARIF fingerprints)
- Hash-based approach (without fingerprints)
- Custom UID generators
"""

import hashlib
import pytest
import sys
import os

# Add parent directory to path to import the module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from enrichments import FindingUIDGenerator


@pytest.fixture
def sast_enrichment():
    """Create a SAST UID generator for testing."""
    return FindingUIDGenerator(sdlc_type='sast')


def test_fingerprint_based_uid_generation(sast_enrichment):
    """Test UID generation using SARIF fingerprints."""
    finding = {
        'metadata': {
            'product': {
                'name': 'Snyk'
            }
        },
        'finding_info': {
            'uid': 'PLACEHOLDER_UID',
            'title': 'SNYK-001: SQL Injection',
            'desc': 'SQL injection vulnerability detected',
            'created_time': 1234567890000
        },
        'enrichments': [
            {
                'name': 'fingerprints',
                'type': 'fingerprints',
                'value': 'SARIF fingerprints',
                'data': {
                    '0': '5c975ae0f1a927717531a9dfcc6bb1eefab85450617dc3db295314aa98660978',
                    '1': '424eddda.9bf9da8e.8d277033.1c2a3430.c9c1f9d4.6c8feca2.f563e0a5.1f55c1aa'
                }
            }
        ]
    }

    result = sast_enrichment.enrich(finding)

    # Should use latest fingerprint (key '1')
    expected_fingerprint = '424eddda.9bf9da8e.8d277033.1c2a3430.c9c1f9d4.6c8feca2.f563e0a5.1f55c1aa'
    expected_hash = hashlib.sha256(expected_fingerprint.encode('utf-8')).hexdigest()
    expected_uid = f'boann:sast:snyk:fingerprint:{expected_hash}'

    assert result['finding_info']['uid'] == expected_uid

    # Verify uid_generation enrichment was added
    uid_enrichment = next((e for e in result['enrichments'] if e.get('name') == 'uid_generation'), None)
    assert uid_enrichment is not None
    assert uid_enrichment['data']['method'] == 'fingerprint'
    assert uid_enrichment['data']['version'] == 'v1'
    assert uid_enrichment['data']['algorithm'] == 'sha256'


def test_hash_based_uid_generation(sast_enrichment):
    """Test UID generation using hash-based approach (no fingerprints)."""
    finding = {
        'metadata': {
            'product': {
                'name': 'Bandit'
            }
        },
        'finding_info': {
            'uid': 'PLACEHOLDER_UID',
            'title': 'CWE-89: SQL injection vulnerability',
            'desc': 'SQL injection vulnerability detected',
            'created_time': 1234567890000
        },
        'vulnerabilities': [
            {
                'affected_code': {
                    'file': 'src/api/query.py',
                    'start_line': 42,
                    'end_line': 45
                }
            }
        ]
    }

    result = sast_enrichment.enrich(finding)

    # Calculate expected hash (using
    title = 'CWE-89: SQL injection vulnerability'
    file_uri = 'src/api/query.py'
    message_text = 'SQL injection vulnerability detected'
    hash_input = '\n'.join([title, file_uri, message_text])
    expected_hash = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
    expected_uid = f'boann:sast:bandit:hash:{expected_hash}'

    assert result['finding_info']['uid'] == expected_uid

    # Verify uid_generation enrichment was added
    uid_enrichment = next((e for e in result.get('enrichments', []) if e.get('name') == 'uid_generation'), None)
    assert uid_enrichment is not None
    assert uid_enrichment['data']['method'] == 'hash'
    assert uid_enrichment['data']['version'] == 'v1'
    assert uid_enrichment['data']['algorithm'] == 'sha256'


def test_fingerprint_selection_alphabetical_order(sast_enrichment):
    """Test that fingerprints are selected in alphabetical order (latest)."""
    finding = {
        'metadata': {
            'product': {
                'name': 'TestTool'
            }
        },
        'finding_info': {
            'uid': 'PLACEHOLDER_UID',
            'title': 'TEST-001',
            'desc': 'Test finding'
        },
        'enrichments': [
            {
                'name': 'fingerprints',
                'data': {
                    'csdiff/v0': 'hash0',
                    'csdiff/v1': 'hash1',
                    'csdiff/v2': 'hash2'
                }
            }
        ]
    }

    result = sast_enrichment.enrich(finding)

    # Should select 'csdiff/v2' (alphabetically last)
    expected_hash = hashlib.sha256('hash2'.encode('utf-8')).hexdigest()
    expected_uid = f'boann:sast:testtool:fingerprint:{expected_hash}'

    assert result['finding_info']['uid'] == expected_uid


def test_tool_name_normalization(sast_enrichment):
    """Test that tool names are normalized (lowercased, spaces to hyphens)."""
    finding = {
        'metadata': {
            'product': {
                'name': 'My Super Tool'
            }
        },
        'finding_info': {
            'uid': 'PLACEHOLDER_UID',
            'title': 'TEST-001',
            'desc': 'Test finding'
        }
    }

    result = sast_enrichment.enrich(finding)

    # Tool name should be normalized to 'my-super-tool'
    assert ':my-super-tool:' in result['finding_info']['uid']


def test_tool_name_normalization_with_special_chars(sast_enrichment):
    """Test that tool names with special characters are normalized correctly."""
    test_cases = [
        ('Tool:With:Colons', 'tool-with-colons'),
        ('Tool::Multiple::Colons', 'tool-multiple-colons'),
        ('Tool @#$ Special!', 'tool-special'),
        ('Tool___With___Underscores', 'tool-with-underscores'),
        ('---Leading-Trailing---', 'leading-trailing'),
        ('Tool/With/Slashes', 'tool-with-slashes'),
        ('Tool.With.Dots', 'tool-with-dots'),
    ]

    for input_name, expected_normalized in test_cases:
        finding = {
            'metadata': {
                'product': {
                    'name': input_name
                }
            },
            'finding_info': {
                'uid': 'PLACEHOLDER_UID',
                'title': 'TEST-001',
                'desc': 'Test finding'
            }
        }

        result = sast_enrichment.enrich(finding)

        # Tool name should be normalized correctly
        assert f':{expected_normalized}:' in result['finding_info']['uid'], \
            f"Expected '{expected_normalized}' in UID for input '{input_name}', got: {result['finding_info']['uid']}"


def test_custom_uid_generator():
    """Test using a custom UID generator function."""
    def custom_generator(finding):
        jira_key = finding.get('jira_key', 'UNKNOWN')
        return f'jira:key:{jira_key}'

    enrichment = FindingUIDGenerator(
        sdlc_type='pentest',
        uid_generator=custom_generator
    )

    finding = {
        'jira_key': 'RHEL-12345',
        'finding_info': {
            'uid': 'PLACEHOLDER_UID'
        }
    }

    result = enrichment.enrich(finding)

    expected_uid = 'boann:pentest:jira:key:RHEL-12345'
    assert result['finding_info']['uid'] == expected_uid


def test_custom_sdlc_type():
    """Test using different SDLC types."""
    enrichment = FindingUIDGenerator(sdlc_type='dast')

    finding = {
        'metadata': {
            'product': {
                'name': 'ZAP'
            }
        },
        'finding_info': {
            'uid': 'PLACEHOLDER_UID',
            'title': 'XSS-001',
            'desc': 'Cross-site scripting'
        }
    }

    result = enrichment.enrich(finding)

    # Should use 'dast' as SDLC type
    assert ':dast:' in result['finding_info']['uid']
    # Should use 'boann' as prefix
    assert result['finding_info']['uid'].startswith('boann:')


def test_sdlc_type_normalization():
    """Test that SDLC types with special characters are normalized correctly."""
    test_cases = [
        ('SAST', 'sast'),
        ('Pen:Test', 'pen-test'),
        ('Security::Review', 'security-review'),
        ('DAST/Dynamic', 'dast-dynamic'),
        ('SAR_2024', 'sar-2024'),
    ]

    for input_sdlc, expected_normalized in test_cases:
        def dummy_generator(finding):
            return 'test:uid:123'

        enrichment = FindingUIDGenerator(sdlc_type=input_sdlc, uid_generator=dummy_generator)

        finding = {
            'finding_info': {
                'uid': 'PLACEHOLDER_UID'
            }
        }

        result = enrichment.enrich(finding)

        # SDLC type should be normalized correctly
        assert f':{expected_normalized}:' in result['finding_info']['uid'], \
            f"Expected '{expected_normalized}' in UID for input '{input_sdlc}', got: {result['finding_info']['uid']}"


def test_boann_prefix_always_used(sast_enrichment):
    """Test that 'boann' prefix is always used."""
    finding = {
        'metadata': {
            'product': {
                'name': 'SonarQube'
            }
        },
        'finding_info': {
            'uid': 'PLACEHOLDER_UID',
            'title': 'SONAR-001',
            'desc': 'Test finding'
        }
    }

    result = sast_enrichment.enrich(finding)

    # Should always start with 'boann:'
    assert result['finding_info']['uid'].startswith('boann:')


def test_hash_generation_with_empty_fields(sast_enrichment):
    """Test hash-based UID generation with some empty fields."""
    finding = {
        'metadata': {
            'product': {
                'name': 'TestTool'
            }
        },
        'finding_info': {
            'uid': 'PLACEHOLDER_UID',
            'title': 'RULE-001',
            'desc': ''  # Empty description
        },
        'vulnerabilities': []  # No vulnerabilities
    }

    result = sast_enrichment.enrich(finding)

    # Should still generate a UID even with empty fields
    assert result['finding_info']['uid'] is not None
    assert ':hash:' in result['finding_info']['uid']


def test_error_handling_invalid_finding(sast_enrichment):
    """Test that enrichment handles invalid findings gracefully."""
    finding = {}  # Missing finding_info

    result = sast_enrichment.enrich(finding)

    # Should create finding_info and set a UID (even if not ideal)
    assert 'finding_info' in result
    assert 'uid' in result['finding_info']


def test_enrichment_preserves_other_fields(sast_enrichment):
    """Test that enrichment only updates UID and preserves other fields."""
    finding = {
        'metadata': {
            'product': {
                'name': 'TestTool'
            }
        },
        'finding_info': {
            'uid': 'PLACEHOLDER_UID',
            'title': 'TEST-001',
            'desc': 'Test finding',
            'created_time': 1234567890000,
            'custom_field': 'custom_value'
        },
        'severity': 'High',
        'severity_id': 5
    }

    result = sast_enrichment.enrich(finding)

    # Should preserve all original fields
    assert result['finding_info']['title'] == 'TEST-001'
    assert result['finding_info']['desc'] == 'Test finding'
    assert result['finding_info']['created_time'] == 1234567890000
    assert result['finding_info']['custom_field'] == 'custom_value'
    assert result['severity'] == 'High'
    assert result['severity_id'] == 5

    # Should update UID
    assert result['finding_info']['uid'] != 'PLACEHOLDER_UID'


def test_empty_fingerprints_falls_back_to_hash(sast_enrichment):
    """Test that empty fingerprints dictionary falls back to hash-based approach."""
    finding = {
        'metadata': {
            'product': {
                'name': 'TestTool'
            }
        },
        'finding_info': {
            'uid': 'PLACEHOLDER_UID',
            'title': 'TEST-001',
            'desc': 'Test finding'
        },
        'enrichments': [
            {
                'name': 'fingerprints',
                'data': {}  # Empty fingerprints
            }
        ]
    }

    result = sast_enrichment.enrich(finding)

    # Should fall back to hash-based approach
    assert ':hash:' in result['finding_info']['uid']


def test_get_name(sast_enrichment):
    """Test that get_name returns the correct plugin name."""
    assert sast_enrichment.get_name() == 'FindingUIDGenerator'
